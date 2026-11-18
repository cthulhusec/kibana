/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Support for the scheduling cases: saved `si-test-` copies (create, enable, disable, hard delete),
 * execution documents read from `.workflows-executions` (scheduled and skipped runs never pass
 * through the harness), bounded polling, and the pure evaluation of the observed runs.
 */

import type { EsClient, KibanaClient } from '../clients';
import { HttpError, isTerminalStatus } from '../clients';
import { WORKFLOW_EXECUTIONS_INDEX, scheduledTaskDocPath } from '../expected/sc';
import { msBetween } from './evidence_support';

export interface Clock {
  readonly sleep: (ms: number) => Promise<void>;
  readonly now: () => number;
}

export const realClock: Clock = {
  sleep: (ms) =>
    new Promise((resolve) => {
      setTimeout(resolve, ms);
    }),
  now: () => Date.now(),
};

/** Reads until `done` holds or `timeoutMs` passes; returns the last value either way. */
export const pollUntil = async <T>(
  read: () => Promise<T>,
  done: (value: T) => boolean,
  { timeoutMs, intervalMs }: { timeoutMs: number; intervalMs: number },
  clock: Clock
): Promise<{ value: T; timedOut: boolean }> => {
  const deadline = clock.now() + timeoutMs;
  for (;;) {
    const value = await read();
    if (done(value)) return { value, timedOut: false };
    if (clock.now() >= deadline) return { value, timedOut: true };
    await clock.sleep(intervalMs);
  }
};

// -------------------------------------------------------------------------------------------------
// Saved copies
// -------------------------------------------------------------------------------------------------

export const createWorkflowCopy = async (
  kibana: KibanaClient,
  { id, yaml }: { id: string; yaml: string }
): Promise<void> => {
  await kibana.request('POST', '/api/workflows/workflow', { body: { id, yaml } });
};

/** `PUT /api/workflows/workflow/{id}` with `enabled` only (allowed for managed workflows too). */
export const setWorkflowEnabled = async (
  kibana: KibanaClient,
  id: string,
  enabled: boolean
): Promise<void> => {
  await kibana.request('PUT', `/api/workflows/workflow/${encodeURIComponent(id)}`, {
    body: { enabled },
  });
};

/** Hard delete; also removes the workflow's executions. Returns false when it did not exist. */
export const hardDeleteWorkflow = async (kibana: KibanaClient, id: string): Promise<boolean> => {
  const { status } = await kibana.request(
    'DELETE',
    `/api/workflows/workflow/${encodeURIComponent(id)}`,
    {
      query: { force: true, acknowledgeAclLoss: true },
      allowStatuses: [404],
    }
  );
  return status !== 404;
};

/** Disables and hard-deletes each copy; never throws, returns one note per action. */
export const cleanupCopies = async (
  kibana: KibanaClient,
  ids: readonly string[]
): Promise<string[]> => {
  const notes: string[] = [];
  for (const id of ids) {
    try {
      await setWorkflowEnabled(kibana, id, false);
    } catch (error) {
      if (!(error instanceof HttpError && error.status === 404)) {
        notes.push(`cleanup: disabling ${id} failed: ${(error as Error).message}`);
      }
    }
    try {
      if (await hardDeleteWorkflow(kibana, id)) notes.push(`cleanup: deleted ${id} (force=true)`);
    } catch (error) {
      notes.push(`cleanup: deleting ${id} FAILED, delete it by hand: ${(error as Error).message}`);
    }
  }
  return notes;
};

export const taskExists = (es: EsClient, workflowId: string): Promise<boolean> =>
  es.exists(scheduledTaskDocPath(workflowId));

// -------------------------------------------------------------------------------------------------
// Executions
// -------------------------------------------------------------------------------------------------

export interface ExecutionDoc {
  readonly id: string;
  readonly workflowId?: string;
  readonly status: string;
  readonly triggeredBy?: string;
  readonly isTestRun?: boolean;
  readonly createdAt?: string;
  readonly startedAt?: string;
  readonly finishedAt?: string;
}

type ExecutionSource = Omit<ExecutionDoc, 'id'>;

/** Executions of `workflowId` created at or after `since`, oldest first. */
export const listExecutions = async (
  es: EsClient,
  { workflowId, since }: { workflowId: string; since: string }
): Promise<ExecutionDoc[]> => {
  const response = await es.search<ExecutionSource>(WORKFLOW_EXECUTIONS_INDEX, {
    size: 100,
    sort: [{ createdAt: 'asc' }],
    _source: [
      'workflowId',
      'status',
      'triggeredBy',
      'isTestRun',
      'createdAt',
      'startedAt',
      'finishedAt',
    ],
    query: {
      bool: {
        filter: [{ term: { workflowId } }, { range: { createdAt: { gte: since } } }],
      },
    },
  });
  return response.hits.hits.flatMap((hit) =>
    hit._source ? [{ ...hit._source, id: hit._id, status: hit._source.status ?? 'unknown' }] : []
  );
};

export const describeRun = (run: ExecutionDoc): string =>
  `${run.id} ${run.triggeredBy ?? '?'} ${run.status} created ${run.createdAt ?? '-'} started ${
    run.startedAt ?? '-'
  } finished ${run.finishedAt ?? '-'}`;

const scheduledTerminal = (runs: readonly ExecutionDoc[]): ExecutionDoc[] =>
  runs.filter((run) => run.triggeredBy === 'scheduled' && isTerminalStatus(run.status));

export const hasScheduledRuns = (runs: readonly ExecutionDoc[], count: number): boolean =>
  scheduledTerminal(runs).length >= count;

/** SC-1: the first `runs` scheduled runs: timely first run, regular cadence, all completed. */
export const evaluateScheduledRuns = (
  runs: readonly ExecutionDoc[],
  {
    enabledAt,
    runs: expectedRuns,
    firstRunWithinMs,
    gapMinMs,
    gapMaxMs,
  }: {
    enabledAt: string;
    runs: number;
    firstRunWithinMs: number;
    gapMinMs: number;
    gapMaxMs: number;
  }
): string[] => {
  const scheduled = scheduledTerminal(runs).slice(0, expectedRuns);
  if (scheduled.length < expectedRuns) {
    return [`expected ${expectedRuns} finished scheduled runs, got ${scheduled.length}`];
  }
  const diffs: string[] = [];
  const firstDelay = msBetween(enabledAt, scheduled[0].createdAt);
  if (!(firstDelay <= firstRunWithinMs)) {
    diffs.push(
      `first scheduled run created ${firstDelay}ms after enabling (limit ${firstRunWithinMs}ms)`
    );
  }
  scheduled.slice(1).forEach((run, index) => {
    const gap = msBetween(scheduled[index].createdAt, run.createdAt);
    if (!(gap >= gapMinMs && gap <= gapMaxMs)) {
      diffs.push(
        `scheduled runs ${index + 1} and ${
          index + 2
        } are ${gap}ms apart (expected ${gapMinMs}..${gapMaxMs}ms)`
      );
    }
  });
  scheduled.forEach((run) => {
    if (run.status !== 'completed') diffs.push(`scheduled run ${run.id}: status ${run.status}`);
    if (run.isTestRun === true) diffs.push(`scheduled run ${run.id}: isTestRun true`);
  });
  return diffs;
};

export const hasDropEvidence = (runs: readonly ExecutionDoc[]): boolean =>
  runs.some((run) => run.status === 'skipped') && runs.some((run) => run.status === 'completed');

/** SC-3: one run held the slot for the wait, and an overlapping run was `skipped` without starting. */
export const evaluateDropRuns = (runs: readonly ExecutionDoc[], waitMs: number): string[] => {
  const holder = runs.find((run) => run.status === 'completed' && run.startedAt && run.finishedAt);
  const skipped = runs.filter((run) => run.status === 'skipped');
  const diffs: string[] = [];
  if (!holder) return ['no completed run held the concurrency slot'];
  const held = msBetween(holder.startedAt, holder.finishedAt);
  if (!(held >= waitMs - 1000))
    diffs.push(`holder ${holder.id} ran ${held}ms, less than the ${waitMs}ms wait`);
  if (skipped.length === 0) return [...diffs, 'no run was skipped'];
  const overlapping = skipped.filter(
    (run) =>
      msBetween(holder.startedAt, run.createdAt) >= 0 &&
      msBetween(run.createdAt, holder.finishedAt) >= 0
  );
  if (overlapping.length === 0) diffs.push('no skipped run was created while the holder ran');
  skipped
    .filter((run) => run.startedAt !== undefined)
    .forEach((run) => diffs.push(`skipped run ${run.id} has startedAt ${run.startedAt}`));
  return diffs;
};
