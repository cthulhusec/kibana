/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * SC: scheduling, concurrency, and failure injection (SC-1..SC-9 in docs/discovery_test_plan.md).
 *
 * The managed workflows stay disabled except in SC-9 (enable then disable `discover-integrations`,
 * harmless while Fleet is empty). Scheduling cases enable saved `si-test-` COPIES in the default
 * space (global workflows are never scheduled) and always disable and hard-delete them in a
 * `finally` block. SC-7 and SC-8 need a Kibana restart (and SC-8 explicit approval): they return
 * `blocked` with the manual procedure.
 */

import { parse } from 'yaml';
import type { LayerResult } from '../assertions';
import { checkEngine, checkSteps, ingestOutput, layerResult } from '../assertions';
import type { CompletedRun } from '../clients';
import {
  OSQUERY_CONCURRENCY_KEY,
  SC1,
  SC3,
  SC4,
  SC6,
  SC7_PROCEDURE,
  SC8_PROCEDURE,
  SC9,
  SC_COPY_IDS,
  WORKFLOWS_INDEX,
} from '../expected/sc';
import { PRODUCTION_WORKFLOWS, getWorkflowId } from '../variants/build_variant';
import type { WorkflowKey } from '../variants/build_variant';
import { buildOsqueryVariant } from '../variants/osquery';
import type { Clock, ExecutionDoc } from './sc_support';
import {
  cleanupCopies,
  createWorkflowCopy,
  describeRun,
  evaluateDropRuns,
  evaluateScheduledRuns,
  hasDropEvidence,
  hasScheduledRuns,
  listExecutions,
  pollUntil,
  realClock,
  setWorkflowEnabled,
  taskExists,
} from './sc_support';
import type { CaseContext, CaseResult, TestCase } from './types';
import { blockedResult, caseResult } from './types';

const DEFAULT_SPACE_REASON =
  'Scheduled triggers are verified in the default space only; run with --space default.';

const isoAt = (clock: Clock, offsetMs = 0): string =>
  new Date(clock.now() + offsetMs).toISOString();

const waitStep = (duration: string, extra: object = {}) => ({
  kind: 'step' as const,
  step: { type: 'wait', with: { duration }, 'on-failure': { continue: true }, ...extra },
});

/** Creates and enables a copy, runs `body`, and always disables and deletes the copy. */
const withEnabledCopy = async (
  ctx: CaseContext,
  { id, yaml }: { id: string; yaml: string },
  body: (enabledAt: string) => Promise<LayerResult[]>,
  clock: Clock
): Promise<CaseResult> => {
  const notes: string[] = [];
  let layers: LayerResult[] = [];
  try {
    notes.push(...(await cleanupCopies(ctx.kibana, [id])).map((note) => `pre-clean: ${note}`));
    await createWorkflowCopy(ctx.kibana, { id, yaml });
    const enabledAt = isoAt(clock, -1000);
    await setWorkflowEnabled(ctx.kibana, id, true);
    layers = await body(enabledAt);
  } finally {
    notes.push(...(await cleanupCopies(ctx.kibana, [id])));
  }
  return caseResult(layers, notes);
};

const sc1 =
  (clock: Clock) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    if (ctx.config.space !== 'default') return blockedResult(DEFAULT_SPACE_REASON);
    const id = SC_COPY_IDS.sched;
    const yaml = buildOsqueryVariant({
      label: 'SC-1 scheduled',
      steps: {},
      every: SC1.every,
      concurrencyKey: SC1.concurrencyKey,
    });
    return withEnabledCopy(
      ctx,
      { id, yaml },
      async (enabledAt) => {
        const taskAfterEnable = await taskExists(ctx.es, id);
        const { value: runs } = await pollUntil(
          () => listExecutions(ctx.es, { workflowId: id, since: enabledAt }),
          (value) => hasScheduledRuns(value, SC1.runs),
          { timeoutMs: SC1.timeoutMs, intervalMs: 5000 },
          clock
        );
        await setWorkflowEnabled(ctx.kibana, id, false);
        const { value: taskLeft } = await pollUntil(
          () => taskExists(ctx.es, id),
          (exists) => !exists,
          { timeoutMs: 30_000, intervalMs: 2000 },
          clock
        );
        return [
          layerResult('engine', evaluateScheduledRuns(runs, { enabledAt, ...SC1 }), SC1.runs * 2, {
            runs: runs.map(describeRun),
          }),
          layerResult(
            'harness',
            [
              ...(taskAfterEnable ? [] : ['no scheduled task after enabling']),
              ...(taskLeft ? ['scheduled task still present after disabling'] : []),
            ],
            2
          ),
        ];
      },
      clock
    );
  };

interface StoredWorkflowDoc {
  readonly spaceId?: string;
  readonly enabled?: boolean;
  readonly yaml?: string;
}

const sc2 = async (ctx: CaseContext): Promise<CaseResult> => {
  const response = await ctx.es.search<StoredWorkflowDoc>(WORKFLOWS_INDEX, {
    size: 20,
    _source: ['spaceId', 'enabled', 'yaml'],
    query: { term: { managedBy: 'softwareInventory' } },
  });
  const byId = new Map(response.hits.hits.map((hit) => [hit._id, hit._source]));
  const diffs: string[] = [];
  for (const key of Object.keys(PRODUCTION_WORKFLOWS) as WorkflowKey[]) {
    const id = getWorkflowId(key);
    const doc = byId.get(id);
    if (!doc) {
      diffs.push(`${id}: no stored workflow document`);
      continue;
    }
    if (doc.spaceId !== 'default') diffs.push(`${id}: spaceId ${doc.spaceId}, expected default`);
    const triggers = (parse(doc.yaml ?? '') as { triggers?: Array<{ type?: string }> } | null)
      ?.triggers;
    if (triggers?.[0]?.type !== 'scheduled') diffs.push(`${id}: first trigger is not scheduled`);
    if (doc.enabled === false && (await taskExists(ctx.es, id))) {
      diffs.push(`${id}: disabled but a scheduled task exists`);
    }
  }
  return caseResult(
    [layerResult('harness', diffs, Object.keys(PRODUCTION_WORKFLOWS).length * 3)],
    ['Read-only. Global (spaceId "*") workflows are never scheduled; these five are space-scoped.']
  );
};

const sc3 =
  (clock: Clock) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    if (ctx.config.space !== 'default') return blockedResult(DEFAULT_SPACE_REASON);
    const id = SC_COPY_IDS.drop;
    // Production concurrency settings (key, drop, max 1); a 90 s wait replaces query_linux.
    const yaml = buildOsqueryVariant({
      label: 'SC-3 concurrency drop',
      steps: { query_linux: waitStep(SC3.waitDuration) },
      every: SC3.every,
    });
    return withEnabledCopy(
      ctx,
      { id, yaml },
      async (enabledAt) => {
        const { value: runs } = await pollUntil(
          () => listExecutions(ctx.es, { workflowId: id, since: enabledAt }),
          hasDropEvidence,
          { timeoutMs: SC3.timeoutMs, intervalMs: 5000 },
          clock
        );
        return [
          layerResult('engine', evaluateDropRuns(runs, SC3.waitMs), 4, {
            runs: runs.map(describeRun),
          }),
        ];
      },
      clock
    );
  };

interface HolderOutcome {
  readonly run?: CompletedRun;
  readonly error?: Error;
}

const sc4 =
  (clock: Clock) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    const managedId = getWorkflowId('discoverOsquery');
    const since = isoAt(clock, -1000);
    // The holder keeps the production key's slot for 45 s.
    const holder = ctx
      .runWorkflow({
        workflow: 'discoverOsquery',
        yaml: buildOsqueryVariant({
          label: 'SC-4 slot holder',
          steps: { query_linux: waitStep(SC4.holderWaitDuration) },
        }),
      })
      .then(
        (run): HolderOutcome => ({ run }),
        (error: Error): HolderOutcome => ({ error })
      );
    const { timedOut } = await pollUntil(
      () => listExecutions(ctx.es, { workflowId: managedId, since }),
      (runs: ExecutionDoc[]) =>
        runs.some((run) => run.startedAt !== undefined && run.status === 'running'),
      { timeoutMs: SC4.holderStartTimeoutMs, intervalMs: 1000 },
      clock
    );
    if (timedOut) {
      const settled = await holder;
      return caseResult([
        layerResult(
          'engine',
          [
            `the holder never reached "running" (${
              settled.error?.message ?? settled.run?.execution.status
            })`,
          ],
          1
        ),
      ]);
    }
    const same = await ctx.runWorkflow({
      workflow: 'discoverOsquery',
      yaml: buildOsqueryVariant({ label: 'SC-4 same key', steps: {} }),
    });
    const other = await ctx.runWorkflow({
      workflow: 'discoverOsquery',
      yaml: buildOsqueryVariant({
        label: 'SC-4 other key',
        steps: {},
        concurrencyKey: SC4.otherConcurrencyKey,
      }),
    });
    const settled = await holder;
    const diffs = [
      ...(same.execution.status === 'skipped'
        ? []
        : [`same-key test run: status ${same.execution.status}, expected skipped`]),
      ...(same.execution.startedAt
        ? [`same-key test run has startedAt ${same.execution.startedAt}`]
        : []),
      ...(other.execution.status === 'completed'
        ? []
        : [`other-key test run: status ${other.execution.status}, expected completed`]),
      ...(settled.run?.execution.status === 'completed'
        ? []
        : [
            `holder: ${
              settled.error?.message ?? settled.run?.execution.status
            }, expected completed`,
          ]),
    ];
    return caseResult(
      [
        layerResult('engine', diffs, 4, {
          sameKey: same.execution.status,
          otherKey: other.execution.status,
          holder: settled.run?.execution.status ?? 'error',
        }),
      ],
      [`Both test runs used the production key ${OSQUERY_CONCURRENCY_KEY} except "other key".`]
    );
  };

const sc5 = async (ctx: CaseContext): Promise<CaseResult> => {
  // DO-10 and DL-0 cover this in the plan; the case re-proves it with a DO-10 style variant.
  const run = await ctx.runWorkflow({
    workflow: 'discoverOsquery',
    yaml: buildOsqueryVariant({
      label: 'SC-5 on-failure continue',
      steps: { query_linux: { kind: 'throw' } },
    }),
  });
  const engine = checkEngine(run.execution, { steps: { query_linux: 'failed' } });
  const step = await checkSteps(run, {
    ingest_linux: { output: ingestOutput({}), input: { snapshot: false } },
  });
  const covered = ['DO-10', 'DL-0'].map(
    (id) => `${id}: ${ctx.priorResults.get(id)?.status ?? 'not run'}`
  );
  return caseResult([engine, step], [`Plan coverage: ${covered.join(', ')}`]);
};

const sc6 = async (ctx: CaseContext): Promise<CaseResult> => {
  const run = await ctx.runWorkflow({
    workflow: 'discoverOsquery',
    yaml: buildOsqueryVariant({
      label: 'SC-6 step timeout',
      steps: { query_linux: waitStep(SC6.waitDuration, { timeout: SC6.stepTimeout }) },
    }),
  });
  const queryStatus = run.stepsByName.get('query_linux')?.status ?? 'not run';
  const engineDiffs = [
    ...((SC6.acceptedStepStatuses as readonly string[]).includes(queryStatus)
      ? []
      : [`query_linux: ${queryStatus}, expected ${SC6.acceptedStepStatuses.join(' or ')}`]),
    ...((SC6.acceptedRunStatuses as readonly string[]).includes(run.execution.status)
      ? []
      : [`run status ${run.execution.status}`]),
  ];
  const step = run.stepsByName.has('ingest_linux')
    ? await checkSteps(run, {
        ingest_linux: { output: ingestOutput({}), input: { snapshot: false } },
      })
    : layerResult(
        'step',
        run.execution.status === 'completed' ? ['ingest_linux did not run'] : [],
        1
      );
  return caseResult(
    [
      layerResult('engine', engineDiffs, 2, { queryLinux: queryStatus, run: run.execution.status }),
      step,
    ],
    [`Recorded: query_linux ${queryStatus}, run ${run.execution.status}`]
  );
};

const sc9 =
  (clock: Clock) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    if (ctx.config.space !== 'default') return blockedResult(DEFAULT_SPACE_REASON);
    const id = SC9.workflowId;
    const before = await ctx.kibana.getWorkflow(id);
    if (!before) return blockedResult(`${id} is not installed in this space`);
    if (before.enabled)
      return blockedResult(`${id} is already enabled; the plan expects it disabled`);
    const diffs: string[] = [];
    const notes: string[] = [];
    let runs: ExecutionDoc[] = [];
    try {
      const enabledAt = isoAt(clock, -1000);
      await setWorkflowEnabled(ctx.kibana, id, true);
      if (!(await taskExists(ctx.es, id))) diffs.push('no scheduled task after enabling');
      ({ value: runs } = await pollUntil(
        () => listExecutions(ctx.es, { workflowId: id, since: enabledAt }),
        (value) => hasScheduledRuns(value, 1),
        { timeoutMs: SC9.firstRunWithinMs, intervalMs: 5000 },
        clock
      ));
      const scheduled = runs.filter((run) => run.triggeredBy === 'scheduled');
      if (scheduled.length === 0) diffs.push('no scheduled run appeared after enabling');
      scheduled
        .filter((run) => run.status !== 'completed')
        .forEach((run) => diffs.push(`scheduled run ${run.id}: ${run.status}`));
      await setWorkflowEnabled(ctx.kibana, id, false);
      const { value: taskLeft } = await pollUntil(
        () => taskExists(ctx.es, id),
        (exists) => !exists,
        { timeoutMs: SC9.taskRemovedWithinMs, intervalMs: 2000 },
        clock
      );
      if (taskLeft) diffs.push('scheduled task still present after disabling');
      const after = await ctx.kibana.getWorkflow(id);
      if (after?.enabled !== false) diffs.push(`enabled ${after?.enabled} after disabling`);
      if (after?.definitionHash !== before.definitionHash) {
        diffs.push(`definitionHash changed: ${before.definitionHash} -> ${after?.definitionHash}`);
      }
    } finally {
      const current = await ctx.kibana.getWorkflow(id).catch(() => undefined);
      if (current?.enabled !== false) {
        await setWorkflowEnabled(ctx.kibana, id, false).catch((error: Error) =>
          notes.push(`DISABLE ${id} BY HAND: ${error.message}`)
        );
        notes.push(`finally: disabled ${id}`);
      }
    }
    return caseResult([layerResult('engine', diffs, 6, { runs: runs.map(describeRun) })], notes);
  };

export const createScCases = (clock: Clock = realClock): TestCase[] => [
  {
    id: 'SC-1',
    family: 'SC',
    title: 'Scheduled trigger fires (enabled si-test copy, every 1m, 3 runs)',
    requires: ['T0-3'],
    run: sc1(clock),
  },
  {
    id: 'SC-2',
    family: 'SC',
    title: 'Managed workflows are space-scoped (default), not global (read-only)',
    run: sc2,
  },
  {
    id: 'SC-3',
    family: 'SC',
    title: 'Concurrency drop: overlapping scheduled run is skipped without startedAt',
    requires: ['T0-3'],
    run: sc3(clock),
  },
  {
    id: 'SC-4',
    family: 'SC',
    title: 'A test run shares the concurrency slot; another key runs',
    requires: ['T0-3'],
    run: sc4(clock),
  },
  {
    id: 'SC-5',
    family: 'SC',
    title: 'On-failure continue: run completed with a failed step',
    requires: ['T0-3'],
    run: sc5,
  },
  {
    id: 'SC-6',
    family: 'SC',
    title: 'Step timeout on a 30 s wait replacing query_linux',
    requires: ['T0-3'],
    run: sc6,
  },
  {
    id: 'SC-7',
    family: 'SC',
    title: 'Kibana restart mid-run (manual)',
    run: async () => blockedResult(SC7_PROCEDURE.join('\n')),
  },
  {
    id: 'SC-8',
    family: 'SC',
    title: 'Managed every override reverts after restart (manual, needs approval)',
    run: async () => blockedResult(SC8_PROCEDURE.join('\n')),
  },
  {
    id: 'SC-9',
    family: 'SC',
    title: 'Enable then disable managed discover-integrations via the API',
    run: sc9(clock),
  },
];

export const cases: TestCase[] = createScCases();
