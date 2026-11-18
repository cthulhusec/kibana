/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Test doubles for the DO and DI case tests: a fake Elasticsearch "world" built from the same
 * expected values the cases assert on, scripted workflow runs, and a fake `CaseContext`. Only the
 * tests import this module.
 */

import { CATALOG_INDEX, EVENTS_INDEX, INSTANCES_INDEX } from '../../../common/constants';
import type { InventoryEvent } from '../../../common/history';
import type { CatalogEntry, InstanceDoc } from '../../../common/types';
import type { ExpectedCatalogEntry, ExpectedEvent, ExpectedInstance } from '../assertions';
import { ingestOutput } from '../assertions';
import type {
  CompletedRun,
  EsClient,
  JsonValue,
  KibanaClient,
  StepExecutionDetail,
  StepExecutionSummary,
  WorkflowExecution,
} from '../clients';
import type { IngestExpectation, OsqueryRunExpectation } from '../expected/do';
import { INGEST_STEP_OF, QUERY_KEYS, QUERY_STEP_OF } from '../expected/do';
import { instanceIdFor, parseCatalogId } from '../ids';
import type { CaseContext, CaseRecord, RunWorkflowArgs } from './types';

const NOW = '2026-11-18T10:00:00.000Z';

export interface World {
  readonly instances: readonly ExpectedInstance[];
  readonly catalog: readonly ExpectedCatalogEntry[];
  readonly events: readonly ExpectedEvent[];
  /** Counts for `es.count`; defaults to 0 (so "no unexpected writes" holds). */
  readonly count?: (index: string, query: object) => number;
  /** Whether `es.exists` finds the path (for example `/.fleet-agents`). */
  readonly exists?: (path: string) => boolean;
}

export const instanceDoc = (expected: ExpectedInstance): InstanceDoc => {
  const { version } = parseCatalogId(expected.catalogId);
  return {
    id: instanceIdFor(expected),
    host: {
      key: expected.hostKey,
      id: expected.hostId ?? expected.hostKey,
      ...(expected.hostName ? { name: expected.hostName } : {}),
    },
    software_id: expected.catalogId,
    ...(expected.previousSoftwareId ? { previous_software_id: expected.previousSoftwareId } : {}),
    version_history: (expected.versions ?? [version]).map((item) => ({
      version: item,
      software_id: expected.catalogId,
      first_seen: NOW,
      last_seen: NOW,
    })),
    ...(expected.installPath ? { install_path: expected.installPath } : {}),
    sources: [...(expected.sources ?? ['osquery'])],
    status: expected.status ?? 'active',
    first_seen: NOW,
    last_seen: NOW,
    ...(expected.previousSoftwareId ? { version_changed_at: NOW } : {}),
    exposure: { level: expected.exposureLevel ?? 'none', score: 0, evidence: [] },
    '@timestamp': NOW,
  };
};

export const catalogDoc = ({ id, fields }: ExpectedCatalogEntry): CatalogEntry => {
  const { vendor, product, version } = parseCatalogId(id);
  return {
    id,
    vendor,
    product,
    version,
    display_name: product,
    category: 'application',
    cve_count: 0,
    known_exploited: false,
    cve_ids: [],
    '@timestamp': NOW,
    ...fields,
  } as CatalogEntry;
};

export const eventDoc = (expected: ExpectedEvent): InventoryEvent =>
  ({
    '@timestamp': NOW,
    instance_id: 'instance',
    host: { key: 'host' },
    source: 'osquery',
    software_id: 'software',
    ...expected,
  } as InventoryEvent);

/** A fake `EsClient` that serves the world; `world` may depend on how many workflows ran so far. */
export const fakeEs = (worldOf: () => World): EsClient => {
  const fake = {
    mget: async (index: string, ids: readonly string[]) => {
      const world = worldOf();
      const docs: Array<{ _id: string; found?: boolean; _source?: object }> =
        index === INSTANCES_INDEX
          ? world.instances.map((item) => ({
              _id: instanceIdFor(item),
              _source: instanceDoc(item),
            }))
          : index === CATALOG_INDEX
          ? world.catalog.map((item) => ({ _id: item.id, _source: catalogDoc(item) }))
          : [];
      return {
        docs: ids.map((id) => {
          const found = docs.find(({ _id }) => _id === id);
          return found ? { ...found, found: true } : { _id: id, found: false };
        }),
      };
    },
    search: async (index: string) => ({
      hits: {
        hits:
          index === EVENTS_INDEX
            ? worldOf().events.map((item, position) => ({
                _id: String(position),
                _index: index,
                _source: eventDoc(item),
              }))
            : [],
      },
    }),
    count: async (index: string, query: object) => worldOf().count?.(index, query) ?? 0,
    exists: async (path: string) => worldOf().exists?.(path) ?? false,
  };
  return fake as unknown as EsClient;
};

export interface FakeStep {
  readonly name: string;
  readonly status?: string;
  readonly input?: JsonValue;
  readonly output?: JsonValue;
  readonly error?: JsonValue;
  readonly startedAt?: string;
  readonly finishedAt?: string;
}

/** A completed run whose steps and step details are scripted. */
export const fakeRun = ({
  workflowId,
  status = 'completed',
  steps,
  executionId = 'exec-1',
}: {
  workflowId: string;
  status?: string;
  steps: readonly FakeStep[];
  executionId?: string;
}): CompletedRun => {
  const summaries: StepExecutionSummary[] = steps.map((step) => ({
    id: `${step.name}-exec`,
    stepId: step.name,
    status: step.status ?? 'completed',
    ...(step.error !== undefined ? { error: step.error } : {}),
    ...(step.startedAt ? { startedAt: step.startedAt } : {}),
    ...(step.finishedAt ? { finishedAt: step.finishedAt } : {}),
  }));
  const execution: WorkflowExecution = {
    id: executionId,
    workflowId,
    status,
    isTestRun: true,
    stepExecutions: summaries,
  };
  return {
    executionId,
    execution,
    stepsByName: new Map(summaries.map((summary) => [summary.stepId, summary])),
    step: async (name) => {
      const index = steps.findIndex((step) => step.name === name);
      if (index < 0) throw new Error(`Step "${name}" did not run`);
      const detail: StepExecutionDetail = {
        ...summaries[index],
        ...(steps[index].input !== undefined ? { input: steps[index].input } : {}),
        ...(steps[index].output !== undefined ? { output: steps[index].output } : {}),
      };
      return detail;
    },
  };
};

const candidates = (count: number): JsonValue[] => Array.from({ length: count }, () => ({}));

export const ingestStep = (
  name: string,
  { output, snapshot, candidates: count }: IngestExpectation,
  source = 'osquery',
  extra: Partial<FakeStep> = {}
): FakeStep => ({
  name,
  input: { source, snapshot, candidates: candidates(count) },
  output: ingestOutput(output),
  ...extra,
});

/** The twelve steps of a `discover-osquery` run that behaves as `expectation` says. */
export const scriptedOsqueryRun = (
  expectation: OsqueryRunExpectation,
  workflowId = 'system-security-software-inventory-discover-osquery',
  tweak: (steps: FakeStep[]) => FakeStep[] = (steps) => steps
): CompletedRun =>
  fakeRun({
    workflowId,
    steps: tweak(
      QUERY_KEYS.flatMap((key): FakeStep[] => {
        const failed = expectation.failedQueries?.includes(key) === true;
        const ingest = expectation.ingest[key] ?? {
          output: {},
          snapshot: !failed,
          candidates: 0,
        };
        return [
          failed
            ? { name: QUERY_STEP_OF[key], status: 'failed', error: { message: 'boom' } }
            : { name: QUERY_STEP_OF[key], output: {} },
          { name: `build_${key}`, output: {} },
          ingestStep(INGEST_STEP_OF[key], ingest),
        ];
      })
    ),
  });

export const fakeRecord = (id: string, executionIds: readonly string[]): CaseRecord => ({
  id,
  family: 'DO',
  title: id,
  status: 'pass',
  layers: [],
  startedAt: NOW,
  durationMs: 1,
  executionIds,
});

export interface FakeContextOptions {
  /** Called for each `runWorkflow`; returns the scripted run. */
  readonly runs: ReadonlyArray<CompletedRun | ((args: RunWorkflowArgs) => CompletedRun)>;
  readonly world: World | ((runsDone: number) => World);
  readonly priorResults?: ReadonlyMap<string, CaseRecord>;
  readonly t0?: Date;
  /** Runs `getExecution` returns, by execution id. */
  readonly executions?: Readonly<Record<string, CompletedRun>>;
  readonly kibanaRequest?: (
    method: string,
    path: string
  ) => Promise<{ status: number; body: object }>;
}

export interface FakeContext {
  readonly ctx: CaseContext;
  readonly calls: RunWorkflowArgs[];
  readonly logDocs: unknown[][];
}

export const fakeContext = ({
  runs,
  world,
  priorResults = new Map(),
  t0 = new Date(),
  executions = {},
  kibanaRequest,
}: FakeContextOptions): FakeContext => {
  const calls: RunWorkflowArgs[] = [];
  const logDocs: unknown[][] = [];
  const queue = [...runs];
  const worldOf = (): World => (typeof world === 'function' ? world(calls.length) : world);
  const kibana = {
    request: async (method: string, path: string) => {
      if (!kibanaRequest) throw new Error('unexpected kibana.request');
      return kibanaRequest(method, path);
    },
    getExecution: async (id: string): Promise<WorkflowExecution> => {
      const run = executions[id];
      if (!run) throw new Error(`no execution ${id}`);
      return run.execution;
    },
    getStepExecution: async (executionId: string, stepExecutionId: string) => {
      const run = executions[executionId];
      const name = stepExecutionId.replace(/-exec$/, '');
      if (!run) throw new Error(`no execution ${executionId}`);
      return run.step(name);
    },
  };
  const ctx = {
    config: {},
    kibana: kibana as unknown as KibanaClient,
    es: fakeEs(worldOf),
    t0,
    log: { info: () => {}, warn: () => {}, debug: () => {} },
    priorResults,
    runWorkflow: async (args: RunWorkflowArgs) => {
      calls.push(args);
      const next = queue.shift();
      if (!next) throw new Error('unexpected runWorkflow call');
      return typeof next === 'function' ? next(args) : next;
    },
    writeLogs: async () => ({ written: 0, existing: 0 }),
    writeLogDocs: async (docs: readonly unknown[]) => {
      logDocs.push([...docs]);
      return { written: docs.length, existing: 0 };
    },
  } as unknown as CaseContext;
  return { ctx, calls, logDocs };
};
