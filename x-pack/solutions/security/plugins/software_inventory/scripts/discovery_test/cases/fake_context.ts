/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Fakes for the EC, E2E, SC, and RG unit tests: a case context whose clients answer from
 * handlers the test provides and fail loudly on anything else.
 */

import type {
  CompletedRun,
  EsClient,
  JsonValue,
  KibanaClient,
  StepExecutionDetail,
  WorkflowExecution,
} from '../clients';
import { toCompletedRun } from '../clients';
import type { NvdStub, RecordedRequest } from '../nvd_stub/server';
import type { CaseContext, CaseRecord, HarnessConfig, RunWorkflowArgs } from './types';

export const TEST_CONFIG: HarnessConfig = {
  kibanaUrl: 'http://kibana.invalid',
  esUrl: 'http://es.invalid',
  username: 'u',
  password: 'p',
  space: 'default',
  resultsDir: '/nonexistent',
  nvdPort: 5699,
};

const unexpected = (name: string) => () =>
  Promise.reject(new Error(`unexpected call to ${name} in a unit test`));

export const fakeEs = (handlers: Partial<EsClient>): EsClient => ({
  request: unexpected('es.request'),
  search: unexpected('es.search'),
  count: unexpected('es.count'),
  mget: unexpected('es.mget'),
  bulk: unexpected('es.bulk'),
  deleteByQuery: unexpected('es.deleteByQuery'),
  exists: unexpected('es.exists'),
  ...handlers,
});

export const fakeKibana = (handlers: Partial<KibanaClient>): KibanaClient => ({
  baseUrl: 'http://kibana.invalid',
  request: unexpected('kibana.request'),
  internalRequest: unexpected('kibana.internalRequest'),
  testRun: unexpected('kibana.testRun'),
  getExecution: unexpected('kibana.getExecution'),
  getStepExecution: unexpected('kibana.getStepExecution'),
  waitForExecution: unexpected('kibana.waitForExecution'),
  listWorkflows: unexpected('kibana.listWorkflows'),
  getWorkflow: unexpected('kibana.getWorkflow'),
  deleteWorkflow: unexpected('kibana.deleteWorkflow'),
  getInstances: unexpected('kibana.getInstances'),
  getCatalogDetail: unexpected('kibana.getCatalogDetail'),
  getHostTimeline: unexpected('kibana.getHostTimeline'),
  getTrends: unexpected('kibana.getTrends'),
  ...handlers,
});

export interface FakeStep {
  readonly status?: string;
  readonly output?: JsonValue;
  readonly input?: JsonValue;
}

/** A finished run whose steps answer with the given outputs. */
export const fakeRun = (
  steps: Readonly<Record<string, FakeStep>>,
  execution: Partial<WorkflowExecution> = {}
): CompletedRun => {
  const id = execution.id ?? 'exec-1';
  const stepExecutions = Object.entries(steps).map(([stepId, step]) => ({
    id: `${id}-${stepId}`,
    stepId,
    status: step.status ?? 'completed',
  }));
  const details = new Map(
    Object.entries(steps).map(([stepId, step]): [string, StepExecutionDetail] => [
      `${id}-${stepId}`,
      {
        id: `${id}-${stepId}`,
        stepId,
        status: step.status ?? 'completed',
        ...(step.output !== undefined ? { output: step.output } : {}),
        ...(step.input !== undefined ? { input: step.input } : {}),
      },
    ])
  );
  return toCompletedRun(
    {
      getStepExecution: async (_executionId, stepExecutionId) => {
        const detail = details.get(stepExecutionId);
        if (!detail) throw new Error(`no step ${stepExecutionId}`);
        return detail;
      },
    },
    { id, status: 'completed', stepExecutions, ...execution }
  );
};

export interface FakeStubState {
  log: RecordedRequest[];
  resets: number;
  modes: string[];
}

/** A stub whose request log is whatever `onRun` puts in `state.log` during the run. */
export const fakeStub = (state: FakeStubState): NvdStub => ({
  url: 'http://127.0.0.1:5699',
  port: 5699,
  requests: () => [...state.log],
  reset: () => {
    state.log = [];
    state.resets++;
  },
  setMode: (mode) => {
    state.modes.push(JSON.stringify(mode));
  },
  close: async () => {},
});

export const nvdRequest = (at: string, cpe: string, status: number): RecordedRequest => ({
  at,
  method: 'GET',
  path: '/rest/json/cves/2.0',
  query: { cpeName: cpe, noRejected: '' },
  status,
});

export const kevRequest = (at: string, status = 200): RecordedRequest => ({
  at,
  method: 'GET',
  path: '/kev.json',
  query: {},
  status,
});

export const fakeContext = ({
  es = fakeEs({}),
  kibana = fakeKibana({}),
  runWorkflow = unexpected('runWorkflow'),
  nvdStub,
  priorResults = new Map(),
  config = TEST_CONFIG,
  writeLogDocs = async () => ({ written: 0, existing: 0 }),
}: {
  es?: EsClient;
  kibana?: KibanaClient;
  runWorkflow?: (args: RunWorkflowArgs) => Promise<CompletedRun>;
  nvdStub?: NvdStub;
  priorResults?: ReadonlyMap<string, CaseRecord>;
  config?: HarnessConfig;
  writeLogDocs?: CaseContext['writeLogDocs'];
}): CaseContext => ({
  config,
  kibana,
  es,
  t0: new Date('2026-11-18T10:00:00Z'),
  log: { info: () => {}, warn: () => {}, debug: () => {} },
  ...(nvdStub ? { nvdStub } : {}),
  priorResults,
  runWorkflow,
  writeLogs: unexpected('writeLogs'),
  writeLogDocs,
  writeEndpointLogs: unexpected('writeEndpointLogs'),
  writeEndpointDocs: unexpected('writeEndpointDocs'),
});

/** Test-only: hands a typed fixture to a generic client method (`search<T>`, `mget<T>`). */
export const asType = <T>(value: object): T => value as T;

/** A passing record carrying the given evidence, as the runner stores it. */
export const passingRecord = (
  id: string,
  evidence: Readonly<Record<string, JsonValue>>
): CaseRecord => ({
  id,
  family: 'EC',
  title: id,
  status: 'pass',
  layers: [{ layer: 'harness', pass: true, checks: 1, diffs: [], evidence }],
  startedAt: '2026-11-18T10:00:00.000Z',
  durationMs: 1,
  executionIds: [],
});
