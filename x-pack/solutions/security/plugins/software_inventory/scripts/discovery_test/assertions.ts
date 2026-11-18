/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Three-layer assertions (see "Assertion approach" in docs/discovery_test_plan.md):
 * 1. Engine: run status and every step status.
 * 2. Step contract: step `output` (and `input`, for example `snapshot`).
 * 3. Inventory: oracle queries on the plugin indices, by deterministic id where possible.
 * Every helper returns a `LayerResult` with readable diffs instead of throwing.
 */

import { isDeepStrictEqual } from 'util';
import { CATALOG_INDEX, EVENTS_INDEX, INSTANCES_INDEX } from '../../common/constants';
import type { InventoryEvent } from '../../common/history';
import type {
  CatalogEntry,
  DiscoverySource,
  InstanceDoc,
  InstanceStatus,
} from '../../common/types';
import type { CompletedRun, EsClient, JsonValue, WorkflowExecution } from './clients';
import { instanceIdFor } from './ids';

export type LayerName = 'engine' | 'step' | 'inventory' | 'harness';

export interface LayerResult {
  readonly layer: LayerName;
  readonly pass: boolean;
  /** Number of individual expectations checked. */
  readonly checks: number;
  readonly diffs: readonly string[];
  /** Actual values worth keeping in the report (step outputs, counts, ids). */
  readonly evidence?: Readonly<Record<string, JsonValue>>;
}

export const layerResult = (
  layer: LayerName,
  diffs: readonly string[],
  checks: number,
  evidence?: Readonly<Record<string, JsonValue>>
): LayerResult => ({
  layer,
  pass: diffs.length === 0,
  checks,
  diffs,
  ...(evidence ? { evidence } : {}),
});

const show = (value: JsonValue | object | undefined): string =>
  value === undefined ? 'undefined' : JSON.stringify(value);

type Comparable = JsonValue | undefined | object;

const isPlainObject = (value: Comparable): value is Record<string, Comparable> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * Compares `actual` with `expected`. Objects compare as a SUBSET (only the expected keys); arrays
 * and primitives compare exactly. An expected `undefined` asserts the key is absent or undefined.
 * Returns one readable line per mismatch, prefixed with its path.
 */
export const diffValues = (expected: Comparable, actual: Comparable, path = '$'): string[] => {
  if (isPlainObject(expected)) {
    if (!isPlainObject(actual)) {
      return [`${path}: expected an object, got ${show(actual)}`];
    }
    return Object.entries(expected).flatMap(([key, value]) =>
      diffValues(value, actual[key], `${path}.${key}`)
    );
  }
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) {
      return [`${path}: expected an array, got ${show(actual)}`];
    }
    if (expected.length !== actual.length) {
      return [
        `${path}: expected ${expected.length} item(s) ${show(expected)}, got ${show(actual)}`,
      ];
    }
    return expected.flatMap((value, index) =>
      diffValues(value, actual[index], `${path}[${index}]`)
    );
  }
  return isDeepStrictEqual(expected, actual)
    ? []
    : [`${path}: expected ${show(expected)}, got ${show(actual)}`];
};

/** Counts the leaf expectations `diffValues` checks, for the report. */
const countChecks = (expected: Comparable): number => {
  if (isPlainObject(expected)) {
    return Object.values(expected).reduce<number>((sum, value) => sum + countChecks(value), 0);
  }
  if (Array.isArray(expected)) return Math.max(1, expected.length);
  return 1;
};

// -------------------------------------------------------------------------------------------------
// Layer 1: engine
// -------------------------------------------------------------------------------------------------

export interface EngineExpectation {
  /** Run status; default `completed`. */
  readonly status?: string;
  /** Status per step name; steps not listed must have `defaultStepStatus`. */
  readonly steps?: Readonly<Record<string, string>>;
  /** Default `completed`. Use `null` to ignore unlisted steps. */
  readonly defaultStepStatus?: string | null;
  /** Steps that must not have run at all. */
  readonly notRun?: readonly string[];
  readonly workflowId?: string;
  readonly isTestRun?: boolean;
}

export const checkEngine = (
  execution: WorkflowExecution,
  expected: EngineExpectation = {}
): LayerResult => {
  const diffs: string[] = [];
  let checks = 1;
  const status = expected.status ?? 'completed';
  if (execution.status !== status)
    diffs.push(`run status: expected ${status}, got ${execution.status}`);
  if (expected.workflowId !== undefined) {
    checks++;
    if (execution.workflowId !== expected.workflowId) {
      diffs.push(`workflowId: expected ${expected.workflowId}, got ${execution.workflowId}`);
    }
  }
  if (expected.isTestRun !== undefined) {
    checks++;
    if (execution.isTestRun !== expected.isTestRun) {
      diffs.push(`isTestRun: expected ${expected.isTestRun}, got ${execution.isTestRun}`);
    }
  }
  const actualSteps = new Map(execution.stepExecutions.map((step) => [step.stepId, step]));
  for (const [stepId, stepStatus] of Object.entries(expected.steps ?? {})) {
    checks++;
    const actual = actualSteps.get(stepId);
    if (!actual) diffs.push(`step ${stepId}: expected ${stepStatus}, but it did not run`);
    else if (actual.status !== stepStatus) {
      diffs.push(
        `step ${stepId}: expected ${stepStatus}, got ${actual.status}${errorSuffix(actual.error)}`
      );
    }
  }
  const defaultStatus =
    expected.defaultStepStatus === undefined ? 'completed' : expected.defaultStepStatus;
  if (defaultStatus !== null) {
    for (const step of execution.stepExecutions) {
      if (expected.steps?.[step.stepId] !== undefined) continue;
      checks++;
      if (step.status !== defaultStatus) {
        diffs.push(
          `step ${step.stepId}: expected ${defaultStatus}, got ${step.status}${errorSuffix(
            step.error
          )}`
        );
      }
    }
  }
  for (const stepId of expected.notRun ?? []) {
    checks++;
    if (actualSteps.has(stepId)) diffs.push(`step ${stepId}: expected not to run, but it ran`);
  }
  return layerResult('engine', diffs, checks, {
    executionId: execution.id,
    status: execution.status,
    steps: execution.stepExecutions.map((step) => `${step.stepId}:${step.status}`),
  });
};

const errorSuffix = (error: JsonValue | undefined): string =>
  error === undefined || error === null ? '' : ` (${JSON.stringify(error).slice(0, 300)})`;

// -------------------------------------------------------------------------------------------------
// Layer 2: step contract
// -------------------------------------------------------------------------------------------------

export interface StepExpectation {
  /** Subset of the step `output`; use `null` to assert the output is null (failed step). */
  readonly output?: Comparable | null;
  /** Subset of the step `input` (for example `{ snapshot: false }`). */
  readonly input?: Comparable;
}

/** Fetches each named step's detail and compares `output`/`input` with the expectations. */
export const checkSteps = async (
  run: CompletedRun,
  expectations: Readonly<Record<string, StepExpectation>>
): Promise<LayerResult> => {
  const diffs: string[] = [];
  const evidence: Record<string, JsonValue> = {};
  let checks = 0;
  for (const [stepName, expected] of Object.entries(expectations)) {
    let detail;
    try {
      detail = await run.step(stepName);
    } catch (error) {
      checks++;
      diffs.push(`${stepName}: ${(error as Error).message}`);
      continue;
    }
    evidence[stepName] = { output: detail.output ?? null, input: detail.input ?? null };
    if (expected.output !== undefined) {
      checks += countChecks(expected.output);
      diffs.push(...diffValues(expected.output, detail.output ?? null, `${stepName}.output`));
    }
    if (expected.input !== undefined) {
      checks += countChecks(expected.input);
      diffs.push(...diffValues(expected.input, detail.input ?? null, `${stepName}.input`));
    }
  }
  return layerResult('step', diffs, checks, evidence);
};

/** An ingest output where omitted counters are 0, as the plan's tables read. */
export const ingestOutput = (
  partial: Partial<Record<'created' | 'unchanged' | 'patched' | 'removed' | 'skipped', number>>
): Record<'created' | 'unchanged' | 'patched' | 'removed' | 'skipped', number> => ({
  created: 0,
  unchanged: 0,
  patched: 0,
  removed: 0,
  skipped: 0,
  ...partial,
});

// -------------------------------------------------------------------------------------------------
// Layer 3: inventory oracle
// -------------------------------------------------------------------------------------------------

export interface ExpectedInstance {
  readonly hostKey: string;
  /** Current catalog id; its vendor and product also select the instance id. */
  readonly catalogId: string;
  readonly installPath?: string;
  readonly status?: InstanceStatus;
  readonly sources?: readonly DiscoverySource[];
  /** `version_history[].version` in order. */
  readonly versions?: readonly string[];
  /** Stored `host.name`; `null` asserts that none is stored. */
  readonly hostName?: string | null;
  readonly hostId?: string;
  readonly previousSoftwareId?: string;
  readonly exposureLevel?: InstanceDoc['exposure']['level'];
  /** The instance must not exist (for example a dropped row). */
  readonly absent?: boolean;
}

const describeInstance = ({ hostKey, catalogId, installPath }: ExpectedInstance): string =>
  `${hostKey}/${catalogId}${installPath ? `@${installPath}` : ''}`;

/** Pure comparison of one instance document with its expectation; exported for tests. */
export const diffInstance = (
  expected: ExpectedInstance,
  doc: InstanceDoc | undefined
): string[] => {
  const label = describeInstance(expected);
  if (expected.absent)
    return doc ? [`${label}: expected no instance, found status ${doc.status}`] : [];
  if (!doc) return [`${label}: missing`];
  const diffs: string[] = [];
  if (doc.software_id !== expected.catalogId) {
    diffs.push(`software_id ${doc.software_id} != ${expected.catalogId}`);
  }
  if (expected.status !== undefined && doc.status !== expected.status) {
    diffs.push(`status ${doc.status} != ${expected.status}`);
  }
  if (
    expected.sources !== undefined &&
    !isDeepStrictEqual([...doc.sources].sort(), [...expected.sources].sort())
  ) {
    diffs.push(`sources ${show(doc.sources)} != ${show(expected.sources)}`);
  }
  if (expected.versions !== undefined) {
    const versions = doc.version_history.map((item) => item.version);
    if (!isDeepStrictEqual(versions, expected.versions)) {
      diffs.push(`version_history ${show(versions)} != ${show(expected.versions)}`);
    }
  }
  if (expected.hostName !== undefined && (doc.host.name ?? null) !== expected.hostName) {
    diffs.push(`host.name ${show(doc.host.name ?? null)} != ${show(expected.hostName)}`);
  }
  if (expected.hostId !== undefined && doc.host.id !== expected.hostId) {
    diffs.push(`host.id ${doc.host.id} != ${expected.hostId}`);
  }
  if (doc.host.key !== expected.hostKey)
    diffs.push(`host.key ${doc.host.key} != ${expected.hostKey}`);
  if (
    expected.previousSoftwareId !== undefined &&
    doc.previous_software_id !== expected.previousSoftwareId
  ) {
    diffs.push(
      `previous_software_id ${doc.previous_software_id} != ${expected.previousSoftwareId}`
    );
  }
  if (expected.exposureLevel !== undefined && doc.exposure.level !== expected.exposureLevel) {
    diffs.push(`exposure.level ${doc.exposure.level} != ${expected.exposureLevel}`);
  }
  return diffs.map((diff) => `${label}: ${diff}`);
};

/** Reads the expected instances by deterministic id and compares them. */
export const checkInstances = async (
  es: EsClient,
  expected: readonly ExpectedInstance[]
): Promise<LayerResult> => {
  if (expected.length === 0) return layerResult('inventory', [], 0);
  const ids = expected.map((item) => instanceIdFor(item));
  const { docs } = await es.mget<InstanceDoc>(INSTANCES_INDEX, ids);
  const diffs = expected.flatMap((item, index) =>
    diffInstance(item, docs[index]?.found ? docs[index]._source : undefined)
  );
  return layerResult('inventory', diffs, expected.length);
};

export interface ExpectedCatalogEntry {
  readonly id: string;
  /** Subset of the catalog document. */
  readonly fields?: Partial<Record<keyof CatalogEntry, Comparable>>;
  readonly absent?: boolean;
}

export const checkCatalogEntries = async (
  es: EsClient,
  expected: readonly ExpectedCatalogEntry[]
): Promise<LayerResult> => {
  if (expected.length === 0) return layerResult('inventory', [], 0);
  const { docs } = await es.mget<CatalogEntry>(
    CATALOG_INDEX,
    expected.map(({ id }) => id)
  );
  const diffs = expected.flatMap((item, index) => {
    const doc = docs[index]?.found ? docs[index]._source : undefined;
    if (item.absent) return doc ? [`catalog ${item.id}: expected absent, found`] : [];
    if (!doc) return [`catalog ${item.id}: missing`];
    return item.fields ? diffValues(item.fields, doc, `catalog ${item.id}`) : [];
  });
  return layerResult('inventory', diffs, expected.length);
};

/**
 * Events with `@timestamp >= since` on the given host keys, oldest first. `types` and
 * `softwareIds` narrow them further, for a case that shares a host with other cases.
 */
export const findEvents = async (
  es: EsClient,
  {
    hostKeys,
    since,
    types,
    softwareIds,
  }: {
    hostKeys: readonly string[];
    since: string;
    types?: readonly string[];
    softwareIds?: readonly string[];
  }
): Promise<InventoryEvent[]> => {
  const response = await es.search<InventoryEvent>(EVENTS_INDEX, {
    size: 10_000,
    sort: [{ '@timestamp': 'asc' }],
    query: {
      bool: {
        filter: [
          { terms: { 'host.key': hostKeys } },
          { range: { '@timestamp': { gte: since } } },
          ...(types ? [{ terms: { type: types } }] : []),
          ...(softwareIds ? [{ terms: { software_id: softwareIds } }] : []),
        ],
      },
    },
  });
  return response.hits.hits.flatMap((hit) => (hit._source ? [hit._source] : []));
};

export type ExpectedEvent = Partial<Record<keyof InventoryEvent, Comparable>> & {
  readonly type: InventoryEvent['type'];
};

const eventSortKey = (event: { type?: Comparable; software_id?: Comparable; host?: Comparable }) =>
  `${String(event.type)}|${String(event.software_id ?? '')}|${JSON.stringify(event.host ?? '')}`;

/** Pure: compares event lists as multisets, ordered by type, software id, and host. */
export const diffEvents = (
  expected: readonly ExpectedEvent[],
  actual: readonly InventoryEvent[]
): string[] => {
  const sortedExpected = [...expected].sort((a, b) =>
    eventSortKey(a).localeCompare(eventSortKey(b))
  );
  const sortedActual = [...actual].sort((a, b) => eventSortKey(a).localeCompare(eventSortKey(b)));
  if (sortedExpected.length !== sortedActual.length) {
    return [
      `events: expected ${sortedExpected.length} ${show(
        sortedExpected.map((e) => `${e.type}:${e.software_id ?? '*'}`)
      )}, ` +
        `got ${sortedActual.length} ${show(sortedActual.map((e) => `${e.type}:${e.software_id}`))}`,
    ];
  }
  return sortedExpected.flatMap((event, index) =>
    diffValues(event, sortedActual[index], `events[${index}]`)
  );
};

/** Asserts the exact set of events written on `hostKeys` since `since`. */
export const checkEvents = async (
  es: EsClient,
  args: {
    hostKeys: readonly string[];
    since: string;
    expected: readonly ExpectedEvent[];
    softwareIds?: readonly string[];
  }
): Promise<LayerResult> => {
  const actual = await findEvents(es, args);
  return layerResult(
    'inventory',
    diffEvents(args.expected, actual),
    Math.max(1, args.expected.length),
    {
      events: actual.map((event) => `${event.type}:${event.host.key}:${event.software_id}`),
    }
  );
};

/**
 * A case fails on any write outside its host keys: counts instances and events with
 * `@timestamp >= since` whose `host.key` is not allowed.
 */
export const checkNoUnexpectedWrites = async (
  es: EsClient,
  { since, allowedHostKeys }: { since: string; allowedHostKeys: readonly string[] }
): Promise<LayerResult> => {
  const query = {
    bool: {
      filter: [{ range: { '@timestamp': { gte: since } } }],
      must_not: [{ terms: { 'host.key': allowedHostKeys } }],
    },
  };
  const [instances, events] = await Promise.all([
    es.count(INSTANCES_INDEX, query),
    es.count(EVENTS_INDEX, query),
  ]);
  const diffs = [
    ...(instances > 0 ? [`${instances} instance(s) written outside the case's host keys`] : []),
    ...(events > 0 ? [`${events} event(s) written outside the case's host keys`] : []),
  ];
  return layerResult('inventory', diffs, 2, {
    unexpectedInstances: instances,
    unexpectedEvents: events,
  });
};

/** Merges several results of the same layer into one. */
export const mergeLayer = (layer: LayerName, results: readonly LayerResult[]): LayerResult =>
  layerResult(
    layer,
    results.flatMap((result) => result.diffs),
    results.reduce((sum, result) => sum + result.checks, 0),
    Object.assign({}, ...results.map((result) => result.evidence ?? {}))
  );
