/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Support for the DO and DI cases: runs a variant, checks the engine and step layers of one run,
 * and reads the inventory documents the checks in `../assertions` do not cover (install path,
 * `version_changed_at`, per-host counts).
 */

import { INSTANCES_INDEX } from '../../../common/constants';
import type { InstanceDoc } from '../../../common/types';
import type { LayerResult, StepExpectation } from '../assertions';
import {
  checkCatalogEntries,
  checkEngine,
  checkEvents,
  checkInstances,
  checkNoUnexpectedWrites,
  checkSteps,
  ingestOutput,
  layerResult,
  mergeLayer,
} from '../assertions';
import type { CompletedRun, EsClient, JsonValue } from '../clients';
import type { DoCaseExpectation, IngestExpectation, OsqueryRunExpectation } from '../expected/do';
import {
  EMPTY_INGEST,
  INGEST_STEP_OF,
  QUERY_KEYS,
  QUERY_STEP_OF,
  THROWN_INGEST,
} from '../expected/do';
import { instanceIdFor } from '../ids';
import { buildOsqueryVariant } from '../variants/osquery';
import { getWorkflowId } from '../variants/build_variant';
import type { CaseContext, CaseResult } from './types';
import { caseResult } from './types';

/** Prefixes each diff with `label`, so merged layers say which run produced them. */
export const labelLayer = (label: string, layer: LayerResult): LayerResult => ({
  ...layer,
  diffs: layer.diffs.map((diff) => `[${label}] ${diff}`),
});

const isRecord = (value: JsonValue | undefined): value is { [key: string]: JsonValue } =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** Number of `candidates` the step received; `undefined` when the input has none. */
export const candidateCountOf = (input: JsonValue | undefined): number | undefined => {
  if (!isRecord(input)) return undefined;
  const { candidates } = input;
  return Array.isArray(candidates) ? candidates.length : undefined;
};

/** Compares the number of candidates each named step received. Does not keep the input as evidence. */
export const checkCandidateCounts = async (
  run: CompletedRun,
  expected: Readonly<Record<string, number>>
): Promise<LayerResult> => {
  const diffs: string[] = [];
  const evidence: Record<string, JsonValue> = {};
  for (const [stepName, count] of Object.entries(expected)) {
    try {
      const { input } = await run.step(stepName);
      const actual = candidateCountOf(input);
      evidence[`${stepName}.candidates`] = actual ?? null;
      if (actual !== count) {
        diffs.push(`${stepName}.input.candidates: expected ${count} item(s), got ${actual}`);
      }
    } catch (error) {
      diffs.push(`${stepName}: ${(error as Error).message}`);
    }
  }
  return layerResult('step', diffs, Object.keys(expected).length, evidence);
};

const ingestOf = (
  run: Pick<OsqueryRunExpectation, 'ingest' | 'failedQueries'>,
  key: (typeof QUERY_KEYS)[number]
): IngestExpectation =>
  run.ingest[key] ?? (run.failedQueries?.includes(key) ? THROWN_INGEST : EMPTY_INGEST);

/** Step expectations of a `discover-osquery` variant run (`input.snapshot` and output counters). */
export const osqueryStepExpectations = (
  run: OsqueryRunExpectation
): Record<string, StepExpectation> => ({
  ...Object.fromEntries(
    QUERY_KEYS.flatMap((key) => {
      const { output, snapshot } = ingestOf(run, key);
      const expectation: StepExpectation = {
        output: ingestOutput(output),
        input: { snapshot },
      };
      return [[INGEST_STEP_OF[key], expectation]];
    })
  ),
  ...Object.fromEntries(
    (run.failedQueries ?? []).map((key) => [QUERY_STEP_OF[key], { output: null }])
  ),
});

export const osqueryCandidateCounts = (run: OsqueryRunExpectation): Record<string, number> =>
  Object.fromEntries(QUERY_KEYS.map((key) => [INGEST_STEP_OF[key], ingestOf(run, key).candidates]));

export interface RunLayers {
  readonly run: CompletedRun;
  readonly engine: LayerResult;
  readonly step: LayerResult;
}

/** Checks the engine and step layers of a finished `discover-osquery` run. */
export const checkOsqueryRun = async (
  run: CompletedRun,
  expectation: OsqueryRunExpectation
): Promise<Omit<RunLayers, 'run'>> => {
  const engine = checkEngine(run.execution, {
    workflowId: getWorkflowId('discoverOsquery'),
    isTestRun: true,
    steps: Object.fromEntries(
      (expectation.failedQueries ?? []).map((key) => [QUERY_STEP_OF[key], 'failed'])
    ),
  });
  const step = mergeLayer('step', [
    await checkSteps(run, osqueryStepExpectations(expectation)),
    await checkCandidateCounts(run, osqueryCandidateCounts(expectation)),
  ]);
  return {
    engine: labelLayer(expectation.label, engine),
    step: labelLayer(expectation.label, step),
  };
};

/** Test-runs one `discover-osquery` variant and checks the engine and step layers. */
export const runOsqueryExpectation = async (
  ctx: CaseContext,
  expectation: OsqueryRunExpectation
): Promise<RunLayers> => {
  const yaml = buildOsqueryVariant({ label: expectation.label, steps: expectation.steps });
  const run = await ctx.runWorkflow({ workflow: 'discoverOsquery', yaml });
  return { run, ...(await checkOsqueryRun(run, expectation)) };
};

/** Runs a data-driven DO case: every run, then the inventory layer once. */
export const executeDoCase = async (
  ctx: CaseContext,
  expectation: DoCaseExpectation
): Promise<CaseResult> => {
  const since = new Date().toISOString();
  const engines: LayerResult[] = [];
  const steps: LayerResult[] = [];
  for (const runExpectation of expectation.runs) {
    const { engine, step } = await runOsqueryExpectation(ctx, runExpectation);
    engines.push(engine);
    steps.push(step);
  }
  const inventory = mergeLayer('inventory', [
    await checkInstances(ctx.es, expectation.instances),
    await checkCatalogEntries(ctx.es, expectation.catalog),
    await checkEvents(ctx.es, {
      hostKeys: expectation.hostKeys,
      since,
      expected: expectation.events,
    }),
    await checkNoUnexpectedWrites(ctx.es, { since, allowedHostKeys: expectation.hostKeys }),
  ]);
  return caseResult([mergeLayer('engine', engines), mergeLayer('step', steps), inventory]);
};

// -------------------------------------------------------------------------------------------------
// Inventory reads the shared check helpers do not cover
// -------------------------------------------------------------------------------------------------

const hostTerm = (hostKey: string) => ({ term: { 'host.key': hostKey } });

/** Number of instances on `hostKey`, optionally excluding some software ids. */
export const countHostInstances = (
  es: EsClient,
  hostKey: string,
  { excludeSoftwareIds = [] }: { excludeSoftwareIds?: readonly string[] } = {}
): Promise<number> =>
  es.count(INSTANCES_INDEX, {
    bool: {
      filter: [hostTerm(hostKey)],
      ...(excludeSoftwareIds.length > 0
        ? { must_not: [{ terms: { software_id: [...excludeSoftwareIds] } }] }
        : {}),
    },
  });

/** Number of instances on `hostKey` whose software id starts with `prefix`. */
export const countHostInstancesWithPrefix = (
  es: EsClient,
  hostKey: string,
  prefix: string
): Promise<number> =>
  es.count(INSTANCES_INDEX, {
    bool: { filter: [hostTerm(hostKey), { prefix: { software_id: prefix } }] },
  });

export interface InstanceRef {
  readonly hostKey: string;
  readonly catalogId: string;
  readonly installPath?: string;
}

const readInstances = async (
  es: EsClient,
  refs: readonly InstanceRef[]
): Promise<Array<InstanceDoc | undefined>> => {
  if (refs.length === 0) return [];
  const { docs } = await es.mget<InstanceDoc>(
    INSTANCES_INDEX,
    refs.map((ref) => instanceIdFor(ref))
  );
  return refs.map((_, index) => (docs[index]?.found ? docs[index]._source : undefined));
};

const label = ({ hostKey, catalogId, installPath }: InstanceRef): string =>
  `${hostKey}/${catalogId}${installPath ? `@${installPath}` : ''}`;

/** Each instance must store `install_path` equal to the reported path. */
export const checkInstallPaths = async (
  es: EsClient,
  refs: ReadonlyArray<InstanceRef & { readonly installPath: string }>
): Promise<LayerResult> => {
  const docs = await readInstances(es, refs);
  const diffs = refs.flatMap((ref, index) => {
    const doc = docs[index];
    if (!doc) return [`${label(ref)}: missing`];
    return doc.install_path === ref.installPath
      ? []
      : [`${label(ref)}: install_path ${doc.install_path} != ${ref.installPath}`];
  });
  return layerResult('inventory', diffs, refs.length);
};

/** The instance must carry `version_changed_at` (a re-run keeps it after a patch). */
export const checkVersionChangedAtKept = async (
  es: EsClient,
  ref: InstanceRef
): Promise<LayerResult> => {
  const [doc] = await readInstances(es, [ref]);
  const diffs = !doc
    ? [`${label(ref)}: missing`]
    : doc.version_changed_at
    ? []
    : [`${label(ref)}: version_changed_at was cleared`];
  return layerResult('inventory', diffs, 1);
};

/** An exact count of documents, as one inventory check. */
export const expectCount = (what: string, expected: number, actual: number): LayerResult =>
  layerResult(
    'inventory',
    actual === expected ? [] : [`${what}: expected ${expected}, got ${actual}`],
    1,
    {
      [what]: actual,
    }
  );

/** Duration of a step from its start and finish times, or `undefined` when either is missing. */
export const stepDurationMs = (run: CompletedRun, stepName: string): number | undefined => {
  const step = run.stepsByName.get(stepName);
  if (!step?.startedAt || !step.finishedAt) return undefined;
  return Date.parse(step.finishedAt) - Date.parse(step.startedAt);
};

/** Reads `error` of a failed step from the run summary, falling back to the step detail. */
export const stepErrorText = async (run: CompletedRun, stepName: string): Promise<string> => {
  const summary = run.stepsByName.get(stepName);
  if (summary?.error !== undefined) return JSON.stringify(summary.error);
  try {
    const detail = await run.step(stepName);
    return detail.error === undefined ? '' : JSON.stringify(detail.error);
  } catch {
    return '';
  }
};
