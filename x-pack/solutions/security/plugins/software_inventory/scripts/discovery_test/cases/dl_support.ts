/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Support for the DL cases: ES|QL row checks against the generator's candidates, query-step error
 * checks, absent-host checks, and sighting-time checks.
 */

import type { LayerResult } from '../assertions';
import { checkSteps, ingestOutput, layerResult, mergeLayer } from '../assertions';
import type { CompletedRun, EsClient, JsonValue } from '../clients';
import {
  SYNTHETIC_DATA_STREAM,
  SYNTHETIC_DATASET,
  ensureSyntheticDataStream,
  deleteSyntheticDataStream,
} from '../logs/template';
import type { ExpectedLogCandidate, SyntheticLogDoc } from '../logs/generate_logs';
import { buildPhaseDocs, writeLogDocs } from '../logs/generate_logs';
import { INSTANCES_INDEX } from '../../../common/constants';
import { appliancesAt, expectedSightingTimes, servicesAt } from '../expected/dl';
import type { DlStage } from '../expected/dl';
import { fetchInstanceDocs } from './synthetic_support';

export { SYNTHETIC_DATA_STREAM, SYNTHETIC_DATASET, ensureSyntheticDataStream };

/** One ES|QL row the workflow reads, as the generator's table implies it. */
export interface ExpectedEsqlRow {
  readonly host_id: string;
  readonly host_name?: string;
  readonly vendor?: string;
  readonly name: string;
  readonly version: string;
  /** ISO instant of `observed_at`. */
  readonly observedAt: string;
}

export const toEsqlRow = (candidate: ExpectedLogCandidate, t0: Date): ExpectedEsqlRow => ({
  host_id: candidate.host_id,
  ...(candidate.host_name ? { host_name: candidate.host_name } : {}),
  ...(candidate.vendor ? { vendor: candidate.vendor } : {}),
  name: candidate.name,
  version: candidate.version,
  observedAt: new Date(t0.getTime() - candidate.observedOffsetMs).toISOString(),
});

export const applianceRowsAt = (stage: DlStage, t0: Date): ExpectedEsqlRow[] =>
  appliancesAt(stage).map((candidate) => toEsqlRow(candidate, t0));

export const serviceRowsAt = (stage: DlStage, t0: Date): ExpectedEsqlRow[] =>
  servicesAt(stage).map((candidate) => toEsqlRow(candidate, t0));

interface EsqlOutput {
  readonly columns: ReadonlyArray<{ readonly name: string }>;
  readonly values: ReadonlyArray<readonly JsonValue[]>;
}

const isEsqlOutput = (
  value: JsonValue | undefined
): value is { columns: JsonValue; values: JsonValue } =>
  typeof value === 'object' && value !== null && !Array.isArray(value) && 'values' in value;

const toEsqlOutput = (value: JsonValue | undefined): EsqlOutput | undefined => {
  if (!isEsqlOutput(value)) return undefined;
  const { columns, values } = value;
  if (!Array.isArray(columns) || !Array.isArray(values)) return undefined;
  const names = columns.flatMap((column) =>
    typeof column === 'object' && column !== null && !Array.isArray(column) && 'name' in column
      ? [String(column.name)]
      : []
  );
  const rows = values.flatMap((row) => (Array.isArray(row) ? [row] : []));
  return { columns: names.map((name) => ({ name })), values: rows };
};

const cell = (row: readonly JsonValue[], names: readonly string[], name: string): string | null => {
  const value = row[names.indexOf(name)];
  return value === undefined || value === null ? null : String(value);
};

const rowKey = (hostId: string | null, name: string | null, version: string | null): string =>
  `${hostId ?? ''}|${name ?? ''}|${version ?? ''}`;

/** Pure: compares an ES|QL step output with the expected rows (any order). */
export const diffEsqlRows = (
  label: string,
  output: JsonValue | undefined,
  expected: readonly ExpectedEsqlRow[]
): string[] => {
  const parsed = toEsqlOutput(output);
  if (!parsed) {
    return expected.length === 0 && (output === null || output === undefined)
      ? []
      : [`${label}: output is not an ES|QL result: ${JSON.stringify(output)}`];
  }
  const names = parsed.columns.map(({ name }) => name);
  const actual = parsed.values.map((row) => ({
    key: rowKey(cell(row, names, 'host_id'), cell(row, names, 'name'), cell(row, names, 'version')),
    row,
  }));
  const wanted = expected.map((item) => ({
    key: rowKey(item.host_id, item.name, item.version),
    item,
  }));
  const diffs: string[] = [];
  if (actual.length !== wanted.length) {
    diffs.push(
      `${label}: expected ${wanted.length} row(s) [${wanted
        .map(({ key }) => key)
        .sort()
        .join('; ')}], ` +
        `got ${actual.length} [${actual
          .map(({ key }) => key)
          .sort()
          .join('; ')}]`
    );
    return diffs;
  }
  for (const { key, item } of wanted) {
    const match = actual.find((candidate) => candidate.key === key);
    if (!match) {
      diffs.push(`${label}: missing row ${key}`);
      continue;
    }
    const { row } = match;
    const compare = (field: string, want: string | undefined) => {
      const got = cell(row, names, field);
      if (got !== (want ?? null)) diffs.push(`${label} ${key}: ${field} ${got} != ${want ?? null}`);
    };
    compare('host_name', item.host_name);
    compare('vendor', item.vendor);
    const observed = cell(row, names, 'observed_at');
    if (observed === null || Date.parse(observed) !== Date.parse(item.observedAt)) {
      diffs.push(`${label} ${key}: observed_at ${observed} != ${item.observedAt}`);
    }
  }
  return diffs;
};

/** Rows of an ES|QL step output as `column -> value` records; `undefined` for a failed step. */
export const esqlRecords = (
  output: JsonValue | undefined
): Array<Record<string, string | null>> | undefined => {
  const parsed = toEsqlOutput(output);
  if (!parsed) return undefined;
  const names = parsed.columns.map(({ name }) => name);
  return parsed.values.map((row) =>
    Object.fromEntries(names.map((name) => [name, cell(row, names, name)]))
  );
};

/** Names of every `logs-*` data stream on the cluster. */
export const listLogsDataStreams = async (es: EsClient): Promise<string[]> => {
  const { body } = await es.request<{ data_streams?: Array<{ name: string }> }>(
    'GET',
    '/_data_stream/logs-*',
    { allowStatuses: [404] }
  );
  return (body?.data_streams ?? []).map(({ name }) => name);
};

const stepErrorText = (run: CompletedRun, stepId: string): string =>
  JSON.stringify(run.stepsByName.get(stepId)?.error ?? null);

export interface DiscoverLogsStepExpectation {
  /** Rows `query_appliances` returns, or `failed` when it fails with `failedPattern`. */
  readonly appliances: readonly ExpectedEsqlRow[] | 'failed';
  readonly services: readonly ExpectedEsqlRow[] | 'failed';
  readonly ingest: Partial<
    Record<'created' | 'unchanged' | 'patched' | 'removed' | 'skipped', number>
  >;
  /** Candidates the YAML passes to `ingest` (rows of both queries). */
  readonly candidateCount: number;
  readonly failedPattern?: RegExp;
}

/** Step-contract layer of a `discover-logs` run: query rows, ingest input and output. */
export const checkDiscoverLogsSteps = async (
  run: CompletedRun,
  expectation: DiscoverLogsStepExpectation
): Promise<LayerResult> => {
  const { appliances, services, ingest, candidateCount } = expectation;
  const failedPattern = expectation.failedPattern ?? /Unknown column/;
  const diffs: string[] = [];
  let checks = 0;
  for (const [stepId, expected] of [
    ['query_appliances', appliances],
    ['query_services', services],
  ] as const) {
    checks++;
    if (expected === 'failed') {
      if (!failedPattern.test(stepErrorText(run, stepId))) {
        diffs.push(
          `${stepId}: error does not match ${failedPattern}: ${stepErrorText(run, stepId)}`
        );
      }
      continue;
    }
    const detail = await run.step(stepId);
    checks += expected.length;
    diffs.push(...diffEsqlRows(stepId, detail.output, expected));
  }
  const ingestDetail = await run.step('ingest');
  const input = ingestDetail.input;
  const candidates =
    typeof input === 'object' && input !== null && !Array.isArray(input) ? input.candidates : null;
  checks++;
  if (!Array.isArray(candidates) || candidates.length !== candidateCount) {
    diffs.push(
      `ingest.input.candidates: expected ${candidateCount} item(s), got ${
        Array.isArray(candidates) ? candidates.length : JSON.stringify(candidates)
      }`
    );
  }
  const contract = await checkSteps(run, {
    ingest: { output: ingestOutput(ingest), input: { source: 'logs', snapshot: false } },
  });
  return mergeLayer('step', [layerResult('step', diffs, checks), contract]);
};

/** Fails for every host key that has any instance document (any status). */
export const checkNoInstancesFor = async (
  es: EsClient,
  hostKeys: readonly string[]
): Promise<LayerResult> => {
  const diffs: string[] = [];
  for (const hostKey of hostKeys) {
    const count = await es.count(INSTANCES_INDEX, { term: { 'host.key': hostKey } });
    if (count > 0) diffs.push(`${hostKey}: expected no instance, found ${count}`);
  }
  return layerResult('inventory', diffs, hostKeys.length);
};

/** Compares `first_seen` and `last_seen` of the stage's instances on `hostKeys` with T0 offsets. */
export const checkSightingTimes = async (
  es: EsClient,
  { stage, t0, hostKeys }: { stage: DlStage; t0: Date; hostKeys: readonly string[] }
): Promise<LayerResult> => {
  const items = expectedSightingTimes(stage, t0).filter(({ hostKey }) =>
    hostKeys.includes(hostKey)
  );
  const docs = await fetchInstanceDocs(es, items);
  const diffs = items.flatMap((item, index) => {
    const doc = docs[index];
    if (!doc) return [`${item.hostKey}/${item.catalogId}: missing`];
    return [
      ...(Date.parse(doc.first_seen) !== Date.parse(item.firstSeen)
        ? [`${item.hostKey}: first_seen ${doc.first_seen} != ${item.firstSeen}`]
        : []),
      ...(Date.parse(doc.last_seen) !== Date.parse(item.lastSeen)
        ? [`${item.hostKey}: last_seen ${doc.last_seen} != ${item.lastSeen}`]
        : []),
    ];
  });
  return layerResult('inventory', diffs, Math.max(1, items.length * 2));
};

/**
 * DL-9: rewrites the synthetic data stream WITHOUT the dedicated template, so
 * `observer.serial_number` is mapped nowhere. Docs that carry the field are left out.
 */
export const rewriteLogsWithoutTemplate = async (
  es: EsClient,
  docs: readonly SyntheticLogDoc[]
): Promise<{ written: number; existing: number }> => {
  await deleteSyntheticDataStream(es);
  // The built-in `logs-*-*` template supplies the data stream mode; without ours, no field is
  // pre-mapped, so `observer.serial_number` stays unknown when no document carries it.
  await es.request('PUT', `/_data_stream/${SYNTHETIC_DATA_STREAM}`);
  return writeLogDocs(
    es,
    docs.filter((doc) => doc._source.observer?.serial_number === undefined)
  );
};

/** Restores the dedicated template and rewrites the phases a case had written (same T0 and ids). */
export const restoreSyntheticLogs = async (
  es: EsClient,
  { t0, phases }: { t0: Date; phases: readonly ('A' | 'B')[] }
): Promise<void> => {
  await deleteSyntheticDataStream(es);
  await ensureSyntheticDataStream(es);
  for (const phase of phases) {
    await writeLogDocs(es, buildPhaseDocs(phase, t0));
  }
};
