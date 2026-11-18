/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Support for the enrich-cves cases: the enrichment timing Kibana runs with (read from the Kibana
 * config files), stub request-log analysis (override detection, retry gaps, spacing), and the
 * catalog order `enrichCatalogEntries` uses, to predict which entries a run checks.
 */

import { existsSync, readFileSync } from 'fs';
import { resolve } from 'path';
import { parse } from 'yaml';
import { CATALOG_INDEX } from '../../../common/constants';
import type { CatalogEntry } from '../../../common/types';
import { buildCpe } from '../../../server/services/enrichment/build_cpe';
import { hasUnknownVersion } from '../../../server/services/enrichment/enrich_catalog_entries';
import type { CompletedRun, EsClient, JsonObject, JsonValue } from '../clients';
import { CPE_RULES } from '../nvd_stub/fixtures';
import type { RecordedRequest } from '../nvd_stub/server';
import { buildEnrichVariant } from '../variants/enrich';
import { BULK_PRODUCT_PREFIX } from '../expected/ec';
import { isJsonObject, readNumber, readString } from './evidence_support';
import type { CaseContext } from './types';

// -------------------------------------------------------------------------------------------------
// Timing Kibana runs with
// -------------------------------------------------------------------------------------------------

export interface EnrichmentTiming {
  readonly spacingMs: number;
  readonly timeoutMs: number;
  readonly backoffBaseMs: number;
  readonly nvdBaseUrl?: string;
  readonly kevUrl?: string;
  /** Where the values came from, for the report. */
  readonly source: string;
}

/** `enrich_catalog_entries.ts` defaults (no `NVD_API_KEY`). */
export const PRODUCTION_TIMING = { spacingMs: 6000, timeoutMs: 30_000, backoffBaseMs: 2000 };
export const ENRICHMENT_CONFIG_PREFIX = 'xpack.softwareInventory.enrichment.';
/** Retries `fetchNvd` makes after the first attempt. */
export const NVD_MAX_RETRIES = 3;

const DURATION_UNITS_MS: Readonly<Record<string, number>> = {
  ms: 1,
  s: 1000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

/** Parses a Kibana duration setting (`100ms`, `2s`, `1m`, or a number of ms). */
export const parseDurationMs = (value: JsonValue | undefined): number | undefined => {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
  if (typeof value !== 'string') return undefined;
  const match = /^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)?\s*$/i.exec(value);
  if (!match) return undefined;
  return Number(match[1]) * DURATION_UNITS_MS[(match[2] ?? 'ms').toLowerCase()];
};

/** Flattens nested YAML maps into dotted keys (`a: {b: 1}` and `a.b: 1` both give `a.b`). */
export const flattenConfig = (
  value: JsonValue | undefined,
  prefix = ''
): Map<string, JsonValue> => {
  const flat = new Map<string, JsonValue>();
  if (!isJsonObject(value)) {
    if (prefix !== '' && value !== undefined) flat.set(prefix, value);
    return flat;
  }
  for (const [key, child] of Object.entries(value)) {
    const path = prefix === '' ? key : `${prefix}.${key}`;
    flattenConfig(child, path).forEach((leaf, leafKey) => flat.set(leafKey, leaf));
  }
  return flat;
};

/** Timing from merged, flattened Kibana settings; unset keys keep the production defaults. */
export const timingFromSettings = (
  settings: ReadonlyMap<string, JsonValue>,
  source: string
): EnrichmentTiming => {
  const get = (key: string) => settings.get(`${ENRICHMENT_CONFIG_PREFIX}${key}`);
  const nvdBaseUrl = readString(get('nvdBaseUrl'));
  const kevUrl = readString(get('kevUrl'));
  return {
    spacingMs: parseDurationMs(get('requestSpacing')) ?? PRODUCTION_TIMING.spacingMs,
    timeoutMs: parseDurationMs(get('requestTimeout')) ?? PRODUCTION_TIMING.timeoutMs,
    backoffBaseMs: parseDurationMs(get('backoffBase')) ?? PRODUCTION_TIMING.backoffBaseMs,
    ...(nvdBaseUrl ? { nvdBaseUrl } : {}),
    ...(kevUrl ? { kevUrl } : {}),
    source,
  };
};

/** Repository root, from `scripts/discovery_test/cases`. */
export const REPO_ROOT = resolve(__dirname, '../../../../../../../..');
/** Kibana dev mode reads `kibana.yml`, then `kibana.dev.yml` on top. */
export const DEFAULT_KIBANA_CONFIG_FILES = ['config/kibana.yml', 'config/kibana.dev.yml'];

export interface TimingSourceDeps {
  /** Comma-separated config paths (`SI_TEST_KIBANA_CONFIG`); relative to the repo root. */
  readonly configEnv?: string;
  readonly readFile?: (path: string) => string | undefined;
}

const readIfExists = (path: string): string | undefined =>
  existsSync(path) ? readFileSync(path, 'utf8') : undefined;

/**
 * The enrichment timing the running Kibana uses, read from its config files. The files can be
 * edited after Kibana started, so the stub log stays the source of truth for whether the override
 * is active; this only sets the expected spacing, timeout, and backoff.
 */
export const resolveEnrichmentTiming = ({
  configEnv = process.env.SI_TEST_KIBANA_CONFIG,
  readFile = readIfExists,
}: TimingSourceDeps = {}): EnrichmentTiming => {
  const files = configEnv
    ? configEnv.split(',').map((file) => file.trim())
    : DEFAULT_KIBANA_CONFIG_FILES;
  const settings = new Map<string, JsonValue>();
  const used: string[] = [];
  for (const file of files) {
    const text = readFile(resolve(REPO_ROOT, file));
    if (text === undefined) continue;
    used.push(file);
    flattenConfig(parse(text) as JsonValue).forEach((value, key) => settings.set(key, value));
  }
  const hasTimingKeys = ['requestSpacing', 'requestTimeout', 'backoffBase'].some((key) =>
    settings.has(`${ENRICHMENT_CONFIG_PREFIX}${key}`)
  );
  return timingFromSettings(
    settings,
    used.length === 0
      ? 'production defaults (no Kibana config file found)'
      : `${used.join(' + ')}${hasTimingKeys ? '' : ' (no timing keys: production defaults)'}`
  );
};

/** Generous upper bound for one enrich run, for the poll timeout. */
export const estimateEnrichWaitMs = (limit: number, timing: EnrichmentTiming): number =>
  120_000 + limit * (timing.spacingMs + 1500) + 4 * timing.timeoutMs + 3 * 7 * timing.backoffBaseMs;

export const describeTiming = (timing: EnrichmentTiming): string =>
  `requestSpacing ${timing.spacingMs}ms, requestTimeout ${timing.timeoutMs}ms, backoffBase ${
    timing.backoffBaseMs
  }ms (from ${timing.source})${timing.nvdBaseUrl ? `, nvdBaseUrl ${timing.nvdBaseUrl}` : ''}`;

// -------------------------------------------------------------------------------------------------
// Stub request log
// -------------------------------------------------------------------------------------------------

export const NVD_PATH = '/rest/json/cves/2.0';
export const KEV_PATH = '/kev.json';

export interface StubRequestRecord {
  readonly at: string;
  readonly path: string;
  readonly status: number;
  readonly cpe?: string;
}

export const compactRequests = (requests: readonly RecordedRequest[]): StubRequestRecord[] =>
  requests.map(({ at, path, status, query }) => ({
    at,
    path,
    status,
    ...(query.cpeName !== undefined ? { cpe: query.cpeName } : {}),
  }));

export const requestsToJson = (requests: readonly StubRequestRecord[]): JsonValue[] =>
  requests.map(
    ({ at, path, status, cpe }): JsonObject => ({ at, path, status, ...(cpe ? { cpe } : {}) })
  );

export const requestsFromJson = (value: JsonValue | undefined): StubRequestRecord[] | undefined => {
  if (!Array.isArray(value)) return undefined;
  const records: StubRequestRecord[] = [];
  for (const item of value) {
    if (!isJsonObject(item)) return undefined;
    const at = readString(item.at);
    const path = readString(item.path);
    const status = readNumber(item.status);
    if (at === undefined || path === undefined || status === undefined) return undefined;
    const cpe = readString(item.cpe);
    records.push({ at, path, status, ...(cpe ? { cpe } : {}) });
  }
  return records;
};

export const nvdRequests = (requests: readonly StubRequestRecord[]): StubRequestRecord[] =>
  requests.filter(({ path }) => path === NVD_PATH);
export const kevRequests = (requests: readonly StubRequestRecord[]): StubRequestRecord[] =>
  requests.filter(({ path }) => path === KEV_PATH);

export const requestsForCpe = (
  requests: readonly StubRequestRecord[],
  cpe: string
): StubRequestRecord[] =>
  nvdRequests(requests)
    .filter((request) => request.cpe === cpe)
    .sort((a, b) => Date.parse(a.at) - Date.parse(b.at));

export const gapsMs = (requests: readonly StubRequestRecord[]): number[] =>
  requests
    .slice(1)
    .map((request, index) => Date.parse(request.at) - Date.parse(requests[index].at));

/** Accepted range for a measured delay: timers never fire early; the event loop can be busy. */
export const gapTolerance = (expectedMs: number): { min: number; max: number } => ({
  min: expectedMs - Math.max(25, expectedMs * 0.1),
  max: expectedMs + Math.max(750, expectedMs * 0.5),
});

export const checkGaps = (
  label: string,
  actual: readonly number[],
  expected: readonly number[]
): string[] => {
  if (actual.length !== expected.length) {
    return [
      `${label}: expected ${expected.length} gap(s) ${JSON.stringify(
        expected
      )}, got ${JSON.stringify(actual)}`,
    ];
  }
  return actual.flatMap((gap, index) => {
    const { min, max } = gapTolerance(expected[index]);
    return gap >= min && gap <= max
      ? []
      : [
          `${label}: gap #${index + 1} ${gap}ms outside [${Math.round(min)}, ${Math.round(
            max
          )}]ms (expected about ${expected[index]}ms)`,
        ];
  });
};

/** Expected delays between attempts: `perAttemptMs + backoffBase * 2^i` for each retry. */
export const retryGapsMs = (backoffBaseMs: number, retries: number, perAttemptMs = 0): number[] =>
  Array.from({ length: retries }, (_, index) => perAttemptMs + backoffBaseMs * 2 ** index);

/**
 * Consecutive NVD requests for DIFFERENT CPEs must be at least `requestSpacing` apart (the step
 * sleeps before each lookup after the first; the previous lookup's own time only adds to it).
 */
export const checkSpacing = (
  requests: readonly StubRequestRecord[],
  spacingMs: number
): string[] => {
  const ordered = nvdRequests(requests).sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  const { min } = gapTolerance(spacingMs);
  return ordered.slice(1).flatMap((request, index) => {
    const previous = ordered[index];
    if (previous.cpe === request.cpe) return [];
    const gap = Date.parse(request.at) - Date.parse(previous.at);
    return gap >= min
      ? []
      : [
          `spacing: ${gap}ms between ${previous.cpe} and ${request.cpe}, below requestSpacing ${spacingMs}ms`,
        ];
  });
};

/**
 * Why the stub log shows that the NVD/KEV URL override is NOT active for this run, or undefined
 * when it is. `expectNvd`: the run looked up at least one entry with a real version.
 */
export const detectOverrideProblem = ({
  requests,
  expectNvd,
  expectKev,
}: {
  requests: readonly StubRequestRecord[];
  expectNvd: boolean;
  expectKev: boolean;
}): string | undefined => {
  const nvd = nvdRequests(requests).length;
  const kev = kevRequests(requests).length;
  const fix =
    'Set xpack.softwareInventory.enrichment.{nvdBaseUrl,kevUrl,requestSpacing,requestTimeout,backoffBase} in config/kibana.dev.yml to the stub and restart Kibana, then re-run the EC cases from a fresh discovery state.';
  if (nvd === 0 && kev === 0 && (expectNvd || expectKev)) {
    return `NVD/KEV override not active: the stub saw no requests during the run, so the step called the live services (entries it touched may now carry live NVD data). ${fix}`;
  }
  if (expectNvd && nvd === 0) {
    return `nvdBaseUrl override not active: the stub saw ${kev} KEV request(s) but no NVD request. ${fix}`;
  }
  if (expectKev && kev === 0) {
    return `kevUrl override not active: the stub saw ${nvd} NVD request(s) but no KEV request. ${fix}`;
  }
  return undefined;
};

// -------------------------------------------------------------------------------------------------
// Catalog order (`cve_checked_at` ascending, missing first)
// -------------------------------------------------------------------------------------------------

export type CatalogOrderEntry = Pick<
  CatalogEntry,
  'id' | 'vendor' | 'product' | 'version' | 'category' | 'cve_checked_at' | 'cve_check_failed'
>;

const ORDER_FIELDS = [
  'id',
  'vendor',
  'product',
  'version',
  'category',
  'cve_checked_at',
  'cve_check_failed',
];

/** Every catalog entry with the fields that decide the enrich order. */
export const readCatalogOrder = async (es: EsClient): Promise<CatalogOrderEntry[]> => {
  const response = await es.search<CatalogOrderEntry>(CATALOG_INDEX, {
    size: 10_000,
    _source: ORDER_FIELDS,
    query: { match_all: {} },
  });
  return sortByCheckOrder(
    response.hits.hits.flatMap((hit) => (hit._source ? [{ ...hit._source, id: hit._id }] : []))
  );
};

const checkKey = ({ cve_checked_at: checkedAt }: Pick<CatalogEntry, 'cve_checked_at'>): number =>
  checkedAt === undefined ? Number.NEGATIVE_INFINITY : Date.parse(checkedAt);

export const sortByCheckOrder = <T extends Pick<CatalogEntry, 'id' | 'cve_checked_at'>>(
  entries: readonly T[]
): T[] => [...entries].sort((a, b) => checkKey(a) - checkKey(b) || a.id.localeCompare(b.id));

export interface PickPrediction {
  /** Entries the run must check. */
  readonly definite: readonly string[];
  /** Entries tied at the `limit` boundary; the run checks `tieCount` of them. */
  readonly tieGroup: readonly string[];
  readonly tieCount: number;
}

/** Which entries a run with `limit` checks; ties at the boundary are left open. */
export const predictPicks = (
  entries: ReadonlyArray<Pick<CatalogEntry, 'id' | 'cve_checked_at'>>,
  limit: number
): PickPrediction => {
  const groups = new Map<number, string[]>();
  for (const entry of sortByCheckOrder(entries)) {
    const key = checkKey(entry);
    groups.set(key, [...(groups.get(key) ?? []), entry.id]);
  }
  const definite: string[] = [];
  for (const ids of groups.values()) {
    if (definite.length + ids.length <= limit) {
      definite.push(...ids);
      continue;
    }
    return { definite, tieGroup: ids, tieCount: limit - definite.length };
  }
  return { definite, tieGroup: [], tieCount: 0 };
};

export const diffPicks = (prediction: PickPrediction, actual: readonly string[]): string[] => {
  const picked = new Set(actual);
  const diffs = prediction.definite
    .filter((id) => !picked.has(id))
    .map((id) => `expected ${id} to be checked, it was not`);
  const allowed = new Set([...prediction.definite, ...prediction.tieGroup]);
  diffs.push(
    ...actual.filter((id) => !allowed.has(id)).map((id) => `${id} was checked, but it was not due`)
  );
  const fromTies = actual.filter((id) => prediction.tieGroup.includes(id)).length;
  if (fromTies !== prediction.tieCount) {
    diffs.push(
      `expected ${prediction.tieCount} of the ${prediction.tieGroup.length} tied entries to be checked, got ${fromTies}`
    );
  }
  return diffs;
};

/** Ids of the entries whose `cve_checked_at` is at or after `since`. */
export const findCheckedSince = async (es: EsClient, since: string): Promise<string[]> => {
  const response = await es.search<{ id: string }>(CATALOG_INDEX, {
    size: 10_000,
    _source: ['id'],
    query: { range: { cve_checked_at: { gte: since } } },
  });
  return response.hits.hits.map((hit) => hit._id).sort();
};

export const NEVER_CHECKED_QUERY = {
  bool: { must_not: [{ exists: { field: 'cve_checked_at' } }] },
};

/**
 * Whether the stub makes the lookup of this entry fail (failure marker): a hang, a persistent
 * error status, or more failures in a row than `fetchNvd` retries.
 */
export const expectsLookupFailure = (
  entry: Pick<CatalogEntry, 'vendor' | 'product' | 'version' | 'category'>
): boolean => {
  if (hasUnknownVersion(entry)) return false;
  const rule = CPE_RULES[buildCpe(entry)];
  if (!rule) return false;
  if (rule.kind === 'hang' || rule.kind === 'status') return true;
  if (rule.kind === 'sequence') return rule.statuses.length > NVD_MAX_RETRIES;
  return false;
};

/**
 * Parks the DO-16 bulk entries (`synth-pkg-*`, thousands of never-checked synthetic entries) by
 * stamping `cve_checked_at`, so the EC runs check the plan's entries instead of the bulk ones.
 * Synthetic documents only; cleanup deletes them.
 */
export const parkBulkEntries = async (es: EsClient, at: string): Promise<number> => {
  const { body } = await es.request<{ updated?: number }>(
    'POST',
    `/${CATALOG_INDEX}/_update_by_query`,
    {
      query: { refresh: true, conflicts: 'proceed' },
      body: {
        query: {
          bool: {
            filter: [{ prefix: { product: BULK_PRODUCT_PREFIX } }],
            must_not: [{ exists: { field: 'cve_checked_at' } }],
          },
        },
        script: {
          lang: 'painless',
          source: 'ctx._source.cve_checked_at = params.at; ctx._source.cve_check_failed = false',
          params: { at },
        },
      },
      timeoutMs: 5 * 60_000,
    }
  );
  return body?.updated ?? 0;
};

/** EC-10 setup: removes `cve_checked_at` from one synthetic entry so the next run re-checks it. */
export const clearCheckedAt = async (es: EsClient, catalogId: string): Promise<void> => {
  await es.request('POST', `/${CATALOG_INDEX}/_update/${encodeURIComponent(catalogId)}`, {
    query: { refresh: 'true' },
    body: { script: { lang: 'painless', source: "ctx._source.remove('cve_checked_at')" } },
  });
};

// -------------------------------------------------------------------------------------------------
// Running the step
// -------------------------------------------------------------------------------------------------

export interface EnrichOutput {
  readonly checked: number;
  readonly updated: number;
  readonly failed: number;
}

export const readEnrichOutput = (value: JsonValue | undefined): EnrichOutput | undefined => {
  if (!isJsonObject(value)) return undefined;
  const checked = readNumber(value.checked);
  const updated = readNumber(value.updated);
  const failed = readNumber(value.failed);
  return checked === undefined || updated === undefined || failed === undefined
    ? undefined
    : { checked, updated, failed };
};

export interface EnrichRun {
  readonly run: CompletedRun;
  /** Wall clock just before the run was started; entries checked by it have `cve_checked_at` >= it. */
  readonly startedAt: string;
  readonly requests: StubRequestRecord[];
  readonly output?: EnrichOutput;
}

/**
 * Resets the stub (log, per-CPE attempts, mode), applies `mode`, and test-runs `enrich-cves`: the
 * variant with `limit`, or the stored production YAML when `limit` is omitted.
 */
export const runEnrich = async (
  ctx: CaseContext,
  {
    label,
    limit,
    timing,
    mode,
  }: {
    label: string;
    limit?: number;
    timing: EnrichmentTiming;
    mode?: Parameters<NonNullable<CaseContext['nvdStub']>['setMode']>[0];
  }
): Promise<EnrichRun> => {
  const stub = ctx.nvdStub;
  if (!stub)
    throw new Error('The NVD stub is not running; the case must declare needs: [nvd-stub]');
  stub.reset();
  if (mode) stub.setMode(mode);
  const startedAt = new Date().toISOString();
  const run = await ctx.runWorkflow({
    workflow: 'enrichCves',
    ...(limit !== undefined ? { yaml: buildEnrichVariant({ label, limit }) } : {}),
    wait: { timeoutMs: estimateEnrichWaitMs(limit ?? 25, timing), intervalMs: 2000 },
  });
  const requests = compactRequests(stub.requests());
  let output: EnrichOutput | undefined;
  if (run.stepsByName.has('enrich')) {
    try {
      output = readEnrichOutput((await run.step('enrich')).output);
    } catch {
      output = undefined;
    }
  }
  return { run, startedAt, requests, ...(output ? { output } : {}) };
};
