/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * EC: enrich-cves (EC-1..EC-12 in docs/discovery_test_plan.md).
 *
 * Every case runs against the local NVD/KEV stub (`needs: ['nvd-stub']`), which Kibana reaches only
 * when `xpack.softwareInventory.enrichment.*` points at it. A run whose stub log shows no request
 * is reported `blocked` (override not active), never pass or fail.
 *
 * The step checks the oldest entries first and never-checked entries tie, so per-case `limit`
 * values cannot target one entry. EC-1 therefore checks EVERY never-checked entry in one run
 * (the DO/DI/DL entries plus any demo entry never checked) and records the stub log as evidence;
 * EC-2..EC-8 assert on that run (catalog state and the recorded log). EC-9..EC-12 make their own
 * runs. The DO-16 bulk entries (`synth-pkg-*`) are parked first, see `parkBulkEntries`.
 */

import { hasUnknownVersion } from '../../../server/services/enrichment/enrich_catalog_entries';
import type { CatalogEntry } from '../../../common/types';
import { CATALOG_INDEX } from '../../../common/constants';
import type { ExpectedCatalogEntry, LayerResult } from '../assertions';
import {
  checkCatalogEntries,
  checkEngine,
  checkSteps,
  diffValues,
  layerResult,
  mergeLayer,
} from '../assertions';
import type { JsonObject } from '../clients';
import { seedCatalogIds } from '../cleanup';
import {
  EC11_LIMIT,
  EC11_SEED_CATALOG_IDS,
  EC11_SEED_ROWS,
  EC9_SEED_CATALOG_IDS,
  EC9_SEED_ROWS,
  EC_CPES,
  EC_IDS,
  EC_MAX_NEVER_CHECKED,
  EC_REQUIRED_CATALOG_IDS,
  EC_RETRY_EXPECTATIONS,
  EC_UNKNOWN_VERSION_IDS,
  EXPECTED_CHROME,
  EXPECTED_FAILURE_MARKER,
  EXPECTED_FORTIOS_7_2_4,
  EXPECTED_LOG4J_2_12_1,
  EXPECTED_LOG4J_2_14_1,
  EXPECTED_NGINX_1_25_2,
  EXPECTED_PANOS_10_2_3,
  EXPECTED_SLACK,
  EXPECTED_SYNTH_CHECKOUT,
} from '../expected/ec';
import type { OsqueryRow } from '../fixtures/osquery';
import { fPartial } from '../fixtures/osquery';
import { MODE_PRESETS } from '../nvd_stub/fixtures';
import { PRODUCTION_ENRICH_LIMIT } from '../variants/enrich';
import { buildOsqueryVariant } from '../variants/osquery';
import type { EnrichmentTiming, StubRequestRecord } from './ec_support';
import {
  checkGaps,
  checkSpacing,
  clearCheckedAt,
  describeTiming,
  detectOverrideProblem,
  diffPicks,
  expectsLookupFailure,
  findCheckedSince,
  gapsMs,
  kevRequests,
  nvdRequests,
  parkBulkEntries,
  predictPicks,
  readCatalogOrder,
  readEnrichOutput,
  requestsForCpe,
  requestsFromJson,
  requestsToJson,
  resolveEnrichmentTiming,
  retryGapsMs,
  runEnrich,
} from './ec_support';
import type { CatalogOrderEntry, EnrichOutput } from './ec_support';
import { isJsonObject, readEvidence, readNumber, readString } from './evidence_support';
import type { CaseContext, CaseResult, TestCase } from './types';
import { blockedResult, caseResult } from './types';

export const NO_STUB_REASON =
  'The NVD stub is not running (the runner sets ctx.nvdStub for cases that declare needs: [nvd-stub]).';

export interface EcDeps {
  /** The enrichment timing Kibana runs with; default: read from the Kibana config files. */
  readonly resolveTiming: () => EnrichmentTiming;
}

// -------------------------------------------------------------------------------------------------
// EC-1 capture, shared with EC-2..EC-8 through the results file
// -------------------------------------------------------------------------------------------------

export const EC1_EVIDENCE_KEY = 'ec1';

export interface Ec1Capture {
  readonly startedAt: string;
  readonly limit: number;
  readonly output: EnrichOutput;
  readonly expectedFailures: number;
  readonly timing: Pick<EnrichmentTiming, 'spacingMs' | 'timeoutMs' | 'backoffBaseMs'>;
  readonly requests: readonly StubRequestRecord[];
}

export const ec1CaptureToJson = (capture: Ec1Capture): JsonObject => ({
  startedAt: capture.startedAt,
  limit: capture.limit,
  output: { ...capture.output },
  expectedFailures: capture.expectedFailures,
  timing: { ...capture.timing },
  requests: requestsToJson(capture.requests),
});

export const readEc1Capture = (ctx: Pick<CaseContext, 'priorResults'>): Ec1Capture | undefined => {
  const value = readEvidence(ctx.priorResults, 'EC-1', EC1_EVIDENCE_KEY);
  if (!isJsonObject(value) || !isJsonObject(value.timing)) return undefined;
  const startedAt = readString(value.startedAt);
  const limit = readNumber(value.limit);
  const expectedFailures = readNumber(value.expectedFailures);
  const output = readEnrichOutput(value.output);
  const requests = requestsFromJson(value.requests);
  const spacingMs = readNumber(value.timing.spacingMs);
  const timeoutMs = readNumber(value.timing.timeoutMs);
  const backoffBaseMs = readNumber(value.timing.backoffBaseMs);
  if (
    startedAt === undefined ||
    limit === undefined ||
    expectedFailures === undefined ||
    output === undefined ||
    requests === undefined ||
    spacingMs === undefined ||
    timeoutMs === undefined ||
    backoffBaseMs === undefined
  ) {
    return undefined;
  }
  return {
    startedAt,
    limit,
    output,
    expectedFailures,
    timing: { spacingMs, timeoutMs, backoffBaseMs },
    requests,
  };
};

const NO_CAPTURE_REASON =
  'EC-1 recorded no stub capture (run EC-1 in this invocation or keep its passing record in the results file).';

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

const checkedSinceLayer = async (
  ctx: CaseContext,
  ids: readonly string[],
  since: string,
  expectChecked: boolean
): Promise<LayerResult> => {
  const { docs } = await ctx.es.mget<CatalogEntry>(CATALOG_INDEX, ids);
  const diffs = ids.flatMap((id, index) => {
    const doc = docs[index]?.found ? docs[index]._source : undefined;
    if (!doc) return [`catalog ${id}: missing`];
    const checkedAt = doc.cve_checked_at;
    const checked = checkedAt !== undefined && Date.parse(checkedAt) >= Date.parse(since);
    if (expectChecked && !checked) {
      return [`catalog ${id}: cve_checked_at ${checkedAt ?? 'missing'} is not after ${since}`];
    }
    if (!expectChecked && checkedAt !== undefined) {
      return [`catalog ${id}: expected no cve_checked_at, got ${checkedAt}`];
    }
    return [];
  });
  return layerResult('inventory', diffs, ids.length);
};

/** Stub-log checks for one CPE: statuses and the delays between attempts. */
const retryLayer = (
  capture: Ec1Capture,
  expectation: (typeof EC_RETRY_EXPECTATIONS)[keyof typeof EC_RETRY_EXPECTATIONS]
): LayerResult => {
  const requests = requestsForCpe(capture.requests, expectation.cpe);
  const statuses = requests.map(({ status }) => status);
  const diffs = diffValues([...expectation.statuses], statuses, `stub ${expectation.cpe} statuses`);
  const perAttempt = expectation.perAttempt === 'timeout' ? capture.timing.timeoutMs : 0;
  diffs.push(
    ...checkGaps(
      `stub ${expectation.cpe}`,
      gapsMs(requests),
      retryGapsMs(capture.timing.backoffBaseMs, expectation.retries, perAttempt)
    )
  );
  return layerResult('harness', diffs, 2, {
    requests: requests.map(({ at, status }) => `${at} ${status}`),
    gapsMs: gapsMs(requests),
  });
};

interface SeedOutcome {
  readonly blocked?: string;
  readonly layer: LayerResult;
}

/**
 * Makes sure the given never-checked synthetic entries exist: when absent, ingests them with a
 * `discover-osquery` variant (Linux `F-partial`, so nothing is removed).
 */
const seedNeverChecked = async (
  ctx: CaseContext,
  label: string,
  rows: readonly OsqueryRow[],
  ids: readonly string[]
): Promise<SeedOutcome> => {
  const order = await readCatalogOrder(ctx.es);
  const byId = new Map(order.map((entry) => [entry.id, entry]));
  const checked = ids.filter((id) => byId.get(id)?.cve_checked_at !== undefined);
  if (checked.length > 0) {
    return {
      blocked: `${checked.join(
        ', '
      )} already checked by an earlier run; run "cleanup --synthetic-only" and the discovery cases again`,
      layer: layerResult('harness', [], 0),
    };
  }
  const missing = ids.filter((id) => !byId.has(id));
  if (missing.length === 0) return { layer: layerResult('harness', [], 0, { seeded: 'present' }) };
  const run = await ctx.runWorkflow({
    workflow: 'discoverOsquery',
    yaml: buildOsqueryVariant({ label, steps: { query_linux: fPartial(rows) } }),
  });
  const engine = checkEngine(run.execution);
  const step = await checkSteps(run, {
    ingest_linux: { output: { created: missing.length, removed: 0 }, input: { snapshot: false } },
  });
  return {
    layer: layerResult(
      'harness',
      [...engine.diffs, ...step.diffs].map((d) => `seed: ${d}`),
      2,
      {
        seededIds: [...missing],
      }
    ),
  };
};

const neverCheckedOf = (order: readonly CatalogOrderEntry[]): CatalogOrderEntry[] =>
  order.filter((entry) => entry.cve_checked_at === undefined);

const outputLayer = async (
  run: Awaited<ReturnType<typeof runEnrich>>,
  expected: Partial<EnrichOutput>,
  limit?: number
): Promise<LayerResult> =>
  checkSteps(run.run, {
    enrich: { output: { ...expected }, ...(limit !== undefined ? { input: { limit } } : {}) },
  });

// -------------------------------------------------------------------------------------------------
// Cases
// -------------------------------------------------------------------------------------------------

const ec1 =
  ({ resolveTiming }: EcDeps) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    if (!ctx.nvdStub) return blockedResult(NO_STUB_REASON);
    const timing = resolveTiming();
    const parked = await parkBulkEntries(ctx.es, new Date().toISOString());
    const order = await readCatalogOrder(ctx.es);
    const byId = new Map(order.map((entry) => [entry.id, entry]));
    const missing = EC_REQUIRED_CATALOG_IDS.filter((id) => !byId.has(id));
    if (missing.length > 0) {
      return blockedResult(
        `Catalog entries missing: ${missing.join(', ')}. Run DO-1, DI-2, and DL-1 first.`
      );
    }
    const alreadyChecked = EC_REQUIRED_CATALOG_IDS.filter(
      (id) => byId.get(id)?.cve_checked_at !== undefined
    );
    if (alreadyChecked.length > 0) {
      return blockedResult(
        `Already checked by an earlier enrich run: ${alreadyChecked.join(
          ', '
        )}. Run "cleanup --synthetic-only", then DO-1, DI-2, and DL-1 again.`
      );
    }
    const neverChecked = neverCheckedOf(order);
    if (neverChecked.length > EC_MAX_NEVER_CHECKED) {
      return blockedResult(
        `${neverChecked.length} never-checked catalog entries (more than ${EC_MAX_NEVER_CHECKED}); one run cannot cover them.`
      );
    }
    const limit = neverChecked.length;
    const enrich = await runEnrich(ctx, {
      label: 'EC-1',
      limit,
      timing,
      mode: MODE_PRESETS.normal,
    });
    const problem = detectOverrideProblem({
      requests: enrich.requests,
      expectNvd: neverChecked.some((entry) => !hasUnknownVersion(entry)),
      expectKev: true,
    });
    if (problem) return blockedResult(problem);

    const expectedFailures = neverChecked.filter(expectsLookupFailure).length;
    const engine = checkEngine(enrich.run.execution);
    const step = await outputLayer(
      enrich,
      { checked: limit, updated: limit - expectedFailures, failed: expectedFailures },
      limit
    );
    const picked = await findCheckedSince(ctx.es, enrich.startedAt);
    const picks = layerResult(
      'inventory',
      diffPicks({ definite: neverChecked.map(({ id }) => id), tieGroup: [], tieCount: 0 }, picked),
      1
    );
    const log4j = await checkCatalogEntries(ctx.es, [
      { id: EC_IDS.log4j2141, fields: EXPECTED_LOG4J_2_14_1 },
    ]);
    const capture: Ec1Capture = {
      startedAt: enrich.startedAt,
      limit,
      output: enrich.output ?? { checked: -1, updated: -1, failed: -1 },
      expectedFailures,
      timing,
      requests: enrich.requests,
    };
    const harness = layerResult(
      'harness',
      kevRequests(enrich.requests).length === 1 ? [] : ['expected exactly 1 KEV request'],
      1,
      { [EC1_EVIDENCE_KEY]: ec1CaptureToJson(capture) }
    );
    return caseResult(
      [engine, step, mergeLayer('inventory', [picks, log4j]), harness],
      [
        `limit ${limit} (every never-checked entry); ${parked} DO-16 bulk entries parked`,
        describeTiming(timing),
      ]
    );
  };

/** EC-2..EC-5: catalog state after the EC-1 run, plus its stub log. */
const catalogAfterEc1 =
  (
    entries: ReadonlyArray<{ id: string; fields: ExpectedCatalogEntry['fields'] }>,
    stubChecks?: (capture: Ec1Capture) => string[]
  ) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    const capture = readEc1Capture(ctx);
    if (!capture) return blockedResult(NO_CAPTURE_REASON);
    const catalog = await checkCatalogEntries(ctx.es, entries);
    const checked = await checkedSinceLayer(
      ctx,
      entries.map(({ id }) => id),
      capture.startedAt,
      true
    );
    const layers = [mergeLayer('inventory', [catalog, checked])];
    if (stubChecks) layers.push(layerResult('harness', stubChecks(capture), 1));
    return caseResult(layers);
  };

const ec4StubChecks = (capture: Ec1Capture): string[] =>
  [EC_CPES.fortios724, EC_CPES.panos1023].flatMap((cpe) => {
    const requests = requestsForCpe(capture.requests, cpe);
    return requests.length === 1 && requests[0].status === 200
      ? []
      : [`stub: expected one answered request for ${cpe}, got ${JSON.stringify(requests)}`];
  });

const ec5StubChecks = (capture: Ec1Capture): string[] => {
  const unknown = nvdRequests(capture.requests).filter(({ cpe }) => cpe?.includes(':unknown:'));
  return unknown.length === 0
    ? []
    : [`stub: unknown-version entries reached NVD: ${unknown.map(({ cpe }) => cpe).join(', ')}`];
};

const ec6 = async (ctx: CaseContext): Promise<CaseResult> => {
  const capture = readEc1Capture(ctx);
  if (!capture) return blockedResult(NO_CAPTURE_REASON);
  const stub = retryLayer(capture, EC_RETRY_EXPECTATIONS.chrome);
  const spacing = layerResult(
    'harness',
    checkSpacing(capture.requests, capture.timing.spacingMs),
    1
  );
  const output = layerResult(
    'step',
    diffValues(capture.expectedFailures, capture.output.failed, 'enrich.output.failed'),
    1
  );
  const catalog = await checkCatalogEntries(ctx.es, [
    { id: EC_IDS.chrome, fields: EXPECTED_CHROME },
  ]);
  return caseResult([output, catalog, mergeLayer('harness', [stub, spacing])]);
};

const failureMarkerCase =
  (id: string, expectation: (typeof EC_RETRY_EXPECTATIONS)['sevenZip' | 'vscode']) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    const capture = readEc1Capture(ctx);
    if (!capture) return blockedResult(NO_CAPTURE_REASON);
    const catalog = await checkCatalogEntries(ctx.es, [{ id, fields: EXPECTED_FAILURE_MARKER }]);
    const checked = await checkedSinceLayer(ctx, [id], capture.startedAt, true);
    return caseResult([
      mergeLayer('inventory', [catalog, checked]),
      retryLayer(capture, expectation),
    ]);
  };

const ec9 =
  ({ resolveTiming }: EcDeps) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    if (!ctx.nvdStub) return blockedResult(NO_STUB_REASON);
    const timing = resolveTiming();
    const seed = await seedNeverChecked(ctx, 'EC-9 seed', EC9_SEED_ROWS, EC9_SEED_CATALOG_IDS);
    if (seed.blocked) return blockedResult(seed.blocked);
    const neverChecked = neverCheckedOf(await readCatalogOrder(ctx.es));
    const realVersion = neverChecked.filter((entry) => !hasUnknownVersion(entry));
    const enrich = await runEnrich(ctx, {
      label: 'EC-9',
      limit: neverChecked.length,
      timing,
      mode: MODE_PRESETS.offline,
    });
    const problem = detectOverrideProblem({
      requests: enrich.requests,
      expectNvd: true,
      expectKev: true,
    });
    if (problem) return blockedResult(problem);
    const engine = checkEngine(enrich.run.execution);
    const outputDiffs = enrich.output
      ? [
          ...diffValues(1, enrich.output.failed, 'enrich.output.failed'),
          ...diffValues(enrich.output.checked - 1, enrich.output.updated, 'enrich.output.updated'),
        ]
      : ['enrich.output missing'];
    const nvd = nvdRequests(enrich.requests);
    const stub = layerResult(
      'harness',
      nvd.length === 1 && nvd[0].status === 0
        ? []
        : [`stub: expected one dropped NVD request, got ${JSON.stringify(nvd)}`],
      1
    );
    const { docs } = await ctx.es.mget<CatalogEntry>(
      CATALOG_INDEX,
      realVersion.map(({ id }) => id)
    );
    const inventoryDiffs = realVersion.flatMap(({ id }, index) => {
      const doc = docs[index]?._source;
      if (!doc) return [`catalog ${id}: missing`];
      return [
        ...(doc.cve_checked_at !== undefined ? [`catalog ${id}: got cve_checked_at`] : []),
        ...(doc.cve_check_failed === true ? [`catalog ${id}: got a failure marker`] : []),
      ];
    });
    return caseResult([
      engine,
      layerResult('step', outputDiffs, 2, enrich.output ? { output: { ...enrich.output } } : {}),
      layerResult('inventory', inventoryDiffs, Math.max(1, realVersion.length)),
      mergeLayer('harness', [seed.layer, stub]),
    ]);
  };

const ec10 =
  ({ resolveTiming }: EcDeps) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    if (!ctx.nvdStub) return blockedResult(NO_STUB_REASON);
    const timing = resolveTiming();
    const {
      docs: [beforeDoc],
    } = await ctx.es.mget<CatalogEntry>(CATALOG_INDEX, [EC_IDS.log4j2141]);
    const before = beforeDoc?.found ? beforeDoc._source : undefined;
    if (!before?.cve_checked_at) {
      return blockedResult(`${EC_IDS.log4j2141} is missing or was never checked; run EC-1 first.`);
    }
    await clearCheckedAt(ctx.es, EC_IDS.log4j2141);
    const neverChecked = neverCheckedOf(await readCatalogOrder(ctx.es));
    const enrich = await runEnrich(ctx, {
      label: 'EC-10',
      limit: neverChecked.length,
      timing,
      mode: MODE_PRESETS['kev-500'],
    });
    const problem = detectOverrideProblem({
      requests: enrich.requests,
      expectNvd: true,
      expectKev: true,
    });
    if (problem) return blockedResult(problem);
    const engine = checkEngine(enrich.run.execution);
    const step = await outputLayer(enrich, {
      checked: neverChecked.length,
      failed: neverChecked.filter(expectsLookupFailure).length,
    });
    const catalog = await checkCatalogEntries(ctx.es, [
      {
        id: EC_IDS.log4j2141,
        fields: {
          known_exploited: before.known_exploited,
          cve_check_failed: false,
          cve_details: (before.cve_details ?? []).map(({ id, known_exploited: exploited }) => ({
            id,
            known_exploited: exploited,
          })),
        },
      },
    ]);
    const checked = await checkedSinceLayer(ctx, [EC_IDS.log4j2141], enrich.startedAt, true);
    const kev = kevRequests(enrich.requests);
    const stub = layerResult(
      'harness',
      kev.length === 1 && kev[0].status === 500
        ? []
        : [`stub: expected one KEV request answered 500, got ${JSON.stringify(kev)}`],
      1
    );
    return caseResult(
      [engine, step, mergeLayer('inventory', [catalog, checked]), stub],
      [
        'Manual: the Kibana log must warn "CISA KEV catalog responded with status 500" (the harness cannot read Kibana logs).',
      ]
    );
  };

class OverrideInactiveError extends Error {}

/** One EC-11 run: predicts the picks from the current order, runs, and compares. */
const orderedRun = async (
  ctx: CaseContext,
  label: string,
  limit: number | undefined,
  timing: EnrichmentTiming
): Promise<{ layers: LayerResult[]; picked: string[]; order: CatalogOrderEntry[] }> => {
  const order = await readCatalogOrder(ctx.es);
  const prediction = predictPicks(order, limit ?? PRODUCTION_ENRICH_LIMIT);
  const enrich = await runEnrich(ctx, { label, limit, timing, mode: MODE_PRESETS.normal });
  const problem = detectOverrideProblem({
    requests: enrich.requests,
    expectNvd: order.some((entry) => !hasUnknownVersion(entry)),
    expectKev: true,
  });
  if (problem) throw new OverrideInactiveError(problem);
  const picked = await findCheckedSince(ctx.es, enrich.startedAt);
  const byId = new Map(order.map((entry) => [entry.id, entry]));
  const failing = picked.filter((id) => {
    const entry = byId.get(id);
    return entry !== undefined && expectsLookupFailure(entry);
  }).length;
  const expectedChecked = Math.min(limit ?? PRODUCTION_ENRICH_LIMIT, order.length);
  return {
    order,
    picked,
    layers: [
      checkEngine(enrich.run.execution),
      await outputLayer(enrich, {
        checked: expectedChecked,
        updated: expectedChecked - failing,
        failed: failing,
      }),
      layerResult(
        'inventory',
        diffPicks(prediction, picked).map((diff) => `${label}: ${diff}`),
        1,
        { [`${label} picked`]: picked }
      ),
    ],
  };
};

const ec11 =
  ({ resolveTiming }: EcDeps) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    if (!ctx.nvdStub) return blockedResult(NO_STUB_REASON);
    const timing = resolveTiming();
    const seed = await seedNeverChecked(ctx, 'EC-11 seed', EC11_SEED_ROWS, EC11_SEED_CATALOG_IDS);
    if (seed.blocked) return blockedResult(seed.blocked);
    try {
      const first = await orderedRun(ctx, 'EC-11 run 1', EC11_LIMIT, timing);
      const neverCheckedFirst = EC11_SEED_CATALOG_IDS.filter((id) => !first.picked.includes(id));
      const markers = first.order.filter((entry) => entry.cve_check_failed === true);
      const markerDiffs = [
        ...neverCheckedFirst.map((id) => `never-checked ${id} was not checked by run 1`),
        ...markers
          .filter((entry) => entry.cve_checked_at === undefined)
          .map((entry) => `failure marker ${entry.id} has no cve_checked_at (would stay first)`),
      ];
      const second = await orderedRun(ctx, 'EC-11 run 2', EC11_LIMIT, timing);
      return caseResult(
        [
          mergeLayer('engine', [first.layers[0], second.layers[0]]),
          mergeLayer('step', [first.layers[1], second.layers[1]]),
          mergeLayer('inventory', [
            first.layers[2],
            second.layers[2],
            layerResult('inventory', markerDiffs, 2),
          ]),
          seed.layer,
        ],
        [`failure-marked entries before run 1: ${markers.map(({ id }) => id).join(', ') || 'none'}`]
      );
    } catch (error) {
      if (error instanceof OverrideInactiveError) return blockedResult(error.message);
      throw error;
    }
  };

const ec12 =
  ({ resolveTiming }: EcDeps) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    if (!ctx.nvdStub) return blockedResult(NO_STUB_REASON);
    const timing = resolveTiming();
    const pending = neverCheckedOf(await readCatalogOrder(ctx.es));
    if (pending.length > 0) {
      return blockedResult(
        `EC-12 runs after every entry is checked; never checked: ${pending
          .map(({ id }) => id)
          .join(', ')}`
      );
    }
    try {
      const run = await orderedRun(ctx, 'EC-12', undefined, timing);
      const seedIds = new Set(seedCatalogIds());
      const demoPicked = run.picked.filter((id) => seedIds.has(id));
      const byId = new Map(run.order.map((entry) => [entry.id, entry]));
      const cleanDemo = demoPicked.filter((id) => {
        const entry = byId.get(id);
        return entry !== undefined && !hasUnknownVersion(entry) && !expectsLookupFailure(entry);
      });
      const demo = await checkCatalogEntries(
        ctx.es,
        cleanDemo.map((id) => ({ id, fields: { cve_count: 0, cve_check_failed: false } }))
      );
      return caseResult(
        [
          run.layers[0],
          run.layers[1],
          mergeLayer('inventory', [
            run.layers[2],
            demo,
            layerResult('inventory', demoPicked.length > 0 ? [] : ['no demo entry was checked'], 1),
          ]),
        ],
        [
          `${demoPicked.length} demo entries checked against the stub (CVE data now empty); restore with seed_demo_data.js --clean`,
        ]
      );
    } catch (error) {
      if (error instanceof OverrideInactiveError) return blockedResult(error.message);
      throw error;
    }
  };

export const createEcCases = (
  deps: EcDeps = { resolveTiming: () => resolveEnrichmentTiming() }
): TestCase[] => {
  const stubCase = (
    id: string,
    title: string,
    requires: readonly string[],
    run: TestCase['run']
  ): TestCase => ({ id, family: 'EC', title, requires, needs: ['nvd-stub'], run });
  return [
    stubCase(
      'EC-1',
      'Multi-CVE safe version (log4j 2.14.1); one run checks every never-checked entry',
      ['DO-1', 'DI-2', 'DL-1'],
      ec1(deps)
    ),
    stubCase(
      'EC-2',
      'Multi-branch fix (log4j 2.12.1)',
      ['EC-1'],
      catalogAfterEc1([{ id: EC_IDS.log4j2121, fields: EXPECTED_LOG4J_2_12_1 }])
    ),
    stubCase(
      'EC-3',
      'Unfixed CVE (synth-checkout), plus the single-range and clean stub entries',
      ['EC-1'],
      catalogAfterEc1([
        { id: EC_IDS.synthCheckout, fields: EXPECTED_SYNTH_CHECKOUT },
        { id: EC_IDS.nginx1252, fields: EXPECTED_NGINX_1_25_2 },
        { id: EC_IDS.slack, fields: EXPECTED_SLACK },
      ])
    ),
    stubCase(
      'EC-4',
      'Appliance CPE part o and the PAN-OS vendor alias',
      ['EC-1'],
      catalogAfterEc1(
        [
          { id: EC_IDS.fortios724, fields: EXPECTED_FORTIOS_7_2_4 },
          { id: EC_IDS.panos1023, fields: EXPECTED_PANOS_10_2_3 },
        ],
        ec4StubChecks
      )
    ),
    stubCase(
      'EC-5',
      'Unknown version skipped: checked without an NVD request',
      ['EC-1'],
      catalogAfterEc1(
        EC_UNKNOWN_VERSION_IDS.map((id) => ({
          id,
          fields: { cve_check_failed: false, cve_count: 0 },
        })),
        ec5StubChecks
      )
    ),
    stubCase('EC-6', 'Rate limit (429, 429, 200) with backoff and spacing', ['EC-1'], ec6),
    stubCase(
      'EC-7',
      'Persistent 403: failure marker after 4 requests',
      ['EC-1'],
      failureMarkerCase(EC_IDS.sevenZip, EC_RETRY_EXPECTATIONS.sevenZip)
    ),
    stubCase(
      'EC-8',
      'Timeout: failure marker after 4 timed-out attempts',
      ['EC-1'],
      failureMarkerCase(EC_IDS.vscode, EC_RETRY_EXPECTATIONS.vscode)
    ),
    stubCase(
      'EC-9',
      'Network unavailable: the run stops and leaves entries unchecked',
      ['EC-1'],
      ec9(deps)
    ),
    stubCase('EC-10', 'KEV unavailable: known_exploited keeps its value', ['EC-1'], ec10(deps)),
    stubCase(
      'EC-11',
      'Ordering: never checked first, then oldest check (two runs, limit 3)',
      ['EC-1'],
      ec11(deps)
    ),
    stubCase(
      'EC-12',
      'Production YAML (limit 25) after every entry is checked',
      ['EC-1'],
      ec12(deps)
    ),
  ];
};

export const cases: TestCase[] = createEcCases();
