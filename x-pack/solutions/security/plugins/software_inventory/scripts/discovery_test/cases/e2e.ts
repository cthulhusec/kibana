/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * E2E: cross-workflow end to end (E2E-1..E2E-5 in docs/discovery_test_plan.md).
 *
 * E2E-1 starts from a clean synthetic state: it runs `cleanup` (synthetic documents, the synthetic
 * logs data stream and template, and `si-test-*` workflows), generates the logs with a fresh T0,
 * and runs the whole pipeline: logs phase A, DO-1 (`R1`), DI-2, DL-1, EC (normal stub), logs
 * phase B, DL-7, and score-exposure. It records T0 and the run times as evidence; E2E-2..E2E-5
 * assert on that state through the plugin routes.
 */

import {
  CATALOG_INDEX,
  EVENTS_INDEX,
  INSTANCES_INDEX,
  INSTANCES_URL,
} from '../../../common/constants';
import type { HostTimelineResponse, InventoryEvent } from '../../../common/history';
import type { CatalogEntry, FindInstancesResponse, InstanceDoc } from '../../../common/types';
import type { LayerResult } from '../assertions';
import {
  checkEngine,
  checkSteps,
  diffEvents,
  diffValues,
  findEvents,
  ingestOutput,
  layerResult,
  mergeLayer,
} from '../assertions';
import type { CompletedRun, JsonObject } from '../clients';
import { cleanup, syntheticHostKeyQuery } from '../cleanup';
import {
  DAY_MS,
  E2E2_DURATION_TOLERANCE_MS,
  E2E2_HOST,
  E2E3_NO_POSTURE,
  E2E3_POSTURE_BEFORE,
  E2E3_REPEAT,
  E2E3_REPEAT_CATALOG_IDS,
  E2E4_CVE_IDS,
  E2E4_HOST,
  E2E4_LOG4J,
  E2E5_HOST_ID,
  E2E_CHECKED_CATALOG_IDS,
  E2E_ENRICH_LIMIT,
  E2E_EVENT_COUNTS,
  E2E_INGEST,
  E2E_SYNTHETIC_INSTANCES,
  E2E_TIMESTAMP_TOLERANCE_MS,
  E2E_UNCHECKED_CATALOG_ID,
  e2e2Expectations,
} from '../expected/e2e';
import type { TimelineExpectation } from '../expected/e2e';
import { FLEET_MAPPED_AND_UNMAPPED } from '../fixtures/fleet';
import { OSQUERY_QUERY_STEPS, R1 } from '../fixtures/osquery';
import { instanceIdFor } from '../ids';
import { buildPhaseDocs, serviceLogSpec, toLogDoc } from '../logs/generate_logs';
import { MODE_PRESETS } from '../nvd_stub/fixtures';
import { buildIntegrationsVariant } from '../variants/integrations';
import { buildOsqueryVariant } from '../variants/osquery';
import type { EnrichmentTiming } from './ec_support';
import {
  NEVER_CHECKED_QUERY,
  describeTiming,
  detectOverrideProblem,
  expectsLookupFailure,
  findCheckedSince,
  readCatalogOrder,
  resolveEnrichmentTiming,
  runEnrich,
} from './ec_support';
import { isJsonObject, readEvidence, readString } from './evidence_support';
import type { CaseContext, CaseResult, TestCase } from './types';
import { blockedResult, caseResult } from './types';

export interface E2eDeps {
  readonly resolveTiming: () => EnrichmentTiming;
  readonly cleanup: typeof cleanup;
  readonly now: () => Date;
}

export const E2E1_EVIDENCE_KEY = 'e2e';

export interface E2e1Capture {
  /** T0 of the synthetic logs E2E-1 generated. */
  readonly t0: string;
  /** Wall clock before the pipeline (after cleanup). */
  readonly startedAt: string;
  readonly doRun: { readonly startedAt?: string; readonly finishedAt?: string };
}

export const readE2e1Capture = (
  ctx: Pick<CaseContext, 'priorResults'>
): E2e1Capture | undefined => {
  const value = readEvidence(ctx.priorResults, 'E2E-1', E2E1_EVIDENCE_KEY);
  if (!isJsonObject(value) || !isJsonObject(value.doRun)) return undefined;
  const t0 = readString(value.t0);
  const startedAt = readString(value.startedAt);
  if (!t0 || !startedAt) return undefined;
  const doStarted = readString(value.doRun.startedAt);
  const doFinished = readString(value.doRun.finishedAt);
  return {
    t0,
    startedAt,
    doRun: {
      ...(doStarted ? { startedAt: doStarted } : {}),
      ...(doFinished ? { finishedAt: doFinished } : {}),
    },
  };
};

const NO_CAPTURE_REASON =
  'E2E-1 recorded no pipeline capture (run E2E-1 in this invocation or keep its passing record).';

const ingestStepOf = (queryStep: string): string => queryStep.replace(/^query_/, 'ingest_');

/** Engine and ingest-output layers of one run. */
const runLayers = async (
  label: string,
  run: CompletedRun,
  ingest: Readonly<Record<string, Parameters<typeof ingestOutput>[0]>>
): Promise<{ engine: LayerResult; step: LayerResult }> => {
  const engine = checkEngine(run.execution);
  const step = await checkSteps(
    run,
    Object.fromEntries(
      Object.entries(ingest).map(([name, partial]) => [name, { output: ingestOutput(partial) }])
    )
  );
  const prefix = (result: LayerResult): LayerResult =>
    layerResult(
      result.layer,
      result.diffs.map((diff) => `${label}: ${diff}`),
      result.checks,
      result.evidence ? { [label]: { ...result.evidence } } : undefined
    );
  return { engine: prefix(engine), step: prefix(step) };
};

const countByType = (events: readonly InventoryEvent[]): Record<string, number> =>
  events.reduce<Record<string, number>>((counts, { type }) => {
    counts[type] = (counts[type] ?? 0) + 1;
    return counts;
  }, {});

// -------------------------------------------------------------------------------------------------
// E2E-1
// -------------------------------------------------------------------------------------------------

const e2e1 =
  (deps: E2eDeps) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    if (!ctx.nvdStub) {
      return blockedResult('The NVD stub is not running (the case declares needs: [nvd-stub]).');
    }
    const timing = deps.resolveTiming();
    const cleaned = await deps.cleanup(ctx.es, ctx.kibana, { syntheticOnly: false });
    const t0 = deps.now();
    const startedAt = t0.toISOString();
    const engine: LayerResult[] = [];
    const step: LayerResult[] = [];
    const add = (layers: { engine: LayerResult; step: LayerResult }) => {
      engine.push(layers.engine);
      step.push(layers.step);
    };

    await ctx.writeLogDocs(buildPhaseDocs('A', t0));
    const doRun = await ctx.runWorkflow({
      workflow: 'discoverOsquery',
      yaml: buildOsqueryVariant({ label: 'E2E-1 R1', steps: R1 }),
    });
    add(
      await runLayers(
        'DO-1',
        doRun,
        Object.fromEntries(
          OSQUERY_QUERY_STEPS.map((query) => [ingestStepOf(query), R1[query].expected.ingest ?? {}])
        )
      )
    );
    const diRun = await ctx.runWorkflow({
      workflow: 'discoverIntegrations',
      yaml: buildIntegrationsVariant({
        label: 'E2E-1 DI-2',
        response: FLEET_MAPPED_AND_UNMAPPED.response,
      }),
    });
    add(await runLayers('DI-2', diRun, { ingest: E2E_INGEST.di2 }));
    add(
      await runLayers('DL-1', await ctx.runWorkflow({ workflow: 'discoverLogs' }), {
        ingest: E2E_INGEST.dl1,
      })
    );

    const neverChecked = await ctx.es.count(CATALOG_INDEX, NEVER_CHECKED_QUERY);
    const limit = Math.max(E2E_ENRICH_LIMIT, neverChecked);
    const order = await readCatalogOrder(ctx.es);
    const enrich = await runEnrich(ctx, {
      label: 'E2E-1 EC',
      limit,
      timing,
      mode: MODE_PRESETS.normal,
    });
    const problem = detectOverrideProblem({
      requests: enrich.requests,
      expectNvd: true,
      expectKev: true,
    });
    if (problem) return blockedResult(problem);
    const picked = await findCheckedSince(ctx.es, enrich.startedAt);
    const byId = new Map(order.map((entry) => [entry.id, entry]));
    const failing = picked.filter((id) => {
      const entry = byId.get(id);
      return entry !== undefined && expectsLookupFailure(entry);
    }).length;
    const checked = Math.min(limit, order.length);
    engine.push(checkEngine(enrich.run.execution));
    step.push(
      await checkSteps(enrich.run, {
        enrich: { output: { checked, updated: checked - failing, failed: failing } },
      })
    );

    await ctx.writeLogDocs(buildPhaseDocs('B', t0));
    add(
      await runLayers('DL-7', await ctx.runWorkflow({ workflow: 'discoverLogs' }), {
        ingest: E2E_INGEST.dl7,
      })
    );

    const seRun = await ctx.runWorkflow({ workflow: 'scoreExposure' });
    engine.push(checkEngine(seRun.execution));
    const scored = await ctx.es.count(INSTANCES_INDEX, {
      bool: { must_not: [{ term: { status: 'removed' } }] },
    });
    step.push(await checkSteps(seRun, { score: { output: { scored } } }));

    const instances = await ctx.es.count(INSTANCES_INDEX, syntheticHostKeyQuery());
    const events = await ctx.es.search<InventoryEvent>(EVENTS_INDEX, {
      size: 10_000,
      query: {
        bool: {
          filter: [syntheticHostKeyQuery(), { range: { '@timestamp': { gte: startedAt } } }],
        },
      },
    });
    const eventCounts = countByType(
      events.hits.hits.flatMap((hit) => (hit._source ? [hit._source] : []))
    );
    const { docs } = await ctx.es.mget<CatalogEntry>(CATALOG_INDEX, [
      ...E2E_CHECKED_CATALOG_IDS,
      E2E_UNCHECKED_CATALOG_ID,
    ]);
    const catalogDiffs = docs.flatMap((doc) => {
      const checkedAt = doc.found ? doc._source?.cve_checked_at : undefined;
      if (!doc.found) return [`catalog ${doc._id}: missing`];
      if (doc._id === E2E_UNCHECKED_CATALOG_ID) {
        return checkedAt === undefined ? [] : [`catalog ${doc._id}: checked before it existed`];
      }
      return checkedAt !== undefined && Date.parse(checkedAt) >= Date.parse(enrich.startedAt)
        ? []
        : [`catalog ${doc._id}: not checked by the EC run (cve_checked_at ${checkedAt})`];
    });
    const inventory = layerResult(
      'inventory',
      [
        ...diffValues(E2E_SYNTHETIC_INSTANCES, instances, 'synthetic instances'),
        ...diffValues({ ...E2E_EVENT_COUNTS }, eventCounts, 'synthetic events by type'),
        ...Object.keys(eventCounts)
          .filter((type) => !(type in E2E_EVENT_COUNTS))
          .map((type) => `unexpected ${eventCounts[type]} ${type} event(s)`),
        ...catalogDiffs,
      ],
      3 + docs.length
    );
    const capture: JsonObject = {
      t0: t0.toISOString(),
      startedAt,
      doRun: {
        ...(doRun.execution.startedAt ? { startedAt: doRun.execution.startedAt } : {}),
        ...(doRun.execution.finishedAt ? { finishedAt: doRun.execution.finishedAt } : {}),
      },
    };
    return caseResult(
      [
        mergeLayer('engine', engine),
        mergeLayer('step', step),
        inventory,
        layerResult('harness', [], 1, {
          [E2E1_EVIDENCE_KEY]: capture,
          cleanup: {
            instancesDeleted: cleaned.instancesDeleted,
            eventsDeleted: cleaned.eventsDeleted,
            catalogDeleted: cleaned.catalogDeleted,
            workflowsDeleted: [...(cleaned.workflowsDeleted ?? [])],
          },
        }),
      ],
      [`T0 ${t0.toISOString()}; EC limit ${limit}`, describeTiming(timing)]
    );
  };

// -------------------------------------------------------------------------------------------------
// Timeline helpers
// -------------------------------------------------------------------------------------------------

const getTimeline = async (
  ctx: CaseContext,
  hostKey: string,
  range: { from: string; to: string }
): Promise<HostTimelineResponse> =>
  (
    await ctx.kibana.internalRequest<HostTimelineResponse>(
      'GET',
      `/internal/software_inventory/hosts/${encodeURIComponent(hostKey)}/timeline`,
      { query: range }
    )
  ).body;

const within = (
  actual: string | number | undefined,
  expected: string | number,
  toleranceMs: number
) => {
  if (actual === undefined) return false;
  const a = typeof actual === 'number' ? actual : Date.parse(actual);
  const e = typeof expected === 'number' ? expected : Date.parse(expected);
  return Math.abs(a - e) <= toleranceMs;
};

/** Pure: compares one timeline response with its expectation. */
export const diffTimeline = (
  expected: TimelineExpectation,
  actual: HostTimelineResponse,
  product = 'nginx'
): string[] => {
  const label = expected.label;
  const diffs: string[] = [];
  if (actual.vulnerable_in_range !== expected.vulnerableInRange) {
    diffs.push(
      `${label}: vulnerable_in_range ${actual.vulnerable_in_range} != ${expected.vulnerableInRange}`
    );
  }
  if (
    expected.firstVulnerableAt !== undefined &&
    !within(actual.first_vulnerable_at, expected.firstVulnerableAt, E2E_TIMESTAMP_TOLERANCE_MS)
  ) {
    diffs.push(
      `${label}: first_vulnerable_at ${actual.first_vulnerable_at} != ${expected.firstVulnerableAt}`
    );
  }
  if (expected.cveIds !== undefined) {
    diffs.push(
      ...diffValues([...expected.cveIds].sort(), [...actual.cve_ids].sort(), `${label}: cve_ids`)
    );
  }
  if (
    expected.vulnerableDurationMs !== undefined &&
    !within(
      actual.vulnerable_duration_ms,
      expected.vulnerableDurationMs,
      E2E2_DURATION_TOLERANCE_MS
    )
  ) {
    diffs.push(
      `${label}: vulnerable_duration_ms ${actual.vulnerable_duration_ms} not within ${E2E2_DURATION_TOLERANCE_MS}ms of ${expected.vulnerableDurationMs}`
    );
  }
  if (expected.itemAbsent && actual.items.some((item) => item.product === product)) {
    diffs.push(`${label}: expected no ${product} item in range`);
  }
  return diffs;
};

const toEvidence = (response: HostTimelineResponse): JsonObject => ({
  vulnerable_in_range: response.vulnerable_in_range,
  vulnerable_duration_ms: response.vulnerable_duration_ms,
  first_vulnerable_at: response.first_vulnerable_at ?? null,
  cve_ids: [...response.cve_ids],
  items: response.items.map((item) => `${item.vendor}:${item.product}:${item.status}`),
});

// -------------------------------------------------------------------------------------------------
// E2E-2..E2E-5
// -------------------------------------------------------------------------------------------------

const e2e2 =
  (deps: E2eDeps) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    const capture = readE2e1Capture(ctx);
    if (!capture) return blockedResult(NO_CAPTURE_REASON);
    const expectations = e2e2Expectations(new Date(capture.t0), deps.now());
    const evidence: JsonObject = {};
    const diffs: string[] = [];
    for (const expectation of expectations) {
      const response = await getTimeline(ctx, E2E2_HOST, {
        from: expectation.from,
        to: expectation.to,
      });
      evidence[expectation.label] = toEvidence(response);
      diffs.push(...diffTimeline(expectation, response));
    }
    return caseResult([layerResult('inventory', diffs, expectations.length * 3, evidence)]);
  };

const writeRepeatDoc = async (
  ctx: CaseContext,
  deps: E2eDeps,
  phase: 'before' | 'after'
): Promise<void> => {
  const spec = serviceLogSpec({
    docId: `E2E3-${phase}`,
    hostName: E2E3_REPEAT.hostKey,
    service: 'nginx',
    version: E2E3_REPEAT[phase],
    offsetMs: phase === 'before' ? E2E3_REPEAT.beforeOffsetMs : E2E3_REPEAT.afterOffsetMs,
  });
  await ctx.writeLogDocs([toLogDoc(spec, deps.now())]);
};

const e2e3 =
  (deps: E2eDeps) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    const capture = readE2e1Capture(ctx);
    if (!capture) return blockedResult(NO_CAPTURE_REASON);
    const patchEvents = await findEvents(ctx.es, {
      hostKeys: [E2E2_HOST],
      since: capture.startedAt,
      types: ['version_changed'],
    });
    const posture = layerResult(
      'inventory',
      diffEvents([{ type: 'version_changed', ...E2E3_POSTURE_BEFORE }], patchEvents).map(
        (diff) => `EC before the patch: ${diff}`
      ),
      1
    );

    // Repeat with the EC run after the patch: neither version is checked, so no posture fields.
    const { docs } = await ctx.es.mget<CatalogEntry>(CATALOG_INDEX, [
      E2E3_REPEAT_CATALOG_IDS.before,
      E2E3_REPEAT_CATALOG_IDS.after,
    ]);
    const checked = docs.filter((doc) => doc.found && doc._source?.cve_checked_at !== undefined);
    if (checked.length > 0) {
      return blockedResult(
        `${checked
          .map((doc) => doc._id)
          .join(', ')} already checked; run "cleanup --synthetic-only" first`
      );
    }
    const repeatStart = deps.now().toISOString();
    await writeRepeatDoc(ctx, deps, 'before');
    const firstRun = await ctx.runWorkflow({ workflow: 'discoverLogs' });
    const firstOutput = await checkSteps(firstRun, {
      ingest: { output: { created: 1, patched: 0, removed: 0 } },
    });
    await writeRepeatDoc(ctx, deps, 'after');
    const secondRun = await ctx.runWorkflow({ workflow: 'discoverLogs' });
    const secondOutput = await checkSteps(secondRun, {
      ingest: { output: { created: 0, patched: 1, removed: 0 } },
    });
    const repeatEvents = await findEvents(ctx.es, {
      hostKeys: [E2E3_REPEAT.hostKey],
      since: repeatStart,
      types: ['version_changed'],
    });
    const noPosture = layerResult(
      'inventory',
      diffEvents([{ type: 'version_changed', ...E2E3_NO_POSTURE }], repeatEvents).map(
        (diff) => `EC after the patch: ${diff}`
      ),
      1
    );
    return caseResult([
      mergeLayer('engine', [checkEngine(firstRun.execution), checkEngine(secondRun.execution)]),
      mergeLayer('step', [firstOutput, secondOutput]),
      mergeLayer('inventory', [posture, noPosture]),
    ]);
  };

const e2e4 =
  (deps: E2eDeps) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    const capture = readE2e1Capture(ctx);
    if (!capture) return blockedResult(NO_CAPTURE_REASON);
    const t0 = Date.parse(capture.t0);
    const response = await getTimeline(ctx, E2E4_HOST, {
      from: new Date(t0 - 3 * DAY_MS).toISOString(),
      to: deps.now().toISOString(),
    });
    const {
      docs: [log4jDoc],
    } = await ctx.es.mget<InstanceDoc>(INSTANCES_INDEX, [instanceIdFor(E2E4_LOG4J)]);
    const firstSeen = log4jDoc?.found ? log4jDoc._source?.first_seen : undefined;
    const diffs = [
      ...(response.vulnerable_in_range ? [] : ['vulnerable_in_range false']),
      ...diffValues([...E2E4_CVE_IDS], [...response.cve_ids].sort(), 'cve_ids'),
    ];
    if (!firstSeen) diffs.push(`log4j instance on ${E2E4_HOST} missing`);
    else if (!within(response.first_vulnerable_at, firstSeen, E2E_TIMESTAMP_TOLERANCE_MS)) {
      diffs.push(
        `first_vulnerable_at ${response.first_vulnerable_at} != log4j first_seen ${firstSeen}`
      );
    }
    const { startedAt, finishedAt } = capture.doRun;
    if (
      startedAt &&
      finishedAt &&
      response.first_vulnerable_at &&
      (Date.parse(response.first_vulnerable_at) <
        Date.parse(startedAt) - E2E_TIMESTAMP_TOLERANCE_MS ||
        Date.parse(response.first_vulnerable_at) >
          Date.parse(finishedAt) + E2E_TIMESTAMP_TOLERANCE_MS)
    ) {
      diffs.push(
        `first_vulnerable_at ${response.first_vulnerable_at} outside the R1 run [${startedAt}, ${finishedAt}]`
      );
    }
    return caseResult([layerResult('inventory', diffs, 4, { timeline: toEvidence(response) })]);
  };

/** Pure: compares the instances route page with the oracle documents. */
export const diffInstancesRoute = (
  route: FindInstancesResponse,
  oracle: readonly InstanceDoc[]
): string[] => {
  const diffs = diffValues(oracle.length, route.total, 'total');
  const byId = new Map(route.items.map((item) => [item.id, item]));
  for (const doc of oracle) {
    const item = byId.get(doc.id);
    if (!item) {
      diffs.push(`${doc.id} (${doc.software_id}) missing from the route`);
      continue;
    }
    diffs.push(
      ...diffValues(
        {
          software_id: doc.software_id,
          status: doc.status,
          host: { key: doc.host.key, id: doc.host.id },
        },
        { software_id: item.software_id, status: item.status, host: { ...item.host } },
        doc.id
      )
    );
    if (item.software?.id !== doc.software_id) {
      diffs.push(`${doc.id}: joined software ${item.software?.id} != ${doc.software_id}`);
    }
  }
  const oracleIds = new Set(oracle.map(({ id }) => id));
  diffs.push(
    ...route.items.filter(({ id }) => !oracleIds.has(id)).map(({ id }) => `${id} not in the oracle`)
  );
  return diffs;
};

const e2e5 = async (ctx: CaseContext): Promise<CaseResult> => {
  if (!readE2e1Capture(ctx)) return blockedResult(NO_CAPTURE_REASON);
  const { body: route } = await ctx.kibana.internalRequest<FindInstancesResponse>(
    'GET',
    INSTANCES_URL,
    { query: { host_id: E2E5_HOST_ID, per_page: 100, page: 1 } }
  );
  const oracle = await ctx.es.search<InstanceDoc>(INSTANCES_INDEX, {
    size: 100,
    query: { term: { 'host.id': E2E5_HOST_ID } },
  });
  const docs = oracle.hits.hits.flatMap((hit) => (hit._source ? [hit._source] : []));
  const diffs = diffInstancesRoute(route, docs);
  if (docs.length === 0) diffs.push(`oracle found no instance with host.id ${E2E5_HOST_ID}`);
  return caseResult([
    layerResult('inventory', diffs, Math.max(1, docs.length), {
      ids: docs.map(({ id, software_id: softwareId }) => `${id} ${softwareId}`),
    }),
  ]);
};

export const createE2eCases = (
  deps: E2eDeps = {
    resolveTiming: () => resolveEnrichmentTiming(),
    cleanup,
    now: () => new Date(),
  }
): TestCase[] => [
  {
    id: 'E2E-1',
    family: 'E2E',
    title:
      'Full pipeline from a clean synthetic state (logs A, R1, DI-2, DL-1, EC, logs B, DL-7, SE)',
    requires: ['T0-3'],
    needs: ['nvd-stub'],
    run: e2e1(deps),
  },
  {
    id: 'E2E-2',
    family: 'E2E',
    title: 'synth-web-02 vulnerable in a 3-day window (host timeline route)',
    requires: ['E2E-1'],
    run: e2e2(deps),
  },
  {
    id: 'E2E-3',
    family: 'E2E',
    title: 'Posture on the patch event; none when EC runs after the patch',
    requires: ['E2E-1'],
    run: e2e3(deps),
  },
  {
    id: 'E2E-4',
    family: 'E2E',
    title: 'log4j host timeline (synth-lin-01)',
    requires: ['E2E-1'],
    run: e2e4(deps),
  },
  {
    id: 'E2E-5',
    family: 'E2E',
    title: 'Instances route by host_id matches the oracle',
    requires: ['E2E-1'],
    run: e2e5,
  },
];

export const cases: TestCase[] = createE2eCases();
