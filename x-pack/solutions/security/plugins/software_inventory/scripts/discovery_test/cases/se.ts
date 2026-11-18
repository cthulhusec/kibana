/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * SE: score-exposure (SE-1..SE-12 in docs/discovery_test_plan.md). The cases run the STORED
 * production YAML under the managed id. Run order and state:
 *
 * - SE-1 sets the manual evidence, records the pre-run oracle numbers and the demo snapshot, runs
 *   the workflow once, and asserts that run. SE-2..SE-9 read the state that run produced.
 * - SE-10 ages the synthetic Slack instance, runs again, then revives it with a discover-osquery
 *   macOS variant. SE-11 and SE-12 run again and compare the rollup with an independent oracle.
 *
 * `score-exposure` is not limited to synthetic hosts, so a run rewrites demo exposure (and could
 * mark demo instances stale). These cases assert only on `synth-` hosts; the demo is restored by
 * the regression step (`seed_demo_data.js --clean`).
 */

import { isDeepStrictEqual } from 'util';
import type { LayerResult } from '../assertions';
import {
  checkEngine,
  checkInstances,
  checkSteps,
  diffValues,
  ingestOutput,
  layerResult,
  mergeLayer,
} from '../assertions';
import type { CompletedRun, JsonValue } from '../clients';
import { toCompletedRun } from '../clients';
import {
  LOOKBACK_DAYS,
  SE1_WEB01,
  SE2_HOST_KEY,
  SE3_FW02,
  SE4_EDGE_ONLY,
  SE5_REDIS,
  SE6_WEB02,
  SE7_POLICY,
  STALE_AFTER_DAYS,
  STALE_CATALOG_ID,
  STALE_HOST_KEY,
  computeRollupOracle,
  dayEndOf,
  dayStartOf,
} from '../expected/se';
import { F_EMPTY, R1, R1_MACOS_ROWS } from '../fixtures/osquery';
import { getWorkflowId } from '../variants/build_variant';
import { buildOsqueryVariant } from '../variants/osquery';
import {
  SCORE_STEP_INPUT,
  checkExposure,
  checkHostExposureNone,
  countRollupDocsForDay,
  countSyntheticStaleEligible,
  currentLevels,
  getRollupDoc,
  makeSlackStale,
  readRollupInputs,
  readScoreOracle,
  setManualEvidence,
  snapshotDemoInbound,
  staleInstanceRef,
  todayUtc,
} from './se_support';
import type { ScoreOracle } from './se_support';
import { blockWhenT0TooOld, checkEventSet, checkSyntheticWrites } from './synthetic_support';
import type { CaseContext, CaseRecord, CaseResult, TestCase } from './types';
import { blockedResult, caseResult } from './types';

const DAY_MS = 24 * 60 * 60 * 1000;
/** Log documents are up to 2 days before T0 and the window is 7 days, so T0 may be this old. */
const SE_MAX_T0_AGE_MS = 5 * DAY_MS;

const scoreEngine = (run: CompletedRun): LayerResult =>
  checkEngine(run.execution, {
    workflowId: getWorkflowId('scoreExposure'),
    isTestRun: true,
  });

const runScoreExposure = async (
  ctx: CaseContext
): Promise<{ run: CompletedRun; since: string; oracle: ScoreOracle }> => {
  const oracle = await readScoreOracle(ctx.es);
  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({ workflow: 'scoreExposure' });
  return { run, since, oracle };
};

/** Step layer of one run: inputs, the scored and marked counts, and the rollup date. */
const scoreSteps = async (
  run: CompletedRun,
  { nonRemoved, staleEligible }: ScoreOracle
): Promise<LayerResult> =>
  mergeLayer('step', [
    await checkSteps(run, {
      score: { input: SCORE_STEP_INPUT.score, output: { scored: nonRemoved } },
      mark_stale: { input: SCORE_STEP_INPUT.mark_stale, output: { marked: staleEligible } },
      snapshot_rollup: { output: { date: todayUtc() } },
    }),
    // The oracle numbers travel in the report, and SE-8 reads them back from this record.
    layerResult('step', [], 0, {
      oracleNonRemoved: nonRemoved,
      oracleStaleEligible: staleEligible,
    }),
  ]);

const t0Guard = (ctx: CaseContext): CaseResult | undefined =>
  blockWhenT0TooOld(ctx.t0, SE_MAX_T0_AGE_MS, {
    hint: `score reads ${LOOKBACK_DAYS} days of logs and the synthetic traffic is up to 2 days before T0`,
  });

const evidenceOf = (record: CaseRecord | undefined, key: string): JsonValue | undefined =>
  record?.layers
    .map((layer) => layer.evidence?.[key])
    .find((value): value is JsonValue => value !== undefined);

// -------------------------------------------------------------------------------------------------
// SE-1..SE-7
// -------------------------------------------------------------------------------------------------

const se1: TestCase['run'] = async (ctx) => {
  const blocked = t0Guard(ctx);
  if (blocked) return blocked;
  // Idempotent (fixed ids): makes sure the phase A traffic documents exist.
  await ctx.writeLogs('A');
  await setManualEvidence(ctx.es);
  const demoBefore = await snapshotDemoInbound(ctx.es);
  const { run, since, oracle } = await runScoreExposure(ctx);
  const engine = scoreEngine(run);
  const step = await scoreSteps(run, oracle);
  const inventory = mergeLayer('inventory', [
    await checkExposure(ctx.es, [SE1_WEB01]),
    await checkSyntheticWrites(ctx.es, { since, allowedHostKeys: [] }),
    layerResult('inventory', [], 0, { demoInboundBefore: demoBefore }),
  ]);
  return caseResult([engine, step, inventory]);
};

const se2: TestCase['run'] = async (ctx) =>
  caseResult([await checkHostExposureNone(ctx.es, SE2_HOST_KEY)]);

const se3: TestCase['run'] = async (ctx) => caseResult([await checkExposure(ctx.es, [SE3_FW02])]);

const se4: TestCase['run'] = async (ctx) =>
  caseResult(
    [await checkExposure(ctx.es, SE4_EDGE_ONLY)],
    ['Inbound traffic of collected appliances arrives under the collector host name (risk R6).']
  );

const se5: TestCase['run'] = async (ctx) => caseResult([await checkExposure(ctx.es, [SE5_REDIS])]);

const se6: TestCase['run'] = async (ctx) => caseResult([await checkExposure(ctx.es, [SE6_WEB02])]);

const se7: TestCase['run'] = async (ctx) => caseResult([await checkExposure(ctx.es, SE7_POLICY)]);

// -------------------------------------------------------------------------------------------------
// SE-8: step output
// -------------------------------------------------------------------------------------------------

const se8: TestCase['run'] = async (ctx) => {
  const record = ctx.priorResults.get('SE-1');
  const executionId = record?.executionIds[0];
  const oracle = evidenceOf(record, 'oracleNonRemoved');
  if (!executionId || typeof oracle !== 'number') {
    return blockedResult('The SE-1 record has no execution id or oracle count; re-run SE-1.');
  }
  const run = toCompletedRun(ctx.kibana, await ctx.kibana.getExecution(executionId));
  return caseResult([
    scoreEngine(run),
    await checkSteps(run, { score: { output: { scored: oracle } } }),
  ]);
};

// -------------------------------------------------------------------------------------------------
// SE-9: demo impact (recorded, never asserted)
// -------------------------------------------------------------------------------------------------

const asLevels = (value: JsonValue | undefined): Record<string, string> | undefined =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(
        Object.entries(value).flatMap(([id, level]) =>
          typeof level === 'string' ? [[id, level]] : []
        )
      )
    : undefined;

const se9: TestCase['run'] = async (ctx) => {
  const before = asLevels(evidenceOf(ctx.priorResults.get('SE-1'), 'demoInboundBefore'));
  if (!before) return blockedResult('The SE-1 record has no demo snapshot; re-run SE-1.');
  const ids = Object.keys(before);
  const after = await currentLevels(ctx.es, ids);
  const stillInbound = await snapshotDemoInbound(ctx.es);
  const lost = ids.filter((id) => stillInbound[id] === undefined);
  const layer = layerResult('inventory', [], 1, {
    demoInboundBefore: before,
    demoLevelsAfter: after,
    demoStillInbound: Object.keys(stillInbound).length,
  });
  return caseResult(
    [layer],
    [
      `${ids.length} demo instance(s) had inbound_public_ip evidence before the run; ` +
        `${lost.length} lost it (no logs back it). Recorded, not asserted.`,
      ...ids.map((id) => `${id}: ${before[id]} -> ${after[id]}`),
      'Restore the demo with the regression step (seed_demo_data.js --clean).',
    ]
  );
};

// -------------------------------------------------------------------------------------------------
// SE-10: mark stale, then revive
// -------------------------------------------------------------------------------------------------

const se10: TestCase['run'] = async (ctx) => {
  const slack = staleInstanceRef();
  await makeSlackStale(ctx.es, ctx.t0);
  const syntheticEligible = await countSyntheticStaleEligible(ctx.es);
  const { run, since, oracle } = await runScoreExposure(ctx);
  const demoEligible = oracle.staleEligible - syntheticEligible;
  const engine = scoreEngine(run);
  const step = await scoreSteps(run, oracle);
  const stale = mergeLayer('inventory', [
    await checkInstances(ctx.es, [{ ...slack, status: 'stale' }]),
    await checkEventSet(ctx.es, {
      hostKeys: [STALE_HOST_KEY],
      since,
      types: ['stale'],
      expected: [
        {
          type: 'stale',
          host: { key: STALE_HOST_KEY },
          software_id: STALE_CATALOG_ID,
          source: 'osquery',
          from_version: '4.41.105',
        },
      ],
    }),
    // Only the Slack instance is synthetic and eligible; anything else is demo data.
    layerResult(
      'inventory',
      syntheticEligible === 1
        ? []
        : [`expected 1 synthetic stale-eligible instance, found ${syntheticEligible}`],
      1
    ),
    await checkSyntheticWrites(ctx.es, { since, allowedHostKeys: [STALE_HOST_KEY] }),
  ]);

  // A later macOS sighting revives the instance.
  const reviveSince = new Date().toISOString();
  const revive = await ctx.runWorkflow({
    workflow: 'discoverOsquery',
    yaml: buildOsqueryVariant({
      label: 'SE-10 revive',
      steps: {
        query_linux: F_EMPTY,
        query_windows: F_EMPTY,
        query_macos: R1.query_macos,
        query_dependencies: F_EMPTY,
      },
    }),
  });
  const reviveEngine = checkEngine(revive.execution, {
    workflowId: getWorkflowId('discoverOsquery'),
    isTestRun: true,
  });
  const reviveSteps = await checkSteps(revive, {
    ingest_macos: {
      output: ingestOutput({ unchanged: R1_MACOS_ROWS.length }),
      input: { snapshot: true },
    },
    ingest_linux: { output: ingestOutput({}) },
    ingest_windows: { output: ingestOutput({}) },
    ingest_dependencies: { output: ingestOutput({}) },
  });
  const revived = mergeLayer('inventory', [
    await checkInstances(ctx.es, [{ ...slack, status: 'active', sources: ['osquery'] }]),
    await checkEventSet(ctx.es, {
      hostKeys: [STALE_HOST_KEY],
      // The revived event carries the fixture row time, which can precede the run start.
      since: new Date(Date.parse(reviveSince) - 2 * DAY_MS).toISOString(),
      types: ['revived'],
      expected: [
        {
          type: 'revived',
          host: { key: STALE_HOST_KEY },
          software_id: STALE_CATALOG_ID,
          source: 'osquery',
        },
      ],
    }),
    await checkSyntheticWrites(ctx.es, { since: reviveSince, allowedHostKeys: [STALE_HOST_KEY] }),
  ]);

  return caseResult(
    [
      mergeLayer('engine', [engine, reviveEngine]),
      mergeLayer('step', [step, reviveSteps]),
      mergeLayer('inventory', [stale, revived]),
    ],
    [
      `mark_stale marked ${oracle.staleEligible} (1 synthetic + ${demoEligible} demo-eligible).`,
      `Threshold ${STALE_AFTER_DAYS} days; revival came from a discover-osquery macOS variant.`,
    ]
  );
};

// -------------------------------------------------------------------------------------------------
// SE-11, SE-12: rollup
// -------------------------------------------------------------------------------------------------

const se11: TestCase['run'] = async (ctx) => {
  const { run, oracle } = await runScoreExposure(ctx);
  const engine = scoreEngine(run);
  const step = await scoreSteps(run, oracle);
  const date = todayUtc();
  const day = { dayStart: dayStartOf(date), dayEnd: dayEndOf(date) };
  const inputs = await readRollupInputs(ctx.es, day);
  const expected = computeRollupOracle({
    dayStart: day.dayStart,
    instances: inputs.instances,
    catalog: inputs.catalog,
    events: inputs.events,
  });
  const stored = await getRollupDoc(ctx.es, date);
  const diffs = [
    ...(inputs.truncated ? ['oracle read hit the 10000 document limit'] : []),
    ...(!stored.found || !stored._source
      ? [`no rollup document with _id ${date}`]
      : diffValues(expected, stored._source, `rollup ${date}`)),
  ];
  const stepOutput = await checkSteps(run, {
    snapshot_rollup: {
      output: {
        date,
        total_instances: expected.total_instances,
        vulnerable_instances: expected.vulnerable_instances,
      },
    },
  });
  const inventory = layerResult('inventory', diffs, Object.keys(expected).length + 1, {
    rollupDate: date,
    totalInstances: expected.total_instances,
  });
  return caseResult([engine, mergeLayer('step', [step, stepOutput]), inventory]);
};

const se12: TestCase['run'] = async (ctx) => {
  const date = todayUtc();
  const day = { dayStart: dayStartOf(date), dayEnd: dayEndOf(date) };
  const before = await getRollupDoc(ctx.es, date);
  if (!before.found || !before._source || before._version === undefined) {
    return blockedResult(`No rollup document ${date} to compare; run SE-11 first.`);
  }
  const { run, oracle } = await runScoreExposure(ctx);
  const engine = scoreEngine(run);
  const step = await scoreSteps(run, oracle);
  const after = await getRollupDoc(ctx.es, date);
  const docsForDay = await countRollupDocsForDay(ctx.es, day);
  const diffs = [
    ...(docsForDay === 1 ? [] : [`expected one rollup document for ${date}, found ${docsForDay}`]),
    ...(after._version === before._version + 1
      ? []
      : [
          `_version ${after._version} != ${before._version + 1} (the same _id must be overwritten)`,
        ]),
    ...(isDeepStrictEqual(before._source, after._source)
      ? []
      : diffValues(before._source, after._source ?? {}, `rollup ${date}`)),
  ];
  return caseResult([
    engine,
    step,
    layerResult('inventory', diffs, 3, { versionBefore: before._version ?? null }),
  ]);
};

export const cases: TestCase[] = [
  {
    id: 'SE-1',
    family: 'SE',
    title: 'Public inbound: synth-web-01 gets inbound_public_ip 44 (medium)',
    requires: ['DO-1', 'DI-2', 'DL-1'],
    run: se1,
  },
  {
    id: 'SE-2',
    family: 'SE',
    title: 'Outbound only: every synth-lin-01 instance stays none',
    requires: ['SE-1'],
    run: se2,
  },
  {
    id: 'SE-3',
    family: 'SE',
    title: 'Edge appliance via the integration map plus inbound: synth-fw-02 is high (100)',
    requires: ['SE-1'],
    run: se3,
  },
  {
    id: 'SE-4',
    family: 'SE',
    title: 'Collected appliances get the edge role only (50, medium)',
    requires: ['SE-1'],
    run: se4,
  },
  {
    id: 'SE-5',
    family: 'SE',
    title: 'Matched by host.id with ingress direction: redis is 40 (medium)',
    requires: ['SE-1'],
    run: se5,
  },
  {
    id: 'SE-6',
    family: 'SE',
    title: 'Manual evidence is preserved on synth-web-02 (30, low)',
    requires: ['SE-1'],
    run: se6,
  },
  {
    id: 'SE-7',
    family: 'SE',
    title: 'Policy pseudo-hosts ignore logs; the edge integration is still edge',
    requires: ['SE-1'],
    run: se7,
  },
  {
    id: 'SE-8',
    family: 'SE',
    title: 'score.output.scored equals the non-removed instance count at run time',
    requires: ['SE-1'],
    run: se8,
  },
  {
    id: 'SE-9',
    family: 'SE',
    title: 'Demo impact: record the demo instances that lose inbound evidence',
    requires: ['SE-1'],
    run: se9,
  },
  {
    id: 'SE-10',
    family: 'SE',
    title: 'Mark stale: aged Slack instance goes stale, then revives on the next sighting',
    requires: ['SE-1'],
    run: se10,
  },
  {
    id: 'SE-11',
    family: 'SE',
    title: "Rollup: today's document equals the oracle counts",
    requires: ['SE-10'],
    run: se11,
  },
  {
    id: 'SE-12',
    family: 'SE',
    title: 'Rollup idempotent: a second run overwrites the same-day document',
    requires: ['SE-11'],
    run: se12,
  },
];
