/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * DL: discover-logs (DL-0..DL-10 in docs/discovery_test_plan.md). Every case that runs the
 * workflow test-runs the STORED production YAML (trigger `prod`) under the managed id. DL-0 must
 * run before any `logs-*` data exists; DL-1 writes phase A, DL-7 writes phase B. DL-2..DL-6 only
 * read the inventory DL-1 produced.
 *
 * The rows the ES|QL steps return are checked against the generator's documents, so a mismatch
 * between the synthetic data and the workflow queries shows up as a step-layer diff.
 */

import type { LayerResult } from '../assertions';
import {
  checkCatalogEntries,
  checkEngine,
  checkInstances,
  checkNoUnexpectedWrites,
  findEvents,
  layerResult,
  mergeLayer,
} from '../assertions';
import type { CompletedRun } from '../clients';
import type { DlStage } from '../expected/dl';
import {
  ABSENT_KEYS_BY_REASON,
  CHECKOUT_CATALOG_ID,
  CHECKOUT_HOST_KEY,
  DL_INGEST,
  DL_MAX_T0_AGE_MS,
  FLIP_FROM_CATALOG_ID,
  FLIP_HOST_KEY,
  FLIP_TO_CATALOG_ID,
  MULTI_VALUED_CATALOG_ID,
  MULTI_VALUED_EXPECTED_HOST_ID,
  MULTI_VALUED_OBSERVED_OFFSET_MS,
  MULTI_VALUED_OTHER_HOST_ID,
  SHARED_CATALOG_ID,
  SHARED_HOST_KEY,
  candidatesAt,
  dlEventHostKeys,
  dlHostKeys,
  expectedCatalogAt,
  expectedEventsAt,
  expectedInstancesAt,
} from '../expected/dl';
import { instanceIdFor, parseCatalogId } from '../ids';
import { MULTI_VALUED_OBSERVER_SPEC, buildPhaseDocs, toLogDoc } from '../logs/generate_logs';
import { getWorkflowId } from '../variants/build_variant';
import {
  applianceRowsAt,
  checkDiscoverLogsSteps,
  checkNoInstancesFor,
  checkSightingTimes,
  esqlRecords,
  listLogsDataStreams,
  restoreSyntheticLogs,
  rewriteLogsWithoutTemplate,
  serviceRowsAt,
} from './dl_support';
import type { ExpectedEsqlRow } from './dl_support';
import {
  blockWhenT0TooOld,
  checkEventSet,
  fetchInstanceDocs,
  findHostInstances,
} from './synthetic_support';
import type { CaseContext, CaseResult, TestCase } from './types';
import { blockedResult, caseResult } from './types';

const HOUR_MS = 60 * 60_000;

/** Events carry the observed time, which is up to 23 h before T0, so the query reaches back. */
const eventsSince = (t0: Date): string => new Date(t0.getTime() - 25 * HOUR_MS).toISOString();

const staleGuard = (ctx: CaseContext): CaseResult | undefined =>
  blockWhenT0TooOld(ctx.t0, DL_MAX_T0_AGE_MS, {
    hint: 'discover-logs reads the last 24 h and the oldest included document is 23 h old',
  });

const discoverLogsEngine = (
  run: CompletedRun,
  steps: Readonly<Record<string, string>> = {}
): LayerResult =>
  checkEngine(run.execution, {
    workflowId: getWorkflowId('discoverLogs'),
    isTestRun: true,
    steps,
  });

/** Instances, catalog categories, exact events, and the no-stray-writes check of one stage. */
const checkStageInventory = async (
  ctx: CaseContext,
  { stage, since, afterFlipRun = false }: { stage: DlStage; since: string; afterFlipRun?: boolean }
): Promise<LayerResult> => {
  const { es, t0 } = ctx;
  return mergeLayer('inventory', [
    await checkInstances(es, expectedInstancesAt(stage, { afterFlipRun })),
    await checkCatalogEntries(
      es,
      expectedCatalogAt(stage).map(({ id, category }) => ({ id, fields: { category } }))
    ),
    await checkEventSet(es, {
      hostKeys: dlEventHostKeys(stage),
      since: eventsSince(t0),
      expected: expectedEventsAt(stage, t0),
    }),
    await checkNoUnexpectedWrites(es, { since, allowedHostKeys: dlHostKeys(stage) }),
  ]);
};

const inventoryOnly = (layer: LayerResult, notes?: readonly string[]): CaseResult =>
  caseResult([layer], notes);

// -------------------------------------------------------------------------------------------------
// DL-0: no logs
// -------------------------------------------------------------------------------------------------

const dl0: TestCase['run'] = async (ctx) => {
  const existing = await listLogsDataStreams(ctx.es);
  if (existing.length > 0) {
    return blockedResult(
      `logs-* data streams exist (${existing.join(', ')}); DL-0 needs a cluster without logs. ` +
        'Run cleanup (it deletes the synthetic data stream) and retry.'
    );
  }
  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({ workflow: 'discoverLogs' });
  const engine = discoverLogsEngine(run, { query_appliances: 'failed', query_services: 'failed' });
  const step = await checkDiscoverLogsSteps(run, {
    appliances: 'failed',
    services: 'failed',
    ingest: {},
    candidateCount: 0,
  });
  const inventory = await checkNoUnexpectedWrites(ctx.es, { since, allowedHostKeys: [] });
  return caseResult([engine, step, inventory]);
};

// -------------------------------------------------------------------------------------------------
// DL-1: baseline (phase A)
// -------------------------------------------------------------------------------------------------

const dl1: TestCase['run'] = async (ctx) => {
  const blocked = staleGuard(ctx);
  if (blocked) return blocked;
  const written = await ctx.writeLogs('A');
  ctx.log.info(`DL-1: phase A written ${written.written}, existing ${written.existing}`);
  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({ workflow: 'discoverLogs' });
  const engine = discoverLogsEngine(run);
  const step = await checkDiscoverLogsSteps(run, {
    appliances: applianceRowsAt('A', ctx.t0),
    services: serviceRowsAt('A', ctx.t0),
    ingest: DL_INGEST.baselineAfterR1,
    candidateCount: candidatesAt('A').length,
  });
  const inventory = await checkStageInventory(ctx, { stage: 'A', since });
  return caseResult([engine, step, inventory]);
};

// -------------------------------------------------------------------------------------------------
// DL-2..DL-6: read-only checks of the DL-1 inventory
// -------------------------------------------------------------------------------------------------

const instancesFor = (hostKeys: readonly string[]) =>
  expectedInstancesAt('A').filter(({ hostKey }) => hostKeys.includes(hostKey));

const dl2: TestCase['run'] = async (ctx) => {
  const appliances = instancesFor(['synth-fw-01', 'synth-fw-02']);
  const [fw01, fw02] = appliances.map((item) => instanceIdFor(item));
  const distinct = layerResult(
    'inventory',
    fw01 === fw02 ? ['synth-fw-01 and synth-fw-02 share one instance id'] : [],
    1
  );
  return inventoryOnly(
    mergeLayer('inventory', [
      await checkInstances(ctx.es, appliances),
      distinct,
      await checkNoInstancesFor(ctx.es, ABSENT_KEYS_BY_REASON.collector),
    ])
  );
};

const dl3: TestCase['run'] = async (ctx) =>
  inventoryOnly(await checkInstances(ctx.es, instancesFor(['synth-sn-0003', '192.0.2.77'])));

const dl4: TestCase['run'] = async (ctx) => {
  const checkout = instancesFor([CHECKOUT_HOST_KEY]);
  const onHost = (await findHostInstances(ctx.es, CHECKOUT_HOST_KEY)).filter(
    ({ software_id: softwareId }) => softwareId === CHECKOUT_CATALOG_ID
  );
  const single = layerResult(
    'inventory',
    onHost.length === 1
      ? []
      : [`${CHECKOUT_HOST_KEY}: expected one synth-checkout instance, found ${onHost.length}`],
    1
  );
  return inventoryOnly(
    mergeLayer('inventory', [
      await checkInstances(ctx.es, checkout),
      single,
      // A1 duplicates collapse to one row observed at T0-30m; the later S2b row wins for web-01.
      await checkSightingTimes(ctx.es, {
        stage: 'A',
        t0: ctx.t0,
        hostKeys: ['synth-fw-01', CHECKOUT_HOST_KEY],
      }),
    ])
  );
};

const dl5: TestCase['run'] = async (ctx) =>
  inventoryOnly(
    mergeLayer('inventory', [
      await checkInstances(ctx.es, instancesFor(['synth-fw-05'])),
      await checkNoInstancesFor(ctx.es, [
        ...ABSENT_KEYS_BY_REASON.outsideWindow,
        ...ABSENT_KEYS_BY_REASON.missingVersion,
      ]),
    ])
  );

const dl6: TestCase['run'] = async (ctx) => {
  const nginx = (await findHostInstances(ctx.es, SHARED_HOST_KEY)).filter(
    ({ software_id: softwareId }) => softwareId.startsWith('f5:nginx:')
  );
  const single = layerResult(
    'inventory',
    nginx.length === 1
      ? []
      : [`${SHARED_HOST_KEY}: expected one nginx instance, found ${nginx.length}`],
    1
  );
  const firstSeen = await findEvents(ctx.es, {
    hostKeys: [SHARED_HOST_KEY],
    since: '1970-01-01T00:00:00.000Z',
    types: ['first_seen'],
  });
  const nginxFirstSeen = firstSeen.filter(({ software_id: id }) => id === SHARED_CATALOG_ID);
  const events = layerResult(
    'inventory',
    nginxFirstSeen.length === 1 && nginxFirstSeen[0].source === 'osquery'
      ? []
      : [
          `expected one osquery first_seen for ${SHARED_CATALOG_ID}, got ${JSON.stringify(
            nginxFirstSeen.map(({ source }) => source)
          )}`,
        ],
    1
  );
  return inventoryOnly(
    mergeLayer('inventory', [
      await checkInstances(ctx.es, instancesFor([SHARED_HOST_KEY])),
      single,
      events,
      await checkNoInstancesFor(ctx.es, ABSENT_KEYS_BY_REASON.hostIdNotAKey),
    ])
  );
};

// -------------------------------------------------------------------------------------------------
// DL-7, DL-8: version flip and idempotence (phase B)
// -------------------------------------------------------------------------------------------------

const flipHistory = async (ctx: CaseContext): Promise<LayerResult> => {
  const [doc] = await fetchInstanceDocs(ctx.es, [
    { hostKey: FLIP_HOST_KEY, catalogId: FLIP_TO_CATALOG_ID },
  ]);
  const wantFirst = new Date(ctx.t0.getTime() - 20 * HOUR_MS).toISOString();
  const wantSecond = new Date(ctx.t0.getTime() - HOUR_MS).toISOString();
  const history = doc?.version_history ?? [];
  const diffs = [
    ...(history.length !== 2 ? [`version_history has ${history.length} item(s), expected 2`] : []),
    ...(history[0] && Date.parse(history[0].first_seen) !== Date.parse(wantFirst)
      ? [`history[0].first_seen ${history[0].first_seen} != ${wantFirst}`]
      : []),
    ...(history[1] && Date.parse(history[1].first_seen) !== Date.parse(wantSecond)
      ? [`history[1].first_seen ${history[1].first_seen} != ${wantSecond}`]
      : []),
    ...(history[0]?.software_id !== FLIP_FROM_CATALOG_ID
      ? [`history[0].software_id ${history[0]?.software_id} != ${FLIP_FROM_CATALOG_ID}`]
      : []),
    ...(history[1]?.software_id !== FLIP_TO_CATALOG_ID
      ? [`history[1].software_id ${history[1]?.software_id} != ${FLIP_TO_CATALOG_ID}`]
      : []),
  ];
  return layerResult('inventory', diffs, 5);
};

const runStageB = async (
  ctx: CaseContext,
  ingest: Parameters<typeof checkDiscoverLogsSteps>[1]['ingest'],
  { afterFlipRun = false }: { afterFlipRun?: boolean } = {}
): Promise<CaseResult> => {
  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({ workflow: 'discoverLogs' });
  const engine = discoverLogsEngine(run);
  const step = await checkDiscoverLogsSteps(run, {
    appliances: applianceRowsAt('B', ctx.t0),
    services: serviceRowsAt('B', ctx.t0),
    ingest,
    candidateCount: candidatesAt('B').length,
  });
  const inventory = mergeLayer('inventory', [
    await checkStageInventory(ctx, { stage: 'B', since, afterFlipRun }),
    await flipHistory(ctx),
    await checkSightingTimes(ctx.es, { stage: 'B', t0: ctx.t0, hostKeys: [FLIP_HOST_KEY] }),
  ]);
  return caseResult([engine, step, inventory]);
};

const dl7: TestCase['run'] = async (ctx) => {
  const blocked = staleGuard(ctx);
  if (blocked) return blocked;
  const written = await ctx.writeLogs('B');
  ctx.log.info(`DL-7: phase B written ${written.written}, existing ${written.existing}`);
  return runStageB(ctx, DL_INGEST.versionFlip);
};

const dl8: TestCase['run'] = async (ctx) => {
  const blocked = staleGuard(ctx);
  if (blocked) return blocked;
  // DL-7 left the flipped instance `patched`; an unchanged re-run returns it to `active`.
  return runStageB(ctx, DL_INGEST.idempotent, { afterFlipRun: true });
};

// -------------------------------------------------------------------------------------------------
// DL-9: appliance query fails without the dedicated template
// -------------------------------------------------------------------------------------------------

const dl9: TestCase['run'] = async (ctx) => {
  const blocked = staleGuard(ctx);
  if (blocked) return blocked;
  const docs = [...buildPhaseDocs('A', ctx.t0), ...buildPhaseDocs('B', ctx.t0)];
  const stage: DlStage = 'B';
  let result: CaseResult;
  try {
    const written = await rewriteLogsWithoutTemplate(ctx.es, docs);
    ctx.log.info(`DL-9: data stream rewritten without the template, ${written.written} docs`);
    const since = new Date().toISOString();
    const run = await ctx.runWorkflow({ workflow: 'discoverLogs' });
    const engine = discoverLogsEngine(run, { query_appliances: 'failed' });
    const step = await checkDiscoverLogsSteps(run, {
      appliances: 'failed',
      services: serviceRowsAt(stage, ctx.t0),
      ingest: DL_INGEST.servicesOnly,
      candidateCount: serviceRowsAt(stage, ctx.t0).length,
    });
    // Nothing changes: the services are already ingested, and appliances are not re-read.
    const inventory = await checkStageInventory(ctx, { stage, since, afterFlipRun: true });
    result = caseResult(
      [engine, step, inventory],
      [
        'Without the dedicated template observer.serial_number is mapped nowhere, so ' +
          'query_appliances fails while query_services still ingests (risk R4).',
      ]
    );
  } finally {
    await restoreSyntheticLogs(ctx.es, { t0: ctx.t0, phases: ['A', 'B'] });
  }
  return result;
};

// -------------------------------------------------------------------------------------------------
// DL-10: multi-valued observer.ip
// -------------------------------------------------------------------------------------------------

const MULTI_VALUED_IPS: readonly string[] = [
  MULTI_VALUED_EXPECTED_HOST_ID,
  MULTI_VALUED_OTHER_HOST_ID,
];

const multiValuedRow = (hostId: string, t0: Date): ExpectedEsqlRow => ({
  host_id: hostId,
  vendor: 'F5',
  name: 'BIG-IP',
  version: parseCatalogId(MULTI_VALUED_CATALOG_ID).version,
  observedAt: new Date(t0.getTime() - MULTI_VALUED_OBSERVED_OFFSET_MS).toISOString(),
});

const dl10: TestCase['run'] = async (ctx) => {
  const blocked = staleGuard(ctx);
  if (blocked) return blocked;
  const written = await ctx.writeLogDocs([toLogDoc(MULTI_VALUED_OBSERVER_SPEC, ctx.t0)]);
  ctx.log.info(`DL-10: multi-valued appliance written ${written.written}`);
  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({ workflow: 'discoverLogs' });
  const engine = discoverLogsEngine(run);

  // Record which value MV_FIRST picks; the plan expects the sorted first doc value.
  const appliancesOutput = (await run.step('query_appliances')).output;
  const known = new Set(applianceRowsAt('B', ctx.t0).map(({ host_id: id }) => id));
  const picked = esqlRecords(appliancesOutput)?.find(
    (record) =>
      record.name === 'BIG-IP' && record.version === '16.1.4' && !known.has(record.host_id ?? '')
  )?.host_id;
  const hostId = picked ?? MULTI_VALUED_EXPECTED_HOST_ID;
  const notes = [`MV_FIRST(observer.ip) became host_id ${picked ?? '(no row found)'}`];
  const pickDiffs = MULTI_VALUED_IPS.includes(hostId)
    ? []
    : [`host_id ${hostId} is neither ${MULTI_VALUED_IPS.join(' nor ')}`];
  if (picked !== undefined && picked !== MULTI_VALUED_EXPECTED_HOST_ID) {
    notes.push(
      `Unexpected order: the plan expects ${MULTI_VALUED_EXPECTED_HOST_ID} (sorted doc values).`
    );
  }

  const step = mergeLayer('step', [
    await checkDiscoverLogsSteps(run, {
      appliances: [...applianceRowsAt('B', ctx.t0), multiValuedRow(hostId, ctx.t0)],
      services: serviceRowsAt('B', ctx.t0),
      ingest: DL_INGEST.multiValued,
      candidateCount: candidatesAt('B').length + 1,
    }),
    layerResult('step', pickDiffs, 1),
  ]);

  const stage: DlStage = 'B';
  const expectedEvents = [
    ...expectedEventsAt(stage, ctx.t0),
    {
      type: 'first_seen' as const,
      '@timestamp': new Date(ctx.t0.getTime() - MULTI_VALUED_OBSERVED_OFFSET_MS).toISOString(),
      instance_id: instanceIdFor({ hostKey: hostId, catalogId: MULTI_VALUED_CATALOG_ID }),
      host: { key: hostId },
      source: 'logs' as const,
      software_id: MULTI_VALUED_CATALOG_ID,
      to_version: parseCatalogId(MULTI_VALUED_CATALOG_ID).version,
    },
  ];
  const inventory = mergeLayer('inventory', [
    await checkInstances(ctx.es, [
      // DL-8 already re-ran phase B, so the flipped instance is back to `active`.
      ...expectedInstancesAt(stage, { afterFlipRun: true }),
      {
        hostKey: hostId,
        catalogId: MULTI_VALUED_CATALOG_ID,
        status: 'active',
        sources: ['logs'],
        hostName: null,
        hostId,
        versions: [parseCatalogId(MULTI_VALUED_CATALOG_ID).version],
      },
    ]),
    await checkEventSet(ctx.es, {
      hostKeys: [...dlEventHostKeys(stage), hostId],
      since: eventsSince(ctx.t0),
      expected: expectedEvents,
    }),
    await checkNoUnexpectedWrites(ctx.es, {
      since,
      allowedHostKeys: [...dlHostKeys(stage), hostId],
    }),
  ]);
  return caseResult([engine, step, inventory], notes);
};

export const cases: TestCase[] = [
  {
    id: 'DL-0',
    family: 'DL',
    title: 'No logs: both queries fail on unknown columns, ingest writes nothing',
    run: dl0,
  },
  {
    id: 'DL-1',
    family: 'DL',
    title: 'Baseline: phase A logs create 9 instances and merge one with Osquery',
    requires: ['DO-1'],
    run: dl1,
  },
  {
    id: 'DL-2',
    family: 'DL',
    title: 'Collector vs appliance: appliances key on observer.hostname',
    requires: ['DL-1'],
    run: dl2,
  },
  {
    id: 'DL-3',
    family: 'DL',
    title: 'Fallback keys: serial number and observer IP without host name',
    requires: ['DL-1'],
    run: dl3,
  },
  {
    id: 'DL-4',
    family: 'DL',
    title: 'Dedupe: duplicate documents and rows collapse to one instance',
    requires: ['DL-1'],
    run: dl4,
  },
  {
    id: 'DL-5',
    family: 'DL',
    title: 'Window edges: 23 h included, 26 h and missing versions excluded',
    requires: ['DL-1'],
    run: dl5,
  },
  {
    id: 'DL-6',
    family: 'DL',
    title: 'Cross-source merge: logs and Osquery share one nginx instance',
    requires: ['DL-1'],
    run: dl6,
  },
  {
    id: 'DL-7',
    family: 'DL',
    title: 'Version flip: phase B patches nginx on synth-web-02',
    requires: ['DL-1'],
    run: dl7,
  },
  {
    id: 'DL-8',
    family: 'DL',
    title: 'Idempotent: a re-run without new data changes nothing',
    requires: ['DL-7'],
    run: dl8,
  },
  {
    id: 'DL-9',
    family: 'DL',
    title: 'Missing field column: appliances fail without the template, services still ingest',
    requires: ['DL-8'],
    run: dl9,
  },
  {
    id: 'DL-10',
    family: 'DL',
    title: 'Multi-valued observer.ip: record which value becomes host_id',
    requires: ['DL-8'],
    run: dl10,
  },
];
