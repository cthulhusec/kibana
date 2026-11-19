/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * DE: discover-endpoint (DE-0..DE-6 in docs/discovery_test_plan.md). Every case that runs the
 * workflow test-runs the STORED production YAML (trigger `prod`) under the managed id, except
 * DE-6's inline Osquery ingest. DE-0 must run while no `logs-endpoint.events.process-*` data
 * stream exists; DE-1 writes phase A, DE-3 writes phase B. DE-2 and DE-5 only read the inventory
 * DE-1 produced.
 */

import { CATALOG_INDEX } from '../../../common/constants';
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
import type { DeStage } from '../expected/de';
import {
  ABSENT_HOST_KEYS,
  BOTH_CATALOG_ID,
  BOTH_HOST_KEY,
  DE_INGEST,
  DE_MAX_T0_AGE_MS,
  DUAL_HOST_KEY,
  EXPECTED_PHASE_A_ROWS,
  EXPECTED_PHASE_B_ROW,
  FIREFOX_FROM_CATALOG_ID,
  FIREFOX_HOST_KEY,
  FIREFOX_TO_CATALOG_ID,
  HOST_NAME_ONLY_CATALOG_ID,
  HOST_NAME_ONLY_HOST_KEY,
  NOEXE_HOST_KEY,
  deHostKeys,
  expectedCatalogIdsAt,
  expectedEventsAt,
  expectedInstancesAt,
  expectedSightingTimes,
  rowsAt,
} from '../expected/de';
import { buildEndpointDocs } from '../logs/generate_endpoint';
import { ENDPOINT_DATA_STREAM, listEndpointDataStreams } from '../logs/endpoint_template';
import { getWorkflowId } from '../variants/build_variant';
import { buildOsqueryMergeYaml, checkDiscoverEndpointSteps, endpointRowsAt } from './de_support';
import { checkNoInstancesFor } from './dl_support';
import {
  blockWhenT0TooOld,
  checkEventSet,
  fetchInstanceDocs,
  findHostInstances,
} from './synthetic_support';
import type { CaseContext, CaseResult, TestCase } from './types';
import { blockedResult, caseResult } from './types';

const HOUR_MS = 60 * 60_000;

/** Events carry the observed time, which is up to 5 h before T0, so the query reaches back. */
const eventsSince = (t0: Date): string => new Date(t0.getTime() - 25 * HOUR_MS).toISOString();

const staleGuard = (ctx: CaseContext): CaseResult | undefined =>
  blockWhenT0TooOld(ctx.t0, DE_MAX_T0_AGE_MS, {
    hint: 'discover-endpoint reads the last 24 h of process events relative to the run time',
  });

const discoverEndpointEngine = (
  run: CompletedRun,
  steps: Readonly<Record<string, string>> = {}
): LayerResult =>
  checkEngine(run.execution, {
    workflowId: getWorkflowId('discoverEndpoint'),
    isTestRun: true,
    steps,
  });

interface StageOptions {
  readonly stage: DeStage;
  readonly afterFlipRun?: boolean;
  readonly osqueryMerged?: boolean;
}

/** Instances, catalog entries, exact events, and the no-stray-writes check of one stage. */
const checkStageInventory = async (
  ctx: CaseContext,
  { stage, afterFlipRun = false, osqueryMerged = false, since }: StageOptions & { since: string }
): Promise<LayerResult> => {
  const { es, t0 } = ctx;
  return mergeLayer('inventory', [
    await checkInstances(es, expectedInstancesAt(stage, { afterFlipRun, osqueryMerged })),
    await checkCatalogEntries(
      es,
      expectedCatalogIdsAt(stage).map((id) => ({
        id,
        fields: { category: 'application' },
      }))
    ),
    await checkEventSet(es, {
      hostKeys: deHostKeys(stage),
      since: eventsSince(t0),
      expected: expectedEventsAt(stage, t0),
    }),
    await checkNoUnexpectedWrites(es, { since, allowedHostKeys: deHostKeys(stage) }),
  ]);
};

/** Compares `first_seen` and `last_seen` of the stage's instances on `hostKeys` with T0 offsets. */
const checkSightingTimes = async (
  ctx: CaseContext,
  { stage, hostKeys }: { stage: DeStage; hostKeys: readonly string[] }
): Promise<LayerResult> => {
  const items = expectedSightingTimes(stage, ctx.t0).filter(({ hostKey }) =>
    hostKeys.includes(hostKey)
  );
  const docs = await fetchInstanceDocs(ctx.es, items);
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

const runStage = async (
  ctx: CaseContext,
  {
    stage,
    ingest,
    afterFlipRun,
    osqueryMerged,
    skipRows = [],
    sightingHosts,
  }: StageOptions & {
    ingest: Parameters<typeof checkDiscoverEndpointSteps>[1]['ingest'];
    /** Host ids whose rows the run no longer reads (DE-4). */
    skipRows?: readonly string[];
    sightingHosts: readonly string[];
  }
): Promise<CaseResult> => {
  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({ workflow: 'discoverEndpoint' });
  const engine = discoverEndpointEngine(run);
  const rows = endpointRowsAt(stage, ctx.t0).filter(({ host_id: id }) => !skipRows.includes(id));
  const step = await checkDiscoverEndpointSteps(run, {
    rows,
    ingest,
    candidateCount: rows.length,
  });
  const inventory = mergeLayer('inventory', [
    await checkStageInventory(ctx, { stage, afterFlipRun, osqueryMerged, since }),
    await checkSightingTimes(ctx, { stage, hostKeys: sightingHosts }),
  ]);
  return caseResult([engine, step, inventory]);
};

// -------------------------------------------------------------------------------------------------
// DE-0: no matching data stream
// -------------------------------------------------------------------------------------------------

const de0: TestCase['run'] = async (ctx) => {
  const existing = await listEndpointDataStreams(ctx.es);
  if (existing.length > 0) {
    return blockedResult(
      `logs-endpoint.events.process-* data streams exist (${existing.join(', ')}); DE-0 needs a ` +
        'cluster without any. Run cleanup (it deletes the synthetic data stream) and retry.'
    );
  }
  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({ workflow: 'discoverEndpoint' });
  const engine = discoverEndpointEngine(run, { query_processes: 'failed' });
  const step = await checkDiscoverEndpointSteps(run, {
    rows: 'failed',
    ingest: {},
    candidateCount: 0,
  });
  const inventory = await checkNoUnexpectedWrites(ctx.es, { since, allowedHostKeys: [] });
  return caseResult([engine, step, inventory]);
};

// -------------------------------------------------------------------------------------------------
// DE-1: baseline (phase A)
// -------------------------------------------------------------------------------------------------

const de1: TestCase['run'] = async (ctx) => {
  const blocked = staleGuard(ctx);
  if (blocked) return blocked;
  const written = await ctx.writeEndpointLogs('A');
  ctx.log.info(`DE-1: phase A written ${written.written}, existing ${written.existing}`);
  return runStage(ctx, {
    stage: 'A',
    ingest: DE_INGEST.baseline,
    sightingHosts: deHostKeys('A'),
  });
};

// -------------------------------------------------------------------------------------------------
// DE-2, DE-5: read-only checks of the DE-1 inventory
// -------------------------------------------------------------------------------------------------

const instancesFor = (hostKeys: readonly string[]) =>
  expectedInstancesAt('A').filter(({ hostKey }) => hostKeys.includes(hostKey));

const de2: TestCase['run'] = async (ctx) => {
  const onHost = await findHostInstances(ctx.es, NOEXE_HOST_KEY);
  const only = layerResult(
    'inventory',
    onHost.length === 1
      ? []
      : [
          `${NOEXE_HOST_KEY}: expected only the document without an executable, found ${JSON.stringify(
            onHost.map(({ software_id: id }) => id)
          )}`,
        ],
    1
  );
  return caseResult([
    mergeLayer('inventory', [
      await checkInstances(ctx.es, instancesFor([NOEXE_HOST_KEY])),
      only,
      await checkNoInstancesFor(ctx.es, [
        ...ABSENT_HOST_KEYS.excluded,
        ...ABSENT_HOST_KEYS.outsideWindow,
      ]),
    ]),
  ]);
};

const de5: TestCase['run'] = async (ctx) => {
  const onHost = await findHostInstances(ctx.es, DUAL_HOST_KEY);
  const single = layerResult(
    'inventory',
    onHost.length === 1
      ? []
      : [`${DUAL_HOST_KEY}: expected one Synth-Dual instance, found ${onHost.length}`],
    1
  );
  const superseded = EXPECTED_PHASE_A_ROWS.find(
    ({ hostKey, version }) => hostKey === DUAL_HOST_KEY && version === '3.0'
  );
  const supersededCount = superseded
    ? await ctx.es.count(CATALOG_INDEX, { term: { id: superseded.catalogId } })
    : 0;
  return caseResult([
    mergeLayer('inventory', [
      await checkInstances(ctx.es, instancesFor([DUAL_HOST_KEY])),
      single,
      layerResult(
        'inventory',
        supersededCount === 0
          ? []
          : [`catalog entry ${superseded?.catalogId} exists; only the latest version is ingested`],
        1
      ),
      await checkSightingTimes(ctx, { stage: 'A', hostKeys: [DUAL_HOST_KEY] }),
    ]),
  ]);
};

// -------------------------------------------------------------------------------------------------
// DE-3: version flip (phase B)
// -------------------------------------------------------------------------------------------------

const flipHistory = async (ctx: CaseContext): Promise<LayerResult> => {
  const [doc] = await fetchInstanceDocs(ctx.es, [
    { hostKey: FIREFOX_HOST_KEY, catalogId: FIREFOX_TO_CATALOG_ID },
  ]);
  const wantFirst = new Date(ctx.t0.getTime() - HOUR_MS).toISOString();
  const wantSecond = new Date(
    ctx.t0.getTime() - EXPECTED_PHASE_B_ROW.observedOffsetMs
  ).toISOString();
  const history = doc?.version_history ?? [];
  const diffs = [
    ...(history.length !== 2 ? [`version_history has ${history.length} item(s), expected 2`] : []),
    ...(history[0] && Date.parse(history[0].first_seen) !== Date.parse(wantFirst)
      ? [`history[0].first_seen ${history[0].first_seen} != ${wantFirst}`]
      : []),
    ...(history[1] && Date.parse(history[1].first_seen) !== Date.parse(wantSecond)
      ? [`history[1].first_seen ${history[1].first_seen} != ${wantSecond}`]
      : []),
    ...(history[0]?.software_id !== FIREFOX_FROM_CATALOG_ID
      ? [`history[0].software_id ${history[0]?.software_id} != ${FIREFOX_FROM_CATALOG_ID}`]
      : []),
    ...(history[1]?.software_id !== FIREFOX_TO_CATALOG_ID
      ? [`history[1].software_id ${history[1]?.software_id} != ${FIREFOX_TO_CATALOG_ID}`]
      : []),
  ];
  return layerResult('inventory', diffs, 5);
};

const de3: TestCase['run'] = async (ctx) => {
  const blocked = staleGuard(ctx);
  if (blocked) return blocked;
  const written = await ctx.writeEndpointLogs('B');
  ctx.log.info(`DE-3: phase B written ${written.written}, existing ${written.existing}`);
  const result = await runStage(ctx, {
    stage: 'B',
    ingest: DE_INGEST.versionFlip,
    sightingHosts: [FIREFOX_HOST_KEY],
  });
  const history = await flipHistory(ctx);
  return caseResult([...result.layers, history], result.notes);
};

// -------------------------------------------------------------------------------------------------
// DE-4: snapshot false (a vanished row does not remove the instance)
// -------------------------------------------------------------------------------------------------

const VIEWER_DOC_QUERY = { term: { 'host.name': HOST_NAME_ONLY_HOST_KEY } } as const;

const de4: TestCase['run'] = async (ctx) => {
  const blocked = staleGuard(ctx);
  if (blocked) return blocked;
  const viewerRow = rowsAt('B').find(({ hostKey }) => hostKey === HOST_NAME_ONLY_HOST_KEY);
  let result: CaseResult;
  try {
    const deleted = await ctx.es.deleteByQuery(ENDPOINT_DATA_STREAM, VIEWER_DOC_QUERY);
    ctx.log.info(`DE-4: removed ${deleted} ${HOST_NAME_ONLY_HOST_KEY} document(s) from the stream`);
    // DE-3 left the flipped instance `patched`; this run sees it unchanged and returns it to active.
    const stage = await runStage(ctx, {
      stage: 'B',
      ingest: DE_INGEST.viewerGone,
      afterFlipRun: true,
      skipRows: viewerRow ? [viewerRow.host_id] : [],
      sightingHosts: deHostKeys('B'),
    });
    const [viewer] = await fetchInstanceDocs(ctx.es, [
      { hostKey: HOST_NAME_ONLY_HOST_KEY, catalogId: HOST_NAME_ONLY_CATALOG_ID },
    ]);
    const kept = layerResult(
      'inventory',
      viewer?.status === 'active'
        ? []
        : [
            `${HOST_NAME_ONLY_HOST_KEY}: expected status active after its rows vanished, got ${viewer?.status}`,
          ],
      1
    );
    result = caseResult(
      [...stage.layers, kept],
      [
        'The workflow ingests with snapshot false, so software missing from the window is not removed.',
      ]
    );
  } finally {
    await ctx.writeEndpointDocs(buildEndpointDocs('A', ctx.t0));
  }
  return result;
};

// -------------------------------------------------------------------------------------------------
// DE-6: cross-source identity with Osquery
// -------------------------------------------------------------------------------------------------

const de6: TestCase['run'] = async (ctx) => {
  const blocked = staleGuard(ctx);
  if (blocked) return blocked;
  const osqueryRun = await ctx.runWorkflow({
    workflow: 'discoverEndpoint',
    yaml: buildOsqueryMergeYaml(),
    workflowId: 'si-test-de-6-osquery-row',
  });
  const osqueryEngine = checkEngine(osqueryRun.execution, { isTestRun: true });

  // Run the stored endpoint workflow again: the merged instance must stay one instance.
  const result = await runStage(ctx, {
    stage: 'B',
    ingest: DE_INGEST.idempotent,
    afterFlipRun: true,
    osqueryMerged: true,
    sightingHosts: [BOTH_HOST_KEY],
  });
  const onHost = (await findHostInstances(ctx.es, BOTH_HOST_KEY)).filter(
    ({ software_id: id }) => id === BOTH_CATALOG_ID
  );
  const single = layerResult(
    'inventory',
    onHost.length === 1
      ? []
      : [`${BOTH_HOST_KEY}: expected one ${BOTH_CATALOG_ID} instance, found ${onHost.length}`],
    1
  );
  const firstSeen = await findEvents(ctx.es, {
    hostKeys: [BOTH_HOST_KEY],
    since: '1970-01-01T00:00:00.000Z',
    types: ['first_seen'],
  });
  const events = layerResult(
    'inventory',
    firstSeen.length === 1 && firstSeen[0].source === 'endpoint'
      ? []
      : [
          `expected one endpoint first_seen for ${BOTH_HOST_KEY}, got ${JSON.stringify(
            firstSeen.map(({ source }) => source)
          )}`,
        ],
    1
  );
  return caseResult(
    [
      mergeLayer('engine', [
        osqueryEngine,
        ...result.layers.filter(({ layer }) => layer === 'engine'),
      ]),
      ...result.layers
        .filter(({ layer }) => layer !== 'engine')
        .map((layer) =>
          layer.layer === 'inventory' ? mergeLayer('inventory', [layer, single, events]) : layer
        ),
    ],
    result.notes
  );
};

export const cases: TestCase[] = [
  {
    id: 'DE-0',
    family: 'DE',
    title: 'No endpoint data stream: the query fails, the run completes, nothing is written',
    run: de0,
  },
  {
    id: 'DE-1',
    family: 'DE',
    title: 'Baseline: phase A events create 6 instances with endpoint as the source',
    run: de1,
  },
  {
    id: 'DE-2',
    family: 'DE',
    title: 'Exclusions: C:\\Windows\\ executables, missing versions, and old events are skipped',
    requires: ['DE-1'],
    run: de2,
  },
  {
    id: 'DE-3',
    family: 'DE',
    title: 'Version flip: phase B patches Firefox on synth-win-01',
    requires: ['DE-1'],
    run: de3,
  },
  {
    id: 'DE-4',
    family: 'DE',
    title: 'Snapshot false: software missing from the window is not removed',
    requires: ['DE-3'],
    run: de4,
  },
  {
    id: 'DE-5',
    family: 'DE',
    title: 'Latest sighting wins: two versions on one host become one instance',
    requires: ['DE-1'],
    run: de5,
  },
  {
    id: 'DE-6',
    family: 'DE',
    title: 'Cross-source identity: endpoint and Osquery share one instance',
    requires: ['DE-4'],
    run: de6,
  },
];
