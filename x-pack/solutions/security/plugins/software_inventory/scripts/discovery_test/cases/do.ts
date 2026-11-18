/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * DO: discover-osquery (DO-1..DO-18 in docs/discovery_test_plan.md), in the plan's matrix order.
 * DO-1 and DO-6..DO-14 are data-driven (`../expected/do.ts`, executed by `executeDoCase`); the
 * others have their own checks. The Fleet agent lookup cannot succeed on this stack
 * (`.fleet-agents` does not exist), so DO-4 asserts the fallback only and DO-18 is blocked when
 * real agents exist.
 */

import { EVENTS_INDEX, INSTANCES_INDEX } from '../../../common/constants';
import type { LayerResult } from '../assertions';
import {
  checkCatalogEntries,
  checkEngine,
  checkEvents,
  checkInstances,
  checkNoUnexpectedWrites,
  checkSteps,
  diffValues,
  ingestOutput,
  layerResult,
  mergeLayer,
} from '../assertions';
import type { CompletedRun } from '../clients';
import { HttpError, toCompletedRun } from '../clients';
import {
  BULK_HOST_KEY,
  BULK_LIMIT,
  DATA_DRIVEN_CASES,
  DO15_BASE_ROWS,
  DO15_CATALOG_ID,
  DO15_HOST,
  DO15_RUN_WITHOUT_SERVICE,
  DO15_RUN_WITH_SERVICE,
  DO15_ROWS_WITH_SERVICE,
  DO15_SERVICE,
  DO15_VERSION,
  DO16_MAX_STEP_MS,
  DO16_SPOT_CHECKS,
  DO18_FAILED_STEPS,
  DO18_INGEST,
  DO2_LIN02_ALLOWED_SOFTWARE_IDS,
  DO2_WIN01_INSTANCE_COUNT,
  DO3_LINUX_CANDIDATES,
  DO3_LINUX_CREATED,
  DO4_R1_HOST_IDENTITY,
  DO4_UNKNOWN_AGENT_RUN,
  DO4_UNKNOWN_INSTANCE,
  DO5_APPLICATION_CATALOG,
  DO5_INSTALL_PATHS,
  QUERY_KEYS,
  firstSeenEvent,
  osqueryInstance,
} from '../expected/do';
import type { DoCaseExpectation, OsqueryRunExpectation } from '../expected/do';
import {
  EXPECTED_PHASE_A_CANDIDATES,
  EXPECTED_PHASE_B_CANDIDATE,
  serviceLogSpec,
  toLogDoc,
} from '../logs/generate_logs';
import type { OsqueryFixture, OsqueryRow } from '../fixtures/osquery';
import { AGENTS, F_BULK_5000, F_BULK_5001, successOutput } from '../fixtures/osquery';
import { instanceIdFor } from '../ids';
import { buildOsqueryVariant } from '../variants/osquery';
import { getWorkflowId } from '../variants/build_variant';
import {
  candidateCountOf,
  checkCandidateCounts,
  checkInstallPaths,
  checkOsqueryRun,
  countHostInstances,
  countHostInstancesWithPrefix,
  executeDoCase,
  expectCount,
  labelLayer,
  runOsqueryExpectation,
  stepDurationMs,
  stepErrorText,
} from './do_support';
import type { CaseContext, TestCase } from './types';
import { blockedResult, caseResult } from './types';

const HOUR_MS = 60 * 60 * 1000;
const FLEET_AGENTS_PATH = '/.fleet-agents';
const BULK_RUN_TIMEOUT_MS = 10 * 60 * 1000;

const dataDriven = (expectation: DoCaseExpectation): TestCase => ({
  id: expectation.id,
  family: 'DO',
  title: expectation.title,
  ...(expectation.requires ? { requires: expectation.requires } : {}),
  run: (ctx) => executeDoCase(ctx, expectation),
});

const byId = (id: string): TestCase => {
  const expectation = DATA_DRIVEN_CASES.find((candidate) => candidate.id === id);
  if (!expectation) throw new Error(`No data-driven DO expectation ${id}`);
  return dataDriven(expectation);
};

/** The DO-1 run, re-read from Kibana; the "within R1" cases assert on it. */
const loadDo1Run = async (ctx: CaseContext): Promise<CompletedRun | undefined> => {
  const executionId = ctx.priorResults.get('DO-1')?.executionIds[0];
  if (!executionId) return undefined;
  return toCompletedRun(ctx.kibana, await ctx.kibana.getExecution(executionId));
};

const NO_DO1_RUN = 'The DO-1 execution id is not in the results; run DO-1 first.';

const linuxFixture = (id: string, rows: readonly OsqueryRow[]): OsqueryFixture => ({
  id,
  description: `Linux rows for ${id}`,
  output: successOutput(rows),
  expected: { snapshot: true },
});

// -------------------------------------------------------------------------------------------------
// DO-2, DO-3, DO-4, DO-5: assertions on the R1 state
// -------------------------------------------------------------------------------------------------

const do2: TestCase['run'] = async (ctx) => {
  const run = await loadDo1Run(ctx);
  if (!run) return blockedResult(NO_DO1_RUN);
  const engine = checkEngine(run.execution, { workflowId: getWorkflowId('discoverOsquery') });
  const step = await checkSteps(run, {
    ingest_windows: { output: ingestOutput({ created: 2, skipped: 1 }) },
    ingest_linux: { output: ingestOutput({ created: 6, skipped: 0 }) },
  });
  const inventory = mergeLayer('inventory', [
    expectCount(
      'synth-lin-02 instances other than its dependency and DO-13 package',
      0,
      await countHostInstances(ctx.es, AGENTS.lin02.hostKey, {
        excludeSoftwareIds: DO2_LIN02_ALLOWED_SOFTWARE_IDS,
      })
    ),
    expectCount(
      'synth-win-01 instances (the (x64) row is skipped)',
      DO2_WIN01_INSTANCE_COUNT,
      await countHostInstances(ctx.es, AGENTS.win01.hostKey)
    ),
  ]);
  return caseResult([engine, step, inventory]);
};

const do3: TestCase['run'] = async (ctx) => {
  const run = await loadDo1Run(ctx);
  if (!run) return blockedResult(NO_DO1_RUN);
  const engine = checkEngine(run.execution, { workflowId: getWorkflowId('discoverOsquery') });
  const step = mergeLayer('step', [
    await checkSteps(run, {
      ingest_linux: { output: ingestOutput({ created: DO3_LINUX_CREATED }) },
    }),
    await checkCandidateCounts(run, { ingest_linux: DO3_LINUX_CANDIDATES }),
  ]);
  const inventory = expectCount(
    'openssl instances on synth-lin-01',
    1,
    await countHostInstancesWithPrefix(ctx.es, AGENTS.lin01.hostKey, 'openssl:')
  );
  return caseResult([engine, step, inventory]);
};

const do4: TestCase['run'] = async (ctx) => {
  const since = new Date().toISOString();
  const fleetAgentsExist = await ctx.es.exists(FLEET_AGENTS_PATH);
  const { run, engine, step } = await runOsqueryExpectation(ctx, DO4_UNKNOWN_AGENT_RUN);
  const inventory = mergeLayer('inventory', [
    await checkInstances(ctx.es, [...DO4_R1_HOST_IDENTITY, DO4_UNKNOWN_INSTANCE]),
    await checkEvents(ctx.es, {
      hostKeys: [AGENTS.unknown.hostKey],
      since,
      expected: [firstSeenEvent(AGENTS.unknown, DO4_UNKNOWN_INSTANCE.catalogId)],
    }),
    await checkNoUnexpectedWrites(ctx.es, { since, allowedHostKeys: [AGENTS.unknown.hostKey] }),
  ]);
  return caseResult(
    [engine, step, inventory],
    [
      fleetAgentsExist
        ? '.fleet-agents exists on this stack; the fallback is still expected because the synthetic agent ids are unknown to Fleet.'
        : '.fleet-agents does not exist: every agent is resolved by the fallback.',
      'The Kibana log line "could not resolve Osquery agent hosts; using agent names" is not asserted (the harness cannot read the Kibana log); check it manually.',
      `Run ${run.executionId}: a found-agent resolution needs a real Fleet agent (plan phase 3).`,
    ]
  );
};

const do5: TestCase['run'] = async (ctx) => {
  const run = await loadDo1Run(ctx);
  if (!run) return blockedResult(NO_DO1_RUN);
  const engine = checkEngine(run.execution, { workflowId: getWorkflowId('discoverOsquery') });
  const step = await checkSteps(run, {
    ingest_windows: { output: ingestOutput({ created: 2, skipped: 1 }) },
    ingest_macos: { output: ingestOutput({ created: 2 }) },
  });
  const inventory = mergeLayer('inventory', [
    await checkCatalogEntries(ctx.es, DO5_APPLICATION_CATALOG),
    await checkInstallPaths(ctx.es, DO5_INSTALL_PATHS),
  ]);
  return caseResult([engine, step, inventory]);
};

// -------------------------------------------------------------------------------------------------
// DO-15: first writer sets the catalog category
// -------------------------------------------------------------------------------------------------

/** Hosts the production `discover-logs` run may write when the synthetic phase documents exist. */
const logsWritableHostKeys = (): string[] => [
  ...new Set([
    DO15_HOST.hostKey,
    ...EXPECTED_PHASE_A_CANDIDATES.map(({ hostKey }) => hostKey),
    EXPECTED_PHASE_B_CANDIDATE.hostKey,
  ]),
];

/** 24 h look-back of the log queries plus a 1 h margin. */
const LOGS_EVENT_LOOKBACK_MS = 25 * 60 * 60 * 1000;

const do15: TestCase['run'] = async (ctx) => {
  const ref = { hostKey: DO15_HOST.hostKey, catalogId: DO15_CATALOG_ID };
  const logTime = ctx.t0.getTime() - HOUR_MS;
  if (logTime < Date.now() - 22 * HOUR_MS) {
    return blockedResult(
      'The log time (t0 minus 1 hour) is older than 22 hours, so query_services (24 hour window) may miss the document. Pass a fresh --t0.'
    );
  }
  const { docs } = await ctx.es.mget<object>(INSTANCES_INDEX, [instanceIdFor(ref)]);
  if (docs[0]?.found) {
    return blockedResult(
      `${DO15_CATALOG_ID} already exists on ${DO15_HOST.hostKey}; run cleanup --synthetic-only first (the first writer must be the logs source).`
    );
  }

  const since = new Date().toISOString();
  const engines: LayerResult[] = [];
  const steps: LayerResult[] = [];
  const inventories: LayerResult[] = [];
  const allowed = logsWritableHostKeys();
  const serviceInstance = (sources: Array<'logs' | 'osquery'>) => ({
    ...ref,
    status: 'active' as const,
    sources,
    hostName: DO15_HOST.hostKey,
  });
  const categoryCheck = () =>
    checkCatalogEntries(ctx.es, [{ id: DO15_CATALOG_ID, fields: { category: 'application' } }]);

  // 1. The logs source creates the instance and the catalog entry (category application).
  await ctx.writeLogDocs([
    toLogDoc(
      serviceLogSpec({
        docId: 'DO15',
        hostName: DO15_HOST.hostKey,
        service: DO15_SERVICE,
        version: DO15_VERSION,
      }),
      ctx.t0
    ),
  ]);
  const logsRun = await ctx.runWorkflow({ workflow: 'discoverLogs' });
  engines.push(
    labelLayer(
      'logs run',
      checkEngine(logsRun.execution, {
        workflowId: getWorkflowId('discoverLogs'),
        isTestRun: true,
      })
    )
  );
  inventories.push(
    labelLayer(
      'after logs run',
      mergeLayer('inventory', [
        await checkInstances(ctx.es, [serviceInstance(['logs'])]),
        await categoryCheck(),
        await checkEvents(ctx.es, {
          hostKeys: [DO15_HOST.hostKey],
          // The event carries the log's observed time, before this case started, so look back 25 h.
          since: new Date(ctx.t0.getTime() - LOGS_EVENT_LOOKBACK_MS).toISOString(),
          // The host also carries events from the Osquery cases; assert only this case's software.
          softwareIds: [DO15_CATALOG_ID],
          expected: [
            {
              type: 'first_seen',
              source: 'logs',
              software_id: DO15_CATALOG_ID,
              host: { key: DO15_HOST.hostKey },
            },
          ],
        }),
      ])
    )
  );

  // 2. The Linux snapshot reports the same software: the instance gains the osquery source.
  const withService: OsqueryRunExpectation = {
    ...DO15_RUN_WITH_SERVICE,
    steps: { query_linux: linuxFixture('DO-15-with-service', DO15_ROWS_WITH_SERVICE) },
  };
  const first = await runOsqueryExpectation(ctx, withService);
  engines.push(first.engine);
  steps.push(first.step);
  inventories.push(
    labelLayer(
      'after osquery with service',
      mergeLayer('inventory', [
        await checkInstances(ctx.es, [serviceInstance(['logs', 'osquery'])]),
        await categoryCheck(),
      ])
    )
  );

  // 3. The Linux snapshot without it: category application is not reported, so nothing is removed.
  const withoutService: OsqueryRunExpectation = {
    ...DO15_RUN_WITHOUT_SERVICE,
    steps: { query_linux: linuxFixture('DO-15-without-service', DO15_BASE_ROWS) },
  };
  const second = await runOsqueryExpectation(ctx, withoutService);
  engines.push(second.engine);
  steps.push(second.step);
  inventories.push(
    labelLayer(
      'after osquery without service',
      mergeLayer('inventory', [
        await checkInstances(ctx.es, [serviceInstance(['logs', 'osquery'])]),
        await categoryCheck(),
        await checkNoUnexpectedWrites(ctx.es, { since, allowedHostKeys: allowed }),
      ])
    )
  );

  return caseResult(
    [
      mergeLayer('engine', engines),
      mergeLayer('step', steps),
      mergeLayer('inventory', inventories),
    ],
    [
      'Known order dependency (risk R5): the catalog category comes from the first writer, so the Linux snapshot never removes an instance first created by logs.',
    ]
  );
};

// -------------------------------------------------------------------------------------------------
// DO-16, DO-17: the 5000-candidate limit
// -------------------------------------------------------------------------------------------------

const bulkVariant = (label: string, fixture: typeof F_BULK_5000 | typeof F_BULK_5001): string =>
  buildOsqueryVariant({ label, steps: { query_linux: fixture } });

const idleIngestSteps = ['ingest_windows', 'ingest_macos', 'ingest_dependencies'] as const;

const do16: TestCase['run'] = async (ctx) => {
  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({
    workflow: 'discoverOsquery',
    yaml: bulkVariant('DO-16 5000 rows', F_BULK_5000),
    wait: { timeoutMs: BULK_RUN_TIMEOUT_MS },
  });
  const engine = checkEngine(run.execution, {
    workflowId: getWorkflowId('discoverOsquery'),
    isTestRun: true,
  });

  // The 5000-candidate input and output stay out of the report: compare them here.
  const detail = await run.step('ingest_linux');
  const diffs = diffValues(
    ingestOutput({ created: BULK_LIMIT }),
    detail.output ?? null,
    'ingest_linux.output'
  );
  const candidates = candidateCountOf(detail.input);
  if (candidates !== BULK_LIMIT) {
    diffs.push(`ingest_linux.input.candidates: expected ${BULK_LIMIT}, got ${candidates}`);
  }
  const snapshot =
    typeof detail.input === 'object' && detail.input !== null && !Array.isArray(detail.input)
      ? detail.input.snapshot
      : undefined;
  if (snapshot !== false) {
    diffs.push(`ingest_linux.input.snapshot: expected false (truncated), got ${String(snapshot)}`);
  }
  const durationMs = stepDurationMs(run, 'ingest_linux');
  if (durationMs !== undefined && durationMs >= DO16_MAX_STEP_MS) {
    diffs.push(`ingest_linux took ${durationMs} ms, expected under ${DO16_MAX_STEP_MS} ms`);
  }
  const step = mergeLayer('step', [
    layerResult('step', diffs, 4, { ingestLinuxDurationMs: durationMs ?? null }),
    await checkSteps(
      run,
      Object.fromEntries(
        idleIngestSteps.map((name) => [
          name,
          { output: ingestOutput({}), input: { snapshot: true } },
        ])
      )
    ),
  ]);

  const eventCount = await ctx.es.count(EVENTS_INDEX, {
    bool: {
      filter: [
        { term: { 'host.key': BULK_HOST_KEY } },
        { term: { type: 'first_seen' } },
        { range: { '@timestamp': { gte: since } } },
      ],
    },
  });
  const inventory = mergeLayer('inventory', [
    expectCount(
      `instances on ${BULK_HOST_KEY}`,
      BULK_LIMIT,
      await countHostInstances(ctx.es, BULK_HOST_KEY)
    ),
    expectCount('first_seen events since the run', BULK_LIMIT, eventCount),
    await checkInstances(
      ctx.es,
      DO16_SPOT_CHECKS.map(({ catalogId }) => osqueryInstance(AGENTS.bulk, catalogId, 'active'))
    ),
    await checkCatalogEntries(
      ctx.es,
      DO16_SPOT_CHECKS.map(({ catalogId }) => ({
        id: catalogId,
        fields: { category: 'os_package' },
      }))
    ),
    await checkNoUnexpectedWrites(ctx.es, { since, allowedHostKeys: [BULK_HOST_KEY] }),
  ]);
  return caseResult([engine, step, inventory]);
};

const do17: TestCase['run'] = async (ctx) => {
  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({
    workflow: 'discoverOsquery',
    yaml: bulkVariant('DO-17 5001 rows', F_BULK_5001),
    wait: { timeoutMs: BULK_RUN_TIMEOUT_MS },
  });
  const engine = checkEngine(run.execution, {
    workflowId: getWorkflowId('discoverOsquery'),
    isTestRun: true,
    steps: { ingest_linux: 'failed' },
  });
  const errorText = await stepErrorText(run, 'ingest_linux');
  const detail = await run.step('ingest_linux');
  const candidates = candidateCountOf(detail.input);
  const stepDiffs = [
    ...(errorText.includes('candidates')
      ? []
      : [`ingest_linux error does not name "candidates": ${errorText.slice(0, 300)}`]),
    ...(candidates === BULK_LIMIT + 1
      ? []
      : [`ingest_linux.input.candidates: expected ${BULK_LIMIT + 1}, got ${candidates}`]),
    ...(detail.output === null || detail.output === undefined
      ? []
      : [
          `ingest_linux.output: expected none for a failed step, got ${JSON.stringify(
            detail.output
          )}`,
        ]),
  ];
  const step = mergeLayer('step', [
    layerResult('step', stepDiffs, 3, { ingestLinuxError: errorText.slice(0, 500) }),
    await checkSteps(
      run,
      Object.fromEntries(
        idleIngestSteps.map((name) => [
          name,
          { output: ingestOutput({}), input: { snapshot: true } },
        ])
      )
    ),
  ]);
  // No host may be written: the validation fails before any write.
  const inventory = await checkNoUnexpectedWrites(ctx.es, { since, allowedHostKeys: [] });
  return caseResult([engine, step, inventory]);
};

// -------------------------------------------------------------------------------------------------
// DO-18: the stored YAML on this stack
// -------------------------------------------------------------------------------------------------

const DO18_EXPECTATION: OsqueryRunExpectation = {
  label: 'DO-18 production YAML',
  steps: {},
  ingest: DO18_INGEST,
  failedQueries: QUERY_KEYS,
};

const OSQUERY_STEPS_UNAVAILABLE =
  'The osquery.runQuery step type is not registered on this stack, so the production discover-osquery ' +
  'YAML cannot be validated or run. Set `xpack.osquery.enableExperimental: [workflowsExtensionsEnabled]` ' +
  'in config/kibana.dev.yml and restart Kibana to run this case. The mocked variants (DO-1..DO-17) ' +
  'do not need it because they replace the query steps.';

/** True for the 400 the test route returns when a workflow uses an unregistered osquery step. */
const isUnknownOsqueryStepError = (error: unknown): boolean =>
  error instanceof HttpError &&
  error.status === 400 &&
  /Invalid step type/.test(error.body) &&
  /query_(linux|windows|macos|dependencies)/.test(error.body);

const do18: TestCase['run'] = async (ctx) => {
  if (await ctx.es.exists(FLEET_AGENTS_PATH)) {
    return blockedResult(
      '.fleet-agents exists, so Osquery agents may be enrolled: the stored YAML would dispatch real queries and ingest real hosts. Run this case only on a stack without agents.'
    );
  }
  const since = new Date().toISOString();
  let run: CompletedRun;
  try {
    run = await ctx.runWorkflow({ workflow: 'discoverOsquery' });
  } catch (error) {
    // The Osquery workflow steps are registered only behind an experimental flag (shipped dark), so
    // without it the production YAML fails validation before it can run at all.
    if (isUnknownOsqueryStepError(error)) {
      return blockedResult(OSQUERY_STEPS_UNAVAILABLE);
    }
    throw error;
  }
  const { engine, step } = await checkOsqueryRun(run, DO18_EXPECTATION);
  const errors = Object.fromEntries(
    await Promise.all(
      DO18_FAILED_STEPS.map(async (name) => [name, (await stepErrorText(run, name)).slice(0, 500)])
    )
  );
  const inventory = await checkNoUnexpectedWrites(ctx.es, { since, allowedHostKeys: [] });
  return caseResult(
    [
      engine,
      mergeLayer('step', [step, layerResult('step', [], 0, { queryErrors: errors })]),
      inventory,
    ],
    ['Record the query errors in the step evidence: each query_* fails before dispatch.']
  );
};

export const cases: TestCase[] = [
  byId('DO-1'),
  {
    id: 'DO-2',
    family: 'DO',
    title: 'Blank and invalid rows: ingest_windows skipped 1, ingest_linux skipped 0',
    requires: ['DO-1'],
    run: do2,
  },
  {
    id: 'DO-3',
    family: 'DO',
    title: 'Duplicate rows: ingest_linux created 6 from 7 candidates, one openssl instance',
    requires: ['DO-1'],
    run: do3,
  },
  {
    id: 'DO-4',
    family: 'DO',
    title: 'Agent-id resolution fallback without .fleet-agents',
    requires: ['DO-1'],
    run: do4,
  },
  {
    id: 'DO-5',
    family: 'DO',
    title: 'Windows and macOS categories and install paths',
    requires: ['DO-1'],
    run: do5,
  },
  byId('DO-6'),
  byId('DO-7'),
  byId('DO-8'),
  byId('DO-9'),
  byId('DO-10'),
  byId('DO-11'),
  byId('DO-12'),
  byId('DO-13'),
  byId('DO-14'),
  {
    id: 'DO-15',
    family: 'DO',
    title: 'First writer sets the catalog category (logs, then Linux snapshot twice)',
    requires: ['DO-7'],
    run: do15,
  },
  {
    id: 'DO-16',
    family: 'DO',
    title: '5000 rows: created 5000 in under 60 seconds, no removal',
    run: do16,
  },
  {
    id: 'DO-17',
    family: 'DO',
    title: 'Over the limit: 5001 candidates fail ingest_linux, run completed',
    run: do17,
  },
  {
    id: 'DO-18',
    family: 'DO',
    title: 'Production YAML on this stack: query steps fail, ingest all zeros',
    run: do18,
  },
];
