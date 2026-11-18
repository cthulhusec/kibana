/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Entry point of the discovery test harness (`scripts/run_discovery_tests.js`). See
 * "Execution procedure" and "Harness to build" in docs/discovery_test_plan.md.
 */

import { spawnSync } from 'child_process';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  CATALOG_INDEX,
  EVENTS_INDEX,
  INSTANCES_INDEX,
  ROLLUPS_INDEX,
} from '../../common/constants';
import type { CompletedRun, EsClient, KibanaClient } from './clients';
import { createEsClient, createKibanaClient, toCompletedRun } from './clients';
import { ALL_CASES, selectCases, validateRegistry } from './cases';
import type {
  CaseContext,
  CaseRecord,
  CaseResult,
  HarnessConfig,
  HarnessLogger,
  TestCase,
} from './cases/types';
import {
  KNOWN_SYNTHETIC_CATALOG_IDS,
  cleanup,
  findSyntheticResidue,
  isResidueEmpty,
  listTestWorkflowIds,
  seedCatalogIds,
  syntheticHostKeyQuery,
} from './cleanup';
import type { LogPhase, SyntheticLogDoc } from './logs/generate_logs';
import {
  EXPECTED_PHASE_A_CANDIDATES,
  EXPECTED_PHASE_B_CANDIDATE,
  LOG_PHASES,
  buildPhaseDocs,
  parseT0,
  writeLogDocs,
} from './logs/generate_logs';
import {
  SYNTHETIC_DATA_STREAM,
  SYNTHETIC_TEMPLATE_NAME,
  ensureSyntheticDataStream,
  simulateTemplate,
} from './logs/template';
import { loadResults, loadState, orderRecords, renderText, saveResults, saveState } from './report';
import type { NvdStub } from './nvd_stub/server';
import { PRODUCTION_WORKFLOWS, getProductionYaml, getWorkflowId } from './variants/build_variant';
import type { WorkflowKey } from './variants/build_variant';

export const DEFAULTS = {
  kibanaUrl: 'http://localhost:5601',
  esUrl: 'http://localhost:9200',
  username: 'elastic',
  // Documented local dev default only; override with --password, KIBANA_PASSWORD, or ES_PASSWORD.
  password: 'changeme',
  space: 'default',
  nvdPort: 5699,
} as const;

export const COMMANDS = [
  'list',
  'preflight',
  'logs',
  'nvd-stub',
  'run',
  'cleanup',
  'restore',
  'regression',
  'report',
] as const;
export type Command = (typeof COMMANDS)[number];

const BOOLEAN_FLAGS = ['dry-run', 'synthetic-only', 'json', 'help', 'verbose'] as const;

export interface ParsedArgs {
  readonly command?: string;
  readonly positionals: readonly string[];
  /** Boolean flags map to `true`; string flags to their value ('' when given without one). */
  readonly flags: ReadonlyMap<string, string | true>;
}

/** Parses `--flag=value`, `--flag value`, and boolean flags; the first positional is the command. */
export const parseCliArgs = (argv: readonly string[]): ParsedArgs => {
  const flags = new Map<string, string | true>();
  const positionals: string[] = [];
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (!arg.startsWith('--')) {
      positionals.push(arg);
      continue;
    }
    const [key, ...rest] = arg.slice(2).split('=');
    if (rest.length > 0) {
      flags.set(key, rest.join('='));
    } else if ((BOOLEAN_FLAGS as readonly string[]).includes(key)) {
      flags.set(key, true);
    } else if (index + 1 < argv.length && !argv[index + 1].startsWith('--')) {
      flags.set(key, argv[++index]);
    } else {
      flags.set(key, '');
    }
  }
  const [command, ...others] = positionals;
  return { command, positionals: others, flags };
};

/** String flags default to '', so an empty value means "not provided". */
export const readStringFlag = (value: unknown, fallback: string): string =>
  typeof value === 'string' && value !== '' ? value : fallback;

const readPort = (value: unknown, fallback: number): number => {
  const text = readStringFlag(value, String(fallback));
  const port = Number(text);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid port "${text}"`);
  }
  return port;
};

export const resolveConfig = (
  { flags }: ParsedArgs,
  env: Readonly<Record<string, string | undefined>>
): HarnessConfig => ({
  kibanaUrl: readStringFlag(flags.get('kibana-url'), env.KIBANA_URL ?? DEFAULTS.kibanaUrl).replace(
    /\/+$/,
    ''
  ),
  esUrl: readStringFlag(flags.get('es-url'), env.ES_URL ?? DEFAULTS.esUrl).replace(/\/+$/, ''),
  username: readStringFlag(flags.get('username'), DEFAULTS.username),
  password: readStringFlag(
    flags.get('password'),
    env.KIBANA_PASSWORD ?? env.ES_PASSWORD ?? DEFAULTS.password
  ),
  space: readStringFlag(flags.get('space'), DEFAULTS.space),
  resultsDir: readStringFlag(
    flags.get('results-dir'),
    join(tmpdir(), 'software_inventory_discovery_test')
  ),
  nvdPort: readPort(flags.get('nvd-port') ?? flags.get('port'), DEFAULTS.nvdPort),
});

export const USAGE = `
Usage: node x-pack/solutions/security/plugins/software_inventory/scripts/run_discovery_tests.js <command> [flags]

Commands:
  list                         List every registered case (id, family, title, prerequisites)
  preflight                    Read-only checks of the stack before a test pass (T0-4)
  logs --phase A|B [--t0 ISO]  Create the synthetic logs template, data stream, and phase documents
       [--dry-run]             Print what would be written; no writes
  nvd-stub [--port 5699]       Run the NVD/KEV stub until Ctrl+C [--mode normal|kev-500|offline]
  run <ids|family|all>         Run cases, for example "T0", "DO-1,DO-6", or "all"
  cleanup [--synthetic-only]   Delete synthetic inventory docs; without the flag also the synthetic
                               logs data stream and template, and si-test-* workflows
  restore                      Regenerate the demo data: runs seed_demo_data.js --clean
  regression                   Residue check plus the RG cases
  report [--json]              Print the recorded results

Flags:
  --kibana-url   Kibana URL including any base path (default: $KIBANA_URL, else ${DEFAULTS.kibanaUrl})
  --es-url       Elasticsearch URL (default: $ES_URL, else ${DEFAULTS.esUrl})
  --username     User for both (default: ${DEFAULTS.username})
  --password     Password (default: $KIBANA_PASSWORD, $ES_PASSWORD, else the local dev default)
  --space        Kibana space (default: ${DEFAULTS.space})
  --t0           Synthetic logs generation time (default: the value 'logs' recorded, else now)
  --results-dir  Where results.json, state.json, and the Markdown report go (default: OS temp dir)
  --nvd-port     Port of the in-process NVD stub for cases that need it (default: ${DEFAULTS.nvdPort})
  --verbose      Debug logging
`;

const createLogger = (verbose: boolean): HarnessLogger => ({
  info: (message) => process.stdout.write(`${message}\n`),
  warn: (message) => process.stderr.write(`WARN ${message}\n`),
  debug: (message) => {
    if (verbose) process.stdout.write(`debug ${message}\n`);
  },
});

// -------------------------------------------------------------------------------------------------
// Runner
// -------------------------------------------------------------------------------------------------

export interface RunnerDeps {
  readonly config: HarnessConfig;
  readonly kibana: KibanaClient;
  readonly es: EsClient;
  readonly t0: Date;
  readonly log: HarnessLogger;
  /** Earlier records (results file). */
  readonly prior: ReadonlyMap<string, CaseRecord>;
  readonly startNvdStub: (port: number) => Promise<NvdStub>;
  /** Called after each case, for incremental persistence. */
  readonly onRecord?: (record: CaseRecord) => Promise<void>;
}

const errorResult = (error: Error): CaseResult => ({
  status: 'error',
  layers: [],
  notes: [error.stack?.split('\n').slice(0, 3).join(' ') ?? error.message],
});

/** Runs the cases in order; never throws for a failing case. */
export const runCases = async (
  selected: readonly TestCase[],
  deps: RunnerDeps
): Promise<CaseRecord[]> => {
  const records = new Map<string, CaseRecord>();
  let stub: NvdStub | undefined;
  try {
    for (const testCase of selected) {
      const startedAt = new Date();
      const executionIds: string[] = [];
      const finish = async (result: CaseResult): Promise<void> => {
        const record: CaseRecord = {
          ...result,
          id: testCase.id,
          family: testCase.family,
          title: testCase.title,
          startedAt: startedAt.toISOString(),
          durationMs: Date.now() - startedAt.getTime(),
          executionIds,
        };
        records.set(record.id, record);
        deps.log.info(`${record.status.toUpperCase().padEnd(7)} ${record.id} ${record.title}`);
        await deps.onRecord?.(record);
      };

      const unmet = (testCase.requires ?? []).filter(
        (id) => (records.get(id) ?? deps.prior.get(id))?.status !== 'pass'
      );
      if (unmet.length > 0) {
        await finish({
          status: 'blocked',
          layers: [],
          notes: [`requires passing ${unmet.join(', ')}`],
        });
        continue;
      }

      try {
        if (testCase.needs?.includes('nvd-stub') && !stub) {
          stub = await deps.startNvdStub(deps.config.nvdPort);
          deps.log.info(`NVD stub listening on ${stub.url}`);
        }
        const ctx: CaseContext = {
          config: deps.config,
          kibana: deps.kibana,
          es: deps.es,
          t0: deps.t0,
          log: deps.log,
          ...(testCase.needs?.includes('nvd-stub') && stub ? { nvdStub: stub } : {}),
          priorResults: new Map([...deps.prior, ...records]),
          runWorkflow: async ({
            workflow,
            yaml,
            workflowId,
            inputs,
            wait,
          }): Promise<CompletedRun> => {
            const id = workflowId ?? getWorkflowId(workflow);
            const executionId = await deps.kibana.testRun({
              workflowId: id,
              ...(yaml ? { workflowYaml: yaml } : {}),
              inputs: inputs ?? {},
            });
            executionIds.push(executionId);
            deps.log.debug(`${testCase.id}: execution ${executionId} (${id})`);
            const execution = await deps.kibana.waitForExecution(executionId, wait);
            return toCompletedRun(deps.kibana, execution);
          },
          writeLogs: async (phase: LogPhase) => {
            await ensureSyntheticDataStream(deps.es);
            return writeLogDocs(deps.es, buildPhaseDocs(phase, deps.t0));
          },
          writeLogDocs: async (docs: readonly SyntheticLogDoc[]) => {
            await ensureSyntheticDataStream(deps.es);
            return writeLogDocs(deps.es, docs);
          },
        };
        await finish(await testCase.run(ctx));
      } catch (error) {
        await finish(errorResult(error as Error));
      }
    }
  } finally {
    await stub?.close();
  }
  return [...records.values()];
};

// -------------------------------------------------------------------------------------------------
// Preflight (read-only)
// -------------------------------------------------------------------------------------------------

type CheckLevel = 'PASS' | 'INFO' | 'WARN' | 'FAIL';
interface Check {
  readonly level: CheckLevel;
  readonly name: string;
  readonly detail: string;
}

const STALE_AFTER_DAYS = 30;

const preflight = async (kibana: KibanaClient, es: EsClient): Promise<Check[]> => {
  const checks: Check[] = [];
  const add = (level: CheckLevel, name: string, detail: string) =>
    checks.push({ level, name, detail });
  const attempt = async (name: string, fn: () => Promise<void>) => {
    try {
      await fn();
    } catch (error) {
      add('FAIL', name, (error as Error).message);
    }
  };

  await attempt('elasticsearch', async () => {
    const { body } = await es.request<{ version?: { number?: string } }>('GET', '/');
    add('PASS', 'elasticsearch', `version ${body.version?.number}`);
  });
  await attempt('kibana', async () => {
    const { body } = await kibana.request<{
      version?: { number?: string };
      status?: { overall?: { level?: string } };
    }>('GET', '/api/status');
    const level = body.status?.overall?.level;
    add(
      level === 'available' ? 'PASS' : 'WARN',
      'kibana',
      `version ${body.version?.number}, ${level}`
    );
  });

  await attempt('managed workflows', async () => {
    const { results } = await kibana.listWorkflows({ managed: true, size: 100 });
    for (const key of Object.keys(PRODUCTION_WORKFLOWS) as WorkflowKey[]) {
      const id = getWorkflowId(key);
      const stored = results.find((workflow) => workflow.id === id);
      if (!stored) {
        add('FAIL', `workflow ${id}`, 'not installed in this space');
        continue;
      }
      if (stored.enabled) {
        add('FAIL', `workflow ${id}`, 'enabled; the plan requires every managed workflow disabled');
        continue;
      }
      const sameYaml = stored.yaml === undefined || stored.yaml === getProductionYaml(key);
      add(
        sameYaml ? 'PASS' : 'WARN',
        `workflow ${id}`,
        `disabled, definitionHash ${stored.definitionHash ?? 'n/a'}${
          sameYaml ? '' : '; stored YAML differs from the registered definition (restart Kibana)'
        }`
      );
    }
  });

  await attempt('plugin indices', async () => {
    const counts = await Promise.all(
      [CATALOG_INDEX, INSTANCES_INDEX, EVENTS_INDEX, ROLLUPS_INDEX].map(
        async (index) =>
          `${index.replace('.kibana-software-inventory-', '')} ${await es.count(index)}`
      )
    );
    add('INFO', 'plugin indices', counts.join(', '));
  });

  await attempt('synthetic documents', async () => {
    const [instances, events] = await Promise.all([
      es.count(INSTANCES_INDEX, syntheticHostKeyQuery()),
      es.count(EVENTS_INDEX, syntheticHostKeyQuery()),
    ]);
    add(
      instances + events === 0 ? 'PASS' : 'FAIL',
      'synthetic documents',
      `${instances} instance(s), ${events} event(s) with synthetic host keys${
        instances + events === 0 ? '' : '; run "cleanup" first'
      }`
    );
  });

  await attempt('synthetic catalog ids', async () => {
    const seed = new Set(seedCatalogIds());
    const collidingWithSeed = KNOWN_SYNTHETIC_CATALOG_IDS.filter((id) => seed.has(id));
    const { docs } = await es.mget<{ id: string }>(CATALOG_INDEX, KNOWN_SYNTHETIC_CATALOG_IDS);
    const existing = docs.filter((doc) => doc.found).map((doc) => doc._id);
    if (collidingWithSeed.length > 0) {
      add(
        'FAIL',
        'synthetic catalog ids',
        `also in the demo seed: ${collidingWithSeed.join(', ')}`
      );
    } else if (existing.length > 0) {
      add(
        'FAIL',
        'synthetic catalog ids',
        `already exist: ${existing.join(', ')}; run "cleanup" first`
      );
    } else {
      add('PASS', 'synthetic catalog ids', `${KNOWN_SYNTHETIC_CATALOG_IDS.length} ids absent`);
    }
  });

  await attempt('stale-eligible instances', async () => {
    const count = await es.count(INSTANCES_INDEX, {
      bool: {
        filter: [
          { terms: { status: ['active', 'patched'] } },
          { range: { last_seen: { lt: `now-${STALE_AFTER_DAYS}d` } } },
        ],
      },
    });
    add(
      'INFO',
      'stale-eligible instances',
      `${count} (SE-10 expects mark_stale.marked = 1 + ${count})`
    );
  });

  await attempt('logs template', async () => {
    const simulation = await simulateTemplate(es);
    const ok = simulation.indexMode === 'logsdb' && simulation.missingFields.length === 0;
    add(
      ok ? 'PASS' : 'FAIL',
      'logs template (simulated)',
      `index.mode ${simulation.indexMode}${
        simulation.missingFields.length ? `, unmapped: ${simulation.missingFields.join(', ')}` : ''
      }`
    );
    const [template, dataStream] = await Promise.all([
      es.exists(`/_index_template/${SYNTHETIC_TEMPLATE_NAME}`),
      es.exists(`/_data_stream/${SYNTHETIC_DATA_STREAM}`),
    ]);
    add(
      'INFO',
      'synthetic logs',
      `template ${template ? 'present' : 'absent'}, data stream ${
        dataStream ? 'present' : 'absent'
      }`
    );
  });

  await attempt('write privileges', async () => {
    const { body } = await es.request<{ has_all_requested?: boolean }>(
      'POST',
      '/_security/user/_has_privileges',
      {
        body: {
          index: [
            {
              names: [SYNTHETIC_DATA_STREAM, '.kibana-software-inventory-*'],
              privileges: ['read', 'write', 'delete'],
              allow_restricted_indices: true,
            },
          ],
        },
      }
    );
    add(
      body.has_all_requested ? 'PASS' : 'FAIL',
      'write privileges',
      `has_all_requested ${body.has_all_requested}`
    );
  });

  await attempt('si-test workflows', async () => {
    const ids = await listTestWorkflowIds(kibana);
    add(
      ids.length === 0 ? 'PASS' : 'WARN',
      'si-test workflows',
      ids.length ? ids.join(', ') : 'none'
    );
  });

  add(
    'INFO',
    'nvd stub config',
    'EC cases need xpack.softwareInventory.enrichment.{nvdBaseUrl,kevUrl} pointing at the stub (not readable from here)'
  );
  return checks;
};

// -------------------------------------------------------------------------------------------------
// Commands
// -------------------------------------------------------------------------------------------------

const resolveT0 = async (args: ParsedArgs, config: HarnessConfig): Promise<Date> => {
  const flag = readStringFlag(args.flags.get('t0'), '');
  if (flag) return parseT0(flag);
  const state = await loadState(config.resultsDir);
  return state.t0 ? parseT0(state.t0) : new Date();
};

const commandLogs = async (
  args: ParsedArgs,
  config: HarnessConfig,
  es: EsClient,
  log: HarnessLogger
) => {
  const phase = readStringFlag(args.flags.get('phase'), '').toUpperCase();
  if (!(LOG_PHASES as readonly string[]).includes(phase)) {
    throw new Error('logs needs --phase A or --phase B');
  }
  const state = await loadState(config.resultsDir);
  const flag = readStringFlag(args.flags.get('t0'), '');
  if (phase === 'B' && !flag && !state.t0) {
    throw new Error('Phase B needs the T0 of phase A: pass --t0 or write phase A first');
  }
  const t0 = flag ? parseT0(flag) : state.t0 && phase === 'B' ? parseT0(state.t0) : new Date();
  const docs = buildPhaseDocs(phase as LogPhase, t0);
  const groups = new Map<string, number>();
  for (const doc of docs) {
    const group = doc.spec.docId.replace(/-\d+$/, '');
    groups.set(group, (groups.get(group) ?? 0) + 1);
  }
  log.info(
    `Phase ${phase}, T0 ${t0.toISOString()}: ${
      docs.length
    } document(s) into ${SYNTHETIC_DATA_STREAM}`
  );
  log.info(
    `  ${[...groups]
      .map(([group, count]) => (count > 1 ? `${group} x${count}` : group))
      .join(', ')}`
  );
  const candidates = phase === 'A' ? EXPECTED_PHASE_A_CANDIDATES : [EXPECTED_PHASE_B_CANDIDATE];
  log.info(`Expected new discover-logs candidate rows (phase ${phase}):`);
  for (const candidate of candidates) {
    log.info(
      `  ${candidate.category.padEnd(11)} ${candidate.host_id.padEnd(20)} ${
        candidate.catalogId
      } (key ${candidate.hostKey})`
    );
  }
  if (args.flags.get('dry-run') === true) {
    log.info(
      `Dry run: template ${SYNTHETIC_TEMPLATE_NAME} and data stream not created; nothing written.`
    );
    return;
  }
  const created = await ensureSyntheticDataStream(es);
  const written = await writeLogDocs(es, docs);
  await saveState(config.resultsDir, {
    ...state,
    t0: t0.toISOString(),
    logPhasesWritten: [...new Set([...(state.logPhasesWritten ?? []), phase])],
  });
  log.info(
    `Template ${created.templateCreated ? 'created' : 'updated'}, data stream ${
      created.dataStreamCreated ? 'created' : 'existed'
    }; ${written.written} written, ${
      written.existing
    } already present. Run workflows within 60 minutes of T0.`
  );
};

const loadStubModule = async (): Promise<(port: number) => Promise<NvdStub>> => {
  const { startNvdStub } = await import('./nvd_stub/server');
  return (port: number) => startNvdStub({ port });
};

const commandNvdStub = async (args: ParsedArgs, config: HarnessConfig, log: HarnessLogger) => {
  const start = await loadStubModule();
  const stub = await start(config.nvdPort);
  const mode = readStringFlag(args.flags.get('mode'), '');
  if (mode) stub.setMode(mode as Parameters<NvdStub['setMode']>[0]);
  log.info(`NVD stub listening on ${stub.url}${mode ? ` (mode ${mode})` : ''}; Ctrl+C to stop.`);
  await new Promise<void>((resolve) => {
    process.once('SIGINT', resolve);
    process.once('SIGTERM', resolve);
  });
  log.info(`Stopping; ${stub.requests().length} request(s) served.`);
  await stub.close();
};

const commandRun = async (
  selector: string,
  args: ParsedArgs,
  config: HarnessConfig,
  clients: { kibana: KibanaClient; es: EsClient },
  log: HarnessLogger
): Promise<CaseRecord[]> => {
  validateRegistry(ALL_CASES);
  const selected = selectCases(selector);
  if (selected.length === 0) {
    log.warn(`No cases registered for "${selector}"`);
    return [];
  }
  const prior = new Map(Object.entries((await loadResults(config.resultsDir)).records));
  const t0 = await resolveT0(args, config);
  const order = ALL_CASES.map(({ id }) => id);
  log.info(
    `Running ${selected.length} case(s); T0 ${t0.toISOString()}; results in ${config.resultsDir}`
  );
  const records = await runCases(selected, {
    config,
    ...clients,
    t0,
    log,
    prior,
    startNvdStub: async (port) => (await loadStubModule())(port),
    onRecord: async (record) => {
      await saveResults(config.resultsDir, [record], order);
    },
  });
  log.info(`\n${renderText(records)}`);
  return records;
};

const commandRestore = (config: HarnessConfig, log: HarnessLogger): void => {
  const seedScript = join(__dirname, '..', 'seed_demo_data.js');
  log.info(`Restoring demo data: node ${seedScript} --clean --es-url=${config.esUrl}`);
  const result = spawnSync(
    process.execPath,
    [seedScript, '--clean', `--es-url=${config.esUrl}`, `--username=${config.username}`],
    { stdio: 'inherit', env: { ...process.env, ES_PASSWORD: config.password } }
  );
  if (result.status !== 0) {
    throw new Error(`seed_demo_data.js --clean exited with ${result.status ?? result.signal}`);
  }
};

const printReport = async (args: ParsedArgs, config: HarnessConfig, log: HarnessLogger) => {
  const results = await loadResults(config.resultsDir);
  const records = orderRecords(
    results,
    ALL_CASES.map(({ id }) => id)
  );
  if (args.flags.get('json') === true) {
    log.info(JSON.stringify(records, null, 2));
    return;
  }
  log.info(`Results in ${config.resultsDir} (updated ${results.updatedAt || 'never'})`);
  log.info(renderText(records));
};

export const main = async (argv: readonly string[], env = process.env): Promise<number> => {
  const args = parseCliArgs(argv);
  const log = createLogger(args.flags.get('verbose') === true);
  if (!args.command || args.flags.get('help') === true) {
    log.info(USAGE);
    return args.command ? 0 : 1;
  }
  if (!(COMMANDS as readonly string[]).includes(args.command)) {
    log.warn(`Unknown command "${args.command}"\n${USAGE}`);
    return 1;
  }
  const command = args.command as Command;
  const config = resolveConfig(args, env);
  const kibana = createKibanaClient(config);
  const es = createEsClient(config);

  switch (command) {
    case 'list': {
      validateRegistry(ALL_CASES);
      for (const testCase of ALL_CASES) {
        const requires = testCase.requires?.length
          ? ` (requires ${testCase.requires.join(', ')})`
          : '';
        log.info(`${testCase.id.padEnd(7)} ${testCase.title}${requires}`);
      }
      log.info(`${ALL_CASES.length} case(s) registered.`);
      return 0;
    }
    case 'preflight': {
      const checks = await preflight(kibana, es);
      for (const check of checks)
        log.info(`${check.level.padEnd(4)} ${check.name}: ${check.detail}`);
      return checks.some((check) => check.level === 'FAIL') ? 1 : 0;
    }
    case 'logs':
      await commandLogs(args, config, es, log);
      return 0;
    case 'nvd-stub':
      await commandNvdStub(args, config, log);
      return 0;
    case 'run': {
      const selector = args.positionals.join(',');
      const records = await commandRun(selector, args, config, { kibana, es }, log);
      return records.every((record) => record.status === 'pass') ? 0 : 1;
    }
    case 'cleanup': {
      const report = await cleanup(es, kibana, {
        syntheticOnly: args.flags.get('synthetic-only') === true,
      });
      log.info(JSON.stringify(report, null, 2));
      return 0;
    }
    case 'restore':
      commandRestore(config, log);
      return 0;
    case 'regression': {
      const residue = await findSyntheticResidue(es, kibana);
      const clean = isResidueEmpty(residue);
      log.info(`Synthetic residue ${clean ? 'none' : 'FOUND'}: ${JSON.stringify(residue)}`);
      const rgCases = ALL_CASES.filter(({ family }) => family === 'RG');
      if (rgCases.length === 0) {
        log.warn('No RG cases registered yet; only the residue check ran.');
        return clean ? 0 : 1;
      }
      const records = await commandRun('RG', args, config, { kibana, es }, log);
      return clean && records.every((record) => record.status === 'pass') ? 0 : 1;
    }
    case 'report':
      await printReport(args, config, log);
      return 0;
  }
};

/** Exits with 1 on failure; used by `scripts/run_discovery_tests.js`. */
export const cli = (): void => {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: Error) => {
      process.stderr.write(`${error.message}\n`);
      process.exitCode = 1;
    });
};
