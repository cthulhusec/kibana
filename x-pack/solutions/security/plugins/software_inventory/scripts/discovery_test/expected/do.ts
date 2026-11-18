/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Expected outcomes of the DISCOVER-OSQUERY cases (DO-1..DO-14 in docs/discovery_test_plan.md).
 * Every instance id comes from the plugin's `buildInstanceId` (through `instanceIdFor` in the
 * assertions), never from a hard-coded hash. Catalog ids come from the fixtures' documented
 * `catalogId` values, and versions are the version part of those ids.
 *
 * The cases run in the plan's order and leave state behind, so the later expectations describe the
 * state after the earlier cases: after DO-7 `openssl` is 3.0.14 and active, `synth-tool` is removed,
 * and the other `synth-lin-01` packages are active.
 */

import type { ExpectedCatalogEntry, ExpectedEvent, ExpectedInstance } from '../assertions';
import type {
  ExpectedRow,
  OsqueryFixture,
  OsqueryQueryStep,
  OsqueryRow,
  SyntheticAgent,
} from '../fixtures/osquery';
import {
  AGENTS,
  DEPS_LIN01_LODASH_AND_LOG4J,
  DEPS_LIN01_LODASH_ONLY,
  F_FAILED,
  F_UNKNOWN_AGENT,
  LINUX_LIN02_ONLY,
  R1,
  R1_DEPENDENCY_ROWS,
  R1_LINUX_ROWS,
  R1_MACOS_ROWS,
  R1_WINDOWS_ROWS,
  R2_LINUX,
  fPartial,
  fTimedOut,
  fTrunc,
  fUnreadable,
  row,
} from '../fixtures/osquery';
import { parseCatalogId } from '../ids';
import type { SoftwareCategory } from '../../../common/types';
import type { OsqueryVariantSpec } from '../variants/osquery';

export type QueryKey = 'linux' | 'windows' | 'macos' | 'dependencies';
export const QUERY_KEYS: readonly QueryKey[] = ['linux', 'windows', 'macos', 'dependencies'];

export const QUERY_STEP_OF: Readonly<Record<QueryKey, OsqueryQueryStep>> = {
  linux: 'query_linux',
  windows: 'query_windows',
  macos: 'query_macos',
  dependencies: 'query_dependencies',
};
export const INGEST_STEP_OF: Readonly<Record<QueryKey, string>> = {
  linux: 'ingest_linux',
  windows: 'ingest_windows',
  macos: 'ingest_macos',
  dependencies: 'ingest_dependencies',
};

export type IngestCounts = Partial<
  Record<'created' | 'unchanged' | 'patched' | 'removed' | 'skipped', number>
>;

/** What one `ingest_*` step must receive and return. */
export interface IngestExpectation {
  /** Expected `ingest_*` output; omitted counters are 0. */
  readonly output: IngestCounts;
  /** Value of the step's `snapshot` input. */
  readonly snapshot: boolean;
  /** Number of candidates the `build_*` step handed to the ingest step. */
  readonly candidates: number;
}

/** An untouched query step: `F-empty` gives a true snapshot, no candidates, and all zeros. */
export const EMPTY_INGEST: IngestExpectation = { output: {}, snapshot: true, candidates: 0 };
/** A query step that threw: no output, so the snapshot is false and no rows exist. */
export const THROWN_INGEST: IngestExpectation = { output: {}, snapshot: false, candidates: 0 };

/** The ingest expectation a fixture documents (`expected.snapshot`, `buildCandidates`, `ingest`). */
export const ingestOfFixture = (
  fixture: OsqueryFixture,
  overrides: Partial<IngestExpectation> = {}
): IngestExpectation => ({
  output: fixture.expected.ingest ?? {},
  snapshot: fixture.expected.snapshot,
  candidates: fixture.expected.buildCandidates ?? fixture.output.rows.length,
  ...overrides,
});

/** One variant run of `discover-osquery`. */
export interface OsqueryRunExpectation {
  readonly label: string;
  /** Fixtures per query step; steps left out get `F-empty`. */
  readonly steps: OsqueryVariantSpec['steps'];
  /** Ingest expectations per query; queries left out use `EMPTY_INGEST`. */
  readonly ingest: Partial<Readonly<Record<QueryKey, IngestExpectation>>>;
  /** Query steps that must end `failed` (thrown fixtures). */
  readonly failedQueries?: readonly QueryKey[];
}

/** A data-driven case: runs, then the inventory the three layers must show. */
export interface DoCaseExpectation {
  readonly id: string;
  readonly title: string;
  readonly requires?: readonly string[];
  readonly runs: readonly OsqueryRunExpectation[];
  readonly instances: readonly ExpectedInstance[];
  readonly catalog: readonly ExpectedCatalogEntry[];
  /** The exact events written since the first run started, on `hostKeys`. */
  readonly events: readonly ExpectedEvent[];
  /** Hosts whose events are listed and on which writes are allowed. */
  readonly hostKeys: readonly string[];
}

// -------------------------------------------------------------------------------------------------
// Builders
// -------------------------------------------------------------------------------------------------

export const versionOfCatalogId = (catalogId: string): string => parseCatalogId(catalogId).version;

const hostOfAgent = (agent: Pick<SyntheticAgent, 'id' | 'name' | 'hostKey'>) => ({
  key: agent.hostKey,
  id: agent.id,
  ...(agent.name ? { name: agent.name } : {}),
});

/** An osquery instance on an agent's host; `host.id` is the agent id (no Fleet agent lookup). */
export const osqueryInstance = (
  agent: SyntheticAgent,
  catalogId: string,
  status: NonNullable<ExpectedInstance['status']>,
  overrides: Partial<ExpectedInstance> = {}
): ExpectedInstance => ({
  hostKey: agent.hostKey,
  catalogId,
  status,
  sources: ['osquery'],
  hostId: agent.id,
  hostName: agent.name ?? null,
  ...overrides,
});

export const firstSeenEvent = (agent: SyntheticAgent, catalogId: string): ExpectedEvent => ({
  type: 'first_seen',
  source: 'osquery',
  software_id: catalogId,
  host: hostOfAgent(agent),
  to_version: versionOfCatalogId(catalogId),
});

export const removedEvent = (agent: SyntheticAgent, catalogId: string): ExpectedEvent => ({
  type: 'removed',
  source: 'osquery',
  software_id: catalogId,
  host: hostOfAgent(agent),
  from_version: versionOfCatalogId(catalogId),
});

export const revivedEvent = (agent: SyntheticAgent, catalogId: string): ExpectedEvent => ({
  type: 'revived',
  source: 'osquery',
  software_id: catalogId,
  host: hostOfAgent(agent),
});

const agentOfRow = ({ agent }: OsqueryRow): SyntheticAgent => {
  const known = Object.values(AGENTS).find(({ id }) => id === agent.id);
  if (!known) throw new Error(`Row agent ${agent.id} is not in AGENTS`);
  return known;
};

const createdRows = (rows: readonly ExpectedRow[]) =>
  rows.flatMap((entry) =>
    entry.outcome === 'created' && entry.hostKey && entry.catalogId
      ? [{ ...entry, hostKey: entry.hostKey, catalogId: entry.catalogId }]
      : []
  );

/** Active osquery instances for the rows a fixture creates. */
export const instancesOfRows = (
  rows: readonly ExpectedRow[],
  status: NonNullable<ExpectedInstance['status']> = 'active'
): ExpectedInstance[] =>
  createdRows(rows).map(({ row: r, catalogId, installPath }) =>
    osqueryInstance(agentOfRow(r), catalogId, status, {
      ...(installPath ? { installPath } : {}),
      versions: [versionOfCatalogId(catalogId)],
    })
  );

export const firstSeenEventsOfRows = (rows: readonly ExpectedRow[]): ExpectedEvent[] =>
  createdRows(rows).map(({ row: r, catalogId }) => firstSeenEvent(agentOfRow(r), catalogId));

export const catalogOfRows = (
  rows: readonly ExpectedRow[],
  category: SoftwareCategory
): ExpectedCatalogEntry[] =>
  createdRows(rows).map(({ catalogId }) => ({
    id: catalogId,
    fields: { category, version: versionOfCatalogId(catalogId) },
  }));

// -------------------------------------------------------------------------------------------------
// R1 (DO-1, DO-2, DO-3, DO-5)
// -------------------------------------------------------------------------------------------------

export const R1_ROWS_BY_QUERY: Readonly<Record<QueryKey, readonly ExpectedRow[]>> = {
  linux: R1_LINUX_ROWS,
  windows: R1_WINDOWS_ROWS,
  macos: R1_MACOS_ROWS,
  dependencies: R1_DEPENDENCY_ROWS,
};

export const R1_ALL_ROWS: readonly ExpectedRow[] = QUERY_KEYS.flatMap(
  (key) => R1_ROWS_BY_QUERY[key]
);

/** Hosts that report in `R1`. */
export const R1_HOST_KEYS: readonly string[] = [
  ...new Set(R1_ALL_ROWS.flatMap(({ hostKey }) => (hostKey ? [hostKey] : []))),
];

export const R1_CATALOG: readonly ExpectedCatalogEntry[] = [
  ...catalogOfRows(R1_LINUX_ROWS, 'os_package'),
  ...catalogOfRows(R1_WINDOWS_ROWS, 'application'),
  ...catalogOfRows(R1_MACOS_ROWS, 'application'),
  ...catalogOfRows(R1_DEPENDENCY_ROWS, 'dependency'),
];

/** `catalog` ids per category that DO-1 creates (6, 4 and 3 entries). */
export const R1_CATEGORY_COUNTS: Readonly<
  Record<'os_package' | 'application' | 'dependency', number>
> = {
  os_package: createdRows(R1_LINUX_ROWS).length,
  application: createdRows(R1_WINDOWS_ROWS).length + createdRows(R1_MACOS_ROWS).length,
  dependency: createdRows(R1_DEPENDENCY_ROWS).length,
};

export const R1_INSTANCES: readonly ExpectedInstance[] = instancesOfRows(R1_ALL_ROWS);

export const R1_EVENTS: readonly ExpectedEvent[] = firstSeenEventsOfRows(R1_ALL_ROWS);

/** Every `R1` step runs with its fixture and documented ingest outcome. */
export const R1_RUN: OsqueryRunExpectation = {
  label: 'R1 baseline',
  steps: R1,
  ingest: {
    linux: ingestOfFixture(R1.query_linux),
    windows: ingestOfFixture(R1.query_windows),
    macos: ingestOfFixture(R1.query_macos),
    dependencies: ingestOfFixture(R1.query_dependencies),
  },
};

/** DO-2: instances for `synth-lin-02` that the dropped rows would have created must not exist. */
export const DO2_LIN02_ALLOWED_SOFTWARE_IDS: readonly string[] = [
  'apache:log4j:2.12.1',
  'synth-lin02-pkg:synth-lin02-pkg:1.2.3',
];
/** DO-2: `synth-win-01` has exactly Chrome and 7-Zip; the `(x64)` row never becomes an instance. */
export const DO2_WIN01_INSTANCE_COUNT = createdRows(R1_WINDOWS_ROWS).length;

/** DO-3: the duplicate `openssl` row yields one instance. */
export const DO3_LINUX_CANDIDATES = 7;
export const DO3_LINUX_CREATED = 6;

/** DO-5: Windows and macOS rows become `application` entries with their install paths. */
export const DO5_APPLICATION_CATALOG: readonly ExpectedCatalogEntry[] = [
  ...catalogOfRows(R1_WINDOWS_ROWS, 'application'),
  ...catalogOfRows(R1_MACOS_ROWS, 'application'),
];
export const DO5_INSTALL_PATHS: ReadonlyArray<{
  readonly hostKey: string;
  readonly catalogId: string;
  readonly installPath: string;
}> = [...R1_WINDOWS_ROWS, ...R1_MACOS_ROWS].flatMap(({ hostKey, catalogId, installPath }) =>
  hostKey && catalogId && installPath ? [{ hostKey, catalogId, installPath }] : []
);

/** DO-4: an agent id unknown to Fleet, without a name, keys the host on the id itself. */
export const DO4_UNKNOWN_AGENT_RUN: OsqueryRunExpectation = {
  label: 'DO-4 unknown agent',
  steps: { query_linux: F_UNKNOWN_AGENT },
  ingest: { linux: ingestOfFixture(F_UNKNOWN_AGENT) },
};
export const DO4_UNKNOWN_INSTANCE: ExpectedInstance = osqueryInstance(
  AGENTS.unknown,
  'synth-orphan:synth-orphan:0.1.0',
  'active',
  { versions: ['0.1.0'] }
);
/** DO-4: `R1` host identity without a Fleet agent index. */
export const DO4_R1_HOST_IDENTITY: readonly ExpectedInstance[] = [
  osqueryInstance(AGENTS.lin01, 'sudo_project:sudo:1.9.9', 'active'),
  osqueryInstance(AGENTS.lin03, 'haxx:curl:7.88.1', 'active'),
  osqueryInstance(AGENTS.win01, 'google:chrome:131.0.6778.86', 'active', {
    installPath: 'C:\\Program Files\\Google\\Chrome\\Application',
  }),
];

// -------------------------------------------------------------------------------------------------
// Linux state after DO-6 and DO-7
// -------------------------------------------------------------------------------------------------

const LIN01_R2_ROWS: readonly OsqueryRow[] = R2_LINUX.output.rows;
const rowsWithout = (name: string): OsqueryRow[] =>
  LIN01_R2_ROWS.filter(({ columns }) => columns.name !== name);

export const OPENSSL_OLD = 'openssl:openssl:3.0.7';
export const OPENSSL_NEW = 'openssl:openssl:3.0.14';
export const SUDO = 'sudo_project:sudo:1.9.9';
export const BASH = 'gnu:bash:5.1';
export const NGINX = 'f5:nginx:1.18.0';
export const SYNTH_TOOL = 'synth-tool:synth-tool:2.0.0';
export const CURL = 'haxx:curl:7.88.1';
export const LOG4J_LIN01 = 'apache:log4j:2.14.1';
export const LOG4J_LIN01_PATH = '/opt/app/lib/log4j-core-2.14.1.jar';
export const LODASH = 'lodash:lodash:4.17.20';
export const LODASH_PATH = '/opt/app/node_modules/lodash';

/** `synth-lin-01` and `synth-agent-lin03` Linux packages after DO-7. */
export const LINUX_STATE_AFTER_DO7: readonly ExpectedInstance[] = [
  osqueryInstance(AGENTS.lin01, OPENSSL_NEW, 'active', { versions: ['3.0.7', '3.0.14'] }),
  osqueryInstance(AGENTS.lin01, SUDO, 'active'),
  osqueryInstance(AGENTS.lin01, BASH, 'active'),
  osqueryInstance(AGENTS.lin01, NGINX, 'active'),
  osqueryInstance(AGENTS.lin01, SYNTH_TOOL, 'removed'),
  osqueryInstance(AGENTS.lin03, CURL, 'active'),
];

// -------------------------------------------------------------------------------------------------
// Data-driven cases
// -------------------------------------------------------------------------------------------------

export const DO1: DoCaseExpectation = {
  id: 'DO-1',
  title: 'Baseline ingest (R1): 13 instances, 13 first_seen events, 13 catalog entries',
  runs: [R1_RUN],
  instances: R1_INSTANCES,
  catalog: R1_CATALOG,
  events: R1_EVENTS,
  hostKeys: R1_HOST_KEYS,
};

const DO6_RUN: OsqueryRunExpectation = {
  label: 'R2 linux, others empty',
  steps: { query_linux: R2_LINUX },
  ingest: { linux: ingestOfFixture(R2_LINUX) },
};

export const DO6: DoCaseExpectation = {
  id: 'DO-6',
  title: 'Patch, history, and events: openssl 3.0.7 to 3.0.14, synth-tool removed',
  requires: ['DO-1'],
  runs: [DO6_RUN],
  instances: [
    osqueryInstance(AGENTS.lin01, OPENSSL_NEW, 'patched', {
      previousSoftwareId: OPENSSL_OLD,
      versions: ['3.0.7', '3.0.14'],
    }),
    osqueryInstance(AGENTS.lin01, SUDO, 'active'),
    osqueryInstance(AGENTS.lin01, BASH, 'active'),
    osqueryInstance(AGENTS.lin01, NGINX, 'active'),
    osqueryInstance(AGENTS.lin01, SYNTH_TOOL, 'removed', { versions: ['2.0.0'] }),
    osqueryInstance(AGENTS.lin03, CURL, 'active'),
  ],
  catalog: [{ id: OPENSSL_NEW, fields: { category: 'os_package', version: '3.0.14' } }],
  events: [
    {
      type: 'version_changed',
      source: 'osquery',
      software_id: OPENSSL_NEW,
      previous_software_id: OPENSSL_OLD,
      from_version: '3.0.7',
      to_version: '3.0.14',
      host: hostOfAgent(AGENTS.lin01),
      // Neither catalog entry was checked for CVEs, so no posture fields are recorded.
      cve_count_before: undefined,
      cve_count_after: undefined,
      max_cvss_before: undefined,
      max_cvss_after: undefined,
      known_exploited_before: undefined,
      known_exploited_after: undefined,
    },
    removedEvent(AGENTS.lin01, SYNTH_TOOL),
  ],
  hostKeys: R1_HOST_KEYS,
};

export const DO7: DoCaseExpectation = {
  id: 'DO-7',
  title: 'Idempotent re-run of the DO-6 fixtures: no new events',
  requires: ['DO-6'],
  runs: [
    {
      ...DO6_RUN,
      label: 'R2 linux again',
      ingest: { linux: ingestOfFixture(R2_LINUX, { output: { unchanged: 4 } }) },
    },
  ],
  instances: LINUX_STATE_AFTER_DO7,
  catalog: [],
  events: [],
  hostKeys: R1_HOST_KEYS,
};

export const DO8_FIXTURE: OsqueryFixture = fTrunc(rowsWithout('nginx'));
export const DO8: DoCaseExpectation = {
  id: 'DO-8',
  title: 'Truncated result: rows are upserted, nothing is removed',
  requires: ['DO-7'],
  runs: [
    {
      label: 'F-trunc without nginx',
      steps: { query_linux: DO8_FIXTURE },
      ingest: { linux: { output: { unchanged: 3 }, snapshot: false, candidates: 3 } },
    },
  ],
  instances: LINUX_STATE_AFTER_DO7,
  catalog: [],
  events: [],
  hostKeys: R1_HOST_KEYS,
};

export const DO9: DoCaseExpectation = {
  id: 'DO-9',
  title: 'Failed query: no candidates and no removal',
  requires: ['DO-7'],
  runs: [
    {
      label: 'F-failed',
      steps: { query_linux: F_FAILED },
      ingest: { linux: ingestOfFixture(F_FAILED) },
    },
  ],
  instances: LINUX_STATE_AFTER_DO7,
  catalog: [],
  events: [],
  hostKeys: R1_HOST_KEYS,
};

export const DO10: DoCaseExpectation = {
  id: 'DO-10',
  title: 'Thrown query step: step failed, run completed, ingest all zeros',
  requires: ['DO-7'],
  runs: [
    {
      label: 'F-throw',
      steps: { query_linux: { kind: 'throw' } },
      ingest: { linux: THROWN_INGEST },
      failedQueries: ['linux'],
    },
  ],
  instances: LINUX_STATE_AFTER_DO7,
  catalog: [],
  events: [],
  hostKeys: R1_HOST_KEYS,
};

const incompleteRun = (label: string, fixture: OsqueryFixture): OsqueryRunExpectation => ({
  label,
  steps: { query_linux: fixture },
  ingest: { linux: { output: { unchanged: 3 }, snapshot: false, candidates: 3 } },
});

export const DO11: DoCaseExpectation = {
  id: 'DO-11',
  title: 'Partial, timed out, and unreadable results: rows upserted, bash never removed',
  requires: ['DO-7'],
  runs: [
    incompleteRun('F-partial', fPartial(rowsWithout('bash'))),
    incompleteRun('F-timedout', fTimedOut(rowsWithout('bash'))),
    incompleteRun('F-unreadable', fUnreadable(rowsWithout('bash'))),
  ],
  instances: LINUX_STATE_AFTER_DO7,
  catalog: [],
  events: [],
  hostKeys: R1_HOST_KEYS,
};

/** Instances every dependency case expects besides its own: OS packages, lin02 and mac01. */
const OTHER_DEPENDENCY_HOSTS: readonly ExpectedInstance[] = [
  osqueryInstance(AGENTS.lin02, 'apache:log4j:2.12.1', 'active', {
    installPath: '/srv/legacy/lib/log4j-core-2.12.1.jar',
  }),
  osqueryInstance(AGENTS.mac01, 'requests:requests:2.31.0', 'active', {
    installPath: '/usr/local/lib/python3.12/site-packages',
  }),
];

export const DO12: DoCaseExpectation = {
  id: 'DO-12',
  title: 'Category-scoped removal: log4j removed, OS packages untouched',
  requires: ['DO-7'],
  runs: [
    {
      label: 'dependencies lodash only',
      steps: { query_dependencies: DEPS_LIN01_LODASH_ONLY },
      ingest: { dependencies: ingestOfFixture(DEPS_LIN01_LODASH_ONLY) },
    },
  ],
  instances: [
    osqueryInstance(AGENTS.lin01, LODASH, 'active', { installPath: LODASH_PATH }),
    osqueryInstance(AGENTS.lin01, LOG4J_LIN01, 'removed', { installPath: LOG4J_LIN01_PATH }),
    ...LINUX_STATE_AFTER_DO7.filter(({ status }) => status === 'active'),
    ...OTHER_DEPENDENCY_HOSTS,
  ],
  catalog: [{ id: LODASH, fields: { category: 'dependency', version: '4.17.20' } }],
  events: [firstSeenEvent(AGENTS.lin01, LODASH), removedEvent(AGENTS.lin01, LOG4J_LIN01)],
  hostKeys: R1_HOST_KEYS,
};

export const DO13_PACKAGE = 'synth-lin02-pkg:synth-lin02-pkg:1.2.3';
export const DO13: DoCaseExpectation = {
  id: 'DO-13',
  title: 'Absent host untouched: lin02 reports, lin01 and lin03 keep their instances',
  requires: ['DO-7'],
  runs: [
    {
      label: 'Linux lin02 only',
      steps: { query_linux: LINUX_LIN02_ONLY },
      ingest: { linux: ingestOfFixture(LINUX_LIN02_ONLY) },
    },
  ],
  instances: [osqueryInstance(AGENTS.lin02, DO13_PACKAGE, 'active'), ...LINUX_STATE_AFTER_DO7],
  catalog: [{ id: DO13_PACKAGE, fields: { category: 'os_package', version: '1.2.3' } }],
  events: [firstSeenEvent(AGENTS.lin02, DO13_PACKAGE)],
  hostKeys: [...R1_HOST_KEYS, AGENTS.lin02.hostKey],
};

export const DO14: DoCaseExpectation = {
  id: 'DO-14',
  title: 'Revive: log4j returns to active with one revived event',
  requires: ['DO-12'],
  runs: [
    {
      label: 'dependencies lodash and log4j',
      steps: { query_dependencies: DEPS_LIN01_LODASH_AND_LOG4J },
      ingest: { dependencies: ingestOfFixture(DEPS_LIN01_LODASH_AND_LOG4J) },
    },
  ],
  instances: [
    osqueryInstance(AGENTS.lin01, LODASH, 'active', { installPath: LODASH_PATH }),
    osqueryInstance(AGENTS.lin01, LOG4J_LIN01, 'active', { installPath: LOG4J_LIN01_PATH }),
  ],
  catalog: [],
  events: [revivedEvent(AGENTS.lin01, LOG4J_LIN01)],
  hostKeys: R1_HOST_KEYS,
};

export const DATA_DRIVEN_CASES: readonly DoCaseExpectation[] = [
  DO1,
  DO6,
  DO7,
  DO8,
  DO9,
  DO10,
  DO11,
  DO12,
  DO13,
  DO14,
];

// -------------------------------------------------------------------------------------------------
// DO-15: first writer sets the catalog category
// -------------------------------------------------------------------------------------------------

export const DO15_HOST = AGENTS.lin01;
export const DO15_SERVICE = 'synth-svc';
export const DO15_VERSION = '1.0';
export const DO15_CATALOG_ID = `${DO15_SERVICE}:${DO15_SERVICE}:${DO15_VERSION}`;

/** The Linux rows of the state after DO-7 (`openssl` 3.0.14, `sudo`, `bash`, `nginx`). */
export const DO15_BASE_ROWS: readonly OsqueryRow[] = LIN01_R2_ROWS;
/** The same rows plus `synth-svc` 1.0 reported by Osquery. */
export const DO15_ROWS_WITH_SERVICE: readonly OsqueryRow[] = [
  ...LIN01_R2_ROWS,
  row(AGENTS.lin01, DO15_SERVICE, DO15_VERSION),
];

export const DO15_RUN_WITH_SERVICE: OsqueryRunExpectation = {
  label: 'Linux with synth-svc',
  steps: {},
  ingest: { linux: { output: { unchanged: 5 }, snapshot: true, candidates: 5 } },
};
export const DO15_RUN_WITHOUT_SERVICE: OsqueryRunExpectation = {
  label: 'Linux without synth-svc',
  steps: {},
  ingest: { linux: { output: { unchanged: 4, removed: 0 }, snapshot: true, candidates: 4 } },
};

// -------------------------------------------------------------------------------------------------
// DO-16, DO-17, DO-18
// -------------------------------------------------------------------------------------------------

export const BULK_HOST_KEY = AGENTS.bulk.hostKey;
export const BULK_LIMIT = 5000;
export const DO16_MAX_STEP_MS = 60_000;
/** Spot-checked bulk packages: first and last of the generated `synth-pkg-<i>` rows. */
export const DO16_SPOT_CHECKS: ReadonlyArray<{
  readonly index: number;
  readonly catalogId: string;
}> = [1, BULK_LIMIT].map((index) => ({
  index,
  catalogId: `synth-pkg-${index}:synth-pkg-${index}:1.0.${index}`,
}));

/** DO-18: the stored YAML on a stack without Osquery agents. */
export const DO18_FAILED_STEPS: readonly OsqueryQueryStep[] = [
  'query_linux',
  'query_windows',
  'query_macos',
  'query_dependencies',
];
export const DO18_INGEST: Readonly<Record<QueryKey, IngestExpectation>> = {
  linux: THROWN_INGEST,
  windows: THROWN_INGEST,
  macos: THROWN_INGEST,
  dependencies: THROWN_INGEST,
};
