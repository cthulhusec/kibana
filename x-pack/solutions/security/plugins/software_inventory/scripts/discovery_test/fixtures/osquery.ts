/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Osquery fixtures for the `discover-osquery` variants. Each fixture is a complete
 * `osquery.runQuery` output (the real contract type), so a `data.set` step that emits it gives the
 * production `build_*` and `ingest_*` steps exactly what a real query would. See "Osquery fixtures"
 * and "Identity reference" in docs/discovery_test_plan.md.
 */

import type { RunQueryOutput } from '@kbn/osquery-plugin/common/workflows/step_types/run_query/run_query_common';
import type { IngestCandidatesOutput } from '../../../common/types';

export type { RunQueryOutput };
export type OsqueryRow = RunQueryOutput['rows'][number];

export const OSQUERY_QUERY_STEPS = [
  'query_linux',
  'query_windows',
  'query_macos',
  'query_dependencies',
] as const;
export type OsqueryQueryStep = (typeof OSQUERY_QUERY_STEPS)[number];

/** Fixed row timestamp; the `build_*` steps never read it. */
export const FIXTURE_ROW_TIMESTAMP = '2026-11-18T00:00:00.000Z';

export interface SyntheticAgent {
  readonly id: string;
  /** Omitted when the real result document would have no `agent.name`. */
  readonly name?: string;
  /** Canonical host key the ingest step derives: lower-cased name, else the agent id. */
  readonly hostKey: string;
}

/** Osquery agents of the Identity reference. */
export const AGENTS = {
  lin01: { id: 'synth-agent-lin01', name: 'synth-lin-01', hostKey: 'synth-lin-01' },
  lin02: { id: 'synth-agent-lin02', name: 'synth-lin-02', hostKey: 'synth-lin-02' },
  lin03: { id: 'synth-agent-lin03', hostKey: 'synth-agent-lin03' },
  linBlankId: { id: '', name: 'synth-lin-x', hostKey: '' },
  win01: { id: 'synth-agent-win01', name: 'SYNTH-WIN-01', hostKey: 'synth-win-01' },
  mac01: { id: 'synth-agent-mac01', name: 'synth-mac-01', hostKey: 'synth-mac-01' },
  bulk: { id: 'synth-agent-bulk', name: 'synth-bulk-01', hostKey: 'synth-bulk-01' },
  unknown: { id: 'synth-agent-unknown-99', hostKey: 'synth-agent-unknown-99' },
} as const satisfies Record<string, SyntheticAgent>;

/** Builds one result row the way `build_rows.ts` does: every column value is a string. */
export const row = (
  agent: SyntheticAgent,
  name: string,
  version: string,
  installPath = ''
): OsqueryRow => ({
  agent: agent.name === undefined ? { id: agent.id } : { id: agent.id, name: agent.name },
  '@timestamp': FIXTURE_ROW_TIMESTAMP,
  columns: { name, version, install_path: installPath },
  ecs: {},
});

const agentsSummary = (total: number, responded = total, failed = 0) => ({
  total,
  responded,
  pending: total - responded - failed,
  failed,
});

/** A complete `status: success` result for the given rows. */
export const successOutput = (rows: readonly OsqueryRow[], agentCount = 1): RunQueryOutput => ({
  status: 'success',
  agents: agentsSummary(agentCount),
  rows: [...rows],
  row_count: rows.length,
  truncated: false,
});

/** What the plan expects one fixture to do to the production YAML and the ingest step. */
export interface FixtureExpectation {
  /** Value the `ingest_*` step's `snapshot` input must evaluate to. */
  readonly snapshot: boolean;
  /** Candidates the `build_*` step emits after the YAML drops blank rows. */
  readonly buildCandidates?: number;
  /** Expected `ingest_*` output; omitted fields are 0. */
  readonly ingest?: Partial<IngestCandidatesOutput>;
  /** Catalog ids the rows normalize to (created ones only). */
  readonly catalogIds?: readonly string[];
}

export interface OsqueryFixture {
  readonly id: string;
  readonly description: string;
  readonly output: RunQueryOutput;
  readonly expected: FixtureExpectation;
}

/** One documented row of `R1`, with the outcome the plan expects. */
export interface ExpectedRow {
  readonly row: OsqueryRow;
  /** Host key, absent when the YAML drops the row. */
  readonly hostKey?: string;
  readonly catalogId?: string;
  readonly installPath?: string;
  readonly outcome: 'created' | 'deduped' | 'dropped by YAML' | 'skipped by ingest';
}

// ---------------------------------------------------------------------------------------------
// R1: baseline, all four queries `status: success`, `truncated: false`.
// ---------------------------------------------------------------------------------------------

export const R1_LINUX_ROWS: readonly ExpectedRow[] = [
  {
    row: row(AGENTS.lin01, 'openssl', '3.0.7-1ubuntu1'),
    hostKey: 'synth-lin-01',
    catalogId: 'openssl:openssl:3.0.7',
    outcome: 'created',
  },
  {
    row: row(AGENTS.lin01, 'openssl', '3.0.7-1ubuntu1'),
    hostKey: 'synth-lin-01',
    catalogId: 'openssl:openssl:3.0.7',
    outcome: 'deduped',
  },
  {
    row: row(AGENTS.lin01, 'sudo', '1.9.9-1ubuntu2.4'),
    hostKey: 'synth-lin-01',
    catalogId: 'sudo_project:sudo:1.9.9',
    outcome: 'created',
  },
  {
    row: row(AGENTS.lin01, 'bash', '5.1-6ubuntu1.1'),
    hostKey: 'synth-lin-01',
    catalogId: 'gnu:bash:5.1',
    outcome: 'created',
  },
  {
    row: row(AGENTS.lin01, 'nginx', '1.18.0-6ubuntu14.4'),
    hostKey: 'synth-lin-01',
    catalogId: 'f5:nginx:1.18.0',
    outcome: 'created',
  },
  {
    row: row(AGENTS.lin01, 'synth-tool', '2.0.0'),
    hostKey: 'synth-lin-01',
    catalogId: 'synth-tool:synth-tool:2.0.0',
    outcome: 'created',
  },
  { row: row(AGENTS.lin02, '', '1.0'), outcome: 'dropped by YAML' },
  { row: row(AGENTS.lin02, '   ', '1.0'), outcome: 'dropped by YAML' },
  { row: row(AGENTS.linBlankId, 'bash', '5.1'), outcome: 'dropped by YAML' },
  {
    row: row(AGENTS.lin03, 'curl', '7.88.1-10+deb12u5'),
    hostKey: 'synth-agent-lin03',
    catalogId: 'haxx:curl:7.88.1',
    outcome: 'created',
  },
];

export const R1_WINDOWS_ROWS: readonly ExpectedRow[] = [
  {
    row: row(
      AGENTS.win01,
      'Google Chrome',
      '131.0.6778.86',
      'C:\\Program Files\\Google\\Chrome\\Application'
    ),
    hostKey: 'synth-win-01',
    catalogId: 'google:chrome:131.0.6778.86',
    installPath: 'C:\\Program Files\\Google\\Chrome\\Application',
    outcome: 'created',
  },
  {
    row: row(AGENTS.win01, '7-Zip 23.01 (x64)', '23.01', 'C:\\Program Files\\7-Zip'),
    hostKey: 'synth-win-01',
    catalogId: '7-zip:7-zip:23.01',
    installPath: 'C:\\Program Files\\7-Zip',
    outcome: 'created',
  },
  { row: row(AGENTS.win01, '(x64)', '1.0', 'C:\\x'), outcome: 'skipped by ingest' },
];

export const R1_MACOS_ROWS: readonly ExpectedRow[] = [
  {
    row: row(AGENTS.mac01, 'Slack', '4.41.105', '/Applications/Slack.app'),
    hostKey: 'synth-mac-01',
    catalogId: 'slack:slack:4.41.105',
    installPath: '/Applications/Slack.app',
    outcome: 'created',
  },
  {
    row: row(AGENTS.mac01, 'Code', '1.95.3', '/Applications/Visual Studio Code.app'),
    hostKey: 'synth-mac-01',
    catalogId: 'microsoft:visual_studio_code:1.95.3',
    installPath: '/Applications/Visual Studio Code.app',
    outcome: 'created',
  },
];

export const R1_DEPENDENCY_ROWS: readonly ExpectedRow[] = [
  {
    row: row(AGENTS.lin01, 'log4j-core', '2.14.1', '/opt/app/lib/log4j-core-2.14.1.jar'),
    hostKey: 'synth-lin-01',
    catalogId: 'apache:log4j:2.14.1',
    installPath: '/opt/app/lib/log4j-core-2.14.1.jar',
    outcome: 'created',
  },
  {
    row: row(AGENTS.lin02, 'log4j-core', '2.12.1', '/srv/legacy/lib/log4j-core-2.12.1.jar'),
    hostKey: 'synth-lin-02',
    catalogId: 'apache:log4j:2.12.1',
    installPath: '/srv/legacy/lib/log4j-core-2.12.1.jar',
    outcome: 'created',
  },
  {
    row: row(AGENTS.mac01, 'requests', '2.31.0', '/usr/local/lib/python3.12/site-packages'),
    hostKey: 'synth-mac-01',
    catalogId: 'requests:requests:2.31.0',
    installPath: '/usr/local/lib/python3.12/site-packages',
    outcome: 'created',
  },
];

const rowsOf = (rows: readonly ExpectedRow[]): OsqueryRow[] => rows.map(({ row: r }) => r);
const createdCatalogIds = (rows: readonly ExpectedRow[]): string[] =>
  rows.flatMap(({ outcome, catalogId }) =>
    outcome === 'created' && catalogId !== undefined ? [catalogId] : []
  );

export const R1: Readonly<Record<OsqueryQueryStep, OsqueryFixture>> = {
  query_linux: {
    id: 'R1-linux',
    description: 'Baseline Linux packages: duplicates, blank names, blank agent id, unnamed agent',
    output: successOutput(rowsOf(R1_LINUX_ROWS), 4),
    expected: {
      snapshot: true,
      buildCandidates: 7,
      ingest: { created: 6, unchanged: 0, patched: 0, removed: 0, skipped: 0 },
      catalogIds: createdCatalogIds(R1_LINUX_ROWS),
    },
  },
  query_windows: {
    id: 'R1-windows',
    description: 'Baseline Windows programs, one row the ingest step skips',
    output: successOutput(rowsOf(R1_WINDOWS_ROWS)),
    expected: {
      snapshot: true,
      buildCandidates: 3,
      ingest: { created: 2, skipped: 1 },
      catalogIds: createdCatalogIds(R1_WINDOWS_ROWS),
    },
  },
  query_macos: {
    id: 'R1-macos',
    description: 'Baseline macOS apps',
    output: successOutput(rowsOf(R1_MACOS_ROWS)),
    expected: {
      snapshot: true,
      buildCandidates: 2,
      ingest: { created: 2 },
      catalogIds: createdCatalogIds(R1_MACOS_ROWS),
    },
  },
  query_dependencies: {
    id: 'R1-dependencies',
    description: 'Baseline language dependencies on three hosts',
    output: successOutput(rowsOf(R1_DEPENDENCY_ROWS), 3),
    expected: {
      snapshot: true,
      buildCandidates: 3,
      ingest: { created: 3 },
      catalogIds: createdCatalogIds(R1_DEPENDENCY_ROWS),
    },
  },
};

/** `R1` creates 13 instances, 13 `first_seen` events, and 13 catalog entries. */
export const R1_EXPECTED_TOTALS = {
  instances: 13,
  firstSeenEvents: 13,
  catalogEntries: 13,
} as const;

// ---------------------------------------------------------------------------------------------
// R2: DO-6 patch and removal on synth-lin-01.
// ---------------------------------------------------------------------------------------------

export const R2_LINUX: OsqueryFixture = {
  id: 'R2-linux',
  description: 'lin01 patches openssl to 3.0.14 and drops synth-tool; lin02 and lin03 absent',
  output: successOutput([
    row(AGENTS.lin01, 'openssl', '3.0.14-0ubuntu3.4'),
    row(AGENTS.lin01, 'sudo', '1.9.9-1ubuntu2.4'),
    row(AGENTS.lin01, 'bash', '5.1-6ubuntu1.1'),
    row(AGENTS.lin01, 'nginx', '1.18.0-6ubuntu14.4'),
  ]),
  expected: {
    snapshot: true,
    buildCandidates: 4,
    ingest: { unchanged: 3, patched: 1, removed: 1 },
    catalogIds: ['openssl:openssl:3.0.14'],
  },
};

// ---------------------------------------------------------------------------------------------
// Failure injections. Builders take the rows "as given" by the case; constants use the rows the
// test matrix names.
// ---------------------------------------------------------------------------------------------

/** `F-empty`: complete, no rows. The snapshot is true but no host reported, so nothing is removed. */
export const F_EMPTY: OsqueryFixture = {
  id: 'F-empty',
  description: 'status success, truncated false, rows []',
  output: successOutput([], 0),
  expected: { snapshot: true, buildCandidates: 0, ingest: {} },
};

/** `F-failed`: the action was not confirmed; every agent is still pending. */
export const F_FAILED: OsqueryFixture = {
  id: 'F-failed',
  description: 'status failed, error_code DISPATCH_UNCONFIRMED, rows []',
  output: {
    status: 'failed',
    agents: { total: 4, responded: 0, pending: 4, failed: 0 },
    rows: [],
    row_count: 0,
    truncated: false,
    error_code: 'DISPATCH_UNCONFIRMED',
  },
  expected: { snapshot: false, buildCandidates: 0, ingest: {} },
};

export const fTrunc = (rows: readonly OsqueryRow[]): OsqueryFixture => ({
  id: 'F-trunc',
  description: 'status success, truncated true, row_count 9000',
  output: { ...successOutput(rows), row_count: 9000, truncated: true },
  expected: { snapshot: false, ingest: { removed: 0 } },
});

export const fPartial = (rows: readonly OsqueryRow[]): OsqueryFixture => ({
  id: 'F-partial',
  description: 'status partial, one agent failed',
  output: {
    status: 'partial',
    agents: agentsSummary(2, 1, 1),
    rows: [...rows],
    row_count: rows.length,
    truncated: false,
  },
  expected: { snapshot: false, ingest: { removed: 0 } },
});

export const fTimedOut = (rows: readonly OsqueryRow[]): OsqueryFixture => ({
  id: 'F-timedout',
  description: 'status timed_out, rows received before the deadline',
  output: {
    status: 'timed_out',
    agents: agentsSummary(2, 1),
    rows: [...rows],
    row_count: rows.length,
    truncated: false,
  },
  expected: { snapshot: false, ingest: { removed: 0 } },
});

export const fUnreadable = (rows: readonly OsqueryRow[]): OsqueryFixture => ({
  id: 'F-unreadable',
  description: 'status success, error_code RESULTS_UNREADABLE, truncated false',
  output: { ...successOutput(rows), error_code: 'RESULTS_UNREADABLE' },
  expected: { snapshot: false, ingest: { removed: 0 } },
});

/** lin01's `R1` rows without one package, for DO-8 (`nginx`) and DO-11 (`bash`). */
export const lin01R1RowsWithout = (name: string): OsqueryRow[] =>
  R1_LINUX_ROWS.filter(
    ({ row: r, outcome }) =>
      outcome !== 'deduped' && r.agent.id === AGENTS.lin01.id && r.columns.name !== name
  ).map(({ row: r }) => r);

/** DO-8: truncated Linux result whose rows miss `nginx`. */
export const F_TRUNC_LINUX_WITHOUT_NGINX = fTrunc(lin01R1RowsWithout('nginx'));
/** DO-11: incomplete Linux results whose rows miss `bash`. */
export const F_PARTIAL_LINUX_WITHOUT_BASH = fPartial(lin01R1RowsWithout('bash'));
export const F_TIMEDOUT_LINUX_WITHOUT_BASH = fTimedOut(lin01R1RowsWithout('bash'));
export const F_UNREADABLE_LINUX_WITHOUT_BASH = fUnreadable(lin01R1RowsWithout('bash'));

/** Edge rows in one fixture: missing `agent.name` and an agent id no Fleet index knows. */
export const F_UNKNOWN_AGENT: OsqueryFixture = {
  id: 'F-unknown-agent',
  description: 'Agent id unknown to Fleet and no agent.name: the host key falls back to the id',
  output: successOutput([row(AGENTS.unknown, 'synth-orphan', '0.1.0')]),
  expected: {
    snapshot: true,
    buildCandidates: 1,
    ingest: { created: 1 },
    catalogIds: ['synth-orphan:synth-orphan:0.1.0'],
  },
};

/** DO-12: lin01 reports `lodash` only, so `log4j-core` is removed (dependencies category only). */
export const DEPS_LIN01_LODASH_ONLY: OsqueryFixture = {
  id: 'DEPS-lodash-only',
  description: 'lin01 dependencies: lodash 4.17.20 only',
  output: successOutput([row(AGENTS.lin01, 'lodash', '4.17.20', '/opt/app/node_modules/lodash')]),
  expected: {
    snapshot: true,
    buildCandidates: 1,
    ingest: { created: 1, removed: 1 },
    catalogIds: ['lodash:lodash:4.17.20'],
  },
};

/** DO-14: lin01 reports `lodash` and `log4j-core` again, reviving `log4j`. */
export const DEPS_LIN01_LODASH_AND_LOG4J: OsqueryFixture = {
  id: 'DEPS-lodash-log4j',
  description: 'lin01 dependencies: lodash 4.17.20 and log4j-core 2.14.1',
  output: successOutput([
    row(AGENTS.lin01, 'lodash', '4.17.20', '/opt/app/node_modules/lodash'),
    row(AGENTS.lin01, 'log4j-core', '2.14.1', '/opt/app/lib/log4j-core-2.14.1.jar'),
  ]),
  expected: { snapshot: true, buildCandidates: 2, ingest: { unchanged: 2 } },
};

/** DO-13: Linux result from lin02 only; lin01 and lin03 must stay untouched. */
export const LINUX_LIN02_ONLY: OsqueryFixture = {
  id: 'LINUX-lin02-only',
  description: 'Linux packages from synth-lin-02 only',
  output: successOutput([row(AGENTS.lin02, 'synth-lin02-pkg', '1.2.3')]),
  expected: {
    snapshot: true,
    buildCandidates: 1,
    ingest: { created: 1 },
    catalogIds: ['synth-lin02-pkg:synth-lin02-pkg:1.2.3'],
  },
};

// ---------------------------------------------------------------------------------------------
// Bulk rows. The variant inserts a helper `data.set` step that renders this liquid template into a
// JSON string, and the replaced query step parses it into `rows` with `json_parse`.
// ---------------------------------------------------------------------------------------------

export interface BulkRowsSpec {
  readonly count: number;
  readonly agent: SyntheticAgent;
}

/** Liquid that renders `count` rows `synth-pkg-<i>` / `1.0.<i>` as a JSON array. */
export const bulkRowsTemplate = ({ count, agent }: BulkRowsSpec): string => {
  const agentJson = JSON.stringify(
    agent.name === undefined ? { id: agent.id } : { id: agent.id, name: agent.name }
  );
  return (
    `[{%- for i in (1..${count}) -%}{%- if i > 1 -%},{%- endif -%}` +
    `{"agent":${agentJson},"@timestamp":"${FIXTURE_ROW_TIMESTAMP}",` +
    `"columns":{"name":"synth-pkg-{{ i }}","version":"1.0.{{ i }}","install_path":""},"ecs":{}}` +
    `{%- endfor -%}]`
  );
};

export interface BulkOsqueryFixture {
  readonly id: string;
  readonly description: string;
  /** The output without `rows`; the variant adds `rows` from the generator. */
  readonly output: Omit<RunQueryOutput, 'rows'>;
  readonly rows: BulkRowsSpec;
  readonly expected: FixtureExpectation & { readonly ingestFails?: boolean };
}

export const F_BULK_5000: BulkOsqueryFixture = {
  id: 'F-bulk-5000',
  description: '5000 generated rows for synth-agent-bulk, truncated true',
  output: { status: 'success', agents: agentsSummary(1), row_count: 9000, truncated: true },
  rows: { count: 5000, agent: AGENTS.bulk },
  expected: { snapshot: false, buildCandidates: 5000, ingest: { created: 5000, removed: 0 } },
};

export const F_BULK_5001: BulkOsqueryFixture = {
  id: 'F-bulk-5001',
  description: '5001 generated rows, truncated false: ingest fails its 5000-candidate validation',
  output: { status: 'success', agents: agentsSummary(1), row_count: 5001, truncated: false },
  rows: { count: 5001, agent: AGENTS.bulk },
  expected: { snapshot: true, buildCandidates: 5001, ingestFails: true },
};

/** Every fixture with a literal output, for contract checks (T0-2). */
export const ALL_OSQUERY_FIXTURES: readonly OsqueryFixture[] = [
  ...Object.values(R1),
  R2_LINUX,
  F_EMPTY,
  F_FAILED,
  F_TRUNC_LINUX_WITHOUT_NGINX,
  F_PARTIAL_LINUX_WITHOUT_BASH,
  F_TIMEDOUT_LINUX_WITHOUT_BASH,
  F_UNREADABLE_LINUX_WITHOUT_BASH,
  F_UNKNOWN_AGENT,
  DEPS_LIN01_LODASH_ONLY,
  DEPS_LIN01_LODASH_AND_LOG4J,
  LINUX_LIN02_ONLY,
];

export const ALL_BULK_FIXTURES: readonly BulkOsqueryFixture[] = [F_BULK_5000, F_BULK_5001];
