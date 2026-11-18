/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  CATALOG_INDEX,
  EVENTS_INDEX,
  INSTANCES_INDEX,
  ROLLUPS_INDEX,
  WORKFLOW_IDS,
} from '../../common/constants';

/**
 * Test tooling for the discovery workflows. It is defined as code, installed with the Dashboards
 * API (`PUT /api/dashboards/{id}`) and stays editable in the dashboard UI.
 */
export const DASHBOARD_ID = 'software-inventory-discovery-monitoring';
export const DASHBOARD_TITLE = 'Software inventory: discovery workflow monitoring (test tool)';
export const TEST_PLAN_PATH =
  'x-pack/solutions/security/plugins/software_inventory/docs/discovery_test_plan.md';

export const WORKFLOW_EXECUTIONS_INDEX = '.workflows-executions';
export const WORKFLOW_STEP_EXECUTIONS_INDEX = '.workflows-step-executions';

/** Every index a panel query may read. */
export const ALLOWED_INDICES: readonly string[] = [
  WORKFLOW_EXECUTIONS_INDEX,
  WORKFLOW_STEP_EXECUTIONS_INDEX,
  EVENTS_INDEX,
  INSTANCES_INDEX,
  CATALOG_INDEX,
  ROLLUPS_INDEX,
];

/** Execution statuses that count as a failure. Change them here to change every panel. */
export const FAILED_STATUSES = ['failed', 'timed_out'] as const;
/** Execution statuses that mean a run has not finished yet. */
export const ACTIVE_STATUSES = [
  'pending',
  'running',
  'waiting',
  'waiting_for_input',
  'waiting_for_child',
  'queued',
] as const;

export const WORKFLOW_ID_LIST: readonly string[] = Object.values(WORKFLOW_IDS);

const quoteList = (values: readonly string[]): string => values.map((v) => `"${v}"`).join(', ');
const FAILED = `status IN (${quoteList(FAILED_STATUSES)})`;
const ACTIVE = `status IN (${quoteList(ACTIVE_STATUSES)})`;

/**
 * The managed workflows are stored with `id` equal to the workflow id, and runs carry it in
 * `workflowId`. The `managedBy` match is a fallback if an id prefix ever changes.
 */
const WORKFLOW_ID_PATTERN = 'system-security-software-inventory-*';
const IS_OURS = `(workflowId LIKE "${WORKFLOW_ID_PATTERN}" OR managedBy == "softwareInventory")`;
const STEP_IS_OURS = `workflowId LIKE "${WORKFLOW_ID_PATTERN}"`;
const RUN_IN_RANGE = 'startedAt >= ?_tstart AND startedAt <= ?_tend';

const RUNS = `FROM ${WORKFLOW_EXECUTIONS_INDEX}\n| WHERE ${IS_OURS} AND ${RUN_IN_RANGE}`;
const STEPS = `FROM ${WORKFLOW_STEP_EXECUTIONS_INDEX}\n| WHERE ${STEP_IS_OURS} AND ${RUN_IN_RANGE}`;
const SUCCESS_PCT =
  'success_pct = CASE(completed + failed == 0, null, ROUND(100.0 * completed / (completed + failed), 1))';

export const QUERIES = {
  runsTotal: `${RUNS}\n| STATS runs = COUNT(*)`,
  runsFailed: `${RUNS} AND ${FAILED}\n| STATS failed_runs = COUNT(*)`,
  successRate: `${RUNS}\n| STATS completed = COUNT(*) WHERE status == "completed", failed = COUNT(*) WHERE ${FAILED}\n| EVAL ${SUCCESS_PCT}\n| KEEP success_pct`,
  // Not limited to the time range: a run that started earlier is still running now.
  runsActive: `FROM ${WORKFLOW_EXECUTIONS_INDEX}\n| WHERE ${IS_OURS} AND ${ACTIVE}\n| STATS running = COUNT(*)`,
  avgDuration: `${RUNS} AND duration IS NOT NULL\n| STATS avg_duration_s = ROUND(AVG(duration) / 1000.0, 1)`,
  runsOverTime: `${RUNS}\n| STATS runs = COUNT(*) BY bucket = BUCKET(startedAt, 75, ?_tstart, ?_tend), status`,
  perWorkflow: `${RUNS}\n| STATS runs = COUNT(*), completed = COUNT(*) WHERE status == "completed", failed = COUNT(*) WHERE ${FAILED}, avg_duration_s = ROUND(AVG(duration) / 1000.0, 1), max_duration_s = ROUND(MAX(duration) / 1000.0, 1), last_run = MAX(startedAt) BY workflowId\n| EVAL ${SUCCESS_PCT}\n| SORT last_run DESC\n| KEEP workflowId, runs, failed, success_pct, avg_duration_s, max_duration_s, last_run`,
  stepsByStatus: `${STEPS}\n| STATS step_runs = COUNT(*), avg_duration_s = ROUND(AVG(duration) / 1000.0, 1) BY workflowId, stepId, status\n| EVAL not_failed = CASE(${FAILED}, 0, 1)\n| SORT not_failed ASC, step_runs DESC\n| KEEP workflowId, stepId, status, step_runs, avg_duration_s`,
  stepAvgDuration: `${STEPS} AND duration IS NOT NULL\n| STATS avg_duration_s = ROUND(AVG(duration) / 1000.0, 1) BY stepId\n| SORT avg_duration_s DESC\n| LIMIT 25`,
  recentFailures: `${RUNS} AND ${FAILED}\n| SORT startedAt DESC\n| LIMIT 25\n| EVAL duration_s = ROUND(duration / 1000.0, 1)\n| KEEP workflowId, startedAt, duration_s, status, triggeredBy`,
  eventsPerDay: `FROM ${EVENTS_INDEX}\n| WHERE @timestamp >= ?_tstart AND @timestamp <= ?_tend\n| STATS events = COUNT(*) BY day = BUCKET(@timestamp, 1 day), type`,
  instancesByStatus: `FROM ${INSTANCES_INDEX}\n| STATS instances = COUNT(*) BY status`,
  instancesBySource: `FROM ${INSTANCES_INDEX}\n| MV_EXPAND sources\n| STATS instances = COUNT(*) BY sources`,
  freshnessBySource: `FROM ${INSTANCES_INDEX}\n| MV_EXPAND sources\n| STATS instances = COUNT(*), last_seen = MAX(last_seen) BY sources\n| SORT last_seen DESC`,
  freshnessByStatus: `FROM ${INSTANCES_INDEX}\n| STATS instances = COUNT(*), last_seen = MAX(last_seen) BY status\n| SORT last_seen DESC`,
  catalogTotal: `FROM ${CATALOG_INDEX}\n| STATS catalog_entries = COUNT(*)`,
  catalogChecked: `FROM ${CATALOG_INDEX}\n| WHERE cve_checked_at IS NOT NULL\n| STATS checked = COUNT(*)`,
  catalogNeverChecked: `FROM ${CATALOG_INDEX}\n| WHERE cve_checked_at IS NULL\n| STATS never_checked = COUNT(*)`,
  catalogCheckFailed: `FROM ${CATALOG_INDEX}\n| WHERE cve_check_failed == true\n| STATS check_failed = COUNT(*)`,
  inventoryTrend: `FROM ${ROLLUPS_INDEX}\n| WHERE @timestamp >= ?_tstart AND @timestamp <= ?_tend\n| STATS vulnerable = MAX(vulnerable_instances), exposed = MAX(exposed_instances), known_exploited = MAX(known_exploited_instances) BY day = BUCKET(@timestamp, 1 day)`,
} as const;

export interface PanelGrid {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface DashboardPanel {
  type: 'markdown' | 'vis';
  grid: PanelGrid;
  config: Record<string, unknown>;
}

export interface DashboardSection {
  title: string;
  collapsed: boolean;
  grid: { y: number };
  panels: DashboardPanel[];
}

export interface DashboardDefinition {
  title: string;
  description: string;
  time_range: { from: string; to: string };
  refresh_interval: { pause: boolean; value: number };
  panels: Array<DashboardPanel | DashboardSection>;
}

const esql = (query: string) => ({ type: 'esql', query } as const);

const markdown = (grid: PanelGrid, content: string, title?: string): DashboardPanel => ({
  type: 'markdown',
  grid,
  config: { content, ...(title ? { title } : {}) },
});

const metric = (
  grid: PanelGrid,
  title: string,
  query: string,
  column: string,
  format?: Record<string, unknown>
): DashboardPanel => ({
  type: 'vis',
  grid,
  config: {
    type: 'metric',
    data_source: esql(query),
    metrics: [{ type: 'primary', column, label: title, ...(format ? { format } : {}) }],
  },
});

const table = (
  grid: PanelGrid,
  title: string,
  query: string,
  columns: Array<{ column: string; label: string }>
): DashboardPanel => ({
  type: 'vis',
  grid,
  config: {
    type: 'data_table',
    title,
    data_source: esql(query),
    rows: columns.map(({ column, label }) => ({ column, label })),
  },
});

const xy = (
  grid: PanelGrid,
  title: string,
  query: string,
  layer: {
    type: 'bar' | 'bar_stacked' | 'bar_horizontal' | 'line';
    x: string;
    y: string[];
    breakdown?: string;
  }
): DashboardPanel => ({
  type: 'vis',
  grid,
  config: {
    type: 'xy',
    title,
    layers: [
      {
        type: layer.type,
        data_source: esql(query),
        x: { column: layer.x },
        y: layer.y.map((column) => ({ column })),
        ...(layer.breakdown ? { breakdown_by: { column: layer.breakdown } } : {}),
      },
    ],
  },
});

const donut = (
  grid: PanelGrid,
  title: string,
  query: string,
  metricColumn: string,
  groupColumn: string
): DashboardPanel => ({
  type: 'vis',
  grid,
  config: {
    type: 'pie',
    title,
    data_source: esql(query),
    styling: { donut_hole: 'm' },
    metrics: [{ column: metricColumn }],
    group_by: [{ column: groupColumn }],
  },
});

const HEADER = `## Software inventory: discovery workflow monitoring

**This page is test tooling.** It exists to check that the software inventory discovery workflows run and produce data, and it may not ship with the product. Edit it freely in the dashboard UI. The installer script overwrites those edits when you run it again.

The five managed workflows (ids start with \`system-security-software-inventory-\`):

${WORKFLOW_ID_LIST.map(
  (id) => `* \`${id.replace('system-security-software-inventory-', '')}\``
).join('\n')}

**How to read it:** the workflow health and step sections read \`${WORKFLOW_EXECUTIONS_INDEX}\` and \`${WORKFLOW_STEP_EXECUTIONS_INDEX}\` and follow the time picker. The discovery output and trend sections read the plugin indices. Instance and catalog panels show current state and ignore the time picker. Runs with status ${FAILED_STATUSES.map(
  (s) => `\`${s}\``
).join(' or ')} count as failed.

**How to run a test pass:** follow \`${TEST_PLAN_PATH}\`. Panels stay empty until a workflow runs.`;

const STEP_NOTE = `**Expected failures.** The Osquery query steps use \`continue on failure\` by design. A failed Osquery step is normal when no agent of that platform exists, for example no Windows agents for the Windows programs query. Investigate failures in other steps first.`;

const section = (title: string, y: number, panels: DashboardPanel[]): DashboardSection => ({
  title,
  collapsed: false,
  grid: { y },
  panels,
});

const PCT = { type: 'number', decimals: 1, suffix: '%' };
const SECONDS = { type: 'number', decimals: 1, suffix: ' s' };

export const buildDefinition = (): DashboardDefinition => ({
  title: DASHBOARD_TITLE,
  description:
    'Test aid for the software inventory discovery workflows. Defined as code in the software_inventory plugin scripts.',
  time_range: { from: 'now-24h', to: 'now' },
  refresh_interval: { pause: false, value: 30000 },
  panels: [
    markdown({ x: 0, y: 0, w: 48, h: 14 }, HEADER),
    section('Workflow health', 14, [
      metric({ x: 0, y: 0, w: 10, h: 6 }, 'Runs', QUERIES.runsTotal, 'runs'),
      metric({ x: 10, y: 0, w: 10, h: 6 }, 'Failed runs', QUERIES.runsFailed, 'failed_runs'),
      metric({ x: 20, y: 0, w: 10, h: 6 }, 'Success rate', QUERIES.successRate, 'success_pct', PCT),
      metric({ x: 30, y: 0, w: 9, h: 6 }, 'Currently running', QUERIES.runsActive, 'running'),
      metric(
        { x: 39, y: 0, w: 9, h: 6 },
        'Average duration',
        QUERIES.avgDuration,
        'avg_duration_s',
        SECONDS
      ),
      xy({ x: 0, y: 6, w: 48, h: 12 }, 'Runs over time by status', QUERIES.runsOverTime, {
        type: 'bar_stacked',
        x: 'bucket',
        y: ['runs'],
        breakdown: 'status',
      }),
      table({ x: 0, y: 18, w: 48, h: 12 }, 'Per-workflow summary', QUERIES.perWorkflow, [
        { column: 'workflowId', label: 'Workflow' },
        { column: 'runs', label: 'Runs' },
        { column: 'failed', label: 'Failed' },
        { column: 'success_pct', label: 'Success %' },
        { column: 'avg_duration_s', label: 'Avg duration (s)' },
        { column: 'max_duration_s', label: 'Max duration (s)' },
        { column: 'last_run', label: 'Last run' },
      ]),
    ]),
    section('Step level', 15, [
      markdown({ x: 0, y: 0, w: 48, h: 4 }, STEP_NOTE),
      table({ x: 0, y: 4, w: 28, h: 14 }, 'Step runs (failing first)', QUERIES.stepsByStatus, [
        { column: 'workflowId', label: 'Workflow' },
        { column: 'stepId', label: 'Step' },
        { column: 'status', label: 'Status' },
        { column: 'step_runs', label: 'Step runs' },
        { column: 'avg_duration_s', label: 'Avg duration (s)' },
      ]),
      xy({ x: 28, y: 4, w: 20, h: 14 }, 'Average duration by step (s)', QUERIES.stepAvgDuration, {
        type: 'bar_horizontal',
        x: 'stepId',
        y: ['avg_duration_s'],
      }),
    ]),
    section('Recent failures', 16, [
      table(
        { x: 0, y: 0, w: 48, h: 12 },
        'Last 25 failed or timed-out runs',
        QUERIES.recentFailures,
        [
          { column: 'workflowId', label: 'Workflow' },
          { column: 'startedAt', label: 'Started' },
          { column: 'duration_s', label: 'Duration (s)' },
          { column: 'status', label: 'Status' },
          { column: 'triggeredBy', label: 'Triggered by' },
        ]
      ),
    ]),
    section('Discovery output', 17, [
      xy({ x: 0, y: 0, w: 30, h: 12 }, 'Events per day by type', QUERIES.eventsPerDay, {
        type: 'bar_stacked',
        x: 'day',
        y: ['events'],
        breakdown: 'type',
      }),
      donut(
        { x: 30, y: 0, w: 18, h: 12 },
        'Instances by status',
        QUERIES.instancesByStatus,
        'instances',
        'status'
      ),
      xy(
        { x: 0, y: 12, w: 16, h: 12 },
        'Instances by discovery source',
        QUERIES.instancesBySource,
        {
          type: 'bar',
          x: 'sources',
          y: ['instances'],
        }
      ),
      table({ x: 16, y: 12, w: 16, h: 12 }, 'Freshness by source', QUERIES.freshnessBySource, [
        { column: 'sources', label: 'Source' },
        { column: 'instances', label: 'Instances' },
        { column: 'last_seen', label: 'Last seen' },
      ]),
      table({ x: 32, y: 12, w: 16, h: 12 }, 'Freshness by status', QUERIES.freshnessByStatus, [
        { column: 'status', label: 'Status' },
        { column: 'instances', label: 'Instances' },
        { column: 'last_seen', label: 'Last seen' },
      ]),
      metric(
        { x: 0, y: 24, w: 12, h: 6 },
        'Catalog entries',
        QUERIES.catalogTotal,
        'catalog_entries'
      ),
      metric({ x: 12, y: 24, w: 12, h: 6 }, 'CVE checked', QUERIES.catalogChecked, 'checked'),
      metric(
        { x: 24, y: 24, w: 12, h: 6 },
        'Never checked',
        QUERIES.catalogNeverChecked,
        'never_checked'
      ),
      metric(
        { x: 36, y: 24, w: 12, h: 6 },
        'CVE check failed',
        QUERIES.catalogCheckFailed,
        'check_failed'
      ),
    ]),
    section('Inventory trend', 18, [
      xy(
        { x: 0, y: 0, w: 48, h: 12 },
        'Vulnerable, exposed and known exploited instances per day',
        QUERIES.inventoryTrend,
        {
          type: 'line',
          x: 'day',
          y: ['vulnerable', 'exposed', 'known_exploited'],
        }
      ),
    ]),
  ],
});
