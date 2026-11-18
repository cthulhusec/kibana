/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * RG: regression checks on demo data (RG-1..RG-6 in docs/discovery_test_plan.md), run after
 * `cleanup` and `restore` (`seed_demo_data.js --clean`). The restore regenerates timestamps
 * relative to now, so "equals the backup" means equal to `generateSeedData` without time fields:
 * ids, statuses, versions, CVE posture, exposure levels (see `expected/rg.ts`). Read-only.
 */

import { isDeepStrictEqual } from 'util';
import {
  CATALOG_INDEX,
  EVENTS_INDEX,
  INSTANCES_INDEX,
  ROLLUPS_INDEX,
} from '../../../common/constants';
import type { DailyRollup, InventoryEvent } from '../../../common/history';
import type { CatalogEntry, InstanceDoc } from '../../../common/types';
import { diffValues, layerResult } from '../assertions';
import type { EsClient, JsonObject } from '../clients';
import { findSyntheticResidue, listTestWorkflowIds } from '../cleanup';
import { taskExists } from './sc_support';
import {
  EXPECTED_SEED_COUNTS,
  EXTRA_SYNTHETIC_CATALOG_IDS,
  MONITORING_DASHBOARD_ID,
  TASK_FREE_WORKFLOW_IDS,
  diffRollupDays,
  eventKey,
  expectedDemo,
  projectCatalog,
  projectInstance,
  projectRollup,
} from '../expected/rg';
import { SYNTHETIC_DATA_STREAM, SYNTHETIC_TEMPLATE_NAME } from '../logs/template';
import { PRODUCTION_WORKFLOWS, getProductionYaml, getWorkflowId } from '../variants/build_variant';
import type { WorkflowKey } from '../variants/build_variant';
import type { CaseContext, CaseResult, TestCase } from './types';
import { caseResult } from './types';

export interface RgDeps {
  readonly now: () => Date;
}

const readAll = async <T>(es: EsClient, index: string): Promise<Array<{ id: string; doc: T }>> => {
  const response = await es.search<T>(index, { size: 10_000, query: { match_all: {} } });
  return response.hits.hits.flatMap((hit) =>
    hit._source ? [{ id: hit._id, doc: hit._source }] : []
  );
};

/** Pure: compares two id lists as sets. */
export const diffIdSets = (
  label: string,
  expected: readonly string[],
  actual: readonly string[]
): string[] => {
  const actualSet = new Set(actual);
  const expectedSet = new Set(expected);
  return [
    ...expected.filter((id) => !actualSet.has(id)).map((id) => `${label}: missing ${id}`),
    ...actual.filter((id) => !expectedSet.has(id)).map((id) => `${label}: unexpected ${id}`),
  ];
};

/** Pure: compares multisets of event keys. */
export const diffEventKeys = (expected: readonly string[], actual: readonly string[]): string[] => {
  const counts = new Map<string, number>();
  expected.forEach((key) => counts.set(key, (counts.get(key) ?? 0) + 1));
  actual.forEach((key) => counts.set(key, (counts.get(key) ?? 0) - 1));
  return [...counts]
    .filter(([, count]) => count !== 0)
    .map(([key, count]) =>
      count > 0 ? `events: missing ${count} x ${key}` : `events: ${-count} unexpected x ${key}`
    );
};

/** Pure: projections compared by id, both directions. */
export const diffProjections = (
  label: string,
  expected: readonly JsonObject[],
  actual: readonly JsonObject[]
): string[] => {
  const actualById = new Map(actual.map((item) => [String(item.id), item]));
  return expected.flatMap((item) => {
    const other = actualById.get(String(item.id));
    if (!other) return [`${label} ${item.id}: missing`];
    if (isDeepStrictEqual(item, other)) return [];
    const diffs = [
      ...diffValues(item, other, `${label} ${item.id}`),
      ...diffValues(other, item, `${label} ${item.id} (extra)`),
    ];
    return diffs.length > 0 ? diffs.slice(0, 5) : [`${label} ${item.id}: differs`];
  });
};

const countsLayer = (): string[] => {
  const demo = expectedDemo(new Date());
  const actual = {
    catalog: demo.catalog.length,
    instances: demo.instances.length,
    events: demo.eventKeys.length,
    rollups: demo.rollupCount,
  };
  return diffValues({ ...EXPECTED_SEED_COUNTS }, actual, 'generateSeedData counts (seed changed?)');
};

const rg1 =
  ({ now }: RgDeps) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    const at = now();
    const demo = expectedDemo(at);
    const [catalog, instances, events, rollups] = await Promise.all([
      readAll<CatalogEntry>(ctx.es, CATALOG_INDEX),
      readAll<InstanceDoc>(ctx.es, INSTANCES_INDEX),
      readAll<InventoryEvent>(ctx.es, EVENTS_INDEX),
      readAll<DailyRollup>(ctx.es, ROLLUPS_INDEX),
    ]);
    const diffs = [
      ...diffIdSets(
        'catalog',
        demo.catalog.map(({ id }) => String(id)),
        catalog.map(({ id }) => id)
      ),
      ...diffIdSets(
        'instances',
        demo.instances.map(({ id }) => String(id)),
        instances.map(({ id }) => id)
      ),
      ...diffEventKeys(
        demo.eventKeys,
        events.map(({ doc }) => eventKey(doc))
      ),
      ...diffRollupDays(
        rollups.map(({ id }) => id),
        demo.rollupCount,
        at
      ),
    ];
    return caseResult([
      layerResult('inventory', diffs, 4, {
        counts: {
          catalog: catalog.length,
          instances: instances.length,
          events: events.length,
          rollups: rollups.length,
        },
      }),
      layerResult('harness', countsLayer(), 4),
    ]);
  };

const rg2 =
  ({ now }: RgDeps) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    const demo = expectedDemo(now());
    const [catalog, instances] = await Promise.all([
      readAll<CatalogEntry>(ctx.es, CATALOG_INDEX),
      readAll<InstanceDoc>(ctx.es, INSTANCES_INDEX),
    ]);
    const diffs = [
      ...diffProjections(
        'catalog',
        demo.catalog,
        catalog.map(({ doc }) => projectCatalog(doc))
      ),
      ...diffProjections(
        'instance',
        demo.instances,
        instances.map(({ doc }) => projectInstance(doc))
      ),
    ];
    return caseResult([
      layerResult('inventory', diffs, demo.catalog.length + demo.instances.length),
    ]);
  };

const rg3 = async (ctx: CaseContext): Promise<CaseResult> => {
  const residue = await findSyntheticResidue(ctx.es, ctx.kibana);
  const { docs } = await ctx.es.mget<CatalogEntry>(CATALOG_INDEX, EXTRA_SYNTHETIC_CATALOG_IDS);
  const diffs = [
    ...(residue.syntheticInstances > 0
      ? [`${residue.syntheticInstances} synthetic instance(s)`]
      : []),
    ...(residue.syntheticEvents > 0 ? [`${residue.syntheticEvents} synthetic event(s)`] : []),
    ...residue.syntheticCatalogIds.map((id) => `synthetic catalog entry ${id}`),
    ...docs.filter((doc) => doc.found).map((doc) => `synthetic catalog entry ${doc._id}`),
  ];
  return caseResult([layerResult('inventory', diffs, 3 + EXTRA_SYNTHETIC_CATALOG_IDS.length)]);
};

const rg4 =
  ({ now }: RgDeps) =>
  async (ctx: CaseContext): Promise<CaseResult> => {
    const { todayRollup } = expectedDemo(now());
    const {
      docs: [doc],
    } = await ctx.es.mget<DailyRollup>(ROLLUPS_INDEX, [todayRollup.id]);
    const actual = doc?.found && doc._source ? projectRollup(doc._source) : undefined;
    const diffs = actual
      ? diffValues(todayRollup.counts, actual, `rollup ${todayRollup.id}`)
      : [`rollup ${todayRollup.id}: missing (restore ran on an earlier UTC day?)`];
    return caseResult([layerResult('inventory', diffs, Object.keys(todayRollup.counts).length)]);
  };

const rg5 = async (ctx: CaseContext): Promise<CaseResult> => {
  const { results } = await ctx.kibana.listWorkflows({ managed: true, size: 100 });
  const diffs: string[] = [];
  for (const key of Object.keys(PRODUCTION_WORKFLOWS) as WorkflowKey[]) {
    const id = getWorkflowId(key);
    const stored = results.find((workflow) => workflow.id === id);
    if (!stored) {
      diffs.push(`${id}: not installed`);
      continue;
    }
    if (stored.enabled) diffs.push(`${id}: enabled`);
    if (!stored.definitionHash) diffs.push(`${id}: no definitionHash`);
    if (stored.yaml !== undefined && stored.yaml !== getProductionYaml(key)) {
      diffs.push(`${id}: stored YAML differs from the registered definition`);
    }
  }
  return caseResult([
    layerResult('harness', diffs, Object.keys(PRODUCTION_WORKFLOWS).length * 3, {
      definitionHashes: results
        .filter(({ id }) => id.startsWith('system-security-software-inventory-'))
        .map(({ id, definitionHash }) => `${id} ${definitionHash ?? '-'}`),
    }),
  ]);
};

const listTestNamedWorkflows = async (ctx: CaseContext): Promise<string[]> => {
  const ids: string[] = [];
  for (let page = 1; ; page++) {
    const { results, total } = await ctx.kibana.listWorkflows({ page, size: 100 });
    results.filter(({ name }) => name.includes('[test: ')).forEach(({ id }) => ids.push(id));
    if (results.length === 0 || page * 100 >= total) return ids;
  }
};

const rg6 = async (ctx: CaseContext): Promise<CaseResult> => {
  const [dataStream, template, testWorkflows, testNamed, dashboard, tasks] = await Promise.all([
    ctx.es.exists(`/_data_stream/${SYNTHETIC_DATA_STREAM}`),
    ctx.es.exists(`/_index_template/${SYNTHETIC_TEMPLATE_NAME}`),
    listTestWorkflowIds(ctx.kibana),
    listTestNamedWorkflows(ctx),
    ctx.kibana.request('GET', `/api/saved_objects/dashboard/${MONITORING_DASHBOARD_ID}`, {
      allowStatuses: [404],
    }),
    Promise.all(
      TASK_FREE_WORKFLOW_IDS.map(async (id) => ((await taskExists(ctx.es, id)) ? [id] : []))
    ),
  ]);
  const diffs = [
    ...(dataStream ? [`data stream ${SYNTHETIC_DATA_STREAM} still exists`] : []),
    ...(template ? [`index template ${SYNTHETIC_TEMPLATE_NAME} still exists`] : []),
    ...testWorkflows.map((id) => `workflow ${id} remains`),
    ...testNamed.map((id) => `workflow ${id} is a saved test variant`),
    ...(dashboard.status === 404 ? [`dashboard ${MONITORING_DASHBOARD_ID} is not installed`] : []),
    ...tasks.flat().map((id) => `scheduled task for ${id} remains`),
  ];
  return caseResult([layerResult('harness', diffs, 6)]);
};

export const createRgCases = (deps: RgDeps = { now: () => new Date() }): TestCase[] => [
  {
    id: 'RG-1',
    family: 'RG',
    title: 'Doc counts and id sets of the four plugin indices match the demo seed',
    run: rg1(deps),
  },
  {
    id: 'RG-2',
    family: 'RG',
    title: 'Every demo instance and catalog entry matches the seed (time fields excluded)',
    run: rg2(deps),
  },
  {
    id: 'RG-3',
    family: 'RG',
    title: 'No synthetic host key, synthetic catalog id, or 192.0.2.77 document remains',
    run: rg3,
  },
  {
    id: 'RG-4',
    family: 'RG',
    title: "Today's rollup matches the seed",
    run: rg4(deps),
  },
  {
    id: 'RG-5',
    family: 'RG',
    title: 'The five managed workflows are disabled with the registered definition',
    run: rg5,
  },
  {
    id: 'RG-6',
    family: 'RG',
    title: 'Synthetic logs, si-test workflows, and scheduled tasks are gone; dashboard installed',
    run: rg6,
  },
];

export const cases: TestCase[] = createRgCases();
