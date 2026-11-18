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
} from '../../../common/constants';
import { generateSeedData } from '../../seed/generate_seed_data';
import type {
  JsonValue,
  MgetResponse,
  RawResponse,
  SearchResponse,
  WorkflowList,
} from '../clients';
import { getProductionYaml, getWorkflowId, PRODUCTION_WORKFLOWS } from '../variants/build_variant';
import type { WorkflowKey } from '../variants/build_variant';
import { createRgCases, diffEventKeys, diffIdSets } from './rg';
import { fakeContext, fakeEs, fakeKibana, asType } from './fake_context';

const RESTORED_AT = new Date('2026-11-18T08:00:00.000Z');
const CHECKED_AT = new Date('2026-11-18T10:00:00.000Z');

type Docs = Record<string, Array<{ id: string; source: object }>>;

/** The four plugin indices right after `seed_demo_data.js --clean` at `RESTORED_AT`. */
const restoredIndices = (): Docs => {
  const seed = generateSeedData(RESTORED_AT);
  return {
    [CATALOG_INDEX]: seed.catalog.map((doc) => ({ id: doc.id, source: doc })),
    [INSTANCES_INDEX]: seed.instances.map((doc) => ({ id: doc.id, source: doc })),
    [EVENTS_INDEX]: seed.events.map((doc, index) => ({ id: `e${index}`, source: doc })),
    [ROLLUPS_INDEX]: seed.rollups.map((doc) => ({
      id: doc['@timestamp'].slice(0, 10),
      source: doc,
    })),
  };
};

const esOver = (docs: Docs) =>
  fakeEs({
    search: async <T>(index: string): Promise<SearchResponse<T>> => ({
      hits: {
        hits: (docs[index] ?? []).map(({ id, source }) => ({
          _id: id,
          _index: index,
          _source: asType<T>(source),
        })),
      },
    }),
    mget: async <T>(index: string, ids: readonly string[]): Promise<MgetResponse<T>> => ({
      docs: ids.map((id) => {
        const found = (docs[index] ?? []).find((doc) => doc.id === id);
        return found
          ? { _id: id, found: true, _source: asType<T>(found.source) }
          : { _id: id, found: false };
      }),
    }),
  });

const rgCases = createRgCases({ now: () => CHECKED_AT });
const rgCase = (id: string) => {
  const found = rgCases.find((testCase) => testCase.id === id);
  if (!found) throw new Error(`no case ${id}`);
  return found;
};

describe('RG pure helpers', () => {
  it('compares id sets and event multisets', () => {
    expect(diffIdSets('x', ['a', 'b'], ['b', 'c'])).toEqual(['x: missing a', 'x: unexpected c']);
    expect(diffEventKeys(['k', 'k', 'j'], ['k', 'j', 'j'])).toEqual([
      'events: missing 1 x k',
      'events: 1 unexpected x j',
    ]);
  });
});

describe('RG cases on a restored demo', () => {
  it('registers RG-1..RG-6 without prerequisites', () => {
    expect(rgCases.map(({ id }) => id)).toEqual(['RG-1', 'RG-2', 'RG-3', 'RG-4', 'RG-5', 'RG-6']);
    expect(rgCases.every(({ requires }) => requires === undefined)).toBe(true);
  });

  it.each(['RG-1', 'RG-2', 'RG-4'])(
    '%s passes on a demo restored two hours earlier',
    async (id) => {
      const result = await rgCase(id).run(fakeContext({ es: esOver(restoredIndices()) }));
      expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
      expect(result.status).toBe('pass');
    }
  );

  it('RG-1 fails on a leftover catalog entry and a missing event', async () => {
    const docs = restoredIndices();
    docs[CATALOG_INDEX].push({ id: 'apache:log4j:2.14.1', source: { id: 'apache:log4j:2.14.1' } });
    docs[EVENTS_INDEX].pop();
    const result = await rgCase('RG-1').run(fakeContext({ es: esOver(docs) }));
    expect(result.status).toBe('fail');
    const diffs = result.layers.flatMap((layer) => layer.diffs).join('\n');
    expect(diffs).toMatch(/catalog: unexpected apache:log4j:2.14.1/);
    expect(diffs).toMatch(/events: missing 1 x/);
  });

  it('RG-2 fails when score-exposure rewrote a demo exposure', async () => {
    const docs = restoredIndices();
    const [first] = docs[INSTANCES_INDEX];
    const instance = generateSeedData(RESTORED_AT).instances[0];
    docs[INSTANCES_INDEX][0] = {
      id: first.id,
      source: { ...instance, exposure: { level: 'high', score: 90, evidence: [] } },
    };
    const result = await rgCase('RG-2').run(fakeContext({ es: esOver(docs) }));
    expect(result.status).toBe('fail');
    expect(result.layers[0].diffs.join('\n')).toMatch(/exposure/);
  });

  it('RG-5 checks the managed workflows are disabled with the registered YAML', async () => {
    const results = (Object.keys(PRODUCTION_WORKFLOWS) as WorkflowKey[]).map((key) => ({
      id: getWorkflowId(key),
      name: key,
      enabled: key === 'enrichCves',
      definitionHash: 'h',
      yaml: getProductionYaml(key),
    }));
    const kibana = fakeKibana({
      listWorkflows: async (): Promise<WorkflowList> => ({ results, total: results.length }),
    });
    const result = await rgCase('RG-5').run(fakeContext({ kibana }));
    expect(result.status).toBe('fail');
    expect(result.layers[0].diffs).toEqual([`${getWorkflowId('enrichCves')}: enabled`]);
  });

  it('RG-6 passes when every artifact is gone and the dashboard is installed', async () => {
    const es = fakeEs({ exists: async () => false });
    const kibana = fakeKibana({
      listWorkflows: async (): Promise<WorkflowList> => ({
        results: [{ id: 'mine', name: 'My workflow', enabled: false }],
        total: 1,
      }),
      request: async <T>(): Promise<RawResponse<T>> => ({
        status: 200,
        body: {} as JsonValue as T,
      }),
    });
    expect((await rgCase('RG-6').run(fakeContext({ es, kibana }))).status).toBe('pass');

    const leftover = fakeKibana({
      listWorkflows: async (): Promise<WorkflowList> => ({
        results: [{ id: 'si-test-discover-osquery-sched', name: 'x [test: SC-1]', enabled: true }],
        total: 1,
      }),
      request: async <T>(): Promise<RawResponse<T>> => ({
        status: 404,
        body: {} as JsonValue as T,
      }),
    });
    const failed = await rgCase('RG-6').run(fakeContext({ es, kibana: leftover }));
    expect(failed.status).toBe('fail');
    expect(failed.layers[0].diffs).toEqual([
      'workflow si-test-discover-osquery-sched remains',
      'workflow si-test-discover-osquery-sched is a saved test variant',
      'dashboard software-inventory-discovery-monitoring is not installed',
    ]);
  });
});
