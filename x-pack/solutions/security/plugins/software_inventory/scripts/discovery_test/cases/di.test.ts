/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * @jest-environment node
 */

import { INSTANCES_INDEX } from '../../../common/constants';
import { HttpError } from '../clients';
import { DI2, DI3_INSTANCE_COUNTS, DI4, DI5_FIXTURE, DI_HOST_KEYS } from '../expected/di';
import { instanceIdFor } from '../ids';
import { ALL_CASES, validateRegistry } from '.';
import { cases } from './di';
import type { FakeStep } from './do_di_world';
import { fakeContext, fakeRun, ingestStep } from './do_di_world';
import type { TestCase } from './types';

const caseOf = (id: string): TestCase => {
  const found = cases.find((candidate) => candidate.id === id);
  if (!found) throw new Error(`no case ${id}`);
  return found;
};

const WORKFLOW_ID = 'system-security-software-inventory-discover-integrations';
const fleetIngest = (
  output: Record<string, number>,
  candidates: number,
  extra: Partial<FakeStep> = {}
): FakeStep[] => [
  { name: 'list_package_policies', output: { items: [] } },
  { name: 'build_candidates' },
  ingestStep('ingest', { output, snapshot: false, candidates }, 'fleet_integration', extra),
];
const empty = { instances: [], catalog: [], events: [] };

describe('DI registry', () => {
  it('lists DI-1..DI-5 in matrix order with DI-3 and DI-4 requiring DI-2', () => {
    expect(cases.map(({ id }) => id)).toEqual(['DI-1', 'DI-2', 'DI-3', 'DI-4', 'DI-5']);
    expect(cases.every(({ family }) => family === 'DI')).toBe(true);
    expect(Object.fromEntries(cases.map(({ id, requires }) => [id, requires ?? []]))).toEqual({
      'DI-1': [],
      'DI-2': [],
      'DI-3': ['DI-2'],
      'DI-4': ['DI-2'],
      'DI-5': [],
    });
    expect(() => validateRegistry(ALL_CASES)).not.toThrow();
  });
});

describe('DI expected values', () => {
  it('maps panw and nginx to three policy-host instances with unknown versions', () => {
    expect(DI2.ingest).toEqual({
      output: { created: 3, skipped: 2 },
      snapshot: false,
      candidates: 5,
    });
    expect(DI2.instances.map(({ hostKey, catalogId }) => `${hostKey} ${catalogId}`).sort()).toEqual(
      [
        'policy:synth-pol-edge f5:nginx:unknown',
        'policy:synth-pol-edge palo_alto_networks:pan-os:unknown',
        'policy:synth-pol-web f5:nginx:unknown',
      ]
    );
    expect(DI2.instances.every(({ hostId, hostKey }) => hostId === hostKey)).toBe(true);
    expect(DI2.instances.map(({ hostName }) => hostName).sort()).toEqual([
      'synth-pol-edge',
      'synth-pol-edge',
      'synth-pol-web',
    ]);
    expect(DI2.catalog.every(({ fields }) => fields?.version === 'unknown')).toBe(true);
    expect(DI2.catalog.map(({ fields }) => fields?.category).sort()).toEqual([
      'appliance',
      'application',
    ]);
    expect(DI2.events).toHaveLength(3);
    expect(DI3_INSTANCE_COUNTS).toEqual({ 'policy:synth-pol-edge': 2, 'policy:synth-pol-web': 1 });
    expect(new Set(DI2.instances.map((item) => instanceIdFor(item))).size).toBe(3);
  });

  it('DI-4 drops nginx from the edge policy but keeps the instance', () => {
    expect(DI4.ingest).toEqual({
      output: { unchanged: 2, skipped: 2, removed: 0 },
      snapshot: false,
      candidates: 4,
    });
    expect(DI4.instances.filter(({ status }) => status !== 'active')).toEqual([]);
    expect(DI4.instances).toHaveLength(3);
  });
});

describe('DI-1', () => {
  const emptyFleet = async () => ({ status: 200, body: { total: 0 } });
  const prod = fakeRun({
    workflowId: WORKFLOW_ID,
    steps: fleetIngest({}, 0),
  });

  it('runs the stored YAML against an empty Fleet', async () => {
    const { ctx, calls } = fakeContext({ runs: [prod], world: empty, kibanaRequest: emptyFleet });
    const result = await caseOf('DI-1').run(ctx);
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(calls).toEqual([{ workflow: 'discoverIntegrations' }]);
  });

  it('is blocked when Fleet has package policies or cannot be read, without running', async () => {
    const full = fakeContext({
      runs: [],
      world: empty,
      kibanaRequest: async () => ({ status: 200, body: { total: 2 } }),
    });
    const fullResult = await caseOf('DI-1').run(full.ctx);
    expect(fullResult.status).toBe('blocked');
    expect(full.calls).toHaveLength(0);

    const unreadable = fakeContext({
      runs: [],
      world: empty,
      kibanaRequest: async () => {
        throw new HttpError('GET', 'http://k/api/fleet', 500, 'boom');
      },
    });
    expect((await caseOf('DI-1').run(unreadable.ctx)).status).toBe('blocked');
  });

  it('fails when the run ingests something', async () => {
    const run = fakeRun({ workflowId: WORKFLOW_ID, steps: fleetIngest({ created: 1 }, 1) });
    const { ctx } = fakeContext({ runs: [run], world: empty, kibanaRequest: emptyFleet });
    expect((await caseOf('DI-1').run(ctx)).status).toBe('fail');
  });
});

describe('DI-2', () => {
  const run = () =>
    fakeRun({ workflowId: WORKFLOW_ID, steps: fleetIngest({ created: 3, skipped: 2 }, 5) });
  const world = { instances: DI2.instances, catalog: DI2.catalog, events: DI2.events };

  it('passes with created 3 and skipped 2 and instances on policy hosts', async () => {
    const { ctx, calls } = fakeContext({ runs: [run()], world });
    const result = await caseOf('DI-2').run(ctx);
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(calls[0].workflow).toBe('discoverIntegrations');
    expect(calls[0].yaml).toContain('pp-4');
    expect(calls[0].yaml).toContain('osquery_manager');
  });

  it('fails when a catalog version is not unknown', async () => {
    const { ctx } = fakeContext({
      runs: [run()],
      world: {
        ...world,
        catalog: DI2.catalog.map((entry) => ({
          ...entry,
          fields: { ...entry.fields, version: '5.3.0' },
        })),
      },
    });
    const result = await caseOf('DI-2').run(ctx);
    expect(result.status).toBe('fail');
    expect(result.layers[2].diffs.join('\n')).toContain('version');
  });

  it('fails when the skipped count differs', async () => {
    const wrong = fakeRun({
      workflowId: WORKFLOW_ID,
      steps: fleetIngest({ created: 3, skipped: 1 }, 5),
    });
    const { ctx } = fakeContext({ runs: [wrong], world });
    expect((await caseOf('DI-2').run(ctx)).layers[1].diffs.join('\n')).toContain('skipped');
  });
});

describe('DI-3', () => {
  const counts = (edge: number, web: number) => (index: string, query: object) => {
    if (index !== INSTANCES_INDEX) return 0;
    const text = JSON.stringify(query);
    return text.includes('synth-pol-edge') ? edge : text.includes('synth-pol-web') ? web : 0;
  };
  const world = { instances: DI2.instances, catalog: [], events: [] };

  it('passes with 2 instances on the edge policy and 1 on the web policy, no run needed', async () => {
    const { ctx, calls } = fakeContext({ runs: [], world: { ...world, count: counts(2, 1) } });
    const result = await caseOf('DI-3').run(ctx);
    expect(result.status).toBe('pass');
    expect(calls).toHaveLength(0);
  });

  it('fails on a wrong count or a prefixed host name', async () => {
    const wrongCount = fakeContext({ runs: [], world: { ...world, count: counts(3, 1) } });
    expect((await caseOf('DI-3').run(wrongCount.ctx)).status).toBe('fail');
    const prefixed = fakeContext({
      runs: [],
      world: {
        ...world,
        instances: DI2.instances.map((item) => ({ ...item, hostName: `policy:${item.hostName}` })),
        count: counts(2, 1),
      },
    });
    expect((await caseOf('DI-3').run(prefixed.ctx)).layers[0].diffs.join('\n')).toContain(
      'host.name'
    );
  });
});

describe('DI-4', () => {
  const run = fakeRun({
    workflowId: WORKFLOW_ID,
    steps: fleetIngest({ unchanged: 2, skipped: 2, removed: 0 }, 4),
  });

  it('passes when nothing is removed and no events are written', async () => {
    const { ctx, calls } = fakeContext({
      runs: [run],
      world: { instances: DI4.instances, catalog: [], events: [] },
    });
    const result = await caseOf('DI-4').run(ctx);
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(calls[0].yaml).toBeDefined();
  });

  it('fails when nginx on the edge policy was removed', async () => {
    const { ctx } = fakeContext({
      runs: [run],
      world: {
        instances: DI4.instances.map((item) =>
          item.hostKey === 'policy:synth-pol-edge' && item.catalogId.startsWith('f5:')
            ? { ...item, status: 'removed' as const }
            : item
        ),
        catalog: [],
        events: [],
      },
    });
    const result = await caseOf('DI-4').run(ctx);
    expect(result.status).toBe('fail');
    expect(result.layers[2].diffs.join('\n')).toContain('status removed != active');
  });
});

describe('DI-5', () => {
  const failedRun = (message: string, candidates = 5001) =>
    fakeRun({
      workflowId: WORKFLOW_ID,
      status: 'failed',
      steps: [
        { name: 'list_package_policies' },
        { name: 'build_candidates' },
        {
          name: 'ingest',
          status: 'failed',
          input: {
            source: 'fleet_integration',
            snapshot: false,
            candidates: Array.from({ length: candidates }, () => ({})),
          },
          error: { message },
        },
      ],
    });

  it('builds the 5001-policy fixture and expects the run to fail on ingest', async () => {
    expect(DI5_FIXTURE.response.items[0].policy_ids).toHaveLength(5001);
    expect(DI_HOST_KEYS).toHaveLength(2);
    const { ctx, calls } = fakeContext({
      runs: [failedRun('candidates: Too big: expected array to have <=5000 items')],
      world: empty,
    });
    const result = await caseOf('DI-5').run(ctx);
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(calls[0].yaml).toContain('synth-pol-bulk-5001');
  });

  it('fails when the run completed or the error does not name the limit', async () => {
    const completed = fakeContext({
      runs: [
        fakeRun({
          workflowId: WORKFLOW_ID,
          steps: fleetIngest({}, 5001),
        }),
      ],
      world: empty,
    });
    expect((await caseOf('DI-5').run(completed.ctx)).status).toBe('fail');
    const vague = fakeContext({ runs: [failedRun('something else')], world: empty });
    expect((await caseOf('DI-5').run(vague.ctx)).layers[1].diffs.join('\n')).toContain('limit');
  });
});
