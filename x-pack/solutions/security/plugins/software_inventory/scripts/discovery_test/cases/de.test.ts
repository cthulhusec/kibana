/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * @jest-environment node
 */

import { CATALOG_INDEX } from '../../../common/constants';
import { ingestOutput } from '../assertions';
import type { CompletedRun } from '../clients';
import type { DeStage } from '../expected/de';
import {
  BOTH_CATALOG_ID,
  BOTH_HOST_KEY,
  DE_INGEST,
  HOST_NAME_ONLY_CATALOG_ID,
  HOST_NAME_ONLY_HOST_KEY,
  expectedCatalogIdsAt,
  expectedEventsAt,
  expectedInstancesAt,
  expectedSightingTimes,
  rowsAt,
} from '../expected/de';
import { instanceIdFor, parseCatalogId } from '../ids';
import { ENDPOINT_DATA_STREAM } from '../logs/endpoint_template';
import { getWorkflowId } from '../variants/build_variant';
import { ALL_CASES } from '.';
import { cases } from './de';
import { endpointRowsAt } from './de_support';
import type { ExpectedEsqlRow } from './dl_support';
import type { FakeStack } from './fake_stack';
import { buildFakeStack } from './fake_stack';
import { esqlOutput, instanceDoc, putEvent } from './test_seed';
import type { CaseResult, TestCase } from './types';

const T0 = new Date(Date.now() - 5 * 60_000);
const OLD_T0 = new Date(Date.now() - 3 * 3_600_000);
const HOUR_MS = 3_600_000;

const getCase = (id: string): TestCase => {
  const found = cases.find((testCase) => testCase.id === id);
  if (!found) throw new Error(`no case ${id}`);
  return found;
};

interface RunShape {
  rows: readonly ExpectedEsqlRow[] | 'failed';
  ingest: Partial<Record<'created' | 'unchanged' | 'patched' | 'removed' | 'skipped', number>>;
  candidateCount: number;
}

const UNKNOWN_INDEX = {
  message: 'verification_exception: Unknown index [logs-endpoint.events.process-*]',
};

const discoverEndpointRun = (stack: FakeStack, shape: RunShape): CompletedRun =>
  stack.registerRun({
    workflowId: getWorkflowId('discoverEndpoint'),
    steps: {
      query_processes:
        shape.rows === 'failed'
          ? { status: 'failed', error: UNKNOWN_INDEX }
          : { output: esqlOutput(shape.rows) },
      build_candidates: { output: { candidates_json: '[]' } },
      ingest: {
        input: {
          source: 'endpoint',
          snapshot: false,
          candidates: Array.from({ length: shape.candidateCount }, () => ({})),
        },
        output: ingestOutput(shape.ingest),
      },
    },
  });

const stageShape = (stage: DeStage, ingest: RunShape['ingest'], skipHostId?: string): RunShape => {
  const rows = endpointRowsAt(stage, T0).filter(({ host_id: id }) => id !== skipHostId);
  return { rows, ingest, candidateCount: rows.length };
};

/** Seeds the instances, catalog entries, and events the endpoint run at `stage` leaves behind. */
const seedDeState = (
  stack: FakeStack,
  stage: DeStage,
  {
    afterFlipRun = false,
    osqueryMerged = false,
  }: { afterFlipRun?: boolean; osqueryMerged?: boolean } = {}
): void => {
  const times = expectedSightingTimes(stage, T0);
  for (const expected of expectedInstancesAt(stage, { afterFlipRun, osqueryMerged })) {
    const sighting = times.find(
      ({ hostKey, catalogId }) => hostKey === expected.hostKey && catalogId === expected.catalogId
    );
    const flipped = expected.previousSoftwareId !== undefined;
    instanceDoc(stack, {
      hostKey: expected.hostKey,
      catalogId: expected.catalogId,
      status: expected.status,
      sources: expected.sources ? [...expected.sources] : ['endpoint'],
      hostName: expected.hostName ?? null,
      hostId: expected.hostId ?? 'synth-agent-win08',
      previousSoftwareId: expected.previousSoftwareId,
      firstSeen: sighting?.firstSeen,
      lastSeen: sighting?.lastSeen,
      versionHistory: flipped
        ? [
            {
              version: '124.0.1',
              software_id: 'mozilla:firefox:124.0.1',
              first_seen: sighting?.firstSeen ?? '',
              last_seen: sighting?.firstSeen ?? '',
            },
            {
              version: '125.0.1',
              software_id: 'mozilla:firefox:125.0.1',
              first_seen: sighting?.lastSeen ?? '',
              last_seen: sighting?.lastSeen ?? '',
            },
          ]
        : undefined,
    });
  }
  for (const id of expectedCatalogIdsAt(stage)) {
    const { vendor, product, version } = parseCatalogId(id);
    stack.put(CATALOG_INDEX, id, { id, vendor, product, version, category: 'application' });
  }
  for (const event of expectedEventsAt(stage, T0)) putEvent(stack, event);
};

const run = async (
  stack: FakeStack,
  id: string,
  handler: (stack: FakeStack) => CompletedRun = () => {
    throw new Error('the case must not start a workflow');
  },
  t0 = T0
): Promise<{ result: CaseResult; started: number }> => {
  const { ctx, started } = stack.buildContext({ t0, runWorkflow: () => handler(stack) });
  const result = await getCase(id).run(ctx);
  return { result, started: started.length };
};

const diffsOf = (result: CaseResult): string[] => result.layers.flatMap(({ diffs }) => diffs);

describe('DE registry', () => {
  it('registers DE-0..DE-6 in matrix order with prerequisites', () => {
    expect(cases.map(({ id }) => id)).toEqual(
      Array.from({ length: 7 }, (_, index) => `DE-${index}`)
    );
    expect(Object.fromEntries(cases.map(({ id, requires }) => [id, requires ?? []]))).toEqual({
      'DE-0': [],
      'DE-1': [],
      'DE-2': ['DE-1'],
      'DE-3': ['DE-1'],
      'DE-4': ['DE-3'],
      'DE-5': ['DE-1'],
      'DE-6': ['DE-4'],
    });
    expect(cases.every(({ family }) => family === 'DE')).toBe(true);
  });

  it('runs after the DL family and DO-15..18, before EC', () => {
    const order = ALL_CASES.map(({ id }) => id);
    expect(order.indexOf('DE-0')).toBeGreaterThan(order.indexOf('DL-10'));
    expect(order.indexOf('DE-0')).toBeGreaterThan(order.indexOf('DO-18'));
    expect(order.indexOf('DE-6')).toBeLessThan(order.indexOf('EC-1'));
    for (const testCase of cases) {
      for (const required of testCase.requires ?? []) {
        expect(order.indexOf(required)).toBeLessThan(order.indexOf(testCase.id));
      }
    }
  });
});

describe('DE-0', () => {
  it('passes when the query fails on an unknown index and ingest writes nothing', async () => {
    const stack = buildFakeStack();
    const { result, started } = await run(stack, 'DE-0', () =>
      discoverEndpointRun(stack, { rows: 'failed', ingest: {}, candidateCount: 0 })
    );
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(started).toBe(1);
  });

  it('fails when the query succeeds', async () => {
    const stack = buildFakeStack();
    const { result } = await run(stack, 'DE-0', () =>
      discoverEndpointRun(stack, { rows: [], ingest: {}, candidateCount: 0 })
    );
    expect(result.status).toBe('fail');
    expect(diffsOf(result).join('\n')).toMatch(/query_processes: expected failed, got completed/);
  });

  it('is blocked, without running, when an endpoint data stream already exists', async () => {
    const stack = buildFakeStack();
    stack.dataStreams.add(ENDPOINT_DATA_STREAM);
    const { result, started } = await run(stack, 'DE-0');
    expect(result.status).toBe('blocked');
    expect(started).toBe(0);
  });
});

describe('DE-1', () => {
  it('writes phase A, runs the stored YAML, and passes on the expected inventory', async () => {
    const stack = buildFakeStack();
    const { ctx, started } = stack.buildContext({
      t0: T0,
      runWorkflow: () => {
        seedDeState(stack, 'A');
        return discoverEndpointRun(stack, stageShape('A', DE_INGEST.baseline));
      },
    });
    const result = await getCase('DE-1').run(ctx);
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(stack.endpointPhasesWritten).toEqual(['A']);
    expect(started).toEqual([{ workflow: 'discoverEndpoint' }]);
  });

  it('fails with readable diffs on a missing row, a wrong output, and a wrong source', async () => {
    const stack = buildFakeStack();
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: () => {
        seedDeState(stack, 'A');
        const [first] = expectedInstancesAt('A');
        instanceDoc(stack, {
          hostKey: first.hostKey,
          catalogId: first.catalogId,
          sources: ['logs'],
          hostName: first.hostName,
          hostId: first.hostId,
        });
        return discoverEndpointRun(stack, {
          rows: endpointRowsAt('A', T0).slice(1),
          ingest: { created: 5, unchanged: 1 },
          candidateCount: 6,
        });
      },
    });
    const result = await getCase('DE-1').run(ctx);
    const text = diffsOf(result).join('\n');
    expect(result.status).toBe('fail');
    expect(text).toMatch(/query_processes: expected 7 row\(s\)/);
    expect(text).toMatch(/ingest\.output\.created: expected 6, got 5/);
    expect(text).toMatch(/sources \["logs"\] != \["endpoint"\]/);
  });

  it('is blocked when T0 is older than the window margin', async () => {
    const stack = buildFakeStack();
    const { result, started } = await run(stack, 'DE-1', undefined, OLD_T0);
    expect(result.status).toBe('blocked');
    expect(started).toBe(0);
    expect(stack.endpointPhasesWritten).toEqual([]);
  });

  it('fails on a write to a host outside the case', async () => {
    const stack = buildFakeStack();
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: () => {
        seedDeState(stack, 'A');
        instanceDoc(stack, {
          hostKey: 'synth-win-05',
          catalogId: 'microsoft:windows:10.0.19041.1',
        });
        return discoverEndpointRun(stack, stageShape('A', DE_INGEST.baseline));
      },
    });
    const result = await getCase('DE-1').run(ctx);
    expect(result.status).toBe('fail');
    expect(diffsOf(result).join('\n')).toMatch(
      /1 instance\(s\) written outside the case's host keys/
    );
  });
});

describe('DE-2 and DE-5 (read the DE-1 inventory)', () => {
  const seeded = (): FakeStack => {
    const stack = buildFakeStack();
    seedDeState(stack, 'A');
    return stack;
  };

  it.each(['DE-2', 'DE-5'])('%s passes on the expected state', async (id) => {
    const { result, started } = await run(seeded(), id);
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(started).toBe(0);
  });

  it('DE-2 fails when a Windows system binary got an instance', async () => {
    const stack = seeded();
    instanceDoc(stack, { hostKey: 'synth-win-04', catalogId: 'microsoft:windows:10.0.19041.1' });
    const { result } = await run(stack, 'DE-2');
    expect(diffsOf(result).join('\n')).toMatch(
      /synth-win-04: expected only the document without an executable/
    );
  });

  it('DE-2 fails when an excluded host or the old event got an instance', async () => {
    const stack = seeded();
    instanceDoc(stack, {
      hostKey: 'synth-win-05',
      catalogId: 'synth-noversion:synth-noversion:1.0',
    });
    instanceDoc(stack, { hostKey: 'synth-win-06', catalogId: 'synth-old:synth-old:2.0' });
    const { result } = await run(stack, 'DE-2');
    expect(diffsOf(result)).toEqual([
      'synth-win-05: expected no instance, found 1',
      'synth-win-06: expected no instance, found 1',
    ]);
  });

  it('DE-5 fails on a superseded catalog entry or a second instance', async () => {
    const stack = seeded();
    stack.put(CATALOG_INDEX, 'synth-dual:synth-dual:3.0', { id: 'synth-dual:synth-dual:3.0' });
    instanceDoc(stack, {
      hostKey: 'synth-win-07',
      catalogId: 'synth-dual:synth-dual:3.1',
      installPath: 'C:\\other',
    });
    const text = diffsOf((await run(stack, 'DE-5')).result).join('\n');
    expect(text).toMatch(/expected one Synth-Dual instance, found 2/);
    expect(text).toMatch(/catalog entry synth-dual:synth-dual:3\.0 exists/);
  });
});

describe('DE-3 (phase B)', () => {
  it('writes phase B, patches Firefox, and passes', async () => {
    const stack = buildFakeStack();
    seedDeState(stack, 'A');
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: () => {
        seedDeState(stack, 'B');
        return discoverEndpointRun(stack, stageShape('B', DE_INGEST.versionFlip));
      },
    });
    const result = await getCase('DE-3').run(ctx);
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(stack.endpointPhasesWritten).toEqual(['B']);
  });

  it('fails when nothing is patched', async () => {
    const stack = buildFakeStack();
    seedDeState(stack, 'A');
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: () => discoverEndpointRun(stack, stageShape('B', DE_INGEST.idempotent)),
    });
    const result = await getCase('DE-3').run(ctx);
    expect(result.status).toBe('fail');
    expect(diffsOf(result).join('\n')).toMatch(/status active != patched/);
  });
});

describe('DE-4 (snapshot false)', () => {
  it('passes when the instance of the vanished rows stays active, and restores the documents', async () => {
    const stack = buildFakeStack();
    seedDeState(stack, 'B', { afterFlipRun: true });
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: () =>
        discoverEndpointRun(stack, stageShape('B', DE_INGEST.viewerGone, 'synth-win-03')),
    });
    const result = await getCase('DE-4').run(ctx);
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    // The restore wrote phase A again.
    expect(stack.all(ENDPOINT_DATA_STREAM).length).toBeGreaterThan(0);
  });

  it('fails when the instance was marked removed', async () => {
    const stack = buildFakeStack();
    seedDeState(stack, 'B', { afterFlipRun: true });
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: () => {
        instanceDoc(stack, {
          hostKey: HOST_NAME_ONLY_HOST_KEY,
          catalogId: HOST_NAME_ONLY_CATALOG_ID,
          status: 'removed',
          sources: ['endpoint'],
          hostName: HOST_NAME_ONLY_HOST_KEY,
          hostId: HOST_NAME_ONLY_HOST_KEY,
        });
        return discoverEndpointRun(stack, stageShape('B', DE_INGEST.viewerGone, 'synth-win-03'));
      },
    });
    const result = await getCase('DE-4').run(ctx);
    expect(result.status).toBe('fail');
    expect(diffsOf(result).join('\n')).toMatch(
      /expected status active after its rows vanished, got removed/
    );
  });
});

describe('DE-6 (cross-source identity)', () => {
  const osqueryRun = (stack: FakeStack): CompletedRun =>
    stack.registerRun({
      workflowId: 'si-test-de-6-osquery-row',
      steps: {
        ingest: {
          input: { source: 'osquery', snapshot: false, candidates: [{}] },
          output: ingestOutput({ unchanged: 1 }),
        },
      },
    });

  it('passes when endpoint and Osquery share one instance', async () => {
    const stack = buildFakeStack();
    seedDeState(stack, 'B', { afterFlipRun: true, osqueryMerged: true });
    const { ctx, started } = stack.buildContext({
      t0: T0,
      runWorkflow: (args) =>
        args.yaml
          ? osqueryRun(stack)
          : discoverEndpointRun(stack, stageShape('B', DE_INGEST.idempotent)),
    });
    const result = await getCase('DE-6').run(ctx);
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(started.map(({ workflowId }) => workflowId)).toEqual([
      'si-test-de-6-osquery-row',
      undefined,
    ]);
  });

  it('fails when the Osquery row created a second instance', async () => {
    const stack = buildFakeStack();
    seedDeState(stack, 'B', { afterFlipRun: true, osqueryMerged: true });
    instanceDoc(stack, {
      hostKey: BOTH_HOST_KEY,
      catalogId: BOTH_CATALOG_ID,
      installPath: '/osquery',
      sources: ['osquery'],
    });
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: (args) =>
        args.yaml
          ? osqueryRun(stack)
          : discoverEndpointRun(stack, stageShape('B', DE_INGEST.idempotent)),
    });
    const result = await getCase('DE-6').run(ctx);
    expect(result.status).toBe('fail');
    expect(diffsOf(result).join('\n')).toMatch(/expected one .* instance, found 2/);
  });
});

/** Keeps the helper referenced for the row count the doc table states. */
describe('DE rows', () => {
  it('has 7 rows at stage A and 8 at stage B', () => {
    expect(rowsAt('A')).toHaveLength(7);
    expect(rowsAt('B')).toHaveLength(8);
    expect(instanceIdFor({ hostKey: 'synth-win-01', catalogId: 'mozilla:firefox:124.0.1' })).toBe(
      instanceIdFor({ hostKey: 'synth-win-01', catalogId: 'mozilla:firefox:125.0.1' })
    );
    expect(HOUR_MS).toBeGreaterThan(0);
  });
});
