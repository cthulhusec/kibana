/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * @jest-environment node
 */

import { ingestOutput } from '../assertions';
import type { CompletedRun } from '../clients';
import {
  DL_INGEST,
  candidatesAt,
  dlHostKeys,
  expectedEventsAt,
  expectedInstancesAt,
} from '../expected/dl';
import { MULTI_VALUED_OBSERVER_SPEC, buildPhaseDocs } from '../logs/generate_logs';
import { SYNTHETIC_DATA_STREAM, SYNTHETIC_TEMPLATE_NAME } from '../logs/template';
import { instanceIdFor } from '../ids';
import { getWorkflowId } from '../variants/build_variant';
import { ALL_CASES } from '.';
import { cases } from './dl';
import { applianceRowsAt, serviceRowsAt } from './dl_support';
import type { ExpectedEsqlRow } from './dl_support';
import type { FakeStack } from './fake_stack';
import { buildFakeStack } from './fake_stack';
import { esqlOutput, instanceDoc, putEvent, seedDlState } from './test_seed';
import type { CaseRecord, CaseResult, TestCase } from './types';
import { runCases } from '../cli';

const T0 = new Date(Date.now() - 5 * 60_000);
const OLD_T0 = new Date(Date.now() - 3 * 3_600_000);

const getCase = (id: string): TestCase => {
  const found = cases.find((testCase) => testCase.id === id);
  if (!found) throw new Error(`no case ${id}`);
  return found;
};

interface RunShape {
  appliances: readonly ExpectedEsqlRow[] | 'failed';
  services: readonly ExpectedEsqlRow[] | 'failed';
  ingest: Partial<Record<'created' | 'unchanged' | 'patched' | 'removed' | 'skipped', number>>;
  candidateCount: number;
}

const UNKNOWN_COLUMN = { message: 'verification_exception: Unknown column [observer.product]' };

const discoverLogsRun = (stack: FakeStack, shape: RunShape): CompletedRun =>
  stack.registerRun({
    workflowId: getWorkflowId('discoverLogs'),
    steps: {
      query_appliances:
        shape.appliances === 'failed'
          ? { status: 'failed', error: UNKNOWN_COLUMN }
          : { output: esqlOutput(shape.appliances) },
      query_services:
        shape.services === 'failed'
          ? { status: 'failed', error: UNKNOWN_COLUMN }
          : { output: esqlOutput(shape.services) },
      build_candidates: { output: { candidates_json: '[]' } },
      ingest: {
        input: {
          source: 'logs',
          snapshot: false,
          candidates: Array.from({ length: shape.candidateCount }, () => ({})),
        },
        output: ingestOutput(shape.ingest),
      },
    },
  });

const stageShape = (stage: 'A' | 'B', ingest: RunShape['ingest']): RunShape => ({
  appliances: applianceRowsAt(stage, T0),
  services: serviceRowsAt(stage, T0),
  ingest,
  candidateCount: candidatesAt(stage).length,
});

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

describe('DL registry', () => {
  it('registers DL-0..DL-10 in matrix order with prerequisites', () => {
    expect(cases.map(({ id }) => id)).toEqual(
      Array.from({ length: 11 }, (_, index) => `DL-${index}`)
    );
    const requires = Object.fromEntries(cases.map(({ id, requires: r }) => [id, r ?? []]));
    expect(requires).toEqual({
      'DL-0': [],
      'DL-1': ['DO-1'],
      'DL-2': ['DL-1'],
      'DL-3': ['DL-1'],
      'DL-4': ['DL-1'],
      'DL-5': ['DL-1'],
      'DL-6': ['DL-1'],
      'DL-7': ['DL-1'],
      'DL-8': ['DL-7'],
      'DL-9': ['DL-8'],
      'DL-10': ['DL-8'],
    });
    expect(cases.every(({ family }) => family === 'DL')).toBe(true);
  });

  it('only requires cases that exist and run earlier', () => {
    const order = ALL_CASES.map(({ id }) => id);
    for (const testCase of cases) {
      for (const required of testCase.requires ?? []) {
        expect(order).toContain(required);
        expect(order.indexOf(required)).toBeLessThan(order.indexOf(testCase.id));
      }
    }
  });

  it('blocks a case when its prerequisite has not passed', async () => {
    const stack = buildFakeStack();
    const records = await runCases([getCase('DL-1'), getCase('DL-2')], {
      config: buildFakeStack().buildContext({
        t0: T0,
        runWorkflow: () => discoverLogsRun(stack, stageShape('A', {})),
      }).ctx.config,
      kibana: stack.kibana,
      es: stack.es,
      t0: T0,
      log: { info: () => {}, warn: () => {}, debug: () => {} },
      prior: new Map<string, CaseRecord>(),
      startNvdStub: () => Promise.reject(new Error('not needed')),
    });
    expect(records.map(({ id, status }) => `${id}:${status}`)).toEqual([
      'DL-1:blocked',
      'DL-2:blocked',
    ]);
    expect(records[0].notes).toEqual(['requires passing DO-1']);
  });
});

describe('DL-0', () => {
  it('passes when both queries fail on unknown columns and ingest writes nothing', async () => {
    const stack = buildFakeStack();
    const { result, started } = await run(stack, 'DL-0', () =>
      discoverLogsRun(stack, {
        appliances: 'failed',
        services: 'failed',
        ingest: {},
        candidateCount: 0,
      })
    );
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(started).toBe(1);
    expect(result.layers.map(({ layer }) => layer)).toEqual(['engine', 'step', 'inventory']);
  });

  it('fails when a query succeeds or the error is not an unknown column', async () => {
    const stack = buildFakeStack();
    const { result } = await run(stack, 'DL-0', () =>
      stack.registerRun({
        workflowId: getWorkflowId('discoverLogs'),
        steps: {
          query_appliances: { output: esqlOutput([]) },
          query_services: { status: 'failed', error: { message: 'timeout' } },
          build_candidates: { output: { candidates_json: '[]' } },
          ingest: {
            input: { source: 'logs', snapshot: false, candidates: [] },
            output: ingestOutput({}),
          },
        },
      })
    );
    expect(result.status).toBe('fail');
    expect(diffsOf(result).join('\n')).toMatch(/query_appliances: expected failed, got completed/);
    expect(diffsOf(result).join('\n')).toMatch(/query_services: error does not match/);
  });

  it('is blocked, without running, when logs data streams already exist', async () => {
    const stack = buildFakeStack();
    stack.dataStreams.add(SYNTHETIC_DATA_STREAM);
    const { result, started } = await run(stack, 'DL-0');
    expect(result.status).toBe('blocked');
    expect(started).toBe(0);
  });
});

describe('DL-1', () => {
  it('writes phase A, runs the stored YAML, and passes on the expected inventory', async () => {
    const stack = buildFakeStack();
    instanceDoc(stack, {
      hostKey: 'synth-lin-01',
      catalogId: 'f5:nginx:1.18.0',
      sources: ['osquery'],
      hostName: 'synth-lin-01',
      hostId: 'synth-agent-lin01',
    });
    const { ctx, started } = stack.buildContext({
      t0: T0,
      runWorkflow: () => {
        seedDlState(stack, 'A', T0);
        return discoverLogsRun(stack, stageShape('A', DL_INGEST.baselineAfterR1));
      },
    });
    const result = await getCase('DL-1').run(ctx);
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(stack.logPhasesWritten).toEqual(['A']);
    expect(started).toEqual([{ workflow: 'discoverLogs' }]);
  });

  it('fails with readable diffs when the ES|QL rows, ingest output, or merge are wrong', async () => {
    const stack = buildFakeStack();
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: () => {
        seedDlState(stack, 'A', T0);
        // The shared instance lost its logs source, and one appliance row is missing.
        const [shared] = expectedInstancesAt('A').filter(
          ({ hostKey }) => hostKey === 'synth-lin-01'
        );
        instanceDoc(stack, {
          hostKey: shared.hostKey,
          catalogId: shared.catalogId,
          sources: ['osquery'],
          hostName: 'synth-lin-01',
        });
        return discoverLogsRun(stack, {
          ...stageShape('A', { created: 10 }),
          appliances: applianceRowsAt('A', T0).slice(1),
        });
      },
    });
    const result = await getCase('DL-1').run(ctx);
    const text = diffsOf(result).join('\n');
    expect(result.status).toBe('fail');
    expect(text).toMatch(/query_appliances: expected 6 row\(s\)/);
    expect(text).toMatch(/ingest\.output\.created: expected 9, got 10/);
    expect(text).toMatch(/sources \["osquery"\] != \["osquery","logs"\]/);
  });

  it('is blocked when T0 is older than the 24 h window margin', async () => {
    const stack = buildFakeStack();
    const { result, started } = await run(stack, 'DL-1', undefined, OLD_T0);
    expect(result.status).toBe('blocked');
    expect(result.notes?.[0]).toMatch(/Regenerate the logs with a fresh --t0/);
    expect(started).toBe(0);
    expect(stack.logPhasesWritten).toEqual([]);
  });

  it('fails on a write to a host outside the case', async () => {
    const stack = buildFakeStack();
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: () => {
        seedDlState(stack, 'A', T0);
        instanceDoc(stack, { hostKey: 'synth-collector-01', catalogId: 'fortinet:fortios:7.2.4' });
        return discoverLogsRun(stack, stageShape('A', DL_INGEST.baselineAfterR1));
      },
    });
    const result = await getCase('DL-1').run(ctx);
    expect(result.status).toBe('fail');
    expect(diffsOf(result).join('\n')).toMatch(
      /1 instance\(s\) written outside the case's host keys/
    );
  });
});

describe('DL-2 .. DL-6 (read the DL-1 inventory)', () => {
  const seeded = (): FakeStack => {
    const stack = buildFakeStack();
    seedDlState(stack, 'A', T0);
    return stack;
  };

  it.each(['DL-2', 'DL-3', 'DL-4', 'DL-5', 'DL-6'])(
    '%s passes on the expected state',
    async (id) => {
      const stack = seeded();
      const { result, started } = await run(stack, id);
      expect(diffsOf(result)).toEqual([]);
      expect(result.status).toBe('pass');
      expect(started).toBe(0);
    }
  );

  it('DL-2 fails when the collector gets an instance', async () => {
    const stack = seeded();
    instanceDoc(stack, { hostKey: 'synth-collector-01', catalogId: 'fortinet:fortios:7.2.4' });
    const { result } = await run(stack, 'DL-2');
    expect(diffsOf(result)).toEqual(['synth-collector-01: expected no instance, found 1']);
  });

  it('DL-3 fails when a fallback instance carries a host name', async () => {
    const stack = seeded();
    instanceDoc(stack, {
      hostKey: 'synth-sn-0003',
      catalogId: 'cisco:adaptive_security_appliance_software:9.16.4',
      hostName: 'oops',
      hostId: 'SYNTH-SN-0003',
    });
    const { result } = await run(stack, 'DL-3');
    expect(diffsOf(result)).toEqual([expect.stringMatching(/host\.name "oops" != null/)]);
  });

  it('DL-4 fails on a second synth-checkout instance and on a wrong observed time', async () => {
    const stack = seeded();
    instanceDoc(stack, {
      hostKey: 'synth-web-01',
      catalogId: 'synth-checkout:synth-checkout:2.4.0',
      installPath: '/opt/other',
      hostName: 'SYNTH-Web-01',
    });
    const { result } = await run(stack, 'DL-4');
    expect(diffsOf(result)).toEqual([
      'synth-web-01: expected one synth-checkout instance, found 2',
    ]);
    const other = seeded();
    instanceDoc(other, {
      hostKey: 'synth-fw-01',
      catalogId: 'fortinet:fortios:7.2.4',
      hostName: 'synth-fw-01',
      hostId: 'synth-fw-01',
      firstSeen: new Date(T0.getTime() - 2 * 3_600_000).toISOString(),
      lastSeen: new Date(T0.getTime() - 30 * 60_000).toISOString(),
    });
    expect(diffsOf((await run(other, 'DL-4')).result).join('\n')).toMatch(
      /synth-fw-01: first_seen/
    );
  });

  it('DL-5 fails when the 26 h appliance or a version-less row appears, or the 23 h one is missing', async () => {
    const stack = seeded();
    instanceDoc(stack, { hostKey: 'synth-fw-03', catalogId: 'fortinet:fortios:7.2.4' });
    instanceDoc(stack, { hostKey: 'synth-web-03', catalogId: 'synth-api:synth-api:1.0' });
    const { result } = await run(stack, 'DL-5');
    expect(diffsOf(result)).toEqual([
      'synth-fw-03: expected no instance, found 1',
      'synth-web-03: expected no instance, found 1',
    ]);
  });

  it('DL-6 fails when the merge produced a second nginx instance', async () => {
    const stack = seeded();
    instanceDoc(stack, {
      hostKey: 'synth-lin-01',
      catalogId: 'f5:nginx:1.18.0',
      installPath: '/x',
    });
    const { result } = await run(stack, 'DL-6');
    expect(diffsOf(result)).toEqual(['synth-lin-01: expected one nginx instance, found 2']);
  });
});

describe('DL-7 and DL-8 (phase B)', () => {
  it('DL-7 writes phase B, flips web-02 to patched, and passes', async () => {
    const stack = buildFakeStack();
    seedDlState(stack, 'A', T0);
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: () => {
        seedDlState(stack, 'B', T0);
        return discoverLogsRun(stack, stageShape('B', DL_INGEST.versionFlip));
      },
    });
    const result = await getCase('DL-7').run(ctx);
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(stack.logPhasesWritten).toEqual(['B']);
  });

  it('DL-7 fails when nothing is patched', async () => {
    const stack = buildFakeStack();
    seedDlState(stack, 'A', T0);
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: () => discoverLogsRun(stack, stageShape('B', DL_INGEST.idempotent)),
    });
    const result = await getCase('DL-7').run(ctx);
    expect(result.status).toBe('fail');
    const text = diffsOf(result).join('\n');
    expect(text).toMatch(/ingest\.output\.unchanged: expected 10, got 9|unchanged: expected 9/);
    expect(text).toMatch(/status active != patched/);
    expect(text).toMatch(/events: expected 10/);
  });

  it('DL-8 passes with unchanged output and no new events', async () => {
    const stack = buildFakeStack();
    seedDlState(stack, 'B', T0, { afterFlipRun: true });
    const { result } = await run(stack, 'DL-8', () =>
      discoverLogsRun(stack, stageShape('B', DL_INGEST.idempotent))
    );
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
  });

  it('DL-8 fails on an extra event', async () => {
    const stack = buildFakeStack();
    seedDlState(stack, 'B', T0, { afterFlipRun: true });
    const [first] = expectedEventsAt('B', T0);
    putEvent(stack, {
      ...first,
      '@timestamp': new Date(T0.getTime() - 1000).toISOString(),
      instance_id: 'dup',
    });
    const { result } = await run(stack, 'DL-8', () =>
      discoverLogsRun(stack, stageShape('B', DL_INGEST.idempotent))
    );
    expect(diffsOf(result).join('\n')).toMatch(/events: expected 10 .* got 11/);
  });
});

describe('DL-9', () => {
  const seedLogs = (stack: FakeStack): void => {
    stack.dataStreams.add(SYNTHETIC_DATA_STREAM);
    stack.templates.add(SYNTHETIC_TEMPLATE_NAME);
    for (const doc of [...buildPhaseDocs('A', T0), ...buildPhaseDocs('B', T0)]) {
      stack.put(SYNTHETIC_DATA_STREAM, doc._id, JSON.parse(JSON.stringify(doc._source)));
    }
  };

  it('runs without the template and serial docs, passes, then restores the logs', async () => {
    const stack = buildFakeStack();
    seedDlState(stack, 'B', T0, { afterFlipRun: true });
    seedLogs(stack);
    let seenAtRun: { template: boolean; serialDocs: number } | undefined;
    const { result } = await run(stack, 'DL-9', () => {
      seenAtRun = {
        template: stack.templates.has(SYNTHETIC_TEMPLATE_NAME),
        serialDocs: stack
          .all(SYNTHETIC_DATA_STREAM)
          .filter((doc) => JSON.stringify(doc).includes('serial_number')).length,
      };
      return discoverLogsRun(stack, {
        appliances: 'failed',
        services: serviceRowsAt('B', T0),
        ingest: DL_INGEST.servicesOnly,
        candidateCount: serviceRowsAt('B', T0).length,
      });
    });
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(seenAtRun).toEqual({ template: false, serialDocs: 0 });
    // Restored: template, data stream, and both phases (including the serial document A3).
    expect(stack.templates.has(SYNTHETIC_TEMPLATE_NAME)).toBe(true);
    expect(stack.dataStreams.has(SYNTHETIC_DATA_STREAM)).toBe(true);
    expect(stack.all(SYNTHETIC_DATA_STREAM)).toHaveLength(
      buildPhaseDocs('A', T0).length + buildPhaseDocs('B', T0).length
    );
  });

  it('restores the logs even when the run throws', async () => {
    const stack = buildFakeStack();
    seedDlState(stack, 'B', T0, { afterFlipRun: true });
    seedLogs(stack);
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: () => Promise.reject(new Error('Kibana is down')),
    });
    await expect(getCase('DL-9').run(ctx)).rejects.toThrow('Kibana is down');
    expect(stack.templates.has(SYNTHETIC_TEMPLATE_NAME)).toBe(true);
    expect(stack.all(SYNTHETIC_DATA_STREAM)).toHaveLength(
      buildPhaseDocs('A', T0).length + buildPhaseDocs('B', T0).length
    );
  });

  it('fails when the appliance query still succeeds', async () => {
    const stack = buildFakeStack();
    seedDlState(stack, 'B', T0, { afterFlipRun: true });
    seedLogs(stack);
    const { result } = await run(stack, 'DL-9', () =>
      discoverLogsRun(stack, stageShape('B', DL_INGEST.idempotent))
    );
    expect(result.status).toBe('fail');
    expect(diffsOf(result).join('\n')).toMatch(/query_appliances: expected failed, got completed/);
  });
});

describe('DL-10', () => {
  const multiValuedRun = (stack: FakeStack, hostId: string): CompletedRun => {
    const row = {
      host_id: hostId,
      vendor: 'F5',
      name: 'BIG-IP',
      version: '16.1.4',
      observedAt: new Date(T0.getTime() - 3_600_000).toISOString(),
    };
    instanceDoc(stack, {
      hostKey: hostId,
      catalogId: 'f5:big-ip:16.1.4',
      hostName: null,
      hostId,
      firstSeen: row.observedAt,
      lastSeen: row.observedAt,
    });
    putEvent(stack, {
      type: 'first_seen',
      '@timestamp': row.observedAt,
      instance_id: instanceIdFor({ hostKey: hostId, catalogId: 'f5:big-ip:16.1.4' }),
      host: { key: hostId },
      source: 'logs',
      software_id: 'f5:big-ip:16.1.4',
      to_version: '16.1.4',
    });
    return discoverLogsRun(stack, {
      appliances: [...applianceRowsAt('B', T0), row],
      services: serviceRowsAt('B', T0),
      ingest: DL_INGEST.multiValued,
      candidateCount: candidatesAt('B').length + 1,
    });
  };

  it('writes the multi-valued doc and records the sorted-first value', async () => {
    const stack = buildFakeStack();
    seedDlState(stack, 'B', T0, { afterFlipRun: true });
    const { ctx } = stack.buildContext({
      t0: T0,
      runWorkflow: () => multiValuedRun(stack, '10.9.9.9'),
    });
    const result = await getCase('DL-10').run(ctx);
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(result.notes).toEqual(['MV_FIRST(observer.ip) became host_id 10.9.9.9']);
    expect(stack.all(SYNTHETIC_DATA_STREAM)).toHaveLength(1);
    expect(MULTI_VALUED_OBSERVER_SPEC.fields.observer?.ip).toEqual(['192.0.2.78', '10.9.9.9']);
  });

  it('passes with a note when the other value comes first, and fails on any third value', async () => {
    const stack = buildFakeStack();
    seedDlState(stack, 'B', T0, { afterFlipRun: true });
    const other = stack.buildContext({
      t0: T0,
      runWorkflow: () => multiValuedRun(stack, '192.0.2.78'),
    });
    const passed = await getCase('DL-10').run(other.ctx);
    expect(passed.status).toBe('pass');
    expect(passed.notes?.[1]).toMatch(/Unexpected order/);

    const third = buildFakeStack();
    seedDlState(third, 'B', T0);
    const bad = third.buildContext({
      t0: T0,
      runWorkflow: () => multiValuedRun(third, '172.16.0.1'),
    });
    const failed = await getCase('DL-10').run(bad.ctx);
    expect(failed.status).toBe('fail');
    expect(diffsOf(failed).join('\n')).toMatch(/host_id 172\.16\.0\.1 is neither/);
  });

  it('keeps the expected instance keys in the generator host list', () => {
    expect(dlHostKeys('B')).toHaveLength(10);
    expect(expectedInstancesAt('B').some(({ hostKey }) => hostKey === 'synth-web-02')).toBe(true);
  });
});
