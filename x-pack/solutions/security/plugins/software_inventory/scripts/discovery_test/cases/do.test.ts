/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * @jest-environment node
 */

import { EVENTS_INDEX, INSTANCES_INDEX } from '../../../common/constants';
import { ingestOutput } from '../assertions';
import type { DoCaseExpectation } from '../expected/do';
import {
  DATA_DRIVEN_CASES,
  DO10,
  DO11,
  DO12,
  DO13,
  DO14,
  DO15_CATALOG_ID,
  DO16_SPOT_CHECKS,
  DO1,
  DO6,
  DO7,
  DO8,
  LINUX_STATE_AFTER_DO7,
  OPENSSL_NEW,
  OPENSSL_OLD,
  R1_CATEGORY_COUNTS,
  R1_HOST_KEYS,
  SYNTH_TOOL,
  osqueryInstance,
} from '../expected/do';
import { AGENTS } from '../fixtures/osquery';
import { instanceIdFor } from '../ids';
import { ALL_CASES, validateRegistry } from '.';
import { cases } from './do';
import type { FakeStep } from './do_di_world';
import { fakeContext, fakeRecord, fakeRun, ingestStep, scriptedOsqueryRun } from './do_di_world';
import type { TestCase } from './types';

const caseOf = (id: string): TestCase => {
  const found = cases.find((candidate) => candidate.id === id);
  if (!found) throw new Error(`no case ${id}`);
  return found;
};

const OSQUERY_ID = 'system-security-software-inventory-discover-osquery';
const LOGS_ID = 'system-security-software-inventory-discover-logs';

const worldOf = (expectation: DoCaseExpectation) => ({
  instances: expectation.instances,
  catalog: expectation.catalog,
  events: expectation.events,
});

describe('DO registry', () => {
  it('lists DO-1..DO-18 in matrix order under family DO', () => {
    expect(cases.map(({ id }) => id)).toEqual(
      Array.from({ length: 18 }, (_, index) => `DO-${index + 1}`)
    );
    expect(cases.every(({ family }) => family === 'DO')).toBe(true);
    expect(() => validateRegistry(ALL_CASES)).not.toThrow();
  });

  it('declares the state-sharing requires chains, always on earlier cases', () => {
    const requires = Object.fromEntries(cases.map(({ id, requires: r }) => [id, r ?? []]));
    expect(requires).toMatchObject({
      'DO-1': [],
      'DO-2': ['DO-1'],
      'DO-3': ['DO-1'],
      'DO-4': ['DO-1'],
      'DO-5': ['DO-1'],
      'DO-6': ['DO-1'],
      'DO-7': ['DO-6'],
      'DO-8': ['DO-7'],
      'DO-12': ['DO-7'],
      'DO-13': ['DO-7'],
      'DO-14': ['DO-12'],
      'DO-15': ['DO-7'],
      'DO-16': [],
      'DO-17': [],
      'DO-18': [],
    });
    const order = ALL_CASES.map(({ id }) => id);
    for (const { id, requires: required = [] } of cases) {
      for (const dependency of required) {
        expect(order.indexOf(dependency)).toBeLessThan(order.indexOf(id));
      }
    }
  });
});

describe('DO expected values', () => {
  it('DO-1 expects 13 instances, 13 first_seen events and 13 catalog entries by category', () => {
    expect(DO1.instances).toHaveLength(13);
    expect(DO1.events).toHaveLength(13);
    expect(DO1.events.every(({ type }) => type === 'first_seen')).toBe(true);
    expect(DO1.catalog).toHaveLength(13);
    expect(R1_CATEGORY_COUNTS).toEqual({ os_package: 6, application: 4, dependency: 3 });
    expect(DO1.runs[0].ingest.linux).toMatchObject({ output: { created: 6 }, candidates: 7 });
    expect(DO1.runs[0].ingest.windows).toMatchObject({ output: { created: 2, skipped: 1 } });
    expect(R1_HOST_KEYS).toEqual(
      expect.arrayContaining(['synth-lin-01', 'synth-agent-lin03', 'synth-win-01', 'synth-mac-01'])
    );
  });

  it('DO-1 keys the instances with the plugin id helper, lower-casing the Windows host', () => {
    const win = DO1.instances.find(({ hostKey }) => hostKey === 'synth-win-01');
    expect(win).toMatchObject({ hostName: 'SYNTH-WIN-01', hostId: 'synth-agent-win01' });
    const lin03 = DO1.instances.find(({ hostKey }) => hostKey === 'synth-agent-lin03');
    expect(lin03).toMatchObject({ hostName: null, hostId: 'synth-agent-lin03' });
    const ids = new Set(DO1.instances.map((item) => instanceIdFor(item)));
    expect(ids.size).toBe(13);
    expect([...ids].every((id) => /^[0-9a-f]{64}$/.test(id))).toBe(true);
  });

  it('DO-6 patches openssl on the same instance id and removes synth-tool', () => {
    const [openssl] = DO6.instances;
    expect(openssl).toMatchObject({
      status: 'patched',
      catalogId: OPENSSL_NEW,
      previousSoftwareId: OPENSSL_OLD,
      versions: ['3.0.7', '3.0.14'],
    });
    expect(instanceIdFor(openssl)).toBe(
      instanceIdFor({ hostKey: 'synth-lin-01', catalogId: OPENSSL_OLD })
    );
    expect(DO6.runs[0].ingest.linux?.output).toEqual({ unchanged: 3, patched: 1, removed: 1 });
    expect(DO6.events.map(({ type }) => type).sort()).toEqual(['removed', 'version_changed']);
    expect(DO6.events.find(({ type }) => type === 'version_changed')).toMatchObject({
      from_version: '3.0.7',
      to_version: '3.0.14',
      cve_count_before: undefined,
    });
    expect(DO6.instances.find(({ catalogId }) => catalogId === SYNTH_TOOL)?.status).toBe('removed');
  });

  it('DO-7 to DO-14 compute the removal, revive and no-snapshot outcomes', () => {
    expect(DO7.runs[0].ingest.linux?.output).toEqual({ unchanged: 4 });
    expect(DO7.events).toEqual([]);
    expect(DO8.runs[0].ingest.linux).toEqual({
      output: { unchanged: 3 },
      snapshot: false,
      candidates: 3,
    });
    expect(DO10.runs[0].failedQueries).toEqual(['linux']);
    expect(DO10.runs[0].ingest.linux?.snapshot).toBe(false);
    expect(DO11.runs).toHaveLength(3);
    expect(DO11.runs.every((run) => run.ingest.linux?.snapshot === false)).toBe(true);
    expect(DO12.runs[0].ingest.dependencies?.output).toEqual({ created: 1, removed: 1 });
    expect(DO12.events.map(({ type }) => type).sort()).toEqual(['first_seen', 'removed']);
    expect(DO13.runs[0].ingest.linux?.output).toEqual({ created: 1 });
    expect(DO14.runs[0].ingest.dependencies?.output).toEqual({ unchanged: 2 });
    expect(DO14.events).toEqual([expect.objectContaining({ type: 'revived' })]);
    expect(LINUX_STATE_AFTER_DO7.map(({ status }) => status)).toEqual([
      'active',
      'active',
      'active',
      'active',
      'removed',
      'active',
    ]);
  });
});

describe('data-driven DO cases', () => {
  it.each(DATA_DRIVEN_CASES.map((expectation) => [expectation.id, expectation] as const))(
    '%s passes when the stack matches the expectation',
    async (id, expectation) => {
      const { ctx, calls } = fakeContext({
        runs: expectation.runs.map((run) => scriptedOsqueryRun(run)),
        world: worldOf(expectation),
      });
      const result = await caseOf(id).run(ctx);
      expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
      expect(result.status).toBe('pass');
      expect(calls).toHaveLength(expectation.runs.length);
      // Variant runs are attributed to the managed id by default.
      expect(calls.every(({ workflow, yaml }) => workflow === 'discoverOsquery' && yaml)).toBe(
        true
      );
    }
  );

  it('DO-10 swaps query_linux for a failing request in the variant', async () => {
    const { ctx, calls } = fakeContext({
      runs: [scriptedOsqueryRun(DO10.runs[0])],
      world: worldOf(DO10),
    });
    await caseOf('DO-10').run(ctx);
    expect(calls[0].yaml).toContain('zz-si-test-missing');
  });

  it('fails when an ingest counter differs, naming the step', async () => {
    const wrong = scriptedOsqueryRun(DO6.runs[0], OSQUERY_ID, (steps) =>
      steps.map((step) =>
        step.name === 'ingest_linux'
          ? ingestStep('ingest_linux', {
              output: { unchanged: 4 },
              snapshot: true,
              candidates: 4,
            })
          : step
      )
    );
    const { ctx } = fakeContext({ runs: [wrong], world: worldOf(DO6) });
    const result = await caseOf('DO-6').run(ctx);
    expect(result.status).toBe('fail');
    expect(result.layers.find(({ layer }) => layer === 'step')?.diffs.join('\n')).toContain(
      'ingest_linux.output.unchanged'
    );
  });

  it('fails when a snapshot is wrongly true on a truncated result', async () => {
    const run = scriptedOsqueryRun({
      ...DO8.runs[0],
      ingest: { linux: { output: { unchanged: 3 }, snapshot: true, candidates: 3 } },
    });
    const { ctx } = fakeContext({ runs: [run], world: worldOf(DO8) });
    const result = await caseOf('DO-8').run(ctx);
    expect(result.status).toBe('fail');
    expect(result.layers[1].diffs.join('\n')).toContain('snapshot');
  });

  it('fails on a missing instance, an extra event, or an unexpected write', async () => {
    const missing = fakeContext({
      runs: [scriptedOsqueryRun(DO6.runs[0])],
      world: { ...worldOf(DO6), instances: DO6.instances.slice(1) },
    });
    expect((await caseOf('DO-6').run(missing.ctx)).layers[2].diffs.join('\n')).toContain('missing');

    const extraEvent = fakeContext({
      runs: [scriptedOsqueryRun(DO7.runs[0])],
      world: { ...worldOf(DO7), events: DO6.events },
    });
    expect((await caseOf('DO-7').run(extraEvent.ctx)).status).toBe('fail');

    const unexpected = fakeContext({
      runs: [scriptedOsqueryRun(DO9Run())],
      world: {
        ...worldOf(DATA_DRIVEN_CASES.find(({ id }) => id === 'DO-9') as DoCaseExpectation),
        count: (index) => (index === EVENTS_INDEX ? 2 : 0),
      },
    });
    const result = await caseOf('DO-9').run(unexpected.ctx);
    expect(result.status).toBe('fail');
    expect(result.layers[2].diffs.join('\n')).toContain('2 event(s) written outside');
  });

  it('fails when a step that must fail completed', async () => {
    const run = scriptedOsqueryRun({ ...DO10.runs[0], failedQueries: [] });
    const { ctx } = fakeContext({ runs: [run], world: worldOf(DO10) });
    const result = await caseOf('DO-10').run(ctx);
    expect(result.status).toBe('fail');
    expect(result.layers[0].diffs.join('\n')).toContain('query_linux: expected failed');
  });
});

const DO9Run = () =>
  (DATA_DRIVEN_CASES.find(({ id }) => id === 'DO-9') as DoCaseExpectation).runs[0];

describe('DO cases that read the DO-1 run', () => {
  const do1Run = scriptedOsqueryRun(DO1.runs[0], OSQUERY_ID);
  const prior = new Map([['DO-1', fakeRecord('DO-1', ['exec-1'])]]);
  const hostCount =
    (counts: Record<string, number>) =>
    (index: string, query: object): number => {
      if (index !== INSTANCES_INDEX) return 0;
      const text = JSON.stringify(query);
      if (text.includes('openssl:')) return 1;
      const host = Object.keys(counts).find((key) => text.includes(`"${key}"`));
      return host ? counts[host] : 0;
    };

  it.each(['DO-2', 'DO-3', 'DO-5'])('%s is blocked without the DO-1 execution id', async (id) => {
    const { ctx } = fakeContext({ runs: [], world: worldOf(DO1) });
    const result = await caseOf(id).run(ctx);
    expect(result.status).toBe('blocked');
    expect(result.notes?.[0]).toContain('DO-1');
  });

  it('DO-2 checks skipped counts and the dropped rows', async () => {
    const { ctx } = fakeContext({
      runs: [],
      world: { ...worldOf(DO1), count: hostCount({ 'synth-win-01': 2 }) },
      priorResults: prior,
      executions: { 'exec-1': do1Run },
    });
    const result = await caseOf('DO-2').run(ctx);
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');

    const extra = fakeContext({
      runs: [],
      world: { ...worldOf(DO1), count: hostCount({ 'synth-win-01': 3 }) },
      priorResults: prior,
      executions: { 'exec-1': do1Run },
    });
    expect((await caseOf('DO-2').run(extra.ctx)).status).toBe('fail');
  });

  it('DO-3 expects created 6 from 7 candidates and one openssl instance', async () => {
    const { ctx } = fakeContext({
      runs: [],
      world: { ...worldOf(DO1), count: hostCount({}) },
      priorResults: prior,
      executions: { 'exec-1': do1Run },
    });
    expect((await caseOf('DO-3').run(ctx)).status).toBe('pass');
    const duplicated = fakeContext({
      runs: [],
      world: { ...worldOf(DO1), count: () => 2 },
      priorResults: prior,
      executions: { 'exec-1': do1Run },
    });
    expect((await caseOf('DO-3').run(duplicated.ctx)).status).toBe('fail');
  });

  it('DO-5 checks application categories and install paths', async () => {
    const { ctx } = fakeContext({
      runs: [],
      world: worldOf(DO1),
      priorResults: prior,
      executions: { 'exec-1': do1Run },
    });
    expect((await caseOf('DO-5').run(ctx)).status).toBe('pass');
    const wrongCategory = fakeContext({
      runs: [],
      world: {
        ...worldOf(DO1),
        catalog: DO1.catalog.map((entry) => ({
          ...entry,
          fields: { ...entry.fields, category: 'os_package' as const },
        })),
      },
      priorResults: prior,
      executions: { 'exec-1': do1Run },
    });
    expect((await caseOf('DO-5').run(wrongCategory.ctx)).status).toBe('fail');
  });
});

describe('DO-4', () => {
  const unknownRun = (assertions?: (steps: FakeStep[]) => FakeStep[]) =>
    scriptedOsqueryRun(
      {
        label: 'DO-4',
        steps: {},
        ingest: { linux: { output: { created: 1 }, snapshot: true, candidates: 1 } },
      },
      OSQUERY_ID,
      assertions
    );
  const instances = [
    osqueryInstance(AGENTS.lin01, 'sudo_project:sudo:1.9.9', 'active'),
    osqueryInstance(AGENTS.lin03, 'haxx:curl:7.88.1', 'active'),
    ...DO1.instances.filter(({ hostKey }) => hostKey === 'synth-win-01').slice(0, 1),
    osqueryInstance(AGENTS.unknown, 'synth-orphan:synth-orphan:0.1.0', 'active', {
      versions: ['0.1.0'],
    }),
  ];

  it('passes on the name fallback and notes the unchecked Kibana log line', async () => {
    const { ctx } = fakeContext({
      runs: [unknownRun()],
      world: {
        instances,
        catalog: [],
        events: [
          {
            type: 'first_seen',
            source: 'osquery',
            software_id: 'synth-orphan:synth-orphan:0.1.0',
            host: { key: 'synth-agent-unknown-99', id: 'synth-agent-unknown-99' },
            to_version: '0.1.0',
          },
        ],
      },
    });
    const result = await caseOf('DO-4').run(ctx);
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(result.notes?.join(' ')).toContain('.fleet-agents does not exist');
    expect(result.notes?.join(' ')).toContain('Kibana log');
  });

  it('fails when the unknown agent gets a host name', async () => {
    const { ctx } = fakeContext({
      runs: [unknownRun()],
      world: {
        instances: instances.map((item) =>
          item.hostKey === 'synth-agent-unknown-99' ? { ...item, hostName: 'unexpected' } : item
        ),
        catalog: [],
        events: [
          {
            type: 'first_seen',
            source: 'osquery',
            software_id: 'synth-orphan:synth-orphan:0.1.0',
            host: { key: 'synth-agent-unknown-99' },
          },
        ],
      },
    });
    expect((await caseOf('DO-4').run(ctx)).layers[2].diffs.join('\n')).toContain('host.name');
  });
});

describe('DO-15', () => {
  const service = (sources: Array<'logs' | 'osquery'>) => ({
    hostKey: 'synth-lin-01',
    catalogId: DO15_CATALOG_ID,
    status: 'active' as const,
    sources,
    hostName: 'synth-lin-01',
  });
  const logsRun = fakeRun({
    workflowId: LOGS_ID,
    steps: [
      { name: 'query_appliances' },
      { name: 'query_services' },
      { name: 'build_candidates' },
      { name: 'ingest', output: ingestOutput({ created: 1 }) },
    ],
  });
  const withService = {
    output: { unchanged: 5 },
    snapshot: true,
    candidates: 5,
  };
  const withoutService = { output: { unchanged: 4, removed: 0 }, snapshot: true, candidates: 4 };
  const osqueryRun = (linux: typeof withService) =>
    scriptedOsqueryRun({ label: 'DO-15', steps: {}, ingest: { linux } }, OSQUERY_ID);
  const world = (runsDone: number) => ({
    instances: runsDone === 0 ? [] : [service(runsDone === 1 ? ['logs'] : ['logs', 'osquery'])],
    catalog: [{ id: DO15_CATALOG_ID, fields: { category: 'application' as const } }],
    events: [
      {
        type: 'first_seen' as const,
        source: 'logs' as const,
        software_id: DO15_CATALOG_ID,
        host: { key: 'synth-lin-01' },
      },
    ],
  });

  it('writes a service log, runs logs then Linux twice, and keeps category application', async () => {
    const { ctx, calls, logDocs } = fakeContext({
      runs: [logsRun, osqueryRun(withService), osqueryRun(withoutService)],
      world,
    });
    const result = await caseOf('DO-15').run(ctx);
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(calls.map(({ workflow }) => workflow)).toEqual([
      'discoverLogs',
      'discoverOsquery',
      'discoverOsquery',
    ]);
    expect(calls[0].yaml).toBeUndefined();
    expect(logDocs).toHaveLength(1);
    expect(JSON.stringify(logDocs[0])).toContain('synth-svc');
    expect(calls[1].yaml).toContain('name: synth-svc');
    expect(calls[2].yaml).not.toContain('name: synth-svc');
    expect(result.notes?.join(' ')).toContain('R5');
  });

  it('fails when the third run removes the shared instance', async () => {
    const { ctx } = fakeContext({
      runs: [logsRun, osqueryRun(withService), osqueryRun(withoutService)],
      world: (runsDone) => {
        const base = world(runsDone);
        return runsDone === 3
          ? {
              ...base,
              instances: [{ ...service(['logs', 'osquery']), status: 'removed' as const }],
            }
          : base;
      },
    });
    const result = await caseOf('DO-15').run(ctx);
    expect(result.status).toBe('fail');
    expect(result.layers[2].diffs.join('\n')).toContain('status removed != active');
  });

  it('is blocked for a stale t0 or when the instance already exists', async () => {
    const stale = fakeContext({
      runs: [],
      world,
      t0: new Date(Date.now() - 23 * 60 * 60 * 1000),
    });
    expect((await caseOf('DO-15').run(stale.ctx)).status).toBe('blocked');
    const existing = fakeContext({ runs: [], world: () => world(1) });
    const result = await caseOf('DO-15').run(existing.ctx);
    expect(result.status).toBe('blocked');
    expect(result.notes?.[0]).toContain('already exists');
  });
});

describe('DO-16 and DO-17', () => {
  const bulkSteps = (
    linux: Partial<FakeStep>,
    times: { startedAt: string; finishedAt: string }
  ): FakeStep[] => [
    { name: 'si_test_query_linux_rows' },
    { name: 'query_linux' },
    { name: 'build_linux' },
    { name: 'ingest_linux', ...times, ...linux },
    ...['windows', 'macos', 'dependencies'].flatMap((key): FakeStep[] => [
      { name: `query_${key}` },
      { name: `build_${key}` },
      ingestStep(`ingest_${key}`, { output: {}, snapshot: true, candidates: 0 }),
    ]),
  ];
  const fast = { startedAt: '2026-11-18T10:00:00.000Z', finishedAt: '2026-11-18T10:00:05.000Z' };
  const slow = { startedAt: '2026-11-18T10:00:00.000Z', finishedAt: '2026-11-18T10:01:05.000Z' };
  const ok16: Partial<FakeStep> = ingestStep('ingest_linux', {
    output: { created: 5000, removed: 0 },
    snapshot: false,
    candidates: 5000,
  });
  const world16 = {
    instances: DO16_SPOT_CHECKS.map(({ catalogId }) =>
      osqueryInstance(AGENTS.bulk, catalogId, 'active')
    ),
    catalog: DO16_SPOT_CHECKS.map(({ catalogId }) => ({
      id: catalogId,
      fields: { category: 'os_package' as const },
    })),
    events: [],
    count: (index: string, query: object) =>
      JSON.stringify(query).includes('must_not')
        ? 0
        : index === INSTANCES_INDEX || index === EVENTS_INDEX
        ? 5000
        : 0,
  };

  it('DO-16 passes for 5000 created rows in under 60 seconds', async () => {
    const { ctx, calls } = fakeContext({
      runs: [fakeRun({ workflowId: OSQUERY_ID, steps: bulkSteps(ok16, fast) })],
      world: world16,
    });
    const result = await caseOf('DO-16').run(ctx);
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(calls[0].wait?.timeoutMs).toBeGreaterThan(60_000);
    expect(calls[0].yaml).toContain('synth-pkg-');
  });

  it('DO-16 fails when the step is slow or the instance count is short', async () => {
    const slowRun = fakeContext({
      runs: [fakeRun({ workflowId: OSQUERY_ID, steps: bulkSteps(ok16, slow) })],
      world: world16,
    });
    expect((await caseOf('DO-16').run(slowRun.ctx)).layers[1].diffs.join('\n')).toContain('took');
    const short = fakeContext({
      runs: [fakeRun({ workflowId: OSQUERY_ID, steps: bulkSteps(ok16, fast) })],
      world: { ...world16, count: () => 4999 },
    });
    expect((await caseOf('DO-16').run(short.ctx)).status).toBe('fail');
  });

  const failed17: Partial<FakeStep> = {
    status: 'failed',
    input: {
      source: 'osquery',
      snapshot: true,
      candidates: Array.from({ length: 5001 }, () => ({})),
    },
    error: { message: 'Invalid input: candidates must contain at most 5000 items' },
  };

  it('DO-17 passes when ingest_linux fails validation naming candidates and nothing is written', async () => {
    const { ctx } = fakeContext({
      runs: [fakeRun({ workflowId: OSQUERY_ID, steps: bulkSteps(failed17, fast) })],
      world: { instances: [], catalog: [], events: [] },
    });
    const result = await caseOf('DO-17').run(ctx);
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
  });

  it('DO-17 fails when the step succeeded or writes happened', async () => {
    const succeeded = fakeContext({
      runs: [fakeRun({ workflowId: OSQUERY_ID, steps: bulkSteps(ok16, fast) })],
      world: { instances: [], catalog: [], events: [] },
    });
    expect((await caseOf('DO-17').run(succeeded.ctx)).status).toBe('fail');
    const written = fakeContext({
      runs: [fakeRun({ workflowId: OSQUERY_ID, steps: bulkSteps(failed17, fast) })],
      world: { instances: [], catalog: [], events: [], count: () => 1 },
    });
    expect((await caseOf('DO-17').run(written.ctx)).layers[2].diffs.join('\n')).toContain(
      'written outside'
    );
  });
});

describe('DO-18', () => {
  const prodRun = (queryStatus = 'failed') =>
    fakeRun({
      workflowId: OSQUERY_ID,
      steps: ['linux', 'windows', 'macos', 'dependencies'].flatMap((key): FakeStep[] => [
        queryStatus === 'failed'
          ? {
              name: `query_${key}`,
              status: 'failed',
              error: { message: 'osquery_manager not installed' },
            }
          : { name: `query_${key}`, output: {} },
        { name: `build_${key}` },
        ingestStep(`ingest_${key}`, { output: {}, snapshot: false, candidates: 0 }),
      ]),
    });
  const emptyWorld = { instances: [], catalog: [], events: [] };

  it('is blocked when .fleet-agents exists, without running anything', async () => {
    const { ctx, calls } = fakeContext({
      runs: [],
      world: { ...emptyWorld, exists: (path) => path === '/.fleet-agents' },
    });
    const result = await caseOf('DO-18').run(ctx);
    expect(result.status).toBe('blocked');
    expect(calls).toHaveLength(0);
  });

  it('runs the stored YAML and records the query errors', async () => {
    const { ctx, calls } = fakeContext({ runs: [prodRun()], world: emptyWorld });
    const result = await caseOf('DO-18').run(ctx);
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(calls[0]).toEqual({ workflow: 'discoverOsquery' });
    expect(JSON.stringify(result.layers[1].evidence)).toContain('osquery_manager not installed');
  });

  it('fails when a query step completes', async () => {
    const { ctx } = fakeContext({ runs: [prodRun('completed')], world: emptyWorld });
    expect((await caseOf('DO-18').run(ctx)).status).toBe('fail');
  });
});
