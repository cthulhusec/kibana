/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * @jest-environment node
 */

import { EVENTS_INDEX, INSTANCES_INDEX, ROLLUPS_INDEX } from '../../../common/constants';
import { ingestOutput } from '../assertions';
import type { CompletedRun } from '../clients';
import {
  SE1_WEB01,
  SE3_FW02,
  SE4_EDGE_ONLY,
  SE5_REDIS,
  SE6_WEB02,
  SE7_POLICY,
  computeRollupOracle,
  dayEndOf,
  dayStartOf,
} from '../expected/se';
import { FIXTURE_ROW_TIMESTAMP } from '../fixtures/osquery';
import { instanceIdFor } from '../ids';
import { getWorkflowId } from '../variants/build_variant';
import { ALL_CASES } from '.';
import type { Doc, FakeStack } from './fake_stack';
import { buildFakeStack } from './fake_stack';
import { cases } from './se';
import { staleInstanceRef, todayUtc } from './se_support';
import { instanceDoc, putEvent, seedDlState, seedExposure } from './test_seed';
import type { CaseContext, CaseRecord, CaseResult, TestCase } from './types';

const T0 = new Date(Date.now() - 5 * 60_000);
const DAY_MS = 24 * 60 * 60 * 1000;
const EARLIER = new Date(Date.now() - 60 * 60_000).toISOString();

const getCase = (id: string): TestCase => {
  const found = cases.find((testCase) => testCase.id === id);
  if (!found) throw new Error(`no case ${id}`);
  return found;
};

const diffsOf = (result: CaseResult): string[] => result.layers.flatMap(({ diffs }) => diffs);

const statusOf = (doc: Doc): string => String(doc.status);

/** The world after a passing DO-1, DI-2, DL-1 and one `score-exposure` run. */
const seedWorld = (stack: FakeStack): void => {
  seedDlState(stack, 'B', T0, { writtenAt: EARLIER });
  for (const expectation of [SE1_WEB01, SE3_FW02, ...SE4_EDGE_ONLY, SE5_REDIS, ...SE7_POLICY]) {
    seedExposure(stack, expectation, { writtenAt: EARLIER });
  }
  instanceDoc(stack, {
    hostKey: 'synth-lin-01',
    catalogId: 'openssl:openssl:3.0.7',
    sources: ['osquery'],
    writtenAt: EARLIER,
  });
  const slack = staleInstanceRef();
  instanceDoc(stack, {
    ...slack,
    writtenAt: EARLIER,
    sources: ['osquery'],
    firstSeen: T0.toISOString(),
    lastSeen: T0.toISOString(),
  });
};

const withManualEvidence = (stack: FakeStack): void => {
  seedExposure(stack, SE6_WEB02, { writtenAt: EARLIER });
};

const scoreRun = (stack: FakeStack, { rollup = true }: { rollup?: boolean } = {}): CompletedRun => {
  const instances = stack.all(INSTANCES_INDEX);
  const cutoff = Date.now() - 30 * DAY_MS;
  const eligible = instances.filter(
    (doc) =>
      ['active', 'patched'].includes(statusOf(doc)) && Date.parse(String(doc.last_seen)) < cutoff
  );
  for (const doc of eligible) {
    stack.put(INSTANCES_INDEX, String(doc.id), { ...doc, status: 'stale' });
    putEvent(stack, {
      type: 'stale',
      '@timestamp': new Date().toISOString(),
      instance_id: String(doc.id),
      host: { key: String((doc.host as { key: string }).key) },
      source: 'osquery',
      software_id: String(doc.software_id),
      from_version: '4.41.105',
    });
  }
  const date = todayUtc();
  const active = stack
    .all(INSTANCES_INDEX)
    .filter((doc) => ['active', 'patched'].includes(statusOf(doc)));
  if (rollup) {
    const start = Date.parse(dayStartOf(date));
    const events = stack.all(EVENTS_INDEX).filter((doc) => {
      const at = Date.parse(String(doc['@timestamp']));
      return at >= start && at < start + DAY_MS;
    });
    const count = (type: string) => events.filter((doc) => doc.type === type).length;
    const doc = computeRollupOracle({
      dayStart: dayStartOf(date),
      instances: active.map((item) => ({
        software_id: String(item.software_id),
        exposureLevel: (item.exposure as { level: 'none' }).level,
      })),
      catalog: stack.all('.kibana-software-inventory-catalog').map((entry) => ({
        id: String(entry.id),
        category: entry.category as 'application',
      })),
      events: {
        first_seen: count('first_seen'),
        version_changed: count('version_changed'),
        removed: count('removed'),
      },
    });
    stack.put(ROLLUPS_INDEX, date, JSON.parse(JSON.stringify(doc)));
  }
  return stack.registerRun({
    workflowId: getWorkflowId('scoreExposure'),
    steps: {
      score: {
        input: { lookback_days: 7 },
        output: { scored: instances.filter((doc) => statusOf(doc) !== 'removed').length },
      },
      mark_stale: { input: { stale_after_days: 30 }, output: { marked: eligible.length } },
      snapshot_rollup: {
        output: { date, total_instances: active.length, vulnerable_instances: 0 },
      },
    },
  });
};

const reviveRun = (stack: FakeStack): CompletedRun => {
  const slack = staleInstanceRef();
  const id = instanceIdFor(slack);
  const doc = stack.get(INSTANCES_INDEX, id);
  if (doc)
    stack.put(INSTANCES_INDEX, id, { ...doc, status: 'active', last_seen: FIXTURE_ROW_TIMESTAMP });
  putEvent(stack, {
    type: 'revived',
    '@timestamp': FIXTURE_ROW_TIMESTAMP,
    instance_id: id,
    host: { key: 'synth-mac-01' },
    source: 'osquery',
    software_id: slack.catalogId,
  });
  return stack.registerRun({
    workflowId: getWorkflowId('discoverOsquery'),
    steps: {
      ingest_linux: { input: { snapshot: true }, output: ingestOutput({}) },
      ingest_windows: { input: { snapshot: true }, output: ingestOutput({}) },
      ingest_macos: { input: { snapshot: true }, output: ingestOutput({ unchanged: 2 }) },
      ingest_dependencies: { input: { snapshot: true }, output: ingestOutput({}) },
    },
  });
};

interface Harness {
  readonly stack: FakeStack;
  readonly started: string[];
  readonly records: Map<string, CaseRecord>;
  readonly ctx: (handler?: (workflow: string) => CompletedRun) => CaseContext;
  readonly run: (id: string, handler?: (workflow: string) => CompletedRun) => Promise<CaseResult>;
}

const harness = (setup: (stack: FakeStack) => void = seedWorld): Harness => {
  const stack = buildFakeStack();
  setup(stack);
  const started: string[] = [];
  const records = new Map<string, CaseRecord>();
  const ctx = (handler: (workflow: string) => CompletedRun = () => scoreRun(stack)): CaseContext =>
    stack.buildContext({
      t0: T0,
      priorResults: records,
      runWorkflow: (args) => {
        started.push(args.workflow);
        return handler(args.workflow);
      },
    }).ctx;
  const run = async (id: string, handler?: (workflow: string) => CompletedRun) => {
    const built = stack.buildContext({
      t0: T0,
      priorResults: records,
      runWorkflow: (args) => {
        started.push(args.workflow);
        return (handler ?? (() => scoreRun(stack)))(args.workflow);
      },
    });
    const result = await getCase(id).run(built.ctx);
    records.set(id, {
      ...result,
      id,
      family: 'SE',
      title: id,
      startedAt: new Date().toISOString(),
      durationMs: 0,
      executionIds: built.executionIds,
    });
    return result;
  };
  return { stack, started, records, ctx, run };
};

describe('SE registry', () => {
  it('registers SE-1..SE-12 in matrix order with a requires chain', () => {
    expect(cases.map(({ id }) => id)).toEqual(
      Array.from({ length: 12 }, (_, index) => `SE-${index + 1}`)
    );
    const requires = Object.fromEntries(cases.map(({ id, requires: r }) => [id, r ?? []]));
    expect(requires).toEqual({
      'SE-1': ['DO-1', 'DI-2', 'DL-1'],
      'SE-2': ['SE-1'],
      'SE-3': ['SE-1'],
      'SE-4': ['SE-1'],
      'SE-5': ['SE-1'],
      'SE-6': ['SE-1'],
      'SE-7': ['SE-1'],
      'SE-8': ['SE-1'],
      'SE-9': ['SE-1'],
      'SE-10': ['SE-1'],
      'SE-11': ['SE-10'],
      'SE-12': ['SE-11'],
    });
    const order = ALL_CASES.map(({ id }) => id);
    for (const testCase of cases) {
      for (const required of testCase.requires ?? []) {
        expect(order.indexOf(required)).toBeGreaterThanOrEqual(0);
        expect(order.indexOf(required)).toBeLessThan(order.indexOf(testCase.id));
      }
    }
  });
});

describe('SE-1 .. SE-9', () => {
  it('SE-1 sets manual evidence, runs score-exposure once, and passes on the scored state', async () => {
    const h = harness();
    withManualEvidence(h.stack);
    // The case writes the manual evidence itself; start without it.
    h.stack.put(
      INSTANCES_INDEX,
      instanceIdFor({ hostKey: 'synth-web-02', catalogId: 'f5:nginx:1.27.4' }),
      {
        ...(h.stack.get(
          INSTANCES_INDEX,
          instanceIdFor({ hostKey: 'synth-web-02', catalogId: 'f5:nginx:1.27.4' })
        ) as Doc),
        exposure: { level: 'none', score: 0, evidence: [] },
      }
    );
    const result = await h.run('SE-1');
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(h.started).toEqual(['scoreExposure']);
    expect(h.stack.logPhasesWritten).toEqual(['A']);
    const stored = h.stack.get(
      INSTANCES_INDEX,
      instanceIdFor({ hostKey: 'synth-web-02', catalogId: 'f5:nginx:1.27.4' })
    );
    expect(stored?.exposure).toEqual({
      level: 'low',
      score: 30,
      evidence: [{ signal: 'manual', detail: 'synthetic manual', weight: 30 }],
    });
  });

  it('SE-1 fails on a wrong score and a wrong scored count', async () => {
    const h = harness();
    withManualEvidence(h.stack);
    seedExposure(h.stack, { ...SE1_WEB01, score: 40, level: 'medium' });
    const result = await h.run('SE-1', () =>
      h.stack.registerRun({
        workflowId: getWorkflowId('scoreExposure'),
        steps: {
          score: { input: { lookback_days: 7 }, output: { scored: 1 } },
          mark_stale: { input: { stale_after_days: 30 }, output: { marked: 0 } },
          snapshot_rollup: { output: { date: todayUtc() } },
        },
      })
    );
    expect(result.status).toBe('fail');
    expect(diffsOf(result).join('\n')).toMatch(/score\.output\.scored: expected \d+, got 1/);
    expect(diffsOf(result).join('\n')).toMatch(/score 40 != 44/);
  });

  it('SE-1 is blocked when T0 is more than 5 days old', async () => {
    const h = harness();
    const { ctx } = h.stack.buildContext({
      t0: new Date(Date.now() - 6 * DAY_MS),
      runWorkflow: () => scoreRun(h.stack),
    });
    const result = await getCase('SE-1').run(ctx);
    expect(result.status).toBe('blocked');
  });

  it.each(['SE-2', 'SE-3', 'SE-4', 'SE-5', 'SE-6', 'SE-7'])(
    '%s passes on the scored state',
    async (id) => {
      const h = harness();
      withManualEvidence(h.stack);
      const result = await h.run(id);
      expect(diffsOf(result)).toEqual([]);
      expect(result.status).toBe('pass');
      expect(h.started).toEqual([]);
    }
  );

  it('SE-2 fails when an outbound-only host gets exposure', async () => {
    const h = harness();
    seedExposure(h.stack, {
      hostKey: 'synth-lin-01',
      catalogId: 'openssl:openssl:3.0.7',
      level: 'medium',
      score: 44,
      evidence: [{ signal: 'inbound_public_ip', weight: 44, detail: 'x' }],
    });
    expect(diffsOf(await h.run('SE-2')).join('\n')).toMatch(/expected none, got medium score 44/);
  });

  it('SE-4 and SE-7 fail when an appliance or policy host gets the wrong evidence', async () => {
    const h = harness();
    seedExposure(h.stack, {
      ...SE4_EDGE_ONLY[0],
      evidence: [{ signal: 'inbound_public_ip', weight: 50 }],
    });
    seedExposure(h.stack, {
      ...SE7_POLICY[1],
      level: 'medium',
      score: 40,
      evidence: [{ signal: 'inbound_public_ip', weight: 40 }],
    });
    expect(diffsOf(await h.run('SE-4')).join('\n')).toMatch(
      /signal inbound_public_ip != edge_device_role/
    );
    expect(diffsOf(await h.run('SE-7')).join('\n')).toMatch(/level medium != none/);
  });

  it('SE-6 fails when the manual evidence was dropped', async () => {
    const h = harness();
    // seedWorld leaves synth-web-02 at none
    expect(diffsOf(await h.run('SE-6')).join('\n')).toMatch(/level none != low/);
  });

  it('SE-8 compares the scored output with the oracle recorded by SE-1', async () => {
    const h = harness();
    withManualEvidence(h.stack);
    expect((await h.run('SE-1')).status).toBe('pass');
    const result = await h.run('SE-8');
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');

    const missing = harness();
    expect((await missing.run('SE-8')).status).toBe('blocked');
  });

  it('SE-8 fails when the recorded oracle differs from the step output', async () => {
    const h = harness();
    withManualEvidence(h.stack);
    await h.run('SE-1');
    const record = h.records.get('SE-1') as CaseRecord;
    h.records.set('SE-1', {
      ...record,
      layers: record.layers.map((layer) =>
        layer.layer === 'step'
          ? { ...layer, evidence: { ...layer.evidence, oracleNonRemoved: 1 } }
          : layer
      ),
    });
    expect(diffsOf(await h.run('SE-8')).join('\n')).toMatch(
      /score\.output\.scored: expected 1, got/
    );
  });

  it('SE-9 records the demo instances that lost inbound evidence and never fails on them', async () => {
    const h = harness();
    withManualEvidence(h.stack);
    instanceDoc(h.stack, {
      hostKey: 'demo-host-1',
      catalogId: 'demo:app:1.0',
      exposure: {
        level: 'medium',
        score: 40,
        evidence: [{ signal: 'inbound_public_ip', weight: 40, detail: 'demo' }],
      },
    });
    const demoId = instanceIdFor({ hostKey: 'demo-host-1', catalogId: 'demo:app:1.0' });
    expect(
      (
        await h.run('SE-1', () => {
          const run = scoreRun(h.stack);
          // score-exposure rewrote the demo instance: the seeded evidence has no logs behind it.
          const doc = h.stack.get(INSTANCES_INDEX, demoId) as Doc;
          h.stack.put(INSTANCES_INDEX, demoId, {
            ...doc,
            exposure: { level: 'none', score: 0, evidence: [] },
          });
          return run;
        })
      ).status
    ).toBe('pass');
    const result = await h.run('SE-9');
    expect(result.status).toBe('pass');
    expect(result.notes?.[0]).toBe(
      '1 demo instance(s) had inbound_public_ip evidence before the run; 1 lost it (no logs back it). Recorded, not asserted.'
    );
    expect(result.notes?.[1]).toBe(`${demoId}: medium -> none`);
  });

  it('SE-9 is blocked without an SE-1 record', async () => {
    expect((await harness().run('SE-9')).status).toBe('blocked');
  });
});

describe('SE-10 .. SE-12', () => {
  const syntheticRun = (h: Harness) => (workflow: string) =>
    workflow === 'discoverOsquery' ? reviveRun(h.stack) : scoreRun(h.stack);

  it('SE-10 ages Slack, marks it stale with one stale event, then revives it', async () => {
    const h = harness();
    withManualEvidence(h.stack);
    const result = await h.run('SE-10', syntheticRun(h));
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(h.started).toEqual(['scoreExposure', 'discoverOsquery']);
    expect(result.layers.map(({ layer }) => layer)).toEqual(['engine', 'step', 'inventory']);
    expect(result.notes?.[0]).toBe('mark_stale marked 1 (1 synthetic + 0 demo-eligible).');
    const slack = h.stack.get(INSTANCES_INDEX, instanceIdFor(staleInstanceRef()));
    expect(slack?.status).toBe('active');
    expect(
      h.stack
        .all(EVENTS_INDEX)
        .filter((event) => event.type === 'stale' || event.type === 'revived')
    ).toHaveLength(2);
  });

  it('SE-10 counts demo-eligible instances in marked but only expects the synthetic one', async () => {
    const h = harness();
    withManualEvidence(h.stack);
    instanceDoc(h.stack, {
      hostKey: 'demo-old',
      catalogId: 'demo:old:1.0',
      lastSeen: new Date(Date.now() - 40 * DAY_MS).toISOString(),
    });
    const result = await h.run('SE-10', syntheticRun(h));
    expect(diffsOf(result)).toEqual([]);
    expect(result.notes?.[0]).toBe('mark_stale marked 2 (1 synthetic + 1 demo-eligible).');
  });

  it('SE-10 fails when Slack is not stale or not revived', async () => {
    const h = harness();
    withManualEvidence(h.stack);
    const result = await h.run('SE-10', (workflow) =>
      workflow === 'discoverOsquery'
        ? h.stack.registerRun({
            workflowId: getWorkflowId('discoverOsquery'),
            steps: {
              ingest_macos: { input: { snapshot: true }, output: ingestOutput({ unchanged: 2 }) },
            },
          })
        : h.stack.registerRun({
            workflowId: getWorkflowId('scoreExposure'),
            steps: {
              score: { input: { lookback_days: 7 }, output: { scored: 99 } },
              mark_stale: { input: { stale_after_days: 30 }, output: { marked: 0 } },
              snapshot_rollup: { output: { date: todayUtc() } },
            },
          })
    );
    expect(result.status).toBe('fail');
    const text = diffsOf(result).join('\n');
    expect(text).toMatch(/status active != stale/);
    expect(text).toMatch(/events: expected 1/);
  });

  it("SE-11 compares today's rollup with the oracle and fails on a tampered count", async () => {
    const h = harness();
    withManualEvidence(h.stack);
    const pass = await h.run('SE-11');
    expect(diffsOf(pass)).toEqual([]);
    expect(pass.status).toBe('pass');

    const tampered = harness();
    withManualEvidence(tampered.stack);
    const fail = await tampered.run('SE-11', () => {
      const run = scoreRun(tampered.stack);
      const doc = tampered.stack.get(ROLLUPS_INDEX, todayUtc()) as Doc;
      tampered.stack.put(ROLLUPS_INDEX, todayUtc(), { ...doc, total_instances: 999 });
      return run;
    });
    expect(fail.status).toBe('fail');
    expect(diffsOf(fail).join('\n')).toMatch(
      /rollup \d{4}-\d{2}-\d{2}\.total_instances: expected \d+, got 999/
    );
  });

  it('SE-11 fails when no rollup document exists', async () => {
    const h = harness();
    withManualEvidence(h.stack);
    const result = await h.run('SE-11', () => scoreRun(h.stack, { rollup: false }));
    expect(diffsOf(result).join('\n')).toMatch(/no rollup document with _id/);
  });

  it('SE-12 overwrites the same-day document (version +1, still one document)', async () => {
    const h = harness();
    withManualEvidence(h.stack);
    expect((await h.run('SE-11')).status).toBe('pass');
    const before = h.stack.version(ROLLUPS_INDEX, todayUtc());
    const result = await h.run('SE-12');
    expect(diffsOf(result)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(h.stack.version(ROLLUPS_INDEX, todayUtc())).toBe((before ?? 0) + 1);
    expect(h.stack.all(ROLLUPS_INDEX)).toHaveLength(1);
    expect(dayEndOf(todayUtc()) > dayStartOf(todayUtc())).toBe(true);
  });

  it('SE-12 fails when the second run adds a document or does not overwrite', async () => {
    const h = harness();
    withManualEvidence(h.stack);
    await h.run('SE-11');
    const duplicate = await h.run('SE-12', () => {
      const run = scoreRun(h.stack, { rollup: false });
      h.stack.put(ROLLUPS_INDEX, 'extra', {
        '@timestamp': dayStartOf(todayUtc()),
        total_instances: 1,
      });
      return run;
    });
    expect(duplicate.status).toBe('fail');
    const text = diffsOf(duplicate).join('\n');
    expect(text).toMatch(/expected one rollup document .* found 2/);
    expect(text).toMatch(/_version \d+ != \d+/);
  });

  it('SE-12 is blocked without a rollup to compare', async () => {
    const h = harness();
    expect((await h.run('SE-12')).status).toBe('blocked');
  });
});
