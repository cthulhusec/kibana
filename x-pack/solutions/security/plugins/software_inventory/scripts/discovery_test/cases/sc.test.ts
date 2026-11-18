/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { JsonValue, RawResponse, SearchResponse } from '../clients';
import { SC1, SC3, SC_COPY_IDS } from '../expected/sc';
import { createScCases } from './sc';
import type { Clock, ExecutionDoc } from './sc_support';
import { evaluateDropRuns, evaluateScheduledRuns, pollUntil } from './sc_support';
import { TEST_CONFIG, fakeContext, fakeEs, fakeKibana, fakeRun } from './fake_context';

const BASE = Date.parse('2026-11-18T10:00:00.000Z');
const at = (seconds: number) => new Date(BASE + seconds * 1000).toISOString();

/** A clock that advances on every sleep, so polling finishes instantly. */
const fakeClock = (): Clock & { slept: number } => {
  let now = BASE;
  const clock = {
    slept: 0,
    now: () => now,
    sleep: async (ms: number) => {
      now += ms;
      clock.slept += ms;
    },
  };
  return clock;
};

const run = (id: string, overrides: Partial<ExecutionDoc>): ExecutionDoc => ({
  id,
  workflowId: SC_COPY_IDS.sched,
  status: 'completed',
  triggeredBy: 'scheduled',
  isTestRun: false,
  ...overrides,
});

describe('evaluateScheduledRuns', () => {
  const enabledAt = at(0);
  const good = [
    run('r1', { createdAt: at(5) }),
    run('r2', { createdAt: at(65) }),
    run('r3', { createdAt: at(125) }),
  ];

  it('accepts a prompt first run and a one-minute cadence', () => {
    expect(evaluateScheduledRuns(good, { enabledAt, ...SC1 })).toEqual([]);
  });

  it('reports too few runs, a late first run, an irregular gap, and a failed run', () => {
    expect(evaluateScheduledRuns(good.slice(0, 2), { enabledAt, ...SC1 })).toEqual([
      'expected 3 finished scheduled runs, got 2',
    ]);
    const diffs = evaluateScheduledRuns(
      [
        run('r1', { createdAt: at(120) }),
        run('r2', { createdAt: at(300), status: 'failed' }),
        run('r3', { createdAt: at(360) }),
      ],
      { enabledAt, ...SC1 }
    );
    expect(diffs).toEqual([
      'first scheduled run created 120000ms after enabling (limit 90000ms)',
      'scheduled runs 1 and 2 are 180000ms apart (expected 45000..90000ms)',
      'scheduled run r2: status failed',
    ]);
  });
});

describe('evaluateDropRuns', () => {
  const holder = run('h', { createdAt: at(0), startedAt: at(1), finishedAt: at(92) });

  it('accepts a skipped run created while the holder ran, without startedAt', () => {
    expect(
      evaluateDropRuns([holder, run('s', { status: 'skipped', createdAt: at(60) })], SC3.waitMs)
    ).toEqual([]);
  });

  it('reports a missing skip, a started skip, and a short holder', () => {
    expect(evaluateDropRuns([holder], SC3.waitMs)).toEqual(['no run was skipped']);
    expect(
      evaluateDropRuns(
        [
          { ...holder, finishedAt: at(30) },
          run('s', { status: 'skipped', createdAt: at(20), startedAt: at(21) }),
        ],
        SC3.waitMs
      )
    ).toEqual([
      'holder h ran 29000ms, less than the 90000ms wait',
      `skipped run s has startedAt ${at(21)}`,
    ]);
  });
});

describe('pollUntil', () => {
  it('returns the last value when the deadline passes', async () => {
    const clock = fakeClock();
    let reads = 0;
    const result = await pollUntil(
      async () => ++reads,
      () => false,
      { timeoutMs: 10_000, intervalMs: 1000 },
      clock
    );
    expect(result.timedOut).toBe(true);
    expect(reads).toBe(11);
  });
});

describe('SC cases', () => {
  const scCases = createScCases(fakeClock());
  const scCase = (id: string) => {
    const found = scCases.find((testCase) => testCase.id === id);
    if (!found) throw new Error(`no case ${id}`);
    return found;
  };

  it('registers SC-1..SC-9 in order', () => {
    expect(scCases.map(({ id }) => id)).toEqual(
      Array.from({ length: 9 }, (_, index) => `SC-${index + 1}`)
    );
  });

  it.each([
    ['SC-7', /restart in the middle of a run[\s\S]*run DO-16[\s\S]*synth-bulk-01/],
    ['SC-8', /explicit approval[\s\S]*managed\/workflow[\s\S]*every "12h" again/],
  ])('%s is blocked by design with the manual procedure', async (id, pattern) => {
    const result = await scCase(id).run(fakeContext({}));
    expect(result.status).toBe('blocked');
    expect(result.notes?.[0]).toMatch(pattern);
  });

  it('scheduling cases are blocked outside the default space', async () => {
    const ctx = fakeContext({ config: { ...TEST_CONFIG, space: 'other' } });
    for (const id of ['SC-1', 'SC-3', 'SC-9']) {
      expect((await scCase(id).run(ctx)).status).toBe('blocked');
    }
  });

  const scheduledStack = ({ failSearch = false } = {}) => {
    const calls: string[] = [];
    let taskPresent = false;
    const kibana = fakeKibana({
      request: async <T>(
        method: string,
        path: string,
        options?: { body?: object | string }
      ): Promise<RawResponse<T>> => {
        calls.push(`${method} ${path} ${JSON.stringify(options?.body ?? {}).slice(0, 40)}`);
        if (method === 'PUT') taskPresent = JSON.stringify(options?.body) === '{"enabled":true}';
        return { status: 200, body: {} as JsonValue as T };
      },
    });
    const es = fakeEs({
      exists: async () => taskPresent,
      search: async <T>(): Promise<SearchResponse<T>> => {
        if (failSearch) throw new Error('search exploded');
        const created = Date.now();
        return {
          hits: {
            hits: [0, 60, 120].map((offset, index) => ({
              _id: `r${index}`,
              _index: '.workflows-executions',
              _source: {
                workflowId: SC_COPY_IDS.sched,
                status: 'completed',
                triggeredBy: 'scheduled',
                createdAt: new Date(created + offset * 1000).toISOString(),
              } as JsonValue as T,
            })),
          },
        };
      },
    });
    return { kibana, es, calls };
  };

  it('SC-1 creates, enables, observes three runs, and always deletes the copy', async () => {
    const stack = scheduledStack();
    const cases = createScCases({ now: () => Date.now(), sleep: async () => {} });
    const sc1 = cases[0];
    const result = await sc1.run(fakeContext({ es: stack.es, kibana: stack.kibana }));
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(stack.calls.filter((call) => call.startsWith('POST'))).toHaveLength(1);
    expect(stack.calls[stack.calls.length - 1]).toMatch(
      new RegExp(`^DELETE /api/workflows/workflow/${SC_COPY_IDS.sched}`)
    );
    expect(result.notes?.join('\n')).toMatch(
      /deleted si-test-discover-osquery-sched \(force=true\)/
    );
  });

  it('SC-1 still disables and deletes the copy when observing fails', async () => {
    const stack = scheduledStack({ failSearch: true });
    const sc1 = createScCases({ now: () => Date.now(), sleep: async () => {} })[0];
    await expect(sc1.run(fakeContext({ es: stack.es, kibana: stack.kibana }))).rejects.toThrow(
      /search exploded/
    );
    const tail = stack.calls.slice(-2);
    expect(tail[0]).toMatch(/^PUT .*si-test-discover-osquery-sched \{"enabled":false\}/);
    expect(tail[1]).toMatch(/^DELETE .*si-test-discover-osquery-sched/);
  });

  it('SC-6 accepts a timed-out query step and an all-zero ingest', async () => {
    const ctx = fakeContext({
      runWorkflow: async () =>
        fakeRun({
          query_linux: { status: 'timed_out' },
          ingest_linux: {
            output: { created: 0, unchanged: 0, patched: 0, removed: 0, skipped: 0 },
            input: { snapshot: false, candidates: [] },
          },
        }),
    });
    const result = await scCase('SC-6').run(ctx);
    expect(result.status).toBe('pass');
    expect(result.notes?.[0]).toBe('Recorded: query_linux timed_out, run completed');
  });
});
