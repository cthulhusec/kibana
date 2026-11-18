/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { HostTimelineResponse } from '../../../common/history';
import type { FindInstancesResponse, InstanceDoc, InstanceRow } from '../../../common/types';
import type { RawResponse, SearchResponse } from '../clients';
import { DAY_MS, HOUR_MS, e2e2Expectations } from '../expected/e2e';
import {
  E2E1_EVIDENCE_KEY,
  createE2eCases,
  diffInstancesRoute,
  diffTimeline,
  readE2e1Capture,
} from './e2e';
import { fakeContext, fakeEs, fakeKibana, passingRecord, asType } from './fake_context';

const T0 = new Date('2026-11-18T10:00:00.000Z');
const NOW = new Date('2026-11-18T10:30:00.000Z');
const iso = (ms: number) => new Date(ms).toISOString();

const timeline = (overrides: Partial<HostTimelineResponse>): HostTimelineResponse => ({
  host_key: 'synth-web-02',
  from: '',
  to: '',
  vulnerable_in_range: false,
  vulnerable_duration_ms: 0,
  cve_ids: [],
  items: [],
  ...overrides,
});

const nginxItem = {
  instance_id: 'i',
  product: 'nginx',
  vendor: 'f5',
  category: 'application' as const,
  status: 'patched',
  exposure_level: 'none' as const,
  intervals: [],
  vulnerable_in_range: true,
};

/** What the route answers for synth-web-02 when the pipeline behaved as the plan says. */
const correctTimeline = (from: string, to: string): HostTimelineResponse => {
  const start = T0.getTime() - 20 * HOUR_MS;
  const end = T0.getTime() - HOUR_MS;
  const lo = Math.max(Date.parse(from), start);
  const hi = Math.min(Date.parse(to), end);
  const overlapsInstance = Date.parse(to) >= start;
  return timeline(
    hi > lo
      ? {
          vulnerable_in_range: true,
          vulnerable_duration_ms: hi - lo,
          first_vulnerable_at: iso(lo),
          cve_ids: ['CVE-2023-44487'],
          items: [nginxItem],
        }
      : { items: overlapsInstance ? [{ ...nginxItem, vulnerable_in_range: false }] : [] }
  );
};

const capturePrior = () =>
  new Map([
    [
      'E2E-1',
      passingRecord('E2E-1', {
        [E2E1_EVIDENCE_KEY]: {
          t0: T0.toISOString(),
          startedAt: T0.toISOString(),
          doRun: { startedAt: iso(T0.getTime() + 60_000), finishedAt: iso(T0.getTime() + 70_000) },
        },
      }),
    ],
  ]);

const e2eCases = createE2eCases({
  resolveTiming: () => ({ spacingMs: 100, timeoutMs: 2000, backoffBaseMs: 200, source: 'test' }),
  cleanup: async () => ({ instancesDeleted: 0, eventsDeleted: 0, catalogDeleted: 0 }),
  now: () => NOW,
});
const e2eCase = (id: string) => {
  const found = e2eCases.find((testCase) => testCase.id === id);
  if (!found) throw new Error(`no case ${id}`);
  return found;
};

describe('diffTimeline', () => {
  const [threeDays, recent, before] = e2e2Expectations(T0, NOW);

  it('accepts the plan values within the tolerances', () => {
    expect(diffTimeline(threeDays, correctTimeline(threeDays.from, threeDays.to))).toEqual([]);
    expect(diffTimeline(recent, correctTimeline(recent.from, recent.to))).toEqual([]);
    expect(diffTimeline(before, correctTimeline(before.from, before.to))).toEqual([]);
  });

  it('reports a wrong duration, start, CVE list, and a present item', () => {
    const wrong = timeline({
      vulnerable_in_range: true,
      vulnerable_duration_ms: 18 * HOUR_MS,
      first_vulnerable_at: iso(T0.getTime() - 19 * HOUR_MS),
      cve_ids: ['CVE-2023-44487', 'CVE-1'],
      items: [nginxItem],
    });
    expect(diffTimeline(threeDays, wrong)).toHaveLength(3);
    expect(diffTimeline(before, wrong).join('\n')).toMatch(/expected no nginx item/);
  });
});

describe('E2E cases', () => {
  it('registers E2E-1..E2E-5 in order; E2E-1 needs the stub, the others require E2E-1', () => {
    expect(e2eCases.map(({ id }) => id)).toEqual(['E2E-1', 'E2E-2', 'E2E-3', 'E2E-4', 'E2E-5']);
    expect(e2eCase('E2E-1')).toEqual(
      expect.objectContaining({ requires: ['T0-3'], needs: ['nvd-stub'] })
    );
    expect(e2eCases.slice(1).every(({ requires }) => requires?.[0] === 'E2E-1')).toBe(true);
  });

  it('E2E-1 is blocked without the stub', async () => {
    expect((await e2eCase('E2E-1').run(fakeContext({}))).status).toBe('blocked');
  });

  it.each(['E2E-2', 'E2E-3', 'E2E-4', 'E2E-5'])(
    '%s is blocked without the E2E-1 capture',
    async (id) => {
      expect((await e2eCase(id).run(fakeContext({}))).status).toBe('blocked');
    }
  );

  it('reads the capture E2E-1 recorded', () => {
    expect(readE2e1Capture({ priorResults: capturePrior() })?.t0).toBe(T0.toISOString());
  });

  it('E2E-2 queries the three windows and passes on the planned answers', async () => {
    const queries: string[] = [];
    const kibana = fakeKibana({
      internalRequest: async <T>(
        _method: string,
        path: string,
        options?: { query?: Readonly<Record<string, string | number | boolean | undefined>> }
      ): Promise<RawResponse<T>> => {
        const from = String(options?.query?.from);
        const to = String(options?.query?.to);
        queries.push(`${path} ${from} ${to}`);
        return { status: 200, body: asType<T>(correctTimeline(from, to)) };
      },
    });
    const result = await e2eCase('E2E-2').run(
      fakeContext({ kibana, priorResults: capturePrior() })
    );
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(queries).toEqual([
      `/internal/software_inventory/hosts/synth-web-02/timeline ${iso(
        T0.getTime() - 3 * DAY_MS
      )} ${NOW.toISOString()}`,
      `/internal/software_inventory/hosts/synth-web-02/timeline ${iso(
        T0.getTime() - 30 * 60_000
      )} ${NOW.toISOString()}`,
      `/internal/software_inventory/hosts/synth-web-02/timeline ${iso(
        T0.getTime() - 3 * DAY_MS
      )} ${iso(T0.getTime() - 21 * HOUR_MS)}`,
    ]);
  });
});

describe('diffInstancesRoute and E2E-5', () => {
  const doc = (id: string, softwareId: string): InstanceDoc => ({
    id,
    host: { key: 'synth-lin-01', id: 'synth-agent-lin01', name: 'synth-lin-01' },
    software_id: softwareId,
    version_history: [],
    sources: ['osquery'],
    status: 'active',
    first_seen: '',
    last_seen: '',
    exposure: { level: 'none', score: 0, evidence: [] },
    '@timestamp': '',
  });
  const row = (instance: InstanceDoc): InstanceRow => ({
    ...instance,
    software: {
      id: instance.software_id,
      vendor: 'v',
      product: 'p',
      version: '1',
      display_name: 'd',
      category: 'application',
      cve_count: 0,
      known_exploited: false,
      cve_ids: [],
      '@timestamp': '',
    },
  });
  const oracle = [doc('a', 'openssl:openssl:3.0.7'), doc('b', 'apache:log4j:2.14.1')];
  const page = (items: InstanceRow[]): FindInstancesResponse => ({
    total: items.length,
    page: 1,
    per_page: 100,
    items,
  });

  it('matches when the route returns the oracle documents', () => {
    expect(diffInstancesRoute(page(oracle.map(row)), oracle)).toEqual([]);
  });

  it('reports missing, extra, and changed rows', () => {
    const diffs = diffInstancesRoute(
      page([{ ...row(oracle[0]), status: 'removed' }, row(doc('c', 'x:y:1'))]),
      oracle
    );
    expect(diffs.join('\n')).toMatch(/status/);
    expect(diffs.join('\n')).toMatch(/b \(apache:log4j:2.14.1\) missing/);
    expect(diffs.join('\n')).toMatch(/c not in the oracle/);
  });

  it('E2E-5 compares the route with the ES oracle', async () => {
    const es = fakeEs({
      search: async <T>(): Promise<SearchResponse<T>> => ({
        hits: {
          hits: oracle.map((item) => ({ _id: item.id, _index: 'x', _source: asType<T>(item) })),
        },
      }),
    });
    const kibana = fakeKibana({
      internalRequest: async <T>(): Promise<RawResponse<T>> => ({
        status: 200,
        body: asType<T>(page(oracle.map(row))),
      }),
    });
    const result = await e2eCase('E2E-5').run(
      fakeContext({ es, kibana, priorResults: capturePrior() })
    );
    expect(result.status).toBe('pass');
  });
});
