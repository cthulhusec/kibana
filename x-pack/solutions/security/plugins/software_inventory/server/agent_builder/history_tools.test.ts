/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { elasticsearchServiceMock, httpServerMock } from '@kbn/core/server/mocks';
import { loggingSystemMock } from '@kbn/core/server/mocks';
import type { ToolHandlerReturn } from '@kbn/agent-builder-server';
import { ToolResultType } from '@kbn/agent-builder-common/tools/tool_result';
import {
  createHostVulnerabilityTimelineTool,
  createInventoryTrendsTool,
  resolveDateInput,
  resolveToolRange,
  sampleBuckets,
} from './history_tools';

const DAY = 24 * 60 * 60 * 1000;

const hits = (docs: unknown[], total = docs.length, aggregations?: unknown) =>
  ({
    hits: { total: { value: total, relation: 'eq' }, hits: docs.map((_source) => ({ _source })) },
    ...(aggregations ? { aggregations } : {}),
  } as never);

const first = (out: ToolHandlerReturn): { type: string; data: Record<string, unknown> } => {
  if (!('results' in out)) throw new Error('Expected a standard tool response');
  const [result] = out.results;
  return { type: result.type, data: Object.fromEntries<unknown>(Object.entries(result.data)) };
};

const setup = (allowed = true) => {
  const es = elasticsearchServiceMock.createElasticsearchClient();
  const deps = {
    getEsClient: jest.fn().mockResolvedValue(es),
    hasReadAccess: jest.fn().mockResolvedValue(allowed),
    logger: loggingSystemMock.createLogger(),
  };
  const context = { request: httpServerMock.createKibanaRequest() } as never;
  return { es, deps, context };
};

describe('date input', () => {
  const now = new Date('2026-11-18T12:00:00.000Z');

  it('resolves date math relative to now and ISO dates', () => {
    expect(resolveDateInput('now-3d', { roundUp: false, now })).toBe(now.getTime() - 3 * DAY);
    expect(resolveDateInput('2026-11-01T00:00:00Z', { roundUp: false, now })).toBe(
      Date.parse('2026-11-01T00:00:00Z')
    );
    expect(resolveDateInput('yesterday-ish', { roundUp: false, now })).toBeUndefined();
  });

  it('validates the resolved range', () => {
    expect(resolveToolRange('now-3d', 'now', now)).toEqual({
      range: { from: now.getTime() - 3 * DAY, to: now.getTime() },
    });
    expect(resolveToolRange('now', 'now-3d', now)).toHaveProperty('error');
    expect(resolveToolRange('now-2y', 'now', now)).toHaveProperty('error');
    expect(resolveToolRange('garbage', 'now', now)).toHaveProperty('error');
  });
});

describe('sampleBuckets', () => {
  it('keeps short lists and samples long ones keeping both ends', () => {
    expect(sampleBuckets([1, 2, 3], 5)).toEqual([1, 2, 3]);
    const sampled = sampleBuckets(
      Array.from({ length: 100 }, (_, i) => i),
      5
    );
    expect(sampled).toHaveLength(5);
    expect(sampled[0]).toBe(0);
    expect(sampled[4]).toBe(99);
  });
});

describe('host_vulnerability_timeline', () => {
  const iso = (daysAgo: number) => new Date(Date.now() - daysAgo * DAY).toISOString();

  it('refuses without the read privilege', async () => {
    const { es, deps, context } = setup(false);
    const out = await createHostVulnerabilityTimelineTool(deps).handler({ host: 'web-1' }, context);
    expect(first(out).type).toBe(ToolResultType.error);
    expect(es.search).not.toHaveBeenCalled();
  });

  it('answers whether the host was vulnerable over the last 3 days', async () => {
    const { es, deps, context } = setup();
    es.search
      .mockResolvedValueOnce(hits([], 2)) // exact host key match
      .mockResolvedValueOnce(
        hits([
          {
            id: 'i1',
            host: { key: 'web-1', id: 'h1', name: 'web-1' },
            software_id: 'acme:app:2.0',
            status: 'active',
            first_seen: iso(10),
            last_seen: iso(0),
            exposure: { level: 'high', score: 80, evidence: [] },
            version_history: [
              {
                version: '1.0',
                software_id: 'acme:app:1.0',
                first_seen: iso(10),
                last_seen: iso(2),
              },
              {
                version: '2.0',
                software_id: 'acme:app:2.0',
                first_seen: iso(1),
                last_seen: iso(0),
              },
            ],
          },
        ])
      )
      .mockResolvedValueOnce(
        hits([
          {
            id: 'acme:app:1.0',
            vendor: 'acme',
            product: 'app',
            cve_count: 1,
            cve_ids: ['CVE-A'],
            cve_details: [{ id: 'CVE-A', published: iso(30), cvss: 9.8, known_exploited: true }],
          },
          { id: 'acme:app:2.0', vendor: 'acme', product: 'app', cve_count: 0, cve_ids: [] },
        ])
      )
      .mockResolvedValueOnce(
        hits([
          {
            '@timestamp': iso(1),
            type: 'version_changed',
            software_id: 'acme:app:2.0',
            from_version: '1.0',
            to_version: '2.0',
          },
        ])
      );

    const { type, data } = first(
      await createHostVulnerabilityTimelineTool(deps).handler(
        { host: 'WEB-1', from: 'now-3d', to: 'now' },
        context
      )
    );
    expect(type).toBe(ToolResultType.other);
    expect(data).toMatchObject({
      host_key: 'web-1',
      vulnerable_in_range: true,
      cve_ids: ['CVE-A'],
      vulnerable_software_count: 1,
      events_in_range: [expect.objectContaining({ type: 'version_changed', to_version: '2.0' })],
    });
    expect(data.vulnerable_hours).toBeCloseTo(48, 0);
  });

  it('returns candidates when a partial name matches several hosts', async () => {
    const { es, deps, context } = setup();
    es.search.mockResolvedValueOnce(hits([], 0)).mockResolvedValueOnce(
      hits([], 0, {
        hosts: {
          buckets: [
            { key: 'web-1', doc_count: 3 },
            { key: 'web-2', doc_count: 1 },
          ],
        },
      })
    );
    const { data } = first(
      await createHostVulnerabilityTimelineTool(deps).handler({ host: 'web' }, context)
    );
    expect(data).toMatchObject({
      ambiguous_host: true,
      candidates: [
        { host_key: 'web-1', instances: 3 },
        { host_key: 'web-2', instances: 1 },
      ],
    });
  });

  it('returns an error when no host matches or the dates are invalid', async () => {
    const { es, deps, context } = setup();
    es.search.mockResolvedValueOnce(hits([], 0)).mockResolvedValueOnce(hits([], 0, {}));
    const tool = createHostVulnerabilityTimelineTool(deps);
    expect(first(await tool.handler({ host: 'nope' }, context)).type).toBe(ToolResultType.error);
    expect(first(await tool.handler({ host: 'x', from: 'bad' }, context)).type).toBe(
      ToolResultType.error
    );
  });
});

describe('inventory_trends', () => {
  it('compares the first and last snapshot and reports patch speed', async () => {
    const { es, deps, context } = setup();
    const bucket = (date: string, vulnerable: number) => ({
      '@timestamp': `${date}T00:00:00.000Z`,
      total_instances: 10,
      vulnerable_instances: vulnerable,
      critical_instances: 1,
      known_exploited_instances: 0,
      exposed_and_vulnerable_instances: 0,
      new_instances: 0,
      patched_instances: 0,
      removed_instances: 0,
    });
    es.search
      .mockResolvedValueOnce(hits([bucket('2026-10-19', 8), bucket('2026-11-18', 3)]))
      .mockResolvedValueOnce(hits([], 0))
      .mockResolvedValue(hits([]));
    const { data } = first(
      await createInventoryTrendsTool(deps).handler({ from: 'now-1M' }, context)
    );
    expect(data).toMatchObject({
      days_with_data: 2,
      first: { date: '2026-10-19', vulnerable_instances: 8 },
      last: { date: '2026-11-18', vulnerable_instances: 3 },
      change: { vulnerable_instances: -5 },
      patch_summary: { patches: 0, remediating_patches: 0 },
    });
  });
});
