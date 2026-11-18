/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { elasticsearchServiceMock } from '@kbn/core-elasticsearch-server-mocks';
import { EVENTS_INDEX, ROLLUPS_INDEX } from '../../../common/constants';
import { getHostTimeline, getTrends, validateHistoryRange } from './history_data_access';

const hits = (docs: unknown[], total = docs.length) =>
  ({
    hits: { total: { value: total, relation: 'eq' }, hits: docs.map((_source) => ({ _source })) },
  } as never);

const DAY = 24 * 60 * 60 * 1000;
const T0 = Date.parse('2026-11-01T00:00:00.000Z');
const iso = (n: number) => new Date(T0 + n * DAY).toISOString();

describe('validateHistoryRange', () => {
  it('accepts a valid range', () => {
    expect(validateHistoryRange(iso(0), iso(3))).toEqual({
      range: { from: T0, to: T0 + 3 * DAY },
    });
  });
  it.each([
    ['not-a-date', iso(1)],
    [iso(1), iso(1)],
    [iso(2), iso(1)],
    [iso(0), iso(400)],
  ])('rejects %s .. %s', (from, to) => {
    expect(validateHistoryRange(from, to).error).toEqual(expect.any(String));
  });
});

describe('getTrends', () => {
  it('returns rollup buckets from the start of the first UTC day and a patch summary', async () => {
    const es = elasticsearchServiceMock.createElasticsearchClient();
    const bucket = { '@timestamp': iso(0), total_instances: 3 };
    es.search
      .mockResolvedValueOnce(hits([bucket]))
      .mockResolvedValueOnce(
        hits(
          [
            {
              '@timestamp': iso(4),
              type: 'version_changed',
              software_id: 'a:b:2',
              previous_software_id: 'a:b:1',
              cve_count_before: 2,
              cve_count_after: 0,
            },
          ],
          7
        )
      )
      .mockResolvedValueOnce(
        hits([
          { id: 'a:b:1', cve_count: 2, cve_ids: [], first_published: iso(1) },
          { id: 'a:b:2', cve_count: 0, cve_ids: [] },
        ])
      );
    const trends = await getTrends(es, { from: T0 + DAY / 2, to: T0 + 5 * DAY });
    expect(es.search.mock.calls[0][0]).toMatchObject({
      index: ROLLUPS_INDEX,
      query: { range: { '@timestamp': { gte: iso(0) } } },
    });
    expect(es.search.mock.calls[1][0]).toMatchObject({ index: EVENTS_INDEX, size: 10000 });
    expect(trends).toEqual({
      from: new Date(T0 + DAY / 2).toISOString(),
      to: iso(5),
      buckets: [bucket],
      patch_summary: { patches: 7, remediating_patches: 1, median_time_to_patch_ms: 3 * DAY },
    });
  });

  it('returns empty results when the indices are missing', async () => {
    const es = elasticsearchServiceMock.createElasticsearchClient();
    es.search.mockResolvedValue(hits([]));
    const trends = await getTrends(es, { from: T0, to: T0 + DAY });
    expect(trends.buckets).toEqual([]);
    expect(trends.patch_summary).toEqual({ patches: 0, remediating_patches: 0 });
  });
});

describe('getHostTimeline', () => {
  it('returns undefined when the host has no instances', async () => {
    const es = elasticsearchServiceMock.createElasticsearchClient();
    es.search.mockResolvedValue(hits([]));
    await expect(getHostTimeline(es, 'web-1', { from: T0, to: T0 + DAY })).resolves.toBe(undefined);
  });

  it('joins the catalog entries of every version in range', async () => {
    const es = elasticsearchServiceMock.createElasticsearchClient();
    es.search
      .mockResolvedValueOnce(
        hits([
          {
            id: 'i1',
            host: { key: 'web-1', id: 'h1' },
            software_id: 'acme:app:2.0',
            status: 'active',
            first_seen: iso(0),
            last_seen: iso(19),
            exposure: { level: 'high', score: 80, evidence: [] },
            version_history: [
              { version: '1.0', first_seen: iso(0), last_seen: iso(9) },
              { version: '2.0', first_seen: iso(10), last_seen: iso(19) },
            ],
          },
        ])
      )
      .mockResolvedValueOnce(
        hits([
          {
            id: 'acme:app:1.0',
            product: 'app',
            vendor: 'acme',
            category: 'application',
            cve_count: 1,
            cve_ids: ['CVE-A'],
          },
        ])
      );
    const timeline = await getHostTimeline(
      es,
      'web-1',
      { from: T0 + 3 * DAY, to: T0 + 6 * DAY },
      new Date(T0 + 20 * DAY)
    );
    const catalogQuery = JSON.stringify(es.search.mock.calls[1][0]);
    expect(catalogQuery).toContain('acme:app:1.0');
    expect(catalogQuery).toContain('acme:app:2.0');
    expect(timeline).toMatchObject({
      host_key: 'web-1',
      vulnerable_in_range: true,
      cve_ids: ['CVE-A'],
      items: [{ instance_id: 'i1', exposure_level: 'high', vulnerable_in_range: true }],
    });
  });
});
