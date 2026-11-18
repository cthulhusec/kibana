/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { elasticsearchServiceMock } from '@kbn/core/server/mocks';
import { CATALOG_INDEX, INSTANCES_INDEX } from '../../common/constants';
import { findInstances, getCatalogDetail, getSummary } from './data_access';

const hits = (docs: unknown[], total = docs.length) =>
  ({
    hits: { total: { value: total, relation: 'eq' }, hits: docs.map((_source) => ({ _source })) },
  } as never);

const params = { page: 1, per_page: 25, sort_field: 'last_seen', sort_order: 'desc' } as const;

describe('data_access', () => {
  it('joins catalog entries onto instances', async () => {
    const es = elasticsearchServiceMock.createElasticsearchClient();
    es.search
      .mockResolvedValueOnce(hits([{ id: 's1' }])) // catalog ids for known_exploited
      .mockResolvedValueOnce(
        hits(
          [
            { id: 'i1', software_id: 's1' },
            { id: 'i2', software_id: 'gone' },
          ],
          2
        )
      )
      .mockResolvedValueOnce(hits([{ id: 's1', product: 'nginx' }]));

    const result = await findInstances(es, { ...params, known_exploited: true });

    expect(es.search.mock.calls[0][0]).toMatchObject({ index: CATALOG_INDEX });
    expect(es.search.mock.calls[1][0]).toMatchObject({
      index: INSTANCES_INDEX,
      ignore_unavailable: true,
      query: { bool: { filter: [{ terms: { software_id: ['s1'] } }] } },
    });
    expect(result.total).toBe(2);
    expect(result.items).toEqual([
      { id: 'i1', software_id: 's1', software: { id: 's1', product: 'nginx' } },
    ]);
  });

  it('returns an empty page without querying instances when no catalog entry matches', async () => {
    const es = elasticsearchServiceMock.createElasticsearchClient();
    es.search.mockResolvedValueOnce(hits([]));
    const result = await findInstances(es, { ...params, category: ['application'] });
    expect(result).toEqual({ total: 0, page: 1, per_page: 25, items: [] });
    expect(es.search).toHaveBeenCalledTimes(1);
  });

  it('returns an empty summary when the instances index has no aggregations', async () => {
    const es = elasticsearchServiceMock.createElasticsearchClient();
    es.search.mockResolvedValue(hits([]));
    const summary = await getSummary(es);
    expect(summary.total_instances).toBe(0);
    expect(summary.by_category).toEqual([]);
  });

  it('returns undefined for a missing catalog entry', async () => {
    const es = elasticsearchServiceMock.createElasticsearchClient();
    es.search.mockResolvedValue(hits([]));
    await expect(getCatalogDetail(es, 'nope')).resolves.toBeUndefined();
    expect(es.search).toHaveBeenCalledTimes(1);
  });

  it('returns entry with instances capped at 1000', async () => {
    const es = elasticsearchServiceMock.createElasticsearchClient();
    es.search
      .mockResolvedValueOnce(hits([{ id: 's1' }]))
      .mockResolvedValueOnce(hits([{ id: 'i1', software_id: 's1' }]));
    const detail = await getCatalogDetail(es, 's1');
    expect(detail?.instances).toHaveLength(1);
    expect(es.search.mock.calls[1][0]).toMatchObject({ size: 1000 });
  });

  describe('as_of', () => {
    const DAY = 24 * 60 * 60 * 1000;
    const T0 = Date.parse('2026-11-01T00:00:00.000Z');
    const iso = (n: number) => new Date(T0 + n * DAY).toISOString();
    const now = new Date(T0 + 20 * DAY);
    const asOf = { from: T0 + 3 * DAY, to: T0 + 6 * DAY };
    const doc = {
      id: 'i1',
      software_id: 'acme:app:2.0',
      status: 'active',
      first_seen: iso(0),
      last_seen: iso(19),
      version_history: [
        { version: '1.0', software_id: 'acme:app:1.0', first_seen: iso(0), last_seen: iso(9) },
        { version: '2.0', software_id: 'acme:app:2.0', first_seen: iso(10), last_seen: iso(19) },
      ],
    };
    const oldEntry = {
      id: 'acme:app:1.0',
      cve_count: 1,
      cve_ids: ['CVE-A'],
      cve_details: [{ id: 'CVE-A', published: iso(-5), known_exploited: false }],
    };
    const newEntry = { id: 'acme:app:2.0', cve_count: 0, cve_ids: [] };

    it('scopes to the range, joins the version that ran then, and flags vulnerability', async () => {
      const es = elasticsearchServiceMock.createElasticsearchClient();
      es.search
        .mockResolvedValueOnce(hits([doc]))
        .mockResolvedValueOnce(hits([oldEntry, newEntry]));
      const result = await findInstances(es, { ...params, as_of: asOf }, now);
      expect(JSON.stringify(es.search.mock.calls[0][0])).toContain('"path":"version_history"');
      expect(result.items[0]).toMatchObject({
        software: { id: 'acme:app:1.0' },
        vulnerable_in_range: true,
      });
    });

    it('filters to vulnerable rows in code when vulnerable_in_range is true', async () => {
      const es = elasticsearchServiceMock.createElasticsearchClient();
      const clean = {
        ...doc,
        id: 'i2',
        version_history: [doc.version_history[1]],
        first_seen: iso(10),
      };
      es.search
        .mockResolvedValueOnce(hits([{ id: 'acme:app:1.0' }])) // vulnerable catalog ids
        .mockResolvedValueOnce(hits([doc, clean]))
        .mockResolvedValueOnce(hits([oldEntry, newEntry]));
      const result = await findInstances(
        es,
        { ...params, as_of: { from: T0 + 3 * DAY, to: T0 + 12 * DAY }, vulnerable_in_range: true },
        now
      );
      expect(es.search.mock.calls[1][0]).toMatchObject({ size: 1000 });
      expect(result.total).toBe(1);
      expect(result.items.map(({ id }) => id)).toEqual(['i1']);
    });

    it('returns an empty page when no catalog entry is vulnerable', async () => {
      const es = elasticsearchServiceMock.createElasticsearchClient();
      es.search.mockResolvedValueOnce(hits([]));
      const result = await findInstances(
        es,
        { ...params, as_of: asOf, vulnerable_in_range: true },
        now
      );
      expect(result).toEqual({ total: 0, page: 1, per_page: 25, items: [] });
    });
  });
});
