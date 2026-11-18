/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient } from '@kbn/core/server';
import { loggingSystemMock } from '@kbn/core-logging-server-mocks';
import { elasticsearchServiceMock } from '@kbn/core-elasticsearch-server-mocks';
import type { CatalogEntry } from '../../../common/types';
import { buildCatalogUpdate, enrichCatalogEntries } from './enrich_catalog_entries';

const catalogHit = (id: string, product: string, version = '1.0.0') => ({
  _id: id,
  _source: {
    id,
    vendor: product,
    product,
    version,
    display_name: product,
    category: 'application',
    cve_count: 0,
    known_exploited: false,
    cve_ids: [],
    '@timestamp': '2024-01-01T00:00:00Z',
  },
});

const json = (body: unknown, status = 200): Response =>
  ({ ok: status >= 200 && status < 300, status, json: async () => body } as Response);

const nvdBody = {
  vulnerabilities: [
    { cve: { id: 'CVE-1', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }] } } },
  ],
};
const kevBody = { vulnerabilities: [{ cveID: 'CVE-1' }] };

describe('enrichCatalogEntries', () => {
  let esClient: ReturnType<typeof elasticsearchServiceMock.createElasticsearchClient>;
  const logger = loggingSystemMock.createLogger();

  beforeEach(() => {
    jest.useFakeTimers();
    jest.clearAllMocks();
    esClient = elasticsearchServiceMock.createElasticsearchClient();
    esClient.bulk.mockResolvedValue({ errors: false, items: [], took: 1 });
    delete process.env.NVD_API_KEY;
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  const run = async (fetchFn: jest.Mock, hits = [catalogHit('a:a:1', 'a')]) => {
    esClient.search.mockResolvedValue({ hits: { hits } } as never);
    const promise = enrichCatalogEntries({
      esClient: esClient as unknown as ElasticsearchClient,
      logger,
      limit: 10,
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    await jest.advanceTimersByTimeAsync(120000);
    return promise;
  };

  it('enriches entries and sets known_exploited from KEV', async () => {
    const fetchFn = jest.fn(async (url: string) =>
      url.includes('cisa.gov') ? json(kevBody) : json(nvdBody)
    );
    const result = await run(fetchFn);
    expect(result).toEqual({ checked: 1, updated: 1, failed: 0 });
    const ops = esClient.bulk.mock.calls[0][0]?.operations as Array<{
      doc: Record<string, unknown>;
    }>;
    expect(ops[1].doc).toMatchObject({
      cve_ids: ['CVE-1'],
      max_cvss: 9.8,
      known_exploited: true,
    });
    expect(ops[1].doc.cve_checked_at).toBeDefined();
  });

  it('tolerates KEV failure and leaves the flag unchanged', async () => {
    const fetchFn = jest.fn(async (url: string) =>
      url.includes('cisa.gov') ? json({}, 500) : json(nvdBody)
    );
    await run(fetchFn);
    const ops = esClient.bulk.mock.calls[0][0]?.operations as Array<{
      doc: Record<string, unknown>;
    }>;
    expect('known_exploited' in ops[1].doc).toBe(false);
    expect(logger.warn).toHaveBeenCalled();
  });

  it('spaces sequential requests by about 6 seconds without an API key', async () => {
    const times: number[] = [];
    const fetchFn = jest.fn(async (url: string) => {
      if (!url.includes('cisa.gov')) times.push(Date.now());
      return url.includes('cisa.gov') ? json(kevBody) : json(nvdBody);
    });
    await run(fetchFn, [catalogHit('a:a:1', 'a'), catalogHit('b:b:1', 'b')]);
    expect(times).toHaveLength(2);
    expect(times[1] - times[0]).toBeGreaterThanOrEqual(6000);
  });

  it('retries 429 with backoff and then succeeds', async () => {
    let calls = 0;
    const fetchFn = jest.fn(async (url: string) => {
      if (url.includes('cisa.gov')) return json(kevBody);
      calls++;
      return calls < 3 ? json({}, 429) : json(nvdBody);
    });
    const result = await run(fetchFn);
    expect(calls).toBe(3);
    expect(result.updated).toBe(1);
  });

  // Previously a failed entry was not written at all, so it sorted first forever.
  it('counts a failure after max retries and marks the entry so it retries last', async () => {
    let calls = 0;
    const fetchFn = jest.fn(async (url: string) => {
      if (url.includes('cisa.gov')) return json(kevBody);
      calls++;
      return json({}, 503);
    });
    const result = await run(fetchFn);
    expect(calls).toBe(4);
    expect(result).toEqual({ checked: 1, updated: 0, failed: 1 });
    const ops = esClient.bulk.mock.calls[0][0]?.operations as Array<Record<string, unknown>>;
    expect(ops).toEqual([
      { update: { _index: expect.any(String), _id: 'a:a:1' } },
      { doc: { cve_checked_at: expect.any(String), cve_check_failed: true } },
    ]);
  });

  it('keeps making progress when entries fail persistently', async () => {
    const fetchFn = jest.fn(async (url: string) => {
      if (url.includes('cisa.gov')) return json(kevBody);
      return url.includes('broken') ? json({}, 404) : json(nvdBody);
    });
    const result = await run(fetchFn, [
      catalogHit('broken:broken:1', 'broken'),
      catalogHit('b:b:1', 'b'),
    ]);
    expect(result).toEqual({ checked: 2, updated: 1, failed: 1 });
    const ops = esClient.bulk.mock.calls[0][0]?.operations as Array<{
      doc?: Record<string, unknown>;
    }>;
    expect(ops[1].doc).toMatchObject({ cve_check_failed: true });
    expect(ops[3].doc).toMatchObject({ cve_ids: ['CVE-1'], cve_check_failed: false });
    // The next run sorts by `cve_checked_at`, which both entries now carry.
    expect(ops[1].doc?.cve_checked_at).toBeDefined();
  });

  it.each(['unknown', ''])(
    'skips the NVD lookup for version %p and marks the entry checked',
    async (version) => {
      const fetchFn = jest.fn(async (url: string) =>
        url.includes('cisa.gov') ? json(kevBody) : json(nvdBody)
      );
      const result = await run(fetchFn, [catalogHit('panw:pan-os:unknown', 'pan-os', version)]);
      expect(fetchFn.mock.calls.filter(([url]) => !String(url).includes('cisa.gov'))).toHaveLength(
        0
      );
      expect(result).toEqual({ checked: 1, updated: 1, failed: 0 });
      const ops = esClient.bulk.mock.calls[0][0]?.operations as Array<{
        doc?: Record<string, unknown>;
      }>;
      expect(ops[1].doc).toEqual({ cve_checked_at: expect.any(String), cve_check_failed: false });
    }
  );

  it('stops and warns once when the network is unavailable', async () => {
    const fetchFn = jest.fn(async () => {
      throw new TypeError('fetch failed');
    });
    const result = await run(fetchFn, [catalogHit('a:a:1', 'a'), catalogHit('b:b:1', 'b')]);
    expect(result.updated).toBe(0);
    expect(esClient.bulk).not.toHaveBeenCalled();
    const nvdWarns = (logger.warn as jest.Mock).mock.calls.filter(([m]) => /NVD/.test(m));
    expect(nvdWarns).toHaveLength(1);
  });
});

describe('buildCatalogUpdate', () => {
  const entry: CatalogEntry = {
    id: 'acme:widget:1.0.0',
    vendor: 'acme',
    product: 'widget',
    version: '1.0.0',
    display_name: 'Widget',
    category: 'application',
    cve_count: 2,
    max_cvss: 9.8,
    fixed_in: '1.0.1',
    known_exploited: true,
    cve_ids: ['CVE-1', 'CVE-2'],
    '@timestamp': '2024-01-01T00:00:00Z',
  };

  it('sets max_cvss and fixed_in to null when a re-check finds no CVEs, so stale values clear', () => {
    const update = buildCatalogUpdate({
      entry,
      parsed: { cveIds: [] },
      kev: new Set<string>(),
      now: '2024-02-01T00:00:00Z',
    });

    expect(update).toEqual(
      expect.objectContaining({
        cve_ids: [],
        cve_count: 0,
        max_cvss: null,
        fixed_in: null,
        known_exploited: false,
      })
    );
    expect(JSON.parse(JSON.stringify(update))).toHaveProperty('max_cvss', null);
  });

  it('clears stale remediation fields on re-check', () => {
    const stale: CatalogEntry = {
      ...entry,
      latest_known_fix: '2.0.0',
      fully_remediated: false,
      unfixed_cve_ids: ['CVE-2'],
      remediation_caveat: ['low_version_confidence'],
      cve_details: [{ id: 'CVE-1', fixed_in: '1.0.1', known_exploited: true }],
      first_published: '2020-01-01T00:00:00.000Z',
    };
    const update = buildCatalogUpdate({
      entry: stale,
      parsed: { cveIds: [] },
      kev: new Set<string>(),
      now: '2024-02-01T00:00:00Z',
    });
    expect(JSON.parse(JSON.stringify(update))).toMatchObject({
      fixed_in: null,
      latest_known_fix: null,
      fully_remediated: null,
      first_published: null,
      unfixed_cve_ids: [],
      remediation_caveat: [],
      cve_details: [],
    });
  });

  it('writes per-CVE details with KEV flags and the remediation summary', () => {
    const update = buildCatalogUpdate({
      entry,
      parsed: {
        cveIds: ['CVE-1', 'CVE-2'],
        maxCvss: 9.8,
        fixedIn: '1.2.0',
        latestKnownFix: '3.0.0',
        fullyRemediated: false,
        unfixedCveIds: ['CVE-2'],
        caveats: ['distro_backports'],
        cves: [
          { id: 'CVE-1', cvss: 9.8, published: '2021-12-10T10:15:09.143Z', fixedIn: '1.2.0' },
          { id: 'CVE-2', published: '2022-01-01T00:00:00.000Z' },
        ],
        firstPublished: '2021-12-10T10:15:09.143Z',
      },
      kev: new Set(['CVE-2']),
      now: '2024-02-01T00:00:00Z',
    });
    expect(update).toMatchObject({
      fixed_in: '1.2.0',
      latest_known_fix: '3.0.0',
      fully_remediated: false,
      unfixed_cve_ids: ['CVE-2'],
      remediation_caveat: ['distro_backports'],
      first_published: '2021-12-10T10:15:09.143Z',
      known_exploited: true,
      cve_details: [
        {
          id: 'CVE-1',
          cvss: 9.8,
          published: '2021-12-10T10:15:09.143Z',
          fixed_in: '1.2.0',
          known_exploited: false,
        },
        { id: 'CVE-2', published: '2022-01-01T00:00:00.000Z', known_exploited: true },
      ],
    });
  });

  it('keeps earlier per-CVE KEV flags when the KEV catalog is unavailable', () => {
    const update = buildCatalogUpdate({
      entry: { ...entry, cve_details: [{ id: 'CVE-1', known_exploited: true }] },
      parsed: { cveIds: ['CVE-1'], cves: [{ id: 'CVE-1' }] },
      kev: undefined,
      now: '2024-02-01T00:00:00Z',
    });
    expect(update.cve_details).toEqual([{ id: 'CVE-1', known_exploited: true }]);
    expect('known_exploited' in update).toBe(false);
  });
});
