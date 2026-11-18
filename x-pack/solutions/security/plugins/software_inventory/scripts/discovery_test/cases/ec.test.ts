/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { CatalogEntry } from '../../../common/types';
import { buildCpe, toNvdVendor } from '../../../server/services/enrichment/build_cpe';
import { buildCatalogUpdate } from '../../../server/services/enrichment/enrich_catalog_entries';
import { parseKevCveIds, parseNvdResponse } from '../../../server/services/enrichment/nvd_parse';
import type { EsClient, JsonValue, MgetResponse, SearchResponse } from '../clients';
import { EC_CPES, EC_IDS, EC_REQUIRED_CATALOG_IDS } from '../expected/ec';
import { parseCatalogId } from '../ids';
import { CPE_RULES, KEV_BODY } from '../nvd_stub/fixtures';
import type { Ec1Capture } from './ec';
import { EC1_EVIDENCE_KEY, createEcCases, ec1CaptureToJson, readEc1Capture } from './ec';
import type { EnrichmentTiming, StubRequestRecord } from './ec_support';
import {
  checkGaps,
  checkSpacing,
  compactRequests,
  detectOverrideProblem,
  diffPicks,
  expectsLookupFailure,
  parseDurationMs,
  predictPicks,
  requestsFromJson,
  requestsToJson,
  resolveEnrichmentTiming,
  retryGapsMs,
} from './ec_support';
import type { FakeStubState } from './fake_context';
import {
  asType,
  fakeContext,
  fakeEs,
  fakeRun,
  fakeStub,
  kevRequest,
  nvdRequest,
  passingRecord,
} from './fake_context';

const TIMING: EnrichmentTiming = {
  spacingMs: 100,
  timeoutMs: 2000,
  backoffBaseMs: 200,
  source: 'test',
};

const at = (ms: number): string =>
  new Date(Date.parse('2026-11-18T10:00:00.000Z') + ms).toISOString();
const rec = (ms: number, cpe: string, status: number): StubRequestRecord => ({
  at: at(ms),
  path: '/rest/json/cves/2.0',
  cpe,
  status,
});

describe('ec_support: timing from the Kibana config', () => {
  it('parses Kibana durations', () => {
    expect(parseDurationMs('100ms')).toBe(100);
    expect(parseDurationMs('2s')).toBe(2000);
    expect(parseDurationMs('1m')).toBe(60_000);
    expect(parseDurationMs(250)).toBe(250);
    expect(parseDurationMs('soon')).toBeUndefined();
  });

  it('merges kibana.dev.yml over kibana.yml, nested and dotted keys alike', () => {
    const files: Record<string, string> = {
      'kibana.yml': 'xpack.softwareInventory.enrichment.requestSpacing: 5s\n',
      'kibana.dev.yml': [
        'xpack.softwareInventory.enrichment:',
        '  nvdBaseUrl: http://localhost:5699/rest/json/cves/2.0',
        '  requestSpacing: 100ms',
        '  requestTimeout: 2s',
        '  backoffBase: 200ms',
      ].join('\n'),
    };
    const timing = resolveEnrichmentTiming({
      configEnv: 'kibana.yml,kibana.dev.yml',
      readFile: (path) => files[path.split('/').pop() ?? ''],
    });
    expect(timing).toEqual(
      expect.objectContaining({
        spacingMs: 100,
        timeoutMs: 2000,
        backoffBaseMs: 200,
        nvdBaseUrl: 'http://localhost:5699/rest/json/cves/2.0',
      })
    );
  });

  it('falls back to the production defaults and says so', () => {
    const timing = resolveEnrichmentTiming({ configEnv: 'missing.yml', readFile: () => undefined });
    expect(timing).toEqual(
      expect.objectContaining({ spacingMs: 6000, timeoutMs: 30_000, backoffBaseMs: 2000 })
    );
    expect(timing.source).toMatch(/production defaults/);
  });
});

describe('ec_support: stub log analysis', () => {
  it('accepts backoff gaps near b and 2b and rejects spacing-sized or default-sized ones', () => {
    const expected = retryGapsMs(200, 2);
    expect(expected).toEqual([200, 400]);
    expect(checkGaps('chrome', [215, 420], expected)).toEqual([]);
    expect(checkGaps('chrome', [100, 420], expected)[0]).toMatch(/gap #1 100ms outside/);
    expect(checkGaps('chrome', [2000, 4000], expected)).toHaveLength(2);
    expect(checkGaps('chrome', [215], expected)[0]).toMatch(/expected 2 gap/);
    expect(retryGapsMs(200, 3, 2000)).toEqual([2200, 2400, 2800]);
  });

  it('checks spacing only between different CPEs', () => {
    const requests = [rec(0, 'a', 200), rec(150, 'b', 429), rec(360, 'b', 200), rec(380, 'c', 200)];
    expect(checkSpacing(requests, 100)).toEqual([
      'spacing: 20ms between b and c, below requestSpacing 100ms',
    ]);
  });

  it('detects an inactive override from the stub log', () => {
    expect(detectOverrideProblem({ requests: [], expectNvd: true, expectKev: true })).toMatch(
      /override not active: the stub saw no requests/
    );
    expect(
      detectOverrideProblem({
        requests: compactRequests([kevRequest(at(0))]),
        expectNvd: true,
        expectKev: true,
      })
    ).toMatch(/nvdBaseUrl override not active/);
    expect(
      detectOverrideProblem({ requests: [rec(0, 'a', 200)], expectNvd: true, expectKev: true })
    ).toMatch(/kevUrl override not active/);
    expect(
      detectOverrideProblem({
        requests: compactRequests([kevRequest(at(0))]),
        expectNvd: false,
        expectKev: true,
      })
    ).toBeUndefined();
  });

  it('round-trips the request log through JSON evidence', () => {
    const requests = compactRequests([nvdRequest(at(0), 'cpe', 429), kevRequest(at(1))]);
    expect(requestsFromJson(requestsToJson(requests))).toEqual(requests);
    expect(requestsFromJson([{ at: 1 }])).toBeUndefined();
  });
});

describe('ec_support: catalog order', () => {
  const entries = [
    { id: 'c', cve_checked_at: '2026-11-18T09:00:00.000Z' },
    { id: 'a' },
    { id: 'd', cve_checked_at: '2026-11-18T09:00:00.000Z' },
    { id: 'b', cve_checked_at: '2026-11-18T08:00:00.000Z' },
    { id: 'e', cve_checked_at: '2026-11-18T10:00:00.000Z' },
  ];

  it('predicts never-checked first, then the oldest, and leaves boundary ties open', () => {
    const prediction = predictPicks(entries, 3);
    expect(prediction).toEqual({ definite: ['a', 'b'], tieGroup: ['c', 'd'], tieCount: 1 });
    expect(diffPicks(prediction, ['a', 'b', 'd'])).toEqual([]);
    expect(diffPicks(prediction, ['a', 'b', 'c', 'd'])).toEqual([
      'expected 1 of the 2 tied entries to be checked, got 2',
    ]);
    expect(diffPicks(prediction, ['a', 'e', 'c'])).toEqual([
      'expected b to be checked, it was not',
      'e was checked, but it was not due',
    ]);
  });

  it('expects failure markers only for the stub entries that never succeed', () => {
    const entry = (id: string) => {
      const { vendor, product, version } = parseCatalogId(id);
      return { vendor, product, version, category: 'application' as const };
    };
    expect(expectsLookupFailure(entry(EC_IDS.sevenZip))).toBe(true);
    expect(expectsLookupFailure(entry(EC_IDS.vscode))).toBe(true);
    expect(expectsLookupFailure(entry(EC_IDS.chrome))).toBe(false);
    expect(expectsLookupFailure(entry(EC_IDS.slack))).toBe(false);
    expect(expectsLookupFailure(entry(EC_IDS.nginxUnknown))).toBe(false);
  });
});

// -------------------------------------------------------------------------------------------------
// Cases with a fake stack
// -------------------------------------------------------------------------------------------------

const entryFor = (id: string, extra: Partial<CatalogEntry> = {}): CatalogEntry => {
  const { vendor, product, version } = parseCatalogId(id);
  const category =
    id === EC_IDS.fortios724 || id === EC_IDS.panos1023 || id === EC_IDS.panosUnknown
      ? 'appliance'
      : id.startsWith('apache:log4j')
      ? 'dependency'
      : 'application';
  return {
    id,
    vendor,
    product,
    version,
    display_name: id,
    category,
    cve_count: 0,
    known_exploited: false,
    cve_ids: [],
    '@timestamp': at(0),
    ...extra,
  };
};

/** What the real step writes for `entry` when the stub answers normally. */
const enriched = (entry: CatalogEntry, now: string): CatalogEntry => {
  const rule = CPE_RULES[buildCpe(entry)];
  if (rule?.kind === 'hang' || rule?.kind === 'status') {
    return { ...entry, cve_checked_at: now, cve_check_failed: true };
  }
  const body =
    rule?.kind === 'body'
      ? rule.body
      : rule?.kind === 'sequence'
      ? rule.then
      : { vulnerabilities: [] };
  const parsed = parseNvdResponse(body, {
    nvdVendor: toNvdVendor(entry.vendor),
    product: entry.product,
    version: entry.version,
    category: entry.category,
  });
  const update = buildCatalogUpdate({ entry, parsed, kev: parseKevCveIds(KEV_BODY), now });
  return asType<CatalogEntry>(
    Object.fromEntries(
      Object.entries({ ...entry, ...update }).filter(([, value]) => value !== null)
    )
  );
};

const searchResponse = <T>(docs: ReadonlyArray<{ id: string; source: T }>): SearchResponse<T> => ({
  hits: { hits: docs.map(({ id, source }) => ({ _id: id, _index: 'x', _source: source })) },
});

/** A catalog in memory: the step "runs" by enriching every never-checked entry. */
const fakeCatalogStack = ({
  stubSeesRequests,
  tamper,
}: {
  stubSeesRequests: boolean;
  tamper?: (entry: CatalogEntry) => CatalogEntry;
}) => {
  let catalog = new Map(EC_REQUIRED_CATALOG_IDS.map((id) => [id, entryFor(id)]));
  const stubState: FakeStubState = { log: [], resets: 0, modes: [] };
  const es: EsClient = fakeEs({
    request: async <T>() => ({ status: 200, body: { updated: 0 } as JsonValue as T }),
    search: async <T>(_index: string, body: object) => {
      const range = (body as { query: { range?: { cve_checked_at: { gte: string } } } }).query
        .range;
      const docs = [...catalog.values()]
        .filter(
          (entry) =>
            !range ||
            (entry.cve_checked_at !== undefined &&
              Date.parse(entry.cve_checked_at) >= Date.parse(range.cve_checked_at.gte))
        )
        .map((entry) => ({ id: entry.id, source: asType<T>(entry) }));
      return searchResponse<T>(docs);
    },
    mget: async <T>(_index: string, ids: readonly string[]): Promise<MgetResponse<T>> => ({
      docs: ids.map((id) => {
        const entry = catalog.get(id);
        return entry
          ? { _id: id, found: true, _source: asType<T>(entry) }
          : { _id: id, found: false };
      }),
    }),
  });
  const runWorkflow = async () => {
    const now = new Date().toISOString();
    const pending = [...catalog.values()].filter((entry) => entry.cve_checked_at === undefined);
    if (stubSeesRequests) {
      stubState.log.push(kevRequest(now));
      pending
        .filter((entry) => entry.version !== 'unknown')
        .forEach((entry) => stubState.log.push(nvdRequest(now, buildCpe(entry), 200)));
    }
    catalog = new Map(
      [...catalog.values()].map((entry) => {
        if (entry.cve_checked_at !== undefined) return [entry.id, entry];
        const next =
          entry.version === 'unknown'
            ? { ...entry, cve_checked_at: now, cve_check_failed: false }
            : enriched(entry, now);
        return [entry.id, tamper ? tamper(next) : next];
      })
    );
    const failed = pending.filter(expectsLookupFailure).length;
    return fakeRun({
      enrich: {
        output: { checked: pending.length, updated: pending.length - failed, failed },
        input: { limit: pending.length },
      },
    });
  };
  return { es, runWorkflow, stub: fakeStub(stubState), stubState };
};

const ecCases = createEcCases({ resolveTiming: () => TIMING });
const ecCase = (id: string) => {
  const found = ecCases.find((testCase) => testCase.id === id);
  if (!found) throw new Error(`no case ${id}`);
  return found;
};

describe('EC cases', () => {
  it('registers EC-1..EC-12 in matrix order, all on the stub, chained on EC-1', () => {
    expect(ecCases.map(({ id }) => id)).toEqual(
      Array.from({ length: 12 }, (_, index) => `EC-${index + 1}`)
    );
    expect(ecCases.every(({ needs }) => needs?.includes('nvd-stub'))).toBe(true);
    expect(ecCase('EC-1').requires).toEqual(['DO-1', 'DI-2', 'DL-1']);
    expect(ecCases.slice(1).every(({ requires }) => requires?.includes('EC-1'))).toBe(true);
  });

  it('is blocked without the stub', async () => {
    const result = await ecCase('EC-1').run(fakeContext({}));
    expect(result.status).toBe('blocked');
  });

  it('EC-1 is blocked, never pass or fail, when the stub saw no request', async () => {
    const stack = fakeCatalogStack({ stubSeesRequests: false });
    const result = await ecCase('EC-1').run(
      fakeContext({ es: stack.es, runWorkflow: stack.runWorkflow, nvdStub: stack.stub })
    );
    expect(result.status).toBe('blocked');
    expect(result.notes?.[0]).toMatch(/override not active: the stub saw no requests/);
  });

  it('EC-1 passes on the expected catalog state and records the stub capture', async () => {
    const stack = fakeCatalogStack({ stubSeesRequests: true });
    const result = await ecCase('EC-1').run(
      fakeContext({ es: stack.es, runWorkflow: stack.runWorkflow, nvdStub: stack.stub })
    );
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
    expect(stack.stubState.resets).toBe(1);
    const evidence = result.layers.find(({ evidence: e }) => e?.[EC1_EVIDENCE_KEY])?.evidence ?? {};
    const capture = readEc1Capture({
      priorResults: new Map([['EC-1', passingRecord('EC-1', evidence)]]),
    });
    expect(capture?.limit).toBe(EC_REQUIRED_CATALOG_IDS.length);
    expect(capture?.expectedFailures).toBe(2);
  });

  it('EC-1 fails when the parsed outcome differs', async () => {
    const stack = fakeCatalogStack({
      stubSeesRequests: true,
      tamper: (entry) => (entry.id === EC_IDS.log4j2141 ? { ...entry, fixed_in: '2.15.0' } : entry),
    });
    const result = await ecCase('EC-1').run(
      fakeContext({ es: stack.es, runWorkflow: stack.runWorkflow, nvdStub: stack.stub })
    );
    expect(result.status).toBe('fail');
    expect(result.layers.flatMap(({ diffs }) => diffs).join('\n')).toMatch(/fixed_in/);
  });

  it('EC-1 is blocked when the discovery entries are missing', async () => {
    const stack = fakeCatalogStack({ stubSeesRequests: true });
    const es = { ...stack.es, search: async <T>() => searchResponse<T>([]) };
    const result = await ecCase('EC-1').run(
      fakeContext({ es, runWorkflow: stack.runWorkflow, nvdStub: stack.stub })
    );
    expect(result.status).toBe('blocked');
    expect(result.notes?.[0]).toMatch(/Run DO-1, DI-2, and DL-1 first/);
  });
});

describe('EC-6..EC-8 on the EC-1 capture', () => {
  const b = TIMING.backoffBaseMs;
  const t = TIMING.timeoutMs;
  const captureWith = (chromeSecondGap: number): Ec1Capture => ({
    startedAt: at(-1000),
    limit: 3,
    output: { checked: 3, updated: 1, failed: 2 },
    expectedFailures: 2,
    timing: TIMING,
    requests: [
      { at: at(0), path: '/kev.json', status: 200 },
      rec(10, EC_CPES.chrome, 429),
      rec(10 + b + 5, EC_CPES.chrome, 429),
      rec(10 + b + 5 + chromeSecondGap, EC_CPES.chrome, 200),
      rec(1000, EC_CPES.sevenZip, 403),
      rec(1000 + b, EC_CPES.sevenZip, 403),
      rec(1000 + 3 * b, EC_CPES.sevenZip, 403),
      rec(1000 + 7 * b, EC_CPES.sevenZip, 403),
      rec(3000, EC_CPES.vscode, 0),
      rec(3000 + t + b, EC_CPES.vscode, 0),
      rec(3000 + 2 * t + 3 * b, EC_CPES.vscode, 0),
      rec(3000 + 3 * t + 7 * b, EC_CPES.vscode, 0),
    ],
  });
  const markerEs = (entries: CatalogEntry[]) =>
    fakeEs({
      mget: async <T>(_index: string, ids: readonly string[]): Promise<MgetResponse<T>> => ({
        docs: ids.map((id) => {
          const entry = entries.find((candidate) => candidate.id === id);
          return entry
            ? { _id: id, found: true, _source: asType<T>(entry) }
            : { _id: id, found: false };
        }),
      }),
    });
  const prior = (capture: Ec1Capture) =>
    new Map([['EC-1', passingRecord('EC-1', { [EC1_EVIDENCE_KEY]: ec1CaptureToJson(capture) })]]);
  const es = markerEs([
    entryFor(EC_IDS.chrome, {
      cpe: EC_CPES.chrome,
      cve_checked_at: at(500),
      cve_check_failed: false,
    }),
    entryFor(EC_IDS.sevenZip, { cve_checked_at: at(2500), cve_check_failed: true }),
    entryFor(EC_IDS.vscode, { cve_checked_at: at(12000), cve_check_failed: true }),
  ]);

  it.each(['EC-6', 'EC-7', 'EC-8'])('%s passes on the expected stub timing', async (id) => {
    const result = await ecCase(id).run(
      fakeContext({ es, priorResults: prior(captureWith(2 * b)) })
    );
    expect(result.layers.flatMap(({ diffs }) => diffs)).toEqual([]);
    expect(result.status).toBe('pass');
  });

  it('EC-6 fails when the second backoff is not doubled', async () => {
    const result = await ecCase('EC-6').run(
      fakeContext({ es, priorResults: prior(captureWith(b)) })
    );
    expect(result.status).toBe('fail');
    expect(result.layers.flatMap(({ diffs }) => diffs).join('\n')).toMatch(/gap #2/);
  });

  it('is blocked without an EC-1 capture', async () => {
    const result = await ecCase('EC-7').run(fakeContext({ es }));
    expect(result.status).toBe('blocked');
  });
});
