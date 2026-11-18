/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  KevResponse,
  NvdResponse,
  ParsedNvd,
} from '../../../server/services/enrichment/nvd_parse';
import {
  intersectKev,
  parseKevCveIds,
  parseNvdResponse,
} from '../../../server/services/enrichment/nvd_parse';
import http from 'http';
import type { NvdStub } from './server';
import { startNvdStub } from './server';

const cpe = (part: string, vendor: string, product: string, version: string): string =>
  `cpe:2.3:${part}:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;

interface HttpResult {
  status: number;
  text: () => Promise<string>;
  json: () => Promise<unknown>;
}

/** Node `http` client: the jsdom `fetch` polyfill cannot reach a local server. */
const fetch = (
  url: string,
  {
    method = 'GET',
    headers,
    body,
    signal,
  }: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal } = {}
): Promise<HttpResult> =>
  new Promise((resolve, reject) => {
    const req = http.request(url, { method, headers, signal }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({
          status: res.statusCode ?? 0,
          text: async () => text,
          json: async () => JSON.parse(text),
        });
      });
    });
    req.on('error', reject);
    req.end(body);
  });

describe('NVD and KEV stub', () => {
  let stub: NvdStub;

  beforeAll(async () => {
    stub = await startNvdStub({ port: 0 });
  });
  afterAll(async () => {
    await stub.close();
  });
  beforeEach(() => {
    stub.reset();
  });

  const getNvd = (cpeName: string): Promise<HttpResult> =>
    fetch(`${stub.url}/rest/json/cves/2.0?cpeName=${encodeURIComponent(cpeName)}&noRejected`);

  const parse = async (
    cpeName: string,
    target: { nvdVendor: string; product: string; version: string }
  ): Promise<ParsedNvd> => {
    const response = await getNvd(cpeName);
    expect(response.status).toBe(200);
    return parseNvdResponse((await response.json()) as NvdResponse, target);
  };

  it('binds to 127.0.0.1 and reports the real port', () => {
    expect(stub.port).toBeGreaterThan(0);
    expect(stub.url).toBe(`http://127.0.0.1:${stub.port}`);
  });

  describe('fixtures parse like NVD data', () => {
    it('log4j 2.14.1 fixes all four CVEs at 2.17.1', async () => {
      const parsed = await parse(cpe('a', 'apache', 'log4j', '2.14.1'), {
        nvdVendor: 'apache',
        product: 'log4j',
        version: '2.14.1',
      });
      expect(parsed.cveIds).toEqual([
        'CVE-2021-44228',
        'CVE-2021-44832',
        'CVE-2021-45046',
        'CVE-2021-45105',
      ]);
      expect(parsed.maxCvss).toBe(10);
      expect(parsed.fixedIn).toBe('2.17.1');
      expect(parsed.latestKnownFix).toBe('2.17.1');
      expect(parsed.fullyRemediated).toBe(true);
      expect(parsed.unfixedCveIds).toEqual([]);
      expect(parsed.firstPublished).toBe('2021-12-10T10:15:09.143Z');
      expect(parsed.cves?.map(({ id, fixedIn }) => [id, fixedIn])).toEqual([
        ['CVE-2021-44228', '2.15.0'],
        ['CVE-2021-45046', '2.16.0'],
        ['CVE-2021-44832', '2.17.1'],
        ['CVE-2021-45105', '2.17.0'],
      ]);
    });

    it('log4j 2.12.1 is fixed on its own branch at 2.12.4', async () => {
      const parsed = await parse(cpe('a', 'apache', 'log4j', '2.12.1'), {
        nvdVendor: 'apache',
        product: 'log4j',
        version: '2.12.1',
      });
      expect(parsed.cveIds).toHaveLength(4);
      expect(parsed.fixedIn).toBe('2.12.4');
      expect(parsed.latestKnownFix).toBe('2.17.1');
      expect(parsed.fullyRemediated).toBe(true);
    });

    it('synth-checkout has no fix', async () => {
      const parsed = await parse(cpe('a', 'synth-checkout', 'synth-checkout', '2.4.0'), {
        nvdVendor: 'synth-checkout',
        product: 'synth-checkout',
        version: '2.4.0',
      });
      expect(parsed.cveIds).toEqual(['CVE-2099-0001']);
      expect(parsed.maxCvss).toBe(7.5);
      expect(parsed.fixedIn).toBeUndefined();
      expect(parsed.fullyRemediated).toBe(false);
      expect(parsed.unfixedCveIds).toEqual(['CVE-2099-0001']);
    });

    it.each([
      ['o', 'fortinet', 'fortios', '7.2.4', 'CVE-2023-27997', 9.8, '7.2.5'],
      ['o', 'paloaltonetworks', 'pan-os', '10.2.3', 'CVE-2024-3400', 10, '10.2.9-h1'],
      ['a', 'f5', 'nginx', '1.25.2', 'CVE-2023-44487', 7.5, '1.25.3'],
    ])('%s:%s:%s:%s', async (part, vendor, product, version, id, score, fixedIn) => {
      const parsed = await parse(cpe(part, vendor, product, version), {
        nvdVendor: vendor,
        product,
        version,
      });
      expect(parsed.cveIds).toEqual([id]);
      expect(parsed.maxCvss).toBe(score);
      expect(parsed.fixedIn).toBe(fixedIn);
      expect(parsed.fullyRemediated).toBe(true);
    });

    it.each([
      [cpe('a', 'slack', 'slack', '4.41.105'), 'slack', '4.41.105'],
      [cpe('a', 'unlisted', 'thing', '1.0.0'), 'thing', '1.0.0'],
    ])('answers %s with no CVEs', async (cpeName, product, version) => {
      const parsed = await parse(cpeName, { nvdVendor: product, product, version });
      expect(parsed.cveIds).toEqual([]);
      expect(parsed.fullyRemediated).not.toBe(false);
    });
  });

  it('answers 429, 429, then 200 for chrome and logs the sequence', async () => {
    const chrome = cpe('a', 'google', 'chrome', '131.0.6778.86');
    const statuses = [];
    for (let i = 0; i < 4; i++) statuses.push((await getNvd(chrome)).status);
    expect(statuses).toEqual([429, 429, 200, 200]);
    const log = stub.requests();
    expect(log.map((r) => r.status)).toEqual([429, 429, 200, 200]);
    expect(log[0]).toMatchObject({
      method: 'GET',
      path: '/rest/json/cves/2.0',
      query: { cpeName: chrome, noRejected: '' },
    });
    expect(Date.parse(log[1].at)).toBeGreaterThanOrEqual(Date.parse(log[0].at));
  });

  it('answers 7-zip with 403 every time', async () => {
    const zip = cpe('a', '7-zip', '7-zip', '23.01');
    expect(
      await Promise.all([getNvd(zip), getNvd(zip)]).then((r) => r.map((x) => x.status))
    ).toEqual([403, 403]);
  });

  it('never answers VS Code and logs status 0', async () => {
    const controller = new AbortController();
    const pending = fetch(
      `${stub.url}/rest/json/cves/2.0?cpeName=${encodeURIComponent(
        cpe('a', 'microsoft', 'visual_studio_code', '1.95.3')
      )}&noRejected`,
      { signal: controller.signal }
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(stub.requests()).toHaveLength(1);
    expect(stub.requests()[0].status).toBe(0);
    controller.abort();
    await expect(pending).rejects.toThrow();
  });

  describe('KEV', () => {
    const getKev = async (): Promise<KevResponse> =>
      (await (await fetch(`${stub.url}/kev.json`)).json()) as KevResponse;

    it('serves the plan catalog and intersects with the parsed CVE ids', async () => {
      const kev = parseKevCveIds(await getKev());
      expect(kev.size).toBe(4);
      expect(intersectKev(['CVE-2021-44228'], kev)).toBe(true);
      expect(intersectKev(['CVE-2023-27997'], kev)).toBe(true);
      expect(intersectKev(['CVE-2024-3400'], kev)).toBe(true);
      expect(intersectKev(['CVE-2023-44487', 'CVE-2099-0001'], kev)).toBe(false);
    });

    it('answers 500 in kev-500 mode', async () => {
      stub.setMode({ kev: 'status-500' });
      expect((await fetch(`${stub.url}/kev.json`)).status).toBe(500);
    });
  });

  describe('modes', () => {
    const log4j = cpe('a', 'apache', 'log4j', '2.14.1');

    it.each([
      ['always-403', 403],
      ['always-429', 429],
      ['always-500', 500],
    ] as const)('%s overrides the rule table', async (nvd, status) => {
      stub.setMode({ nvd });
      expect((await getNvd(log4j)).status).toBe(status);
    });

    it('returns malformed JSON', async () => {
      stub.setMode({ nvd: 'malformed' });
      const response = await getNvd(log4j);
      expect(response.status).toBe(200);
      await expect(response.json()).rejects.toThrow();
    });

    it('delays the response in slow mode', async () => {
      stub.setMode({ nvd: 'slow', slowMs: 200 });
      const started = Date.now();
      const response = await getNvd(log4j);
      expect(response.status).toBe(200);
      expect(Date.now() - started).toBeGreaterThanOrEqual(190);
    });

    it('destroys the socket in offline mode', async () => {
      stub.setMode({ nvd: 'offline' });
      await expect(getNvd(log4j)).rejects.toThrow();
      expect(stub.requests()[0].status).toBe(0);
    });

    it('switches modes and resets through the control API', async () => {
      const post = (path: string, body?: unknown) =>
        fetch(`${stub.url}${path}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: body === undefined ? undefined : JSON.stringify(body),
        });
      expect((await post('/_stub/mode', { preset: 'kev-500' })).status).toBe(200);
      expect((await fetch(`${stub.url}/kev.json`)).status).toBe(500);
      expect((await post('/_stub/mode', { nvd: 'always-500' })).status).toBe(200);
      expect((await getNvd(log4j)).status).toBe(500);
      expect((await post('/_stub/mode', { nvd: 'bogus' })).status).toBe(400);

      const log = (await (await fetch(`${stub.url}/_stub/requests`)).json()) as Array<{
        path: string;
        status: number;
      }>;
      expect(log.map((r) => [r.path, r.status])).toEqual([
        ['/kev.json', 500],
        ['/rest/json/cves/2.0', 500],
      ]);

      expect((await post('/_stub/reset')).status).toBe(200);
      expect(stub.requests()).toEqual([]);
      expect((await getNvd(log4j)).status).toBe(200);
      expect((await fetch(`${stub.url}/kev.json`)).status).toBe(200);
    });
  });
});
