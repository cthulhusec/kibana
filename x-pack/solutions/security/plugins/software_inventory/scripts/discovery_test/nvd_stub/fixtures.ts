/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  KevResponse,
  NvdCpeMatch,
  NvdResponse,
} from '../../../server/services/enrichment/nvd_parse';

/** NVD behavior: `rules` follows the per-CPE table; the others override every NVD request. */
export type NvdMode =
  | 'rules'
  | 'always-403'
  | 'always-429'
  | 'always-500'
  | 'slow'
  | 'malformed'
  | 'hang'
  | 'offline';

/** KEV behavior. */
export type KevMode = 'ok' | 'status-500' | 'malformed' | 'slow' | 'hang';

export interface StubMode {
  nvd?: NvdMode;
  kev?: KevMode;
  /** Delay for the `slow` modes. Default 35000, above the 30 s client timeout. */
  slowMs?: number;
}

export const DEFAULT_MODE: Required<StubMode> = { nvd: 'rules', kev: 'ok', slowMs: 35000 };

/** The plan's `STUB_MODE` names. */
export const MODE_PRESETS: Record<string, StubMode> = {
  normal: { nvd: 'rules', kev: 'ok' },
  'kev-500': { nvd: 'rules', kev: 'status-500' },
  offline: { nvd: 'offline', kev: 'ok' },
};

export const NVD_NAMES = [
  'rules',
  'always-403',
  'always-429',
  'always-500',
  'slow',
  'malformed',
  'hang',
  'offline',
];
export const KEV_NAMES = ['ok', 'status-500', 'malformed', 'slow', 'hang'];

/** A rule for one CPE: respond with `body`, after optionally failing with `failures` first. */
export type CpeRule =
  | { kind: 'body'; body: NvdResponse }
  | { kind: 'sequence'; statuses: number[]; then: NvdResponse }
  | { kind: 'status'; status: number }
  | { kind: 'hang' };

interface Range {
  startIncluding?: string;
  endExcluding?: string;
}

const cpeMatches = (vendor: string, product: string, part: 'a' | 'o', ranges: Range[]) =>
  ranges.map(
    ({ startIncluding, endExcluding }): NvdCpeMatch => ({
      vulnerable: true,
      criteria: `cpe:2.3:${part}:${vendor}:${product}:*:*:*:*:*:*:*:*`,
      ...(startIncluding ? { versionStartIncluding: startIncluding } : {}),
      ...(endExcluding ? { versionEndExcluding: endExcluding } : {}),
    })
  );

const cve = ({
  id,
  published,
  score,
  vendor,
  product,
  part = 'a',
  ranges,
}: {
  id: string;
  published: string;
  score: number;
  vendor: string;
  product: string;
  part?: 'a' | 'o';
  ranges: Range[];
}): { cve: NonNullable<NvdResponse['vulnerabilities']>[number]['cve'] } => ({
  cve: {
    id,
    published,
    metrics: { cvssMetricV31: [{ cvssData: { baseScore: score } }] },
    configurations: [{ nodes: [{ cpeMatch: cpeMatches(vendor, product, part, ranges) }] }],
  },
});

const log4j = (id: string, published: string, score: number, ranges: Range[]) =>
  cve({ id, published, score, vendor: 'apache', product: 'log4j', ranges });

/** The four Log4Shell-era CVEs with the three maintained branches each. */
const LOG4J_BODY: NvdResponse = {
  vulnerabilities: [
    log4j('CVE-2021-44228', '2021-12-10T10:15:09.143', 10, [
      { startIncluding: '2.0-beta9', endExcluding: '2.3.1' },
      { startIncluding: '2.4', endExcluding: '2.12.2' },
      { startIncluding: '2.13.0', endExcluding: '2.15.0' },
    ]),
    log4j('CVE-2021-45046', '2021-12-14T12:15:07.700', 9, [
      { startIncluding: '2.0-beta9', endExcluding: '2.3.1' },
      { startIncluding: '2.4', endExcluding: '2.12.2' },
      { startIncluding: '2.13.0', endExcluding: '2.16.0' },
    ]),
    log4j('CVE-2021-45105', '2021-12-18T12:15:07.558', 5.9, [
      { startIncluding: '2.0-alpha1', endExcluding: '2.3.1' },
      { startIncluding: '2.4', endExcluding: '2.12.3' },
      { startIncluding: '2.13.0', endExcluding: '2.17.0' },
    ]),
    log4j('CVE-2021-44832', '2021-12-28T21:15:08.150', 6.6, [
      { startIncluding: '2.0-beta7', endExcluding: '2.3.2' },
      { startIncluding: '2.4', endExcluding: '2.12.4' },
      { startIncluding: '2.13.0', endExcluding: '2.17.1' },
    ]),
  ],
};

const SYNTH_BODY: NvdResponse = {
  vulnerabilities: [
    cve({
      id: 'CVE-2099-0001',
      published: '2099-01-01T00:00:00.000',
      score: 7.5,
      vendor: 'synth-checkout',
      product: 'synth-checkout',
      ranges: [{ startIncluding: '2.0.0' }],
    }),
  ],
};

const FORTIOS_BODY: NvdResponse = {
  vulnerabilities: [
    cve({
      id: 'CVE-2023-27997',
      published: '2023-06-13T09:15:09.480',
      score: 9.8,
      vendor: 'fortinet',
      product: 'fortios',
      part: 'o',
      ranges: [
        { startIncluding: '7.2.0', endExcluding: '7.2.5' },
        { startIncluding: '7.0.0', endExcluding: '7.0.12' },
      ],
    }),
  ],
};

const PANOS_BODY: NvdResponse = {
  vulnerabilities: [
    cve({
      id: 'CVE-2024-3400',
      published: '2024-04-12T08:15:06.240',
      score: 10,
      vendor: 'paloaltonetworks',
      product: 'pan-os',
      part: 'o',
      ranges: [{ startIncluding: '10.2.0', endExcluding: '10.2.9-h1' }],
    }),
  ],
};

const NGINX_BODY: NvdResponse = {
  vulnerabilities: [
    cve({
      id: 'CVE-2023-44487',
      published: '2023-10-10T14:15:10.883',
      score: 7.5,
      vendor: 'f5',
      product: 'nginx',
      ranges: [{ startIncluding: '1.9.5', endExcluding: '1.25.3' }],
    }),
  ],
};

export const EMPTY_BODY: NvdResponse = { vulnerabilities: [] };

const cpeName = (part: 'a' | 'o', vendor: string, product: string, version: string): string =>
  `cpe:2.3:${part}:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;

/** Exact `cpeName` to rule. Any other CPE answers 200 with no vulnerabilities. */
export const CPE_RULES: Readonly<Record<string, CpeRule>> = {
  [cpeName('a', 'apache', 'log4j', '2.14.1')]: { kind: 'body', body: LOG4J_BODY },
  [cpeName('a', 'apache', 'log4j', '2.12.1')]: { kind: 'body', body: LOG4J_BODY },
  [cpeName('a', 'synth-checkout', 'synth-checkout', '2.4.0')]: { kind: 'body', body: SYNTH_BODY },
  [cpeName('o', 'fortinet', 'fortios', '7.2.4')]: { kind: 'body', body: FORTIOS_BODY },
  [cpeName('o', 'paloaltonetworks', 'pan-os', '10.2.3')]: { kind: 'body', body: PANOS_BODY },
  [cpeName('a', 'f5', 'nginx', '1.25.2')]: { kind: 'body', body: NGINX_BODY },
  [cpeName('a', 'slack', 'slack', '4.41.105')]: { kind: 'body', body: EMPTY_BODY },
  [cpeName('a', 'google', 'chrome', '131.0.6778.86')]: {
    kind: 'sequence',
    statuses: [429, 429],
    then: EMPTY_BODY,
  },
  [cpeName('a', '7-zip', '7-zip', '23.01')]: { kind: 'status', status: 403 },
  [cpeName('a', 'microsoft', 'visual_studio_code', '1.95.3')]: { kind: 'hang' },
};

export const KEV_BODY: KevResponse = {
  vulnerabilities: [
    { cveID: 'CVE-2021-44228' },
    { cveID: 'CVE-2021-45046' },
    { cveID: 'CVE-2023-27997' },
    { cveID: 'CVE-2024-3400' },
  ],
};
