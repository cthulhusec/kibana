/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { normalizeToken } from '../../../common/normalize';
import { buildCpe } from './build_cpe';
import { combineExposure, levelFromScore } from './combine_exposure';
import { isPublicIp } from './public_ip';
import { intersectKev, parseKevCveIds, parseNvdResponse, compareVersions } from './nvd_parse';
import { resolveIntegration, resolveObserver, isEdgeProduct } from './integration_map';

const nvdFixture = {
  resultsPerPage: 3,
  vulnerabilities: [
    {
      cve: {
        id: 'CVE-2024-0001',
        metrics: {
          cvssMetricV2: [{ cvssData: { baseScore: 9.0 } }],
          cvssMetricV31: [{ cvssData: { baseScore: 7.5 } }],
        },
        configurations: [
          {
            nodes: [
              {
                cpeMatch: [
                  {
                    vulnerable: true,
                    criteria: 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*',
                    versionStartIncluding: '1.0.0',
                    versionEndExcluding: '1.25.4',
                  },
                  {
                    vulnerable: true,
                    criteria: 'cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*',
                    versionEndExcluding: '1.20.0',
                  },
                ],
              },
            ],
          },
        ],
      },
    },
    {
      cve: {
        id: 'CVE-2023-0002',
        metrics: { cvssMetricV30: [{ cvssData: { baseScore: 8.1 } }] },
        configurations: [
          {
            nodes: [
              {
                cpeMatch: [
                  {
                    vulnerable: true,
                    criteria: 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*',
                    versionEndExcluding: '1.24.0',
                  },
                  {
                    vulnerable: true,
                    criteria: 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*',
                    versionEndExcluding: '1.9.0',
                  },
                ],
              },
            ],
          },
        ],
      },
    },
    {
      cve: {
        id: 'CVE-2022-0003',
        metrics: { cvssMetricV2: [{ cvssData: { baseScore: 5.0 } }] },
      },
    },
  ],
};

describe('buildCpe', () => {
  it('builds an application CPE', () => {
    expect(buildCpe({ vendor: 'nginx', product: 'nginx', version: '1.24.0' })).toBe(
      'cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*'
    );
  });

  it('uses part o and NVD vendor name for PAN-OS', () => {
    expect(
      buildCpe({
        vendor: 'palo_alto_networks',
        product: 'pan-os',
        version: '10.2.3',
        category: 'appliance',
      })
    ).toBe('cpe:2.3:o:paloaltonetworks:pan-os:10.2.3:*:*:*:*:*:*:*');
  });

  it('keeps hyphens and quotes other special characters, as NVD names do', () => {
    expect(buildCpe({ vendor: '7-zip', product: '7-zip', version: '23.01' })).toBe(
      'cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*'
    );
    expect(buildCpe({ vendor: 'notepad-plus-plus', product: 'notepad++', version: '8.6.2' })).toBe(
      'cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.6.2:*:*:*:*:*:*:*'
    );
    expect(buildCpe({ vendor: 'a', product: 'b~c', version: '1' })).toContain(':b\\~c:');
  });

  it('builds the NVD CPE from a normalized catalog entry', () => {
    // Catalog vendor and product are normalizeToken output, which now keeps hyphens.
    expect(
      buildCpe({
        vendor: normalizeToken('7-Zip'),
        product: normalizeToken('7-Zip'),
        version: '22.01',
      })
    ).toBe('cpe:2.3:a:7-zip:7-zip:22.01:*:*:*:*:*:*:*');
    expect(normalizeToken('Foo - Bar')).toBe('foo-bar');
    expect(normalizeToken('-foo_')).toBe('foo');
  });

  it('escapes special characters and handles empty versions', () => {
    expect(buildCpe({ vendor: 'a', product: 'b', version: '1:2' })).toContain(':1\\:2:');
    expect(buildCpe({ vendor: 'a', product: 'b', version: '' })).toContain(':b:*:');
  });
});

describe('parseNvdResponse', () => {
  const target = { nvdVendor: 'nginx', product: 'nginx', version: '1.20.1' };

  it('extracts ids and the max CVSS, preferring v3.1 over v2 per CVE', () => {
    const parsed = parseNvdResponse(nvdFixture, target);
    expect(parsed.cveIds).toEqual(['CVE-2022-0003', 'CVE-2023-0002', 'CVE-2024-0001']);
    // CVE-2024-0001 -> 7.5 (v3.1, not v2 9.0); CVE-2023-0002 -> 8.1 (v3.0); CVE-2022-0003 -> 5.0
    expect(parsed.maxCvss).toBe(8.1);
  });

  // Previously the lowest fix (1.24.0), which left CVE-2024-0001 open. Now the minimal safe
  // version that resolves every fixable CVE.
  it('picks the minimal safe version that resolves every fixable CVE for the product', () => {
    const parsed = parseNvdResponse(nvdFixture, target);
    expect(parsed.fixedIn).toBe('1.25.4');
    // CVE-2022-0003 has no configurations, so no fixed version is known.
    expect(parsed.unfixedCveIds).toEqual(['CVE-2022-0003']);
    expect(parsed.fullyRemediated).toBe(false);
  });

  it('returns undefined fixedIn when the version is already past all ranges', () => {
    expect(parseNvdResponse(nvdFixture, { ...target, version: '2.0.0' }).fixedIn).toBeUndefined();
  });

  it('handles empty responses', () => {
    expect(parseNvdResponse({}, target)).toEqual({
      cveIds: [],
      maxCvss: undefined,
      fixedIn: undefined,
      fullyRemediated: true,
      unfixedCveIds: [],
      caveats: [],
      cves: [],
    });
  });

  it('compares versions numerically', () => {
    expect(compareVersions('1.9.0', '1.10.0')).toBe(-1);
    expect(compareVersions('1.0', '1.0.0')).toBe(0);
  });
});

describe('KEV intersection', () => {
  const kev = parseKevCveIds({ vulnerabilities: [{ cveID: 'CVE-2024-0001' }, {}] });

  it('detects known exploited CVEs', () => {
    expect(intersectKev(['CVE-2024-0001'], kev)).toBe(true);
    expect(intersectKev(['CVE-2020-1'], kev)).toBe(false);
    expect(intersectKev([], kev)).toBe(false);
  });
});

describe('isPublicIp', () => {
  it.each(['8.8.8.8', '1.1.1.1', '172.32.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8'])(
    'treats %s as public',
    (ip) => expect(isPublicIp(ip)).toBe(true)
  );

  it.each([
    '10.1.2.3',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '127.0.0.1',
    '169.254.1.1',
    '100.64.0.1',
    '224.0.0.1',
    '::1',
    'fd00::1',
    'fe80::1',
    '::ffff:10.0.0.1',
    'not-an-ip',
    '999.1.1.1',
    '',
  ])('treats %s as non-public', (ip) => expect(isPublicIp(ip)).toBe(false));
});

describe('combineExposure', () => {
  const base = { isEdge: false, distinctPublicSources: 0, lookbackDays: 7 };

  it('returns none for no signals', () => {
    expect(combineExposure(base)).toEqual({ level: 'none', score: 0, evidence: [] });
  });

  it('scores edge only as medium', () => {
    const result = combineExposure({ ...base, isEdge: true });
    expect(result.score).toBe(50);
    expect(result.level).toBe('medium');
  });

  it('scores inbound only as medium and adds bonus for many sources', () => {
    expect(combineExposure({ ...base, distinctPublicSources: 1 }).score).toBe(40);
    expect(combineExposure({ ...base, distinctPublicSources: 100 }).score).toBe(50);
  });

  it('combines to high and caps at 100', () => {
    const result = combineExposure({ ...base, isEdge: true, distinctPublicSources: 10 });
    expect(result.score).toBe(100);
    expect(result.level).toBe('high');
    expect(result.evidence.map((e) => e.signal)).toEqual(['edge_device_role', 'inbound_public_ip']);
  });

  it('keeps manual evidence and drops stale automatic evidence', () => {
    const result = combineExposure({
      ...base,
      existingEvidence: [
        { signal: 'manual', detail: 'analyst', weight: 30 },
        { signal: 'inbound_public_ip', detail: 'old', weight: 40 },
      ],
    });
    expect(result.evidence).toEqual([{ signal: 'manual', detail: 'analyst', weight: 30 }]);
    expect(result.level).toBe('low');
  });

  it('maps thresholds', () => {
    expect(levelFromScore(0)).toBe('none');
    expect(levelFromScore(39)).toBe('low');
    expect(levelFromScore(69)).toBe('medium');
    expect(levelFromScore(70)).toBe('high');
  });
});

describe('integration map', () => {
  it('resolves known packages and returns undefined for unknown', () => {
    expect(resolveIntegration('panw')).toMatchObject({
      vendor: 'palo_alto_networks',
      isEdge: true,
    });
    expect(resolveIntegration('nginx')?.isEdge).toBe(false);
    expect(resolveIntegration('nope')).toBeUndefined();
    expect(resolveIntegration('constructor')).toBeUndefined();
  });

  it('resolves observers', () => {
    expect(resolveObserver('Palo Alto Networks', 'PAN-OS')?.product).toBe('pan-os');
    expect(resolveObserver('Cisco', 'ASA 5500')?.product).toBe(
      'adaptive_security_appliance_software'
    );
    expect(resolveObserver('Acme')).toBeUndefined();
    expect(isEdgeProduct('fortinet', 'fortios')).toBe(true);
  });

  it('matches edge products with hyphens in raw or normalized form', () => {
    expect(isEdgeProduct('palo_alto_networks', 'pan-os')).toBe(true);
    expect(isEdgeProduct('Palo Alto Networks', 'PAN-OS')).toBe(true);
    expect(isEdgeProduct('f5', 'big-ip')).toBe(true);
    expect(isEdgeProduct('f5', 'nginx')).toBe(false);
  });
});
