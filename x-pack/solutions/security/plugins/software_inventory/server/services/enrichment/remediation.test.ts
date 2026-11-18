/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SoftwareCategory } from '../../../common/types';
import { compareVersions, isCleanNumericVersion } from './compare_versions';
import type { NvdCpeMatch, NvdCve, NvdResponse } from './nvd_parse';
import { parseNvdResponse, toAffectedRange } from './nvd_parse';
import type { AffectedRange } from './remediation';
import { computeRemediation, MAX_REMEDIATION_ITERATIONS, rangeContains } from './remediation';

/*
 * Hand-authored fixtures in NVD API 2.0 shape. Ids and versions are illustrative; the log4j ranges
 * mirror the shape of the real multi-branch advisories.
 */

const ANY = 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*';
const exactCpe = (version: string, update = '*'): string =>
  `cpe:2.3:a:acme:widget:${version}:${update}:*:*:*:*:*:*`;

const nvdCve = (
  id: string,
  cpeMatch: NvdCpeMatch[],
  { cvss, published }: { cvss?: number; published?: string } = {}
): { cve: NvdCve } => ({
  cve: {
    id,
    ...(published ? { published } : {}),
    ...(cvss !== undefined
      ? { metrics: { cvssMetricV31: [{ cvssData: { baseScore: cvss } }] } }
      : {}),
    configurations: [{ nodes: [{ cpeMatch }] }],
  },
});

const vuln = (
  match: Omit<NvdCpeMatch, 'vulnerable' | 'criteria'>,
  criteria = ANY
): NvdCpeMatch => ({
  vulnerable: true,
  criteria,
  ...match,
});

const parse = (
  vulnerabilities: NvdResponse['vulnerabilities'],
  version: string,
  category: SoftwareCategory = 'application'
) =>
  parseNvdResponse(
    { vulnerabilities },
    { nvdVendor: 'acme', product: 'widget', version, category }
  );

describe('compareVersions', () => {
  it.each([
    ['1.9.0', '1.10.0', -1],
    ['1.0', '1.0.0', 0],
    ['9.7p1', '9.8p1', -1],
    ['10.0', '8.9p1', 1],
    ['1.9.5', '1.9.5p1', -1],
    ['1.9.5p2', '1.9.5p1', 1],
    ['2.0-beta9', '2.0.1', -1],
    ['2.0', '2.0-rc1', 1],
  ])('compares %s to %s as %d', (a, b, expected) => {
    expect(compareVersions(a, b)).toBe(expected);
  });

  it('detects clean numeric versions', () => {
    expect(isCleanNumericVersion('2.17.1')).toBe(true);
    expect(isCleanNumericVersion('9.8p1')).toBe(false);
    expect(isCleanNumericVersion('1:2.3-1ubuntu1')).toBe(false);
    expect(isCleanNumericVersion('1.0~rc1')).toBe(false);
  });
});

describe('rangeContains', () => {
  it('honors inclusive and exclusive bounds', () => {
    const range: AffectedRange = { startExcluding: '1.0', endIncluding: '2.0' };
    expect(rangeContains(range, '1.0')).toBe(false);
    expect(rangeContains(range, '1.0.1')).toBe(true);
    expect(rangeContains(range, '2.0')).toBe(true);
    expect(rangeContains({ startIncluding: '1.0', endExcluding: '2.0' }, '1.0')).toBe(true);
    expect(rangeContains({ startIncluding: '1.0', endExcluding: '2.0' }, '2.0')).toBe(false);
    expect(rangeContains({ exact: '9.7p1' }, '9.7p1')).toBe(true);
    expect(rangeContains({}, '42')).toBe(true);
  });
});

describe('toAffectedRange', () => {
  const target = { nvdVendor: 'acme', product: 'widget' };

  it('ignores non-vulnerable entries and other products', () => {
    expect(
      toAffectedRange({ ...vuln({ versionEndExcluding: '2' }), vulnerable: false }, target)
    ).toBe(undefined);
    expect(
      toAffectedRange(
        vuln({ versionEndExcluding: '2' }, 'cpe:2.3:a:other:widget:*:*:*:*:*:*:*:*'),
        target
      )
    ).toBeUndefined();
  });

  it('turns a versioned criteria without bounds into an exact match, including the update', () => {
    expect(toAffectedRange(vuln({}, exactCpe('9.7', 'p1')), target)).toEqual({ exact: '9.7p1' });
    expect(toAffectedRange(vuln({}, exactCpe('2.0', '-')), target)).toEqual({ exact: '2.0' });
    expect(toAffectedRange(vuln({}, ANY), target)).toEqual({});
  });
});

describe('parseNvdResponse remediation', () => {
  it('recommends the highest per-CVE fix when two CVEs are fixed in different versions', () => {
    const parsed = parse(
      [
        nvdCve('CVE-A', [vuln({ versionEndExcluding: '2.15.0' })]),
        nvdCve('CVE-B', [vuln({ versionEndExcluding: '2.17.1' })]),
      ],
      '2.14.1'
    );
    expect(parsed.fixedIn).toBe('2.17.1');
    expect(parsed.fullyRemediated).toBe(true);
    expect(parsed.unfixedCveIds).toEqual([]);
    expect(parsed.cves?.map(({ id, fixedIn }) => [id, fixedIn])).toEqual([
      ['CVE-A', '2.15.0'],
      ['CVE-B', '2.17.1'],
    ]);
  });

  describe('multi-branch ranges', () => {
    // Each CVE was fixed on several release branches, like the log4j 2.x advisories.
    const log4jLike = [
      nvdCve('CVE-1', [
        vuln({ versionStartIncluding: '2.0.1', versionEndExcluding: '2.3.1' }),
        vuln({ versionStartIncluding: '2.4', versionEndExcluding: '2.12.2' }),
        vuln({ versionStartIncluding: '2.13.0', versionEndExcluding: '2.15.0' }),
      ]),
      nvdCve('CVE-2', [
        vuln({ versionStartIncluding: '2.0.1', versionEndExcluding: '2.12.2' }),
        vuln({ versionStartIncluding: '2.13.0', versionEndExcluding: '2.16.0' }),
      ]),
      nvdCve('CVE-3', [
        vuln({ versionStartIncluding: '2.0.1', versionEndExcluding: '2.3.1' }),
        vuln({ versionStartIncluding: '2.4', versionEndExcluding: '2.12.3' }),
        vuln({ versionStartIncluding: '2.13.0', versionEndExcluding: '2.17.0' }),
      ]),
      nvdCve('CVE-4', [
        vuln({ versionStartIncluding: '2.0.1', versionEndExcluding: '2.3.2' }),
        vuln({ versionStartIncluding: '2.4', versionEndExcluding: '2.12.4' }),
        vuln({ versionStartIncluding: '2.13.0', versionEndExcluding: '2.17.1' }),
      ]),
    ];

    it('stays on the old branch when the current version is on it', () => {
      const parsed = parse(log4jLike, '2.12.1');
      expect(parsed.fixedIn).toBe('2.12.4');
      expect(parsed.latestKnownFix).toBe('2.17.1');
      expect(parsed.fullyRemediated).toBe(true);
    });

    it('stays on the oldest branch', () => {
      // CVE-2 has no fix on the 2.3 branch; its 2.0.1-2.12.2 range is the containing one.
      const parsed = parse(log4jLike, '2.3.0');
      expect(parsed.cves?.find(({ id }) => id === 'CVE-2')?.fixedIn).toBe('2.12.2');
      // 2.12.2 still sits inside the 2.4-2.12.3 and 2.4-2.12.4 ranges, so it bumps to 2.12.4.
      expect(parsed.fixedIn).toBe('2.12.4');
    });

    it('recommends the newest fix on the newest branch', () => {
      const parsed = parse(log4jLike, '2.14.1');
      expect(parsed.fixedIn).toBe('2.17.1');
      expect(parsed.latestKnownFix).toBe('2.17.1');
    });
  });

  it('bumps the candidate when it lands inside another affected range, until stable', () => {
    const parsed = parse(
      [
        nvdCve('CVE-A', [vuln({ versionEndExcluding: '1.5.0' })]),
        // Regression: 1.5.0 reintroduced CVE-B, fixed again in 1.7.0.
        nvdCve('CVE-B', [
          vuln({ versionEndExcluding: '1.2.0' }),
          vuln({ versionStartIncluding: '1.5.0', versionEndExcluding: '1.7.0' }),
        ]),
        nvdCve('CVE-C', [
          vuln({ versionEndExcluding: '1.1.5' }),
          vuln({ versionStartIncluding: '1.6.0', versionEndExcluding: '1.8.0' }),
        ]),
      ],
      '1.1.0'
    );
    expect(parsed.cves?.map(({ id, fixedIn }) => [id, fixedIn])).toEqual([
      ['CVE-A', '1.5.0'],
      ['CVE-B', '1.2.0'],
      ['CVE-C', '1.1.5'],
    ]);
    expect(parsed.fixedIn).toBe('1.8.0');
    expect(parsed.fullyRemediated).toBe(true);
  });

  it('reports a CVE with only a versionEndIncluding range as unfixed', () => {
    const parsed = parse(
      [
        nvdCve('CVE-A', [vuln({ versionEndExcluding: '1.5.0' })]),
        nvdCve('CVE-B', [vuln({ versionEndIncluding: '2.0.0' })]),
      ],
      '1.0.0'
    );
    expect(parsed.fixedIn).toBe('1.5.0');
    expect(parsed.fullyRemediated).toBe(false);
    expect(parsed.unfixedCveIds).toEqual(['CVE-B']);
    expect(parsed.cves?.find(({ id }) => id === 'CVE-B')?.fixedIn).toBeUndefined();
  });

  it('reports a CVE that matches only the exact version as unfixed', () => {
    const parsed = parse(
      [nvdCve('CVE-X', [vuln({}, exactCpe('9.7', 'p1'))])],
      '9.7p1',
      'os_package'
    );
    expect(parsed.fixedIn).toBeUndefined();
    expect(parsed.fullyRemediated).toBe(false);
    expect(parsed.unfixedCveIds).toEqual(['CVE-X']);
  });

  it('reports a CVE as unfixed when the candidate lands on an exact-match version of it', () => {
    const parsed = parse(
      [
        nvdCve('CVE-A', [vuln({ versionEndExcluding: '1.5.0' })]),
        nvdCve('CVE-B', [vuln({ versionEndExcluding: '1.2.0' }), vuln({}, exactCpe('1.5.0'))]),
      ],
      '1.0.0'
    );
    expect(parsed.fixedIn).toBe('1.5.0');
    expect(parsed.fullyRemediated).toBe(false);
    expect(parsed.unfixedCveIds).toEqual(['CVE-B']);
  });

  it('returns no recommendation when the version is at or above every fix', () => {
    const empty = parse([], '3.0.0');
    expect(empty).toMatchObject({ cveIds: [], fullyRemediated: true, unfixedCveIds: [], cves: [] });
    expect(empty.fixedIn).toBeUndefined();
    expect(empty.latestKnownFix).toBeUndefined();

    const above = parse([nvdCve('CVE-A', [vuln({ versionEndExcluding: '2.0.0' })])], '2.0.0');
    expect(above.fixedIn).toBeUndefined();
    expect(above.latestKnownFix).toBeUndefined();
  });

  it('flags non-numeric versions as low confidence and OS packages for distro backports', () => {
    expect(parse([], '2.4.1').caveats).toEqual([]);
    expect(parse([], '9.8p1').caveats).toEqual(['low_version_confidence']);
    expect(parse([], '1:1.1.1f-1ubuntu2', 'os_package').caveats).toEqual([
      'distro_backports',
      'low_version_confidence',
    ]);
    expect(parse([], '3.0.2', 'os_package').caveats).toEqual(['distro_backports']);
  });

  it('keeps per-CVE CVSS and ISO published dates, highest CVSS first', () => {
    const parsed = parse(
      [
        nvdCve('CVE-LOW', [vuln({ versionEndExcluding: '2.0' })], {
          cvss: 4.3,
          published: '2022-03-01T10:15:00.000',
        }),
        nvdCve('CVE-HIGH', [vuln({ versionEndExcluding: '2.0' })], {
          cvss: 9.8,
          published: '2021-12-10T10:15:09.143',
        }),
        nvdCve('CVE-NONE', [vuln({ versionEndExcluding: '2.0' })]),
      ],
      '1.0'
    );
    expect(parsed.cves).toEqual([
      { id: 'CVE-HIGH', cvss: 9.8, published: '2021-12-10T10:15:09.143Z', fixedIn: '2.0' },
      { id: 'CVE-LOW', cvss: 4.3, published: '2022-03-01T10:15:00.000Z', fixedIn: '2.0' },
      { id: 'CVE-NONE', fixedIn: '2.0' },
    ]);
    expect(parsed.firstPublished).toBe('2021-12-10T10:15:09.143Z');
    expect(parsed.maxCvss).toBe(9.8);
  });
});

describe('computeRemediation', () => {
  it('stops after the iteration cap and does not claim full remediation', () => {
    const chain = Array.from({ length: MAX_REMEDIATION_ITERATIONS + 5 }, (_, i) => ({
      id: `CVE-${i}`,
      ranges: [{ endExcluding: '1' }, { startIncluding: `${i + 1}`, endExcluding: `${i + 2}` }],
    }));
    const result = computeRemediation({
      version: '0',
      cves: chain,
    });
    expect(result.unfixedCveIds).toEqual([]);
    expect(result.fullyRemediated).toBe(false);
    expect(result.minimalSafeVersion).toBe(`${MAX_REMEDIATION_ITERATIONS + 1}`);
  });
});
