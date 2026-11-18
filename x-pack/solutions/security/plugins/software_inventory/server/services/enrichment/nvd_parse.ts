/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { RemediationCaveat, SoftwareCategory } from '../../../common/types';
import type { AffectedRange, CveRanges } from './remediation';
import { computeRemediation } from './remediation';

export { compareVersions } from './compare_versions';

export interface NvdCpeMatch {
  vulnerable?: boolean;
  criteria?: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndExcluding?: string;
  versionEndIncluding?: string;
}

interface NvdMetric {
  cvssData?: { baseScore?: number };
}

export interface NvdCve {
  id?: string;
  /** ISO timestamp, for example `2021-12-10T10:15:09.143`. */
  published?: string;
  metrics?: {
    cvssMetricV31?: NvdMetric[];
    cvssMetricV30?: NvdMetric[];
    cvssMetricV2?: NvdMetric[];
  };
  configurations?: Array<{ nodes?: Array<{ cpeMatch?: NvdCpeMatch[] }> }>;
}

export interface NvdResponse {
  vulnerabilities?: Array<{ cve?: NvdCve }>;
}

export interface ParsedCve {
  id: string;
  cvss?: number;
  published?: string;
  fixedIn?: string;
}

export interface ParsedNvd {
  cveIds: string[];
  maxCvss?: number;
  /** Minimal safe version. */
  fixedIn?: string;
  latestKnownFix?: string;
  fullyRemediated?: boolean;
  unfixedCveIds?: string[];
  caveats?: RemediationCaveat[];
  /** Every CVE, highest CVSS first. */
  cves?: ParsedCve[];
  firstPublished?: string;
}

export interface NvdTarget {
  nvdVendor: string;
  product: string;
  version: string;
  category?: SoftwareCategory;
}

const maxScore = (metrics: NvdMetric[] | undefined): number | undefined => {
  const scores = (metrics ?? [])
    .map((m) => m.cvssData?.baseScore)
    .filter((s): s is number => typeof s === 'number');
  return scores.length > 0 ? Math.max(...scores) : undefined;
};

/** Prefers CVSS v3.1, then v3.0, then v2 for a single CVE. */
export const getCveScore = (cve: NvdCve): number | undefined =>
  maxScore(cve.metrics?.cvssMetricV31) ??
  maxScore(cve.metrics?.cvssMetricV30) ??
  maxScore(cve.metrics?.cvssMetricV2);

const unescapeCpe = (value: string): string => value.replace(/\\(.)/g, '$1');

const isWildcard = (value: string | undefined): boolean =>
  value === undefined || value === '' || value === '*' || value === '-';

/**
 * Converts one cpeMatch entry into a range for the target product, or `undefined` when it is not
 * vulnerable or names another product. A criteria version without range bounds is an exact match;
 * a CPE update component (`9.7:p1`) is appended to it (`9.7p1`).
 */
export const toAffectedRange = (
  match: NvdCpeMatch,
  { nvdVendor, product }: Pick<NvdTarget, 'nvdVendor' | 'product'>
): AffectedRange | undefined => {
  const { criteria, vulnerable } = match;
  if (vulnerable === false || !criteria) return undefined;
  const parts = criteria.split(/(?<!\\):/);
  if (parts[3] !== nvdVendor || parts[4] !== product) return undefined;

  const range: AffectedRange = {
    ...(match.versionStartIncluding ? { startIncluding: match.versionStartIncluding } : {}),
    ...(match.versionStartExcluding ? { startExcluding: match.versionStartExcluding } : {}),
    ...(match.versionEndIncluding ? { endIncluding: match.versionEndIncluding } : {}),
    ...(match.versionEndExcluding ? { endExcluding: match.versionEndExcluding } : {}),
  };
  if (Object.keys(range).length > 0) return range;

  const [, , , , , version, update] = parts;
  if (version === '-') return undefined;
  if (isWildcard(version)) return {};
  return { exact: `${unescapeCpe(version)}${isWildcard(update) ? '' : unescapeCpe(update)}` };
};

export const extractAffectedRanges = (
  cve: NvdCve,
  target: Pick<NvdTarget, 'nvdVendor' | 'product'>
): AffectedRange[] =>
  (cve.configurations ?? []).flatMap((config) =>
    (config.nodes ?? []).flatMap((node) =>
      (node.cpeMatch ?? []).flatMap((match) => {
        const range = toAffectedRange(match, target);
        return range ? [range] : [];
      })
    )
  );

const toIsoDate = (value: string | undefined): string | undefined => {
  if (!value) return undefined;
  // NVD timestamps carry no zone and are UTC.
  const withZone = /[zZ]|[+-]\d\d:?\d\d$/.test(value) || !value.includes('T') ? value : `${value}Z`;
  const ms = Date.parse(withZone);
  return Number.isNaN(ms) ? undefined : new Date(ms).toISOString();
};

const byCvssDesc = (a: ParsedCve, b: ParsedCve): number =>
  (b.cvss ?? -1) - (a.cvss ?? -1) || a.id.localeCompare(b.id);

export const parseNvdResponse = (response: NvdResponse, target: NvdTarget): ParsedNvd => {
  const byId = new Map<string, { cve: NvdCve; ranges: AffectedRange[] }>();
  for (const { cve } of response.vulnerabilities ?? []) {
    if (cve === undefined || typeof cve.id !== 'string') continue;
    const existing = byId.get(cve.id);
    const ranges = extractAffectedRanges(cve, target);
    if (existing) {
      existing.ranges.push(...ranges);
    } else {
      byId.set(cve.id, { cve, ranges });
    }
  }
  const cveIds = [...byId.keys()].sort();
  const cveRanges: CveRanges[] = cveIds.map((id) => ({ id, ranges: byId.get(id)?.ranges ?? [] }));
  const remediation = computeRemediation({
    version: target.version,
    category: target.category,
    cves: cveRanges,
  });
  const fixById = new Map(remediation.perCve.map(({ id, fixedIn }) => [id, fixedIn]));

  const cves: ParsedCve[] = cveIds
    .flatMap((id) => {
      const cve = byId.get(id)?.cve;
      if (!cve) return [];
      const cvss = getCveScore(cve);
      const published = toIsoDate(cve.published);
      const fixedIn = fixById.get(id);
      return [
        {
          id,
          ...(cvss !== undefined ? { cvss } : {}),
          ...(published !== undefined ? { published } : {}),
          ...(fixedIn !== undefined ? { fixedIn } : {}),
        },
      ];
    })
    .sort(byCvssDesc);
  const scores = cves.flatMap(({ cvss }) => (cvss !== undefined ? [cvss] : []));
  const published = cves.flatMap((cve) => (cve.published ? [cve.published] : [])).sort();

  return {
    cveIds,
    maxCvss: scores.length > 0 ? Math.max(...scores) : undefined,
    fixedIn: remediation.minimalSafeVersion,
    latestKnownFix: remediation.latestKnownFix,
    fullyRemediated: remediation.fullyRemediated,
    unfixedCveIds: remediation.unfixedCveIds,
    caveats: remediation.caveats,
    cves,
    firstPublished: published[0],
  };
};

export interface KevResponse {
  vulnerabilities?: Array<{ cveID?: string }>;
}

export const intersectKev = (cveIds: string[], kev: ReadonlySet<string>): boolean =>
  cveIds.some((id) => kev.has(id));

export const parseKevCveIds = (response: KevResponse): Set<string> =>
  new Set(
    (response.vulnerabilities ?? [])
      .map((v) => v.cveID)
      .filter((id): id is string => typeof id === 'string')
  );
