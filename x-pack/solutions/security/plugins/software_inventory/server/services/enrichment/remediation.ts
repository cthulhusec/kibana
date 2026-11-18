/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { RemediationCaveat, SoftwareCategory } from '../../../common/types';
import { compareVersions, isCleanNumericVersion, maxVersion, minVersion } from './compare_versions';

/** Caps the bump loop; each pass moves the candidate to a strictly higher range end. */
export const MAX_REMEDIATION_ITERATIONS = 20;

/** One vulnerable version range (or exact version) for a product, as NVD cpeMatch describes it. */
export interface AffectedRange {
  startIncluding?: string;
  startExcluding?: string;
  endIncluding?: string;
  endExcluding?: string;
  /** Set for an exact-version match; the bounds above are then ignored. */
  exact?: string;
}

export interface CveRanges {
  id: string;
  ranges: readonly AffectedRange[];
}

export interface CveFix {
  id: string;
  /** Smallest `versionEndExcluding` among the ranges that contain the current version. */
  fixedIn?: string;
}

export interface Remediation {
  perCve: CveFix[];
  /** Lowest version that resolves every fixable CVE on the current branch. */
  minimalSafeVersion?: string;
  /** Highest `versionEndExcluding` across all ranges, when above the current version. */
  latestKnownFix?: string;
  fullyRemediated: boolean;
  unfixedCveIds: string[];
  caveats: RemediationCaveat[];
}

export const rangeContains = (range: AffectedRange, version: string): boolean => {
  if (range.exact !== undefined) return compareVersions(version, range.exact) === 0;
  const { startIncluding, startExcluding, endIncluding, endExcluding } = range;
  if (startIncluding !== undefined && compareVersions(version, startIncluding) < 0) return false;
  if (startExcluding !== undefined && compareVersions(version, startExcluding) <= 0) return false;
  if (endExcluding !== undefined && compareVersions(version, endExcluding) >= 0) return false;
  if (endIncluding !== undefined && compareVersions(version, endIncluding) > 0) return false;
  return true;
};

export const getRemediationCaveats = ({
  version,
  category,
}: {
  version: string;
  category?: SoftwareCategory;
}): RemediationCaveat[] => [
  ...(category === 'os_package' ? (['distro_backports'] as const) : []),
  ...(isCleanNumericVersion(version) ? [] : (['low_version_confidence'] as const)),
];

/**
 * Computes the patch recommendation for `version` from the vulnerable ranges of its CVEs.
 *
 * 1. Per CVE, the fix is the smallest `versionEndExcluding` of a range that contains `version`.
 *    A CVE whose containing ranges have no `versionEndExcluding` has no known fix.
 * 2. The minimal safe version starts at the highest per-CVE fix. While it falls inside any range of
 *    any CVE, it moves to the smallest end of those ranges. A range with no `versionEndExcluding`
 *    cannot be escaped, so its CVE is reported as unfixed.
 */
export const computeRemediation = ({
  version,
  category,
  cves,
}: {
  version: string;
  category?: SoftwareCategory;
  cves: readonly CveRanges[];
}): Remediation => {
  const perCve: CveFix[] = cves.map(({ id, ranges }) => {
    const fixes = ranges
      .filter((range) => range.exact === undefined && rangeContains(range, version))
      .flatMap(({ endExcluding }) => (endExcluding !== undefined ? [endExcluding] : []));
    const fixedIn = minVersion(fixes);
    return fixedIn !== undefined ? { id, fixedIn } : { id };
  });

  const unfixed = new Set(
    perCve.filter(({ fixedIn }) => fixedIn === undefined).map(({ id }) => id)
  );
  const allRanges = cves.flatMap(({ id, ranges }) => ranges.map((range) => ({ id, range })));

  let candidate = maxVersion(
    perCve.flatMap(({ fixedIn }) => (fixedIn !== undefined ? [fixedIn] : []))
  );
  let stable = candidate === undefined;
  for (let i = 0; candidate !== undefined && !stable && i < MAX_REMEDIATION_ITERATIONS; i++) {
    const current: string = candidate;
    const containing = allRanges.filter(({ range }) => rangeContains(range, current));
    const ends = containing.flatMap(({ range }) =>
      range.exact === undefined && range.endExcluding !== undefined ? [range.endExcluding] : []
    );
    if (ends.length > 0) {
      candidate = minVersion(ends);
    } else {
      stable = true;
      containing.forEach(({ id }) => unfixed.add(id));
    }
  }

  const ends = allRanges.flatMap(({ range }) =>
    range.exact === undefined && range.endExcluding !== undefined ? [range.endExcluding] : []
  );
  const latest = maxVersion(ends);
  const latestKnownFix =
    latest !== undefined && compareVersions(latest, version) > 0 ? latest : undefined;
  const unfixedCveIds = [...unfixed].sort();

  return {
    perCve,
    ...(candidate !== undefined ? { minimalSafeVersion: candidate } : {}),
    ...(latestKnownFix !== undefined ? { latestKnownFix } : {}),
    fullyRemediated: stable && unfixedCveIds.length === 0,
    unfixedCveIds,
    caveats: getRemediationCaveats({ version, category }),
  };
};
