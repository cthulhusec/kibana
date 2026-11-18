/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

const LEADING_NUMBER = /^(\d+)(.*)$/;

const compareStrings = (a: string, b: string): number => {
  if (a === b) return 0;
  return a < b ? -1 : 1;
};

const compareSegments = (left: string, right: string): number => {
  const leftMatch = LEADING_NUMBER.exec(left);
  const rightMatch = LEADING_NUMBER.exec(right);
  if (leftMatch && rightMatch) {
    const diff = Number(leftMatch[1]) - Number(rightMatch[1]);
    if (diff !== 0) return diff < 0 ? -1 : 1;
    // `5` < `5p1` < `5p2`: an empty suffix sorts first.
    return compareStrings(leftMatch[2], rightMatch[2]);
  }
  // A purely alphabetic segment (`beta9`, `rc1`) is a pre-release, so it sorts before a number.
  if (leftMatch) return 1;
  if (rightMatch) return -1;
  return compareStrings(left, right);
};

/**
 * Compares dotted versions segment by segment. Leading digits compare numerically, missing segments
 * count as `0`, and alphabetic segments sort before numeric ones.
 */
export const compareVersions = (a: string, b: string): number => {
  const split = (v: string): string[] => v.split(/[.\-_+]/).filter((s) => s !== '');
  const left = split(a);
  const right = split(b);
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) {
    const result = compareSegments(left[i] ?? '0', right[i] ?? '0');
    if (result !== 0) return result;
  }
  return 0;
};

/** True when every segment is numeric, so range comparisons against NVD are reliable. */
export const isCleanNumericVersion = (version: string): boolean =>
  /^\d+(\.\d+)*$/.test(version.trim());

export const minVersion = (versions: readonly string[]): string | undefined =>
  versions.reduce<string | undefined>(
    (lowest, v) => (lowest === undefined || compareVersions(v, lowest) < 0 ? v : lowest),
    undefined
  );

export const maxVersion = (versions: readonly string[]): string | undefined =>
  versions.reduce<string | undefined>(
    (highest, v) => (highest === undefined || compareVersions(v, highest) > 0 ? v : highest),
    undefined
  );
