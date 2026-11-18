/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { diffRollupAgainstOracle } from './se';

const rollup = (totalSoftware: number, vulnerable = 10) => ({
  total_instances: 100,
  total_software: totalSoftware,
  vulnerable_instances: vulnerable,
});

describe('diffRollupAgainstOracle', () => {
  it('accepts an exact match', () => {
    expect(diffRollupAgainstOracle(rollup(5057), rollup(5057), 'rollup')).toEqual([]);
  });

  it('accepts a small approximation error in total_software only', () => {
    // 1% of 5057 allows 51; the live cardinality aggregation was off by 1.
    expect(diffRollupAgainstOracle(rollup(5057), rollup(5056), 'rollup')).toEqual([]);
    expect(diffRollupAgainstOracle(rollup(5057), rollup(5100), 'rollup')).toEqual([]);
  });

  it('allows an error of at least one for small totals', () => {
    expect(diffRollupAgainstOracle(rollup(30), rollup(31), 'rollup')).toEqual([]);
    expect(diffRollupAgainstOracle(rollup(30), rollup(32), 'rollup')).toHaveLength(1);
  });

  it('rejects a total_software error beyond the tolerance', () => {
    const diffs = diffRollupAgainstOracle(rollup(5057), rollup(5124 + 100), 'rollup');
    expect(diffs).toEqual([expect.stringMatching(/total_software: expected 5057 \(\+\/- 51\)/)]);
  });

  it('keeps every other field exact', () => {
    const diffs = diffRollupAgainstOracle(rollup(100, 10), rollup(100, 11), 'rollup');
    expect(diffs).toEqual([expect.stringMatching(/vulnerable_instances/)]);
  });

  it('reports a missing total_software', () => {
    const { total_software: _omitted, ...withoutSoftware } = rollup(10);
    expect(diffRollupAgainstOracle(rollup(10), withoutSoftware, 'rollup')).toEqual([
      expect.stringMatching(/total_software: expected a number/),
    ]);
  });
});
