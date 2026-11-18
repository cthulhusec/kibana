/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ALL_CASES, validateRegistry } from '.';

describe('EC, E2E, SC, and RG in the registry', () => {
  it('is valid: every prerequisite they name is registered', () => {
    expect(() => validateRegistry(ALL_CASES)).not.toThrow();
  });

  it('keeps the matrix order and runs prerequisites earlier', () => {
    const ids = ALL_CASES.map(({ id }) => id);
    const mine = ids.filter((id) => /^(EC|E2E|SC|RG)-/.test(id));
    expect(mine).toEqual([
      ...Array.from({ length: 12 }, (_, index) => `EC-${index + 1}`),
      ...Array.from({ length: 5 }, (_, index) => `E2E-${index + 1}`),
      ...Array.from({ length: 9 }, (_, index) => `SC-${index + 1}`),
      ...Array.from({ length: 6 }, (_, index) => `RG-${index + 1}`),
    ]);
    for (const testCase of ALL_CASES.filter(({ id }) => mine.includes(id))) {
      for (const required of testCase.requires ?? []) {
        expect(ids.indexOf(required)).toBeLessThan(ids.indexOf(testCase.id));
      }
    }
  });
});
