/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { parseAsOf } from './register_routes';

describe('parseAsOf', () => {
  const from = '2026-11-01T00:00:00.000Z';
  const to = '2026-11-04T00:00:00.000Z';

  it('is empty without a range', () => {
    expect(parseAsOf({})).toEqual({});
  });

  it('parses a valid range', () => {
    expect(parseAsOf({ as_of_from: from, as_of_to: to })).toEqual({
      asOf: { from: Date.parse(from), to: Date.parse(to) },
    });
  });

  it('requires both ends together', () => {
    expect(parseAsOf({ as_of_from: from }).error).toContain('together');
    expect(parseAsOf({ as_of_to: to }).error).toContain('together');
  });

  it('requires a range for vulnerable_in_range', () => {
    expect(parseAsOf({ vulnerable_in_range: true }).error).toContain('as_of_from');
    expect(parseAsOf({ vulnerable_in_range: false })).toEqual({});
  });

  it('rejects reversed and too long ranges', () => {
    expect(parseAsOf({ as_of_from: to, as_of_to: from }).error).toBeDefined();
    expect(parseAsOf({ as_of_from: '2020-01-01', as_of_to: to }).error).toBeDefined();
  });
});
