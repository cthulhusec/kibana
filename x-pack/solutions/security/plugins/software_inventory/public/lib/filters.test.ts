/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  DEFAULT_TABLE_STATE,
  EMPTY_FILTERS,
  hasActiveFilters,
  toFindInstancesParams,
} from './filters';

describe('toFindInstancesParams', () => {
  it('returns only paging and sorting for empty filters', () => {
    expect(toFindInstancesParams(EMPTY_FILTERS, DEFAULT_TABLE_STATE)).toEqual({
      page: 1,
      per_page: 25,
      sort_field: 'exposure.score',
      sort_order: 'desc',
    });
  });

  it('maps every filter and converts the page index to a 1-based page', () => {
    expect(
      toFindInstancesParams(
        {
          search: '  openssl ',
          category: ['dependency', 'appliance'],
          source: ['osquery'],
          status: ['patched'],
          exposureLevel: ['high', 'medium'],
          minCveCount: '3',
          knownExploited: true,
          patchedWithinDays: '7',
          vulnerableInRange: false,
        },
        { pageIndex: 2, pageSize: 50, sortField: 'last_seen', sortDirection: 'asc' }
      )
    ).toEqual({
      page: 3,
      per_page: 50,
      sort_field: 'last_seen',
      sort_order: 'asc',
      search: 'openssl',
      category: ['dependency', 'appliance'],
      source: ['osquery'],
      status: ['patched'],
      exposure_level: ['high', 'medium'],
      min_cve_count: 3,
      known_exploited: true,
      patched_within_days: 7,
    });
  });

  it('drops invalid numeric input', () => {
    const params = toFindInstancesParams(
      { ...EMPTY_FILTERS, minCveCount: 'abc', patchedWithinDays: '-2' },
      DEFAULT_TABLE_STATE
    );
    expect(params).not.toHaveProperty('min_cve_count');
    expect(params).not.toHaveProperty('patched_within_days');
  });
});

describe('hasActiveFilters', () => {
  it('detects active filters', () => {
    expect(hasActiveFilters(EMPTY_FILTERS)).toBe(false);
    expect(hasActiveFilters({ ...EMPTY_FILTERS, knownExploited: true })).toBe(true);
  });

  it('adds as_of params and vulnerable_in_range only when scoped to a period', () => {
    const period = { from: '2026-01-01T00:00:00.000Z', to: '2026-01-31T00:00:00.000Z' };
    const filters = { ...EMPTY_FILTERS, vulnerableInRange: true };

    const current = toFindInstancesParams(filters, DEFAULT_TABLE_STATE);
    expect(current).not.toHaveProperty('as_of_from');
    expect(current).not.toHaveProperty('as_of_to');
    expect(current).not.toHaveProperty('vulnerable_in_range');

    expect(toFindInstancesParams(EMPTY_FILTERS, DEFAULT_TABLE_STATE, period)).toMatchObject({
      as_of_from: period.from,
      as_of_to: period.to,
    });
    expect(toFindInstancesParams(filters, DEFAULT_TABLE_STATE, period)).toMatchObject({
      as_of_from: period.from,
      as_of_to: period.to,
      vulnerable_in_range: true,
    });
  });
});
