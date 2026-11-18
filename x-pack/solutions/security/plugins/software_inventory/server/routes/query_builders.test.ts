/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  buildCatalogFilterClauses,
  buildCatalogIdsQuery,
  buildInstancesQuery,
  buildSort,
  escapeWildcard,
  hasCatalogFilters,
  toArray,
  validatePageWindow,
} from './query_builders';

describe('query_builders', () => {
  const now = new Date('2026-01-10T00:00:00.000Z');

  it('escapes wildcard metacharacters', () => {
    expect(escapeWildcard('a*b?c\\d')).toBe('a\\*b\\?c\\\\d');
  });

  it('detects catalog-side filters', () => {
    expect(hasCatalogFilters({})).toBe(false);
    expect(hasCatalogFilters({ search: 'x', status: ['active'] })).toBe(false);
    expect(hasCatalogFilters({ known_exploited: false })).toBe(true);
    expect(hasCatalogFilters({ min_cve_count: 0 })).toBe(true);
    expect(hasCatalogFilters({ category: ['application'] })).toBe(true);
  });

  it('builds product, version and host name filters', () => {
    expect(buildCatalogFilterClauses({ product: 'nginx', version: '1.2' })).toEqual([
      { wildcard: { product: { value: '*nginx*', case_insensitive: true } } },
      { term: { version: '1.2' } },
    ]);
    expect(buildInstancesQuery({ filters: { host_name: 'web' }, now })).toEqual({
      bool: {
        filter: [{ wildcard: { 'host.name': { value: '*web*', case_insensitive: true } } }],
      },
    });
  });

  it('builds catalog clauses', () => {
    expect(
      buildCatalogFilterClauses({
        category: ['application'],
        min_cve_count: 1,
        known_exploited: true,
      })
    ).toEqual([
      { terms: { category: ['application'] } },
      { range: { cve_count: { gte: 1 } } },
      { term: { known_exploited: true } },
    ]);
  });

  it('builds match_all for an empty catalog query and includes search on request', () => {
    expect(buildCatalogIdsQuery({}, { includeSearch: true })).toEqual({ match_all: {} });
    const withSearch = buildCatalogIdsQuery({ search: 'nginx' }, { includeSearch: true });
    expect(JSON.stringify(withSearch)).toContain('*nginx*');
    expect(buildCatalogIdsQuery({ search: 'nginx' }, { includeSearch: false })).toEqual({
      match_all: {},
    });
  });

  it('builds a match_all instances query without filters', () => {
    expect(buildInstancesQuery({ filters: {}, now })).toEqual({ match_all: {} });
  });

  it('builds instance-side filters', () => {
    const query = buildInstancesQuery({
      filters: {
        source: ['osquery'],
        status: ['active'],
        exposure_level: ['high'],
        patched_within_days: 7,
        host_id: 'h1',
      },
      now,
    });
    expect(query).toEqual({
      bool: {
        filter: [
          { terms: { sources: ['osquery'] } },
          { terms: { status: ['active'] } },
          { terms: { 'exposure.level': ['high'] } },
          { range: { version_changed_at: { gte: '2026-01-03T00:00:00.000Z' } } },
          { term: { 'host.id': 'h1' } },
        ],
      },
    });
  });

  it('constrains by catalog ids and matches no instance when none were found', () => {
    expect(
      buildInstancesQuery({ filters: { known_exploited: true }, catalogFilterIds: ['a'], now })
    ).toEqual({ bool: { filter: [{ terms: { software_id: ['a'] } }] } });
    expect(buildInstancesQuery({ filters: { known_exploited: true }, now })).toEqual({
      bool: { filter: [{ terms: { software_id: [] } }] },
    });
  });

  it('ORs host name and catalog search ids for free-text search', () => {
    const query = buildInstancesQuery({
      filters: { search: 'web*' },
      catalogSearchIds: ['a', 'b'],
      now,
    });
    expect(query).toEqual({
      bool: {
        filter: [
          {
            bool: {
              should: [
                { wildcard: { 'host.name': { value: '*web\\**', case_insensitive: true } } },
                { terms: { software_id: ['a', 'b'] } },
              ],
              minimum_should_match: 1,
            },
          },
        ],
      },
    });
  });

  it('builds a sort with a stable tiebreaker', () => {
    expect(buildSort('exposure.score', 'asc')).toEqual([
      { 'exposure.score': { order: 'asc', unmapped_type: 'keyword' } },
      { id: 'asc' },
    ]);
  });

  it('validates the result window', () => {
    expect(validatePageWindow(100, 100)).toBeUndefined();
    expect(validatePageWindow(101, 100)).toEqual(expect.stringContaining('10000'));
  });

  it('normalizes single values to arrays', () => {
    expect(toArray(undefined)).toBeUndefined();
    expect(toArray('a')).toEqual(['a']);
    expect(toArray(['a', 'b'])).toEqual(['a', 'b']);
  });
});
