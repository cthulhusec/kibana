/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { buildSummaryAggregations, partitionCatalog, shapeSummary } from './summary';

describe('summary', () => {
  const partition = partitionCatalog([
    { id: 'a', category: 'application', cve_count: 2, known_exploited: true },
    { id: 'b', category: 'application', cve_count: 0, known_exploited: false },
    { id: 'c', category: 'dependency', cve_count: 1 },
    { id: 'd' },
  ]);

  it('partitions catalog rows', () => {
    expect(partition).toEqual({
      vulnerableIds: ['a', 'c'],
      knownExploitedIds: ['a'],
      idsByCategory: { application: ['a', 'b'], dependency: ['c'] },
    });
  });

  it('builds aggregations, matching nothing for empty id lists', () => {
    const aggs = buildSummaryAggregations(
      partitionCatalog([{ id: 'x', category: 'other', cve_count: 0 }]),
      new Date('2026-01-10T00:00:00.000Z')
    );
    expect(aggs.vulnerable).toEqual({ filter: { bool: { must_not: { match_all: {} } } } });
    expect(aggs.category_other).toEqual({ filter: { terms: { software_id: ['x'] } } });
    expect(aggs.recently_patched).toEqual({
      filter: { range: { version_changed_at: { gte: '2026-01-03T00:00:00.000Z' } } },
    });
  });

  it('shapes the aggregation response', () => {
    const summary = shapeSummary(
      {
        hits: { total: { value: 10, relation: 'eq' }, hits: [] },
        aggregations: {
          exposed: { doc_count: 3 },
          vulnerable: { doc_count: 5 },
          known_exploited: { doc_count: 1 },
          recently_patched: { doc_count: 2 },
          software: { value: 4 },
          by_source: { buckets: [{ key: 'osquery', doc_count: 7 }] },
          category_application: { doc_count: 6 },
          category_dependency: { doc_count: 0 },
        },
      },
      partition
    );
    expect(summary).toEqual({
      total_instances: 10,
      total_software: 4,
      exposed_instances: 3,
      vulnerable_instances: 5,
      known_exploited_instances: 1,
      recently_patched_instances: 2,
      by_category: [{ key: 'application', count: 6 }],
      by_source: [{ key: 'osquery', count: 7 }],
    });
  });
});
