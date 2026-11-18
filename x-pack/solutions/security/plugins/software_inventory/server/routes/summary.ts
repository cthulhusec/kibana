/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { estypes } from '@elastic/elasticsearch';
import type { DiscoverySource, SoftwareCategory, SummaryResponse } from '../../common/types';
import { buildPatchedSinceRange, RECENTLY_PATCHED_DAYS } from './query_builders';

export interface CatalogSummaryRow {
  id: string;
  category?: SoftwareCategory;
  cve_count?: number;
  known_exploited?: boolean;
}

export interface CatalogPartition {
  vulnerableIds: string[];
  knownExploitedIds: string[];
  idsByCategory: Partial<Record<SoftwareCategory, string[]>>;
}

/** Groups catalog ids by the properties the summary aggregates over. */
export const partitionCatalog = (rows: CatalogSummaryRow[]): CatalogPartition => {
  const partition: CatalogPartition = {
    vulnerableIds: [],
    knownExploitedIds: [],
    idsByCategory: {},
  };
  for (const { id, category, cve_count: cveCount, known_exploited: knownExploited } of rows) {
    if ((cveCount ?? 0) > 0) partition.vulnerableIds.push(id);
    if (knownExploited === true) partition.knownExploitedIds.push(id);
    if (category) {
      const ids = partition.idsByCategory[category] ?? [];
      ids.push(id);
      partition.idsByCategory[category] = ids;
    }
  }
  return partition;
};

/** A terms filter that matches nothing when the id list is empty. */
const softwareIdsFilter = (ids: string[]): estypes.QueryDslQueryContainer =>
  ids.length === 0 ? { bool: { must_not: { match_all: {} } } } : { terms: { software_id: ids } };

/** Base filter for the summary: removed instances are not counted. */
export const SUMMARY_BASE_QUERY: estypes.QueryDslQueryContainer = {
  bool: { must_not: [{ term: { status: 'removed' } }] },
};

export const buildSummaryAggregations = (
  partition: CatalogPartition,
  now: Date = new Date()
): Record<string, estypes.AggregationsAggregationContainer> => {
  const categoryAggs: Record<string, estypes.AggregationsAggregationContainer> = {};
  for (const [category, ids] of Object.entries(partition.idsByCategory)) {
    categoryAggs[`category_${category}`] = { filter: softwareIdsFilter(ids ?? []) };
  }
  return {
    exposed: { filter: { terms: { 'exposure.level': ['medium', 'high'] } } },
    vulnerable: { filter: softwareIdsFilter(partition.vulnerableIds) },
    known_exploited: { filter: softwareIdsFilter(partition.knownExploitedIds) },
    recently_patched: { filter: buildPatchedSinceRange(RECENTLY_PATCHED_DAYS, now) },
    software: { cardinality: { field: 'software_id', precision_threshold: 3000 } },
    by_source: { terms: { field: 'sources', size: 10 } },
    ...categoryAggs,
  };
};

interface DocCountAgg {
  doc_count?: number;
}

const totalValue = (total: estypes.SearchHitsMetadata['total']): number =>
  typeof total === 'number' ? total : total?.value ?? 0;

export const emptySummary = (): SummaryResponse => ({
  total_instances: 0,
  total_software: 0,
  exposed_instances: 0,
  vulnerable_instances: 0,
  known_exploited_instances: 0,
  recently_patched_instances: 0,
  by_category: [],
  by_source: [],
});

/** Shapes the instances aggregation response into the public summary. */
export const shapeSummary = (
  response: Pick<estypes.SearchResponse, 'hits' | 'aggregations'>,
  partition: CatalogPartition
): SummaryResponse => {
  const aggs = (response.aggregations ?? {}) as Record<string, unknown>;
  const count = (name: string): number => (aggs[name] as DocCountAgg | undefined)?.doc_count ?? 0;

  const sourceBuckets =
    (aggs.by_source as { buckets?: Array<{ key: string; doc_count: number }> } | undefined)
      ?.buckets ?? [];

  const byCategory = (Object.keys(partition.idsByCategory) as SoftwareCategory[])
    .map((key) => ({ key, count: count(`category_${key}`) }))
    .filter(({ count: c }) => c > 0)
    .sort((a, b) => b.count - a.count);

  return {
    total_instances: totalValue(response.hits.total),
    total_software: (aggs.software as { value?: number } | undefined)?.value ?? 0,
    exposed_instances: count('exposed'),
    vulnerable_instances: count('vulnerable'),
    known_exploited_instances: count('known_exploited'),
    recently_patched_instances: count('recently_patched'),
    by_category: byCategory,
    by_source: sourceBuckets.map(({ key, doc_count: docCount }) => ({
      key: key as DiscoverySource,
      count: docCount,
    })),
  };
};
