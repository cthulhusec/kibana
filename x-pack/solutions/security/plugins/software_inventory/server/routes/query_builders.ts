/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { estypes } from '@elastic/elasticsearch';
import type {
  DiscoverySource,
  ExposureLevel,
  InstanceStatus,
  SoftwareCategory,
} from '../../common/types';

/** Maximum catalog ids pulled into a terms filter. */
export const MAX_CATALOG_IDS = 10000;
/** Elasticsearch default `index.max_result_window`. */
export const MAX_RESULT_WINDOW = 10000;
export const MAX_DETAIL_HOSTS = 1000;
export const RECENTLY_PATCHED_DAYS = 7;

export const SORT_FIELDS = [
  'last_seen',
  'first_seen',
  'version_changed_at',
  'exposure.score',
  'host.name',
] as const;
export type SortField = (typeof SORT_FIELDS)[number];
export type SortOrder = 'asc' | 'desc';

export interface InstanceFilters {
  search?: string;
  category?: SoftwareCategory[];
  source?: DiscoverySource[];
  status?: InstanceStatus[];
  exposure_level?: ExposureLevel[];
  min_cve_count?: number;
  known_exploited?: boolean;
  patched_within_days?: number;
  host_id?: string;
  /** Partial, case-insensitive host name match. Used by the Agent Builder tools, not the route. */
  host_name?: string;
  /** Partial, case-insensitive product match (catalog side). */
  product?: string;
  /** Exact version match (catalog side). */
  version?: string;
}

export interface FindInstancesParams extends InstanceFilters {
  page: number;
  per_page: number;
  sort_field: SortField;
  sort_order: SortOrder;
  /** Scopes the inventory to versions that ran during this inclusive epoch-ms range. */
  as_of?: AsOfRange;
  /** With `as_of`: keep only rows vulnerable at some point in the range. */
  vulnerable_in_range?: boolean;
}

export interface AsOfRange {
  from: number;
  to: number;
}

/** Escapes Elasticsearch wildcard metacharacters so user input matches literally. */
export const escapeWildcard = (value: string): string => value.replace(/[\\*?]/g, '\\$&');

const containsPattern = (value: string): string => `*${escapeWildcard(value.trim())}*`;

/** True when any filter can only be evaluated against the catalog index. */
export const hasCatalogFilters = ({
  category,
  min_cve_count: minCveCount,
  known_exploited: knownExploited,
  product,
  version,
}: InstanceFilters): boolean =>
  (category?.length ?? 0) > 0 ||
  minCveCount !== undefined ||
  knownExploited !== undefined ||
  product !== undefined ||
  version !== undefined;

/** Catalog-side clauses that do not include the free-text search. */
export const buildCatalogFilterClauses = ({
  category,
  min_cve_count: minCveCount,
  known_exploited: knownExploited,
  product,
  version,
}: InstanceFilters): estypes.QueryDslQueryContainer[] => {
  const clauses: estypes.QueryDslQueryContainer[] = [];
  if (product) {
    clauses.push({
      wildcard: { product: { value: containsPattern(product), case_insensitive: true } },
    });
  }
  if (version) {
    clauses.push({ term: { version } });
  }
  if (category && category.length > 0) {
    clauses.push({ terms: { category } });
  }
  if (minCveCount !== undefined) {
    clauses.push({ range: { cve_count: { gte: minCveCount } } });
  }
  if (knownExploited !== undefined) {
    clauses.push({ term: { known_exploited: knownExploited } });
  }
  return clauses;
};

/** Catalog-side free-text clause (product, vendor, display name). */
export const buildCatalogSearchClause = (search: string): estypes.QueryDslQueryContainer => ({
  bool: {
    should: [
      { wildcard: { product: { value: containsPattern(search), case_insensitive: true } } },
      { wildcard: { vendor: { value: containsPattern(search), case_insensitive: true } } },
      { match: { 'display_name.text': { query: search, operator: 'and' } } },
      { wildcard: { display_name: { value: containsPattern(search), case_insensitive: true } } },
    ],
    minimum_should_match: 1,
  },
});

/** Catalog query returning only ids of entries that satisfy the catalog filters (and search). */
export const buildCatalogIdsQuery = (
  filters: InstanceFilters,
  { includeSearch }: { includeSearch: boolean }
): estypes.QueryDslQueryContainer => {
  const filter = buildCatalogFilterClauses(filters);
  if (includeSearch && filters.search) {
    filter.push(buildCatalogSearchClause(filters.search));
  }
  return filter.length === 0 ? { match_all: {} } : { bool: { filter } };
};

export interface InstancesQueryInput {
  filters: InstanceFilters;
  /** Ids matching the catalog-side filters; required when `hasCatalogFilters` is true. */
  catalogFilterIds?: string[];
  /** Ids matching catalog filters AND the search text; used when `search` is set. */
  catalogSearchIds?: string[];
  /** With a range, catalog ids also match any version that ran (history `software_id`). */
  asOf?: AsOfRange;
  /** Only instances that ran one of these catalog ids (current or in history). */
  requiredSoftwareIds?: string[];
  now?: Date;
}

/**
 * Matches instances whose current version is one of `ids`, or, with `asOf`, any version in their
 * history. Legacy history entries without `software_id` match only through the current version.
 */
export const softwareIdsClause = (
  ids: string[],
  asOf: AsOfRange | undefined
): estypes.QueryDslQueryContainer =>
  asOf
    ? {
        bool: {
          should: [
            { terms: { software_id: ids } },
            {
              nested: {
                path: 'version_history',
                query: { terms: { 'version_history.software_id': ids } },
              },
            },
          ],
          minimum_should_match: 1,
        },
      }
    : { terms: { software_id: ids } };

/**
 * Instances whose lifetime overlaps the inclusive range: a version was first seen at or before
 * `to`, and the instance is still running or was last seen at or after `from`. Exact per-version
 * overlap is computed in code.
 */
export const buildAsOfClause = ({ from, to }: AsOfRange): estypes.QueryDslQueryContainer => ({
  bool: {
    filter: [
      {
        nested: {
          path: 'version_history',
          query: { range: { 'version_history.first_seen': { lte: new Date(to).toISOString() } } },
        },
      },
      {
        bool: {
          should: [
            { terms: { status: ['active', 'patched'] } },
            { range: { last_seen: { gte: new Date(from).toISOString() } } },
          ],
          minimum_should_match: 1,
        },
      },
    ],
  },
});

const DAY_MS = 24 * 60 * 60 * 1000;

export const buildPatchedSinceRange = (
  days: number,
  now: Date
): estypes.QueryDslQueryContainer => ({
  range: { version_changed_at: { gte: new Date(now.getTime() - days * DAY_MS).toISOString() } },
});

/** Builds the instances-index query from instance-side filters and pre-joined catalog ids. */
export const buildInstancesQuery = ({
  filters,
  catalogFilterIds,
  catalogSearchIds,
  asOf,
  requiredSoftwareIds,
  now = new Date(),
}: InstancesQueryInput): estypes.QueryDslQueryContainer => {
  const filter: estypes.QueryDslQueryContainer[] = [];

  if (asOf) {
    filter.push(buildAsOfClause(asOf));
  }
  if (requiredSoftwareIds) {
    filter.push(softwareIdsClause(requiredSoftwareIds, asOf));
  }
  if (hasCatalogFilters(filters)) {
    filter.push(softwareIdsClause(catalogFilterIds ?? [], asOf));
  }
  if (filters.search) {
    const should: estypes.QueryDslQueryContainer[] = [
      {
        wildcard: {
          'host.name': { value: containsPattern(filters.search), case_insensitive: true },
        },
      },
    ];
    if (catalogSearchIds && catalogSearchIds.length > 0) {
      should.push(softwareIdsClause(catalogSearchIds, asOf));
    }
    filter.push({ bool: { should, minimum_should_match: 1 } });
  }
  if (filters.source && filters.source.length > 0) {
    filter.push({ terms: { sources: filters.source } });
  }
  if (filters.status && filters.status.length > 0) {
    filter.push({ terms: { status: filters.status } });
  }
  if (filters.exposure_level && filters.exposure_level.length > 0) {
    filter.push({ terms: { 'exposure.level': filters.exposure_level } });
  }
  if (filters.patched_within_days !== undefined) {
    filter.push(buildPatchedSinceRange(filters.patched_within_days, now));
  }
  if (filters.host_name) {
    filter.push({
      wildcard: {
        'host.name': { value: containsPattern(filters.host_name), case_insensitive: true },
      },
    });
  }
  if (filters.host_id) {
    filter.push({ term: { 'host.id': filters.host_id } });
  }

  return filter.length === 0 ? { match_all: {} } : { bool: { filter } };
};

export const buildSort = (sortField: SortField, sortOrder: SortOrder): estypes.Sort => [
  { [sortField]: { order: sortOrder, unmapped_type: 'keyword' } },
  { id: 'asc' },
];

/** Returns an error message when the requested page lies beyond the result window. */
export const validatePageWindow = (page: number, perPage: number): string | undefined =>
  page * perPage > MAX_RESULT_WINDOW
    ? `page * per_page must not exceed ${MAX_RESULT_WINDOW}; narrow your filters instead`
    : undefined;

/** Normalizes a query value that may arrive as a single string or an array. */
export const toArray = <T extends string>(value: T | T[] | undefined): T[] | undefined => {
  if (value === undefined) return undefined;
  return Array.isArray(value) ? value : [value];
};
