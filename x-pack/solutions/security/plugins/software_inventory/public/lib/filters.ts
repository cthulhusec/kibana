/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FindInstancesParams, InstanceSortField } from '../api/client';
import { toAsOfParams, type ResolvedPeriod } from './time_range';
import type {
  DiscoverySource,
  ExposureLevel,
  InstanceStatus,
  SoftwareCategory,
} from '../../common/types';

export interface FilterState {
  search: string;
  category: SoftwareCategory[];
  source: DiscoverySource[];
  status: InstanceStatus[];
  exposureLevel: ExposureLevel[];
  /** Raw text from the numeric input. */
  minCveCount: string;
  knownExploited: boolean;
  /** Raw text from the numeric input. */
  patchedWithinDays: string;
  /** Maps to `vulnerable_in_range`; only sent when the table is scoped to a period. */
  vulnerableInRange: boolean;
}

export interface TableState {
  pageIndex: number;
  pageSize: number;
  sortField: InstanceSortField;
  sortDirection: 'asc' | 'desc';
}

export const EMPTY_FILTERS: FilterState = {
  search: '',
  category: [],
  source: [],
  status: [],
  exposureLevel: [],
  minCveCount: '',
  knownExploited: false,
  patchedWithinDays: '',
  vulnerableInRange: false,
};

export const DEFAULT_TABLE_STATE: TableState = {
  pageIndex: 0,
  pageSize: 25,
  sortField: 'exposure.score',
  sortDirection: 'desc',
};

const toPositiveInt = (raw: string): number | undefined => {
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
};

/** Maps UI filter + table state to instances route query params; omits unset filters. */
export const toFindInstancesParams = (
  filters: FilterState,
  table: TableState,
  period?: ResolvedPeriod
): FindInstancesParams => {
  const search = filters.search.trim();
  const minCveCount = toPositiveInt(filters.minCveCount);
  const patchedWithinDays = toPositiveInt(filters.patchedWithinDays);

  return {
    page: table.pageIndex + 1,
    per_page: table.pageSize,
    sort_field: table.sortField,
    sort_order: table.sortDirection,
    ...(search ? { search } : {}),
    ...(filters.category.length > 0 ? { category: filters.category } : {}),
    ...(filters.source.length > 0 ? { source: filters.source } : {}),
    ...(filters.status.length > 0 ? { status: filters.status } : {}),
    ...(filters.exposureLevel.length > 0 ? { exposure_level: filters.exposureLevel } : {}),
    ...(minCveCount !== undefined ? { min_cve_count: minCveCount } : {}),
    ...(filters.knownExploited ? { known_exploited: true } : {}),
    ...(patchedWithinDays !== undefined ? { patched_within_days: patchedWithinDays } : {}),
    ...toAsOfParams(period),
    ...(period && filters.vulnerableInRange ? { vulnerable_in_range: true } : {}),
  };
};

export const hasActiveFilters = (filters: FilterState): boolean =>
  filters.vulnerableInRange ||
  Object.keys(toFindInstancesParams(filters, DEFAULT_TABLE_STATE)).some(
    (key) => !['page', 'per_page', 'sort_field', 'sort_order'].includes(key)
  );
