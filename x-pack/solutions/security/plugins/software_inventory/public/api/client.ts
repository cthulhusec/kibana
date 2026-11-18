/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { HttpSetup } from '@kbn/core/public';
import {
  API_VERSION,
  CATALOG_DETAIL_URL,
  HOST_TIMELINE_URL,
  INSTANCES_URL,
  SUMMARY_URL,
  TRENDS_URL,
} from '../../common/constants';
import type { HostTimelineResponse, TrendsResponse } from '../../common/history';
import type {
  CatalogDetailResponse,
  DiscoverySource,
  ExposureLevel,
  FindInstancesResponse,
  InstanceStatus,
  SoftwareCategory,
  SummaryResponse,
} from '../../common/types';

/** Mirrors the server's sort allowlist (instance-side fields only). */
export type InstanceSortField =
  | 'last_seen'
  | 'first_seen'
  | 'version_changed_at'
  | 'exposure.score'
  | 'host.name';

/** Query-string params accepted by the instances route. */
export interface FindInstancesParams {
  page: number;
  per_page: number;
  sort_field?: InstanceSortField;
  sort_order?: 'asc' | 'desc';
  search?: string;
  category?: SoftwareCategory[];
  source?: DiscoverySource[];
  status?: InstanceStatus[];
  exposure_level?: ExposureLevel[];
  min_cve_count?: number;
  known_exploited?: boolean;
  patched_within_days?: number;
  /** Both or neither; scopes the inventory to a period. */
  as_of_from?: string;
  as_of_to?: string;
  vulnerable_in_range?: boolean;
}

/** Query-string params shared by the history routes. */
export interface HistoryRangeParams {
  from: string;
  to: string;
}

export const fetchInstances = (
  http: HttpSetup,
  query: FindInstancesParams,
  signal?: AbortSignal
): Promise<FindInstancesResponse> =>
  http.get<FindInstancesResponse>(INSTANCES_URL, {
    version: API_VERSION,
    query: { ...query },
    signal,
  });

export const fetchSummary = (http: HttpSetup, signal?: AbortSignal): Promise<SummaryResponse> =>
  http.get<SummaryResponse>(SUMMARY_URL, { version: API_VERSION, signal });

export const fetchCatalogDetail = (
  http: HttpSetup,
  id: string,
  signal?: AbortSignal
): Promise<CatalogDetailResponse> =>
  http.get<CatalogDetailResponse>(CATALOG_DETAIL_URL.replace('{id}', encodeURIComponent(id)), {
    version: API_VERSION,
    signal,
  });

export const fetchTrends = (
  http: HttpSetup,
  query: HistoryRangeParams,
  signal?: AbortSignal
): Promise<TrendsResponse> =>
  http.get<TrendsResponse>(TRENDS_URL, { version: API_VERSION, query: { ...query }, signal });

export const fetchHostTimeline = (
  http: HttpSetup,
  hostKey: string,
  query: HistoryRangeParams,
  signal?: AbortSignal
): Promise<HostTimelineResponse> =>
  http.get<HostTimelineResponse>(
    HOST_TIMELINE_URL.replace('{host_key}', encodeURIComponent(hostKey)),
    {
      version: API_VERSION,
      query: { ...query },
      signal,
    }
  );
