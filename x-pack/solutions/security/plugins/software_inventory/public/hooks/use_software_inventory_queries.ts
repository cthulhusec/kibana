/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useQuery, type UseQueryResult } from '@kbn/react-query';
import { useKibana } from '@kbn/kibana-react-plugin/public';
import type { CoreStart } from '@kbn/core/public';
import {
  fetchCatalogDetail,
  fetchHostTimeline,
  fetchInstances,
  fetchSummary,
  fetchTrends,
  type FindInstancesParams,
} from '../api/client';
import type { HostTimelineResponse, TrendsResponse } from '../../common/history';
import type { ResolvedPeriod } from '../lib/time_range';
import type {
  CatalogDetailResponse,
  FindInstancesResponse,
  SummaryResponse,
} from '../../common/types';

const ROOT_KEY = 'softwareInventory' as const;

export const useInstancesQuery = (
  params: FindInstancesParams,
  enabled: boolean = true
): UseQueryResult<FindInstancesResponse, Error> => {
  const { http } = useKibana<CoreStart>().services;
  return useQuery<FindInstancesResponse, Error>({
    queryKey: [ROOT_KEY, 'instances', params],
    queryFn: ({ signal }) => fetchInstances(http, params, signal),
    keepPreviousData: true,
    enabled,
  });
};

export const useSummaryQuery = (): UseQueryResult<SummaryResponse, Error> => {
  const { http } = useKibana<CoreStart>().services;
  return useQuery<SummaryResponse, Error>({
    queryKey: [ROOT_KEY, 'summary'],
    queryFn: ({ signal }) => fetchSummary(http, signal),
  });
};

export const useCatalogDetailQuery = (
  softwareId: string | undefined
): UseQueryResult<CatalogDetailResponse, Error> => {
  const { http } = useKibana<CoreStart>().services;
  return useQuery<CatalogDetailResponse, Error>({
    queryKey: [ROOT_KEY, 'catalog', softwareId],
    queryFn: ({ signal }) => fetchCatalogDetail(http, softwareId ?? '', signal),
    enabled: softwareId !== undefined,
  });
};

export const useTrendsQuery = (
  period: ResolvedPeriod | undefined
): UseQueryResult<TrendsResponse, Error> => {
  const { http } = useKibana<CoreStart>().services;
  return useQuery<TrendsResponse, Error>({
    queryKey: [ROOT_KEY, 'trends', period],
    queryFn: ({ signal }) =>
      fetchTrends(http, { from: period?.from ?? '', to: period?.to ?? '' }, signal),
    enabled: period !== undefined,
  });
};

export const useHostTimelineQuery = (
  hostKey: string,
  period: ResolvedPeriod
): UseQueryResult<HostTimelineResponse, Error> => {
  const { http } = useKibana<CoreStart>().services;
  return useQuery<HostTimelineResponse, Error>({
    queryKey: [ROOT_KEY, 'hostTimeline', hostKey, period],
    queryFn: ({ signal }) => fetchHostTimeline(http, hostKey, period, signal),
  });
};
