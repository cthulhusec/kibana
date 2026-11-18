/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient } from '@kbn/core/server';
import { CATALOG_INDEX, INSTANCES_INDEX } from '../../common/constants';
import type {
  CatalogDetailResponse,
  CatalogEntry,
  FindInstancesResponse,
  InstanceDoc,
  InstanceRow,
  SummaryResponse,
} from '../../common/types';
import {
  buildCatalogIdsQuery,
  buildInstancesQuery,
  buildSort,
  hasCatalogFilters,
  MAX_CATALOG_IDS,
  MAX_DETAIL_HOSTS,
  type AsOfRange,
  type FindInstancesParams,
} from './query_builders';
import { fetchCatalogEntriesBounded } from '../services/history/history_data_access';
import {
  latestSoftwareIdInRange,
  softwareIdsInRange,
  vulnerableInRange,
} from '../services/history/history_math';
import {
  buildSummaryAggregations,
  emptySummary,
  partitionCatalog,
  shapeSummary,
  SUMMARY_BASE_QUERY,
  type CatalogSummaryRow,
} from './summary';

/** Search options that make missing indices behave like empty ones. */
const LENIENT = { ignore_unavailable: true, allow_no_indices: true } as const;

const fetchCatalogIds = async (
  esClient: ElasticsearchClient,
  query: ReturnType<typeof buildCatalogIdsQuery>
): Promise<string[]> => {
  const response = await esClient.search<Pick<CatalogEntry, 'id'>>({
    index: CATALOG_INDEX,
    ...LENIENT,
    size: MAX_CATALOG_IDS,
    _source: ['id'],
    query,
  });
  return response.hits.hits.flatMap(({ _source: source }) => (source?.id ? [source.id] : []));
};

/** Fetches catalog entries by id; missing ids are simply absent from the map. */
export const fetchCatalogEntries = async (
  esClient: ElasticsearchClient,
  ids: string[]
): Promise<Map<string, CatalogEntry>> => {
  const entries = new Map<string, CatalogEntry>();
  if (ids.length === 0) return entries;
  const response = await esClient.search<CatalogEntry>({
    index: CATALOG_INDEX,
    ...LENIENT,
    size: ids.length,
    query: { terms: { id: ids } },
  });
  for (const { _source: source } of response.hits.hits) {
    if (source) entries.set(source.id, source);
  }
  return entries;
};

const emptyPage = ({ page, per_page: perPage }: FindInstancesParams): FindInstancesResponse => ({
  total: 0,
  page,
  per_page: perPage,
  items: [],
});

/** Instances scanned when `vulnerable_in_range=true` filters in code. Pages past this are empty. */
export const MAX_VULNERABLE_SCAN = 1000;

const totalValue = (total: number | { value: number } | undefined): number =>
  typeof total === 'number' ? total : total?.value ?? 0;

/** Ids of catalog entries with at least one CVE. */
const fetchVulnerableCatalogIds = (esClient: ElasticsearchClient): Promise<string[]> =>
  fetchCatalogIds(esClient, { range: { cve_count: { gt: 0 } } });

/**
 * Joins one page of instances with catalog entries. With `asOf`, `software` is the entry of the
 * latest version that ran during the range and `vulnerable_in_range` is computed per
 * `common/history.ts`.
 */
const toRows = async (
  esClient: ElasticsearchClient,
  docs: InstanceDoc[],
  asOf: AsOfRange | undefined,
  now: Date
): Promise<InstanceRow[]> => {
  if (!asOf) {
    const entries = await fetchCatalogEntries(esClient, [
      ...new Set(docs.map(({ software_id: softwareId }) => softwareId)),
    ]);
    return docs.flatMap((doc): InstanceRow[] => {
      const software = entries.get(doc.software_id);
      return software ? [{ ...doc, software }] : [];
    });
  }
  const entries = await fetchCatalogEntriesBounded(
    esClient,
    docs.flatMap((doc) => [doc.software_id, ...softwareIdsInRange(doc, now, asOf)])
  );
  return docs.flatMap((doc): InstanceRow[] => {
    const latestId = latestSoftwareIdInRange(doc, asOf, now);
    const software = (latestId ? entries.get(latestId) : undefined) ?? entries.get(doc.software_id);
    if (!software) return [];
    return [
      {
        ...doc,
        software,
        vulnerable_in_range: vulnerableInRange({
          instance: doc,
          catalog: entries,
          range: asOf,
          now,
        }),
      },
    ];
  });
};

/**
 * Joins instances with catalog entries: catalog-side filters first, then instances, then page
 * enrichment. With `as_of`, the inventory is scoped to that range (see `InstanceRow`). With
 * `vulnerable_in_range=true`, at most `MAX_VULNERABLE_SCAN` matching instances (in sort order) are
 * evaluated in code, then paginated; `total` counts the vulnerable rows among them.
 */
export const findInstances = async (
  esClient: ElasticsearchClient,
  params: FindInstancesParams,
  now: Date = new Date()
): Promise<FindInstancesResponse> => {
  const { page, per_page: perPage, sort_field: sortField, sort_order: sortOrder } = params;
  const asOf = params.as_of;
  const filterVulnerable = asOf !== undefined && params.vulnerable_in_range === true;

  let catalogFilterIds: string[] | undefined;
  if (hasCatalogFilters(params)) {
    catalogFilterIds = await fetchCatalogIds(
      esClient,
      buildCatalogIdsQuery(params, { includeSearch: false })
    );
    if (catalogFilterIds.length === 0) return emptyPage(params);
  }

  let catalogSearchIds: string[] | undefined;
  if (params.search) {
    catalogSearchIds = await fetchCatalogIds(
      esClient,
      buildCatalogIdsQuery(params, { includeSearch: true })
    );
  }

  let requiredSoftwareIds: string[] | undefined;
  if (filterVulnerable) {
    requiredSoftwareIds = await fetchVulnerableCatalogIds(esClient);
    if (requiredSoftwareIds.length === 0) return emptyPage(params);
  }

  const query = buildInstancesQuery({
    filters: params,
    catalogFilterIds,
    catalogSearchIds,
    asOf,
    requiredSoftwareIds,
    now,
  });
  const sort = buildSort(sortField, sortOrder);

  if (filterVulnerable) {
    const response = await esClient.search<InstanceDoc>({
      index: INSTANCES_INDEX,
      ...LENIENT,
      size: MAX_VULNERABLE_SCAN,
      query,
      sort,
    });
    const docs = response.hits.hits.flatMap(({ _source: source }) => (source ? [source] : []));
    const vulnerable = (await toRows(esClient, docs, asOf, now)).filter(
      (row) => row.vulnerable_in_range === true
    );
    return {
      total: vulnerable.length,
      page,
      per_page: perPage,
      items: vulnerable.slice((page - 1) * perPage, page * perPage),
    };
  }

  const response = await esClient.search<InstanceDoc>({
    index: INSTANCES_INDEX,
    ...LENIENT,
    from: (page - 1) * perPage,
    size: perPage,
    track_total_hits: true,
    query,
    sort,
  });

  const docs = response.hits.hits.flatMap(({ _source: source }) => (source ? [source] : []));
  return {
    total: totalValue(response.hits.total),
    page,
    per_page: perPage,
    items: await toRows(esClient, docs, asOf, now),
  };
};

export const getSummary = async (esClient: ElasticsearchClient): Promise<SummaryResponse> => {
  const catalog = await esClient.search<CatalogSummaryRow>({
    index: CATALOG_INDEX,
    ...LENIENT,
    size: MAX_CATALOG_IDS,
    _source: ['id', 'category', 'cve_count', 'known_exploited'],
    query: { match_all: {} },
  });
  const partition = partitionCatalog(
    catalog.hits.hits.flatMap(({ _source: source }) => (source ? [source] : []))
  );

  const response = await esClient.search({
    index: INSTANCES_INDEX,
    ...LENIENT,
    size: 0,
    track_total_hits: true,
    query: SUMMARY_BASE_QUERY,
    aggs: buildSummaryAggregations(partition),
  });

  if (!response.aggregations) return emptySummary();
  return shapeSummary(response, partition);
};

export const getCatalogDetail = async (
  esClient: ElasticsearchClient,
  id: string
): Promise<CatalogDetailResponse | undefined> => {
  const entry = (await fetchCatalogEntries(esClient, [id])).get(id);
  if (!entry) return undefined;

  const response = await esClient.search<InstanceDoc>({
    index: INSTANCES_INDEX,
    ...LENIENT,
    size: MAX_DETAIL_HOSTS,
    query: { term: { software_id: id } },
    sort: [{ last_seen: { order: 'desc', unmapped_type: 'date' } }],
  });
  return {
    entry,
    instances: response.hits.hits.flatMap(({ _source: source }) => (source ? [source] : [])),
  };
};
