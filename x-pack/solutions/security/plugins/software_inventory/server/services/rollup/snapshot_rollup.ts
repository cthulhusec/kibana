/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { estypes } from '@elastic/elasticsearch';
import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import {
  CARDINALITY_PRECISION_THRESHOLD,
  CATALOG_INDEX,
  EVENTS_INDEX,
  INSTANCES_INDEX,
  ROLLUPS_INDEX,
} from '../../../common/constants';
import type { DailyRollup } from '../../../common/history';
import type { CatalogEntry, SoftwareCategory } from '../../../common/types';

/** Catalog entries read per rollup; terms filters stay below the Elasticsearch default limits. */
export const MAX_ROLLUP_CATALOG_IDS = 10000;

const DAY_MS = 24 * 60 * 60 * 1000;
const LENIENT = { ignore_unavailable: true, allow_no_indices: true } as const;
const CATEGORIES: readonly SoftwareCategory[] = [
  'application',
  'dependency',
  'appliance',
  'os_package',
  'other',
];

export type RollupCatalogRow = Pick<
  CatalogEntry,
  'id' | 'category' | 'cve_count' | 'max_cvss' | 'known_exploited'
>;

export interface RollupPartition {
  vulnerable: string[];
  critical: string[];
  high: string[];
  knownExploited: string[];
  byCategory: Record<SoftwareCategory, string[]>;
}

/** UTC day of `now` as `YYYY-MM-DD` and its start and end (exclusive) in ISO. */
export const utcDay = (now: Date): { id: string; start: string; end: string } => {
  const start = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return {
    id: new Date(start).toISOString().slice(0, 10),
    start: new Date(start).toISOString(),
    end: new Date(start + DAY_MS).toISOString(),
  };
};

/** Groups catalog ids by the properties the rollup counts. */
export const partitionRollupCatalog = (rows: readonly RollupCatalogRow[]): RollupPartition => {
  const partition: RollupPartition = {
    vulnerable: [],
    critical: [],
    high: [],
    knownExploited: [],
    byCategory: { application: [], dependency: [], appliance: [], os_package: [], other: [] },
  };
  for (const row of rows) {
    const maxCvss = row.max_cvss ?? 0;
    if ((row.cve_count ?? 0) > 0) partition.vulnerable.push(row.id);
    if (maxCvss >= 9) partition.critical.push(row.id);
    else if (maxCvss >= 7) partition.high.push(row.id);
    if (row.known_exploited === true) partition.knownExploited.push(row.id);
    partition.byCategory[CATEGORIES.includes(row.category) ? row.category : 'other'].push(row.id);
  }
  return partition;
};

const idsFilter = (ids: readonly string[]): estypes.QueryDslQueryContainer =>
  ids.length === 0
    ? { bool: { must_not: { match_all: {} } } }
    : { terms: { software_id: [...ids] } };

const EXPOSED: estypes.QueryDslQueryContainer = {
  terms: { 'exposure.level': ['medium', 'high'] },
};

/** Instances counted by the rollup: active or patched. */
export const ROLLUP_INSTANCES_QUERY: estypes.QueryDslQueryContainer = {
  terms: { status: ['active', 'patched'] },
};

export const buildRollupAggregations = (
  partition: RollupPartition
): Record<string, estypes.AggregationsAggregationContainer> => ({
  software: { cardinality: { field: 'software_id', precision_threshold: CARDINALITY_PRECISION_THRESHOLD } },
  vulnerable: { filter: idsFilter(partition.vulnerable) },
  critical: { filter: idsFilter(partition.critical) },
  high: { filter: idsFilter(partition.high) },
  known_exploited: { filter: idsFilter(partition.knownExploited) },
  exposed: { filter: EXPOSED },
  exposed_and_vulnerable: {
    filter: { bool: { filter: [EXPOSED, idsFilter(partition.vulnerable)] } },
  },
  ...Object.fromEntries(
    CATEGORIES.map((category) => [
      `category_${category}`,
      { filter: idsFilter(partition.byCategory[category]) },
    ])
  ),
});

const totalOf = (total: estypes.SearchHitsMetadata['total']): number =>
  typeof total === 'number' ? total : total?.value ?? 0;

/** Shapes the instance aggregations and per-type event counts into a `DailyRollup`. */
export const shapeRollup = ({
  dayStart,
  instances,
  eventCounts,
}: {
  dayStart: string;
  instances: Pick<estypes.SearchResponse, 'hits' | 'aggregations'>;
  eventCounts: Partial<Record<string, number>>;
}): DailyRollup => {
  const aggs = (instances.aggregations ?? {}) as Record<
    string,
    { doc_count?: number; value?: number } | undefined
  >;
  const count = (name: string): number => aggs[name]?.doc_count ?? 0;
  return {
    '@timestamp': dayStart,
    total_instances: totalOf(instances.hits.total),
    total_software: aggs.software?.value ?? 0,
    vulnerable_instances: count('vulnerable'),
    critical_instances: count('critical'),
    high_instances: count('high'),
    exposed_instances: count('exposed'),
    known_exploited_instances: count('known_exploited'),
    exposed_and_vulnerable_instances: count('exposed_and_vulnerable'),
    new_instances: eventCounts.first_seen ?? 0,
    patched_instances: eventCounts.version_changed ?? 0,
    removed_instances: eventCounts.removed ?? 0,
    categories: Object.fromEntries(
      CATEGORIES.map((category) => [category, count(`category_${category}`)])
    ) as Record<SoftwareCategory, number>,
  };
};

/**
 * Computes today's (UTC) `DailyRollup` from the current instances and catalog plus today's events,
 * and writes it with `_id` = `YYYY-MM-DD`, so re-runs on the same day overwrite it.
 */
export const snapshotRollup = async ({
  esClient,
  logger,
  now = new Date(),
}: {
  esClient: ElasticsearchClient;
  logger: Logger;
  now?: Date;
}): Promise<{ date: string; rollup: DailyRollup }> => {
  const day = utcDay(now);

  const catalog = await esClient.search<RollupCatalogRow>({
    index: CATALOG_INDEX,
    ...LENIENT,
    size: MAX_ROLLUP_CATALOG_IDS,
    _source: ['id', 'category', 'cve_count', 'max_cvss', 'known_exploited'],
    query: { match_all: {} },
  });
  const rows = catalog.hits.hits.flatMap(({ _source: source }) => (source ? [source] : []));
  if (totalOf(catalog.hits.total) > rows.length) {
    logger.warn(
      `Software inventory rollup read only ${rows.length} catalog entries; counts may be low`
    );
  }

  const instances = await esClient.search({
    index: INSTANCES_INDEX,
    ...LENIENT,
    size: 0,
    track_total_hits: true,
    query: ROLLUP_INSTANCES_QUERY,
    aggs: buildRollupAggregations(partitionRollupCatalog(rows)),
  });

  const events = await esClient.search({
    index: EVENTS_INDEX,
    ...LENIENT,
    size: 0,
    query: { range: { '@timestamp': { gte: day.start, lt: day.end } } },
    aggs: { by_type: { terms: { field: 'type', size: 10 } } },
  });
  const buckets =
    (
      events.aggregations?.by_type as
        | { buckets?: Array<{ key: string; doc_count: number }> }
        | undefined
    )?.buckets ?? [];
  const eventCounts = Object.fromEntries(buckets.map(({ key, doc_count: n }) => [key, n]));

  const rollup = shapeRollup({ dayStart: day.start, instances, eventCounts });
  await esClient.index({ index: ROLLUPS_INDEX, id: day.id, document: rollup, refresh: 'wait_for' });
  logger.debug(`Software inventory wrote the rollup for ${day.id}`);
  return { date: day.id, rollup };
};
