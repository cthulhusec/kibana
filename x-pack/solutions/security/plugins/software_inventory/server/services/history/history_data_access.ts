/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient } from '@kbn/core/server';
import {
  CATALOG_INDEX,
  EVENTS_INDEX,
  INSTANCES_INDEX,
  MAX_HISTORY_RANGE_DAYS,
  ROLLUPS_INDEX,
} from '../../../common/constants';
import type {
  DailyRollup,
  HostTimelineResponse,
  InventoryEvent,
  TrendsResponse,
} from '../../../common/history';
import type { CatalogEntry, InstanceDoc } from '../../../common/types';
import { chunk } from '../ingest/chunk';
import {
  buildHostTimeline,
  isRemediatingPatch,
  medianTimeToPatch,
  softwareIdsInRange,
  type MsRange,
} from './history_math';

const DAY_MS = 24 * 60 * 60 * 1000;
const LENIENT = { ignore_unavailable: true, allow_no_indices: true } as const;

/** Patch events read per trends request to compute remediation and time to patch. */
export const MAX_PATCH_EVENTS = 10000;
/** Instances read for one host timeline. */
export const MAX_HOST_INSTANCES = 1000;
/** Distinct catalog ids joined per request; ids past this are treated as unknown (not vulnerable). */
export const MAX_JOINED_CATALOG_IDS = 10000;
const CATALOG_TERMS_CHUNK = 1000;

export type RangeValidation = { range: MsRange; error?: undefined } | { error: string };

/** Parses and validates an ISO `from`/`to` pair for the history routes. */
export const validateHistoryRange = (from: string, to: string): RangeValidation => {
  const fromMs = Date.parse(from);
  const toMs = Date.parse(to);
  if (Number.isNaN(fromMs) || Number.isNaN(toMs)) {
    return { error: '`from` and `to` must be ISO 8601 dates' };
  }
  if (fromMs >= toMs) return { error: '`from` must be before `to`' };
  if (toMs - fromMs > MAX_HISTORY_RANGE_DAYS * DAY_MS) {
    return { error: `The range must not exceed ${MAX_HISTORY_RANGE_DAYS} days` };
  }
  return { range: { from: fromMs, to: toMs } };
};

const toIso = (ms: number): string => new Date(ms).toISOString();

const sources = <T>(hits: ReadonlyArray<{ _source?: T }>): T[] =>
  hits.flatMap(({ _source: source }) => (source ? [source] : []));

/** Fetches catalog entries by id in bounded terms chunks; missing ids are absent from the map. */
export const fetchCatalogEntriesBounded = async (
  esClient: ElasticsearchClient,
  ids: Iterable<string>
): Promise<Map<string, CatalogEntry>> => {
  const unique = [...new Set(ids)].slice(0, MAX_JOINED_CATALOG_IDS);
  const entries = new Map<string, CatalogEntry>();
  for (const idsChunk of chunk(unique, CATALOG_TERMS_CHUNK)) {
    const response = await esClient.search<CatalogEntry>({
      index: CATALOG_INDEX,
      ...LENIENT,
      size: idsChunk.length,
      query: { terms: { id: idsChunk } },
    });
    for (const source of sources(response.hits.hits)) entries.set(source.id, source);
  }
  return entries;
};

type PatchEvent = Pick<
  InventoryEvent,
  | '@timestamp'
  | 'type'
  | 'software_id'
  | 'previous_software_id'
  | 'cve_count_before'
  | 'cve_count_after'
>;

/** Patch summary over `[from, to]` from the event log. */
const getPatchSummary = async (
  esClient: ElasticsearchClient,
  range: MsRange
): Promise<TrendsResponse['patch_summary']> => {
  const response = await esClient.search<PatchEvent>({
    index: EVENTS_INDEX,
    ...LENIENT,
    size: MAX_PATCH_EVENTS,
    track_total_hits: true,
    query: {
      bool: {
        filter: [
          { term: { type: 'version_changed' } },
          { range: { '@timestamp': { gte: toIso(range.from), lte: toIso(range.to) } } },
        ],
      },
    },
    sort: [{ '@timestamp': { order: 'desc', unmapped_type: 'date' } }],
    _source: [
      '@timestamp',
      'type',
      'software_id',
      'previous_software_id',
      'cve_count_before',
      'cve_count_after',
    ],
  });
  const events = sources(response.hits.hits);
  const { total } = response.hits;
  const patches = typeof total === 'number' ? total : total?.value ?? events.length;
  const catalog = await fetchCatalogEntriesBounded(
    esClient,
    events.flatMap(({ software_id: id, previous_software_id: previous }) =>
      previous ? [id, previous] : [id]
    )
  );
  const medianMs = medianTimeToPatch(events, catalog);
  return {
    patches,
    remediating_patches: events.filter((event) => isRemediatingPatch(event, catalog)).length,
    ...(medianMs !== undefined ? { median_time_to_patch_ms: medianMs } : {}),
  };
};

/**
 * Daily rollups whose UTC day intersects `[from, to]`, ascending, plus the patch summary. Missing
 * indices return empty buckets. Remediation counts and the median read at most
 * `MAX_PATCH_EVENTS` most recent patches; `patches` is the exact total.
 */
export const getTrends = async (
  esClient: ElasticsearchClient,
  range: MsRange
): Promise<TrendsResponse> => {
  const dayStart = Math.floor(range.from / DAY_MS) * DAY_MS;
  const response = await esClient.search<DailyRollup>({
    index: ROLLUPS_INDEX,
    ...LENIENT,
    size: MAX_HISTORY_RANGE_DAYS + 1,
    query: { range: { '@timestamp': { gte: toIso(dayStart), lte: toIso(range.to) } } },
    sort: [{ '@timestamp': { order: 'asc', unmapped_type: 'date' } }],
  });
  return {
    from: toIso(range.from),
    to: toIso(range.to),
    buckets: sources(response.hits.hits),
    patch_summary: await getPatchSummary(esClient, range),
  };
};

/** Every instance of a host (by `host.key`), at most `MAX_HOST_INSTANCES`. */
export const fetchHostInstances = async (
  esClient: ElasticsearchClient,
  hostKey: string
): Promise<InstanceDoc[]> => {
  const response = await esClient.search<InstanceDoc>({
    index: INSTANCES_INDEX,
    ...LENIENT,
    size: MAX_HOST_INSTANCES,
    query: { term: { 'host.key': hostKey } },
    sort: [{ id: 'asc' }],
  });
  return sources(response.hits.hits);
};

/**
 * Host timeline for `[from, to]`, or undefined when the host has no instances. Joins the catalog
 * entries of every version that ran during the range plus each instance's current entry.
 */
export const getHostTimeline = async (
  esClient: ElasticsearchClient,
  hostKey: string,
  range: MsRange,
  now: Date = new Date()
): Promise<HostTimelineResponse | undefined> => {
  const instances = await fetchHostInstances(esClient, hostKey);
  if (instances.length === 0) return undefined;
  const ids = instances.flatMap((instance) => [
    instance.software_id,
    ...softwareIdsInRange(instance, now, range),
  ]);
  const catalog = await fetchCatalogEntriesBounded(esClient, ids);
  return buildHostTimeline({ hostKey, instances, catalog, range, now });
};

/** Patch, removal and revival events of one host inside `[from, to]`, newest first. */
export const fetchHostEvents = async (
  esClient: ElasticsearchClient,
  hostKey: string,
  range: MsRange,
  size: number
): Promise<InventoryEvent[]> => {
  const response = await esClient.search<InventoryEvent>({
    index: EVENTS_INDEX,
    ...LENIENT,
    size,
    query: {
      bool: {
        filter: [
          { term: { 'host.key': hostKey } },
          { terms: { type: ['version_changed', 'removed', 'revived', 'stale'] } },
          { range: { '@timestamp': { gte: toIso(range.from), lte: toIso(range.to) } } },
        ],
      },
    },
    sort: [{ '@timestamp': { order: 'desc', unmapped_type: 'date' } }],
  });
  return sources(response.hits.hits);
};
