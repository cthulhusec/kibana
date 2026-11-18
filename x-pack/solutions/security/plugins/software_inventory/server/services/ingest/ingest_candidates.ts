/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import type {
  BulkResponse,
  QueryDslQueryContainer,
  SortResults,
} from '@elastic/elasticsearch/lib/api/types';
import { CATALOG_INDEX, EVENTS_INDEX, INSTANCES_INDEX } from '../../../common/constants';
import type { InventoryEvent } from '../../../common/history';
import type {
  CatalogEntry,
  IngestCandidatesInput,
  IngestCandidatesOutput,
  InstanceDoc,
  SoftwareCategory,
} from '../../../common/types';
import { normalizeCandidate } from './normalize_candidate';
import type { NormalizedCandidate } from './normalize_candidate';
import {
  buildCatalogEntry,
  catalogIdForCandidate,
  dedupeCandidates,
  planInstance,
  planRemovals,
  reportedCategoriesByHost,
} from './plan_instance';
import type { PlannedInstance, RemovalCandidate } from './plan_instance';
import { planSightingEvents, planStatusEvents } from './plan_events';
import type { EventInstance, PostureEntry } from './plan_events';
import { resolveOsqueryHosts } from './resolve_osquery_hosts';
import { chunk } from './chunk';

const MGET_CHUNK_SIZE = 1000;
const BULK_CHUNK_SIZE = 1000;
const SEARCH_PAGE_SIZE = 1000;
const HOST_TERMS_CHUNK_SIZE = 500;

/** Removal candidate with the host fields that removal events record. */
type StoredRemovalCandidate = RemovalCandidate & EventInstance;

/** Bulk operations that append events to the event log; ids are generated. */
export const toEventOperations = (events: readonly InventoryEvent[]): object[] =>
  events.flatMap((event) => [{ index: { _index: EVENTS_INDEX } }, event]);

const mgetSources = async <T>(
  esClient: ElasticsearchClient,
  index: string,
  ids: readonly string[],
  withSource: boolean
): Promise<Map<string, T | undefined>> => {
  const found = new Map<string, T | undefined>();
  for (const idsChunk of chunk(ids, MGET_CHUNK_SIZE)) {
    const { docs } = await esClient.mget<T>({ index, ids: idsChunk, _source: withSource });
    for (const doc of docs) {
      if ('found' in doc && doc.found) {
        found.set(doc._id, doc._source);
      }
    }
  }
  return found;
};

/** Reads every instance of the reported hosts that the source discovered and is not removed. */
const findInstancesForHosts = async (
  esClient: ElasticsearchClient,
  hostKeys: readonly string[],
  source: IngestCandidatesInput['source']
): Promise<StoredRemovalCandidate[]> => {
  const results: StoredRemovalCandidate[] = [];
  for (const hostChunk of chunk(hostKeys, HOST_TERMS_CHUNK_SIZE)) {
    const query: QueryDslQueryContainer = {
      bool: {
        filter: [{ terms: { 'host.key': hostChunk } }, { term: { sources: source } }],
        must_not: [{ term: { status: 'removed' } }],
      },
    };
    let searchAfter: SortResults | undefined;
    for (;;) {
      const response = await esClient.search<StoredRemovalCandidate>({
        index: INSTANCES_INDEX,
        size: SEARCH_PAGE_SIZE,
        query,
        sort: [{ id: 'asc' }],
        _source: ['id', 'host.key', 'host.id', 'host.name', 'software_id', 'sources', 'status'],
        ...(searchAfter ? { search_after: searchAfter } : {}),
      });
      const { hits } = response.hits;
      for (const hit of hits) {
        if (hit._source) {
          results.push(hit._source);
        }
      }
      const last = hits[hits.length - 1];
      if (hits.length < SEARCH_PAGE_SIZE || !last?.sort) {
        break;
      }
      searchAfter = last.sort;
    }
  }
  return results;
};

/** Catalog category of each software id; ids without a catalog entry are left out. */
const loadCategories = async (
  esClient: ElasticsearchClient,
  softwareIds: readonly string[]
): Promise<Map<string, SoftwareCategory>> => {
  const entries = await mgetSources<Pick<CatalogEntry, 'category'>>(
    esClient,
    CATALOG_INDEX,
    softwareIds,
    true
  );
  const categories = new Map<string, SoftwareCategory>();
  for (const [id, entry] of entries) {
    if (entry?.category) {
      categories.set(id, entry.category);
    }
  }
  return categories;
};

/**
 * Snapshot removals, scoped by host and category: see `planRemovals`. Removals are planned before
 * this call's catalog entries are written, so only categories of already stored entries count.
 */
const planSnapshotRemovals = async ({
  esClient,
  normalized,
  seenInstanceIds,
  source,
}: {
  esClient: ElasticsearchClient;
  normalized: readonly NormalizedCandidate[];
  seenInstanceIds: ReadonlySet<string>;
  source: IngestCandidatesInput['source'];
}): Promise<StoredRemovalCandidate[]> => {
  const reportedCategories = reportedCategoriesByHost(normalized);
  const existing = await findInstancesForHosts(esClient, [...reportedCategories.keys()], source);
  const unseen = existing.filter(({ id }) => !seenInstanceIds.has(id));
  if (unseen.length === 0) {
    return [];
  }
  const categoryBySoftwareId = await loadCategories(esClient, [
    ...new Set(unseen.map(({ software_id: softwareId }) => softwareId)),
  ]);
  const removedIds = new Set(
    planRemovals({
      existing: unseen,
      reportedCategories,
      categoryBySoftwareId,
      seenInstanceIds,
      source,
    })
  );
  return unseen.filter(({ id }) => removedIds.has(id));
};

const countBulkErrors = (response: BulkResponse): number =>
  response.errors ? response.items.filter((item) => Object.values(item)[0]?.error).length : 0;

export const runBulk = async (
  esClient: ElasticsearchClient,
  logger: Logger,
  operations: object[],
  opsPerItem: number
): Promise<void> => {
  for (const operationsChunk of chunk(operations, BULK_CHUNK_SIZE * opsPerItem)) {
    const response = await esClient.bulk({ operations: operationsChunk, refresh: 'wait_for' });
    const failed = countBulkErrors(response);
    if (failed > 0) {
      logger.warn(`Software inventory bulk write had ${failed} failed item(s)`);
    }
  }
};

/** Catalog entries of both sides of every patch in this call, for the event posture fields. */
const loadPostureCatalog = async (
  esClient: ElasticsearchClient,
  sightings: ReadonlyArray<{ existing: InstanceDoc | undefined; planned: PlannedInstance }>
): Promise<Map<string, PostureEntry>> => {
  const ids = new Set<string>();
  for (const { existing, planned } of sightings) {
    if (planned.outcome === 'patched' && existing) {
      ids.add(existing.software_id);
      ids.add(planned.doc.software_id);
    }
  }
  const entries = new Map<string, PostureEntry>();
  if (ids.size === 0) return entries;
  const found = await mgetSources<PostureEntry>(esClient, CATALOG_INDEX, [...ids], true);
  for (const [id, entry] of found) {
    if (entry) entries.set(id, entry);
  }
  return entries;
};

/**
 * Normalizes raw rows, diffs them against stored instances, and writes the result. Catalog entries
 * are created only when missing, so CVE enrichment on existing entries is never overwritten. Every
 * state transition is appended to the event log in the same chunked bulk writes as the instances.
 */
export const ingestCandidates = async ({
  esClient,
  logger,
  input,
}: {
  esClient: ElasticsearchClient;
  logger: Logger;
  input: IngestCandidatesInput;
}): Promise<IngestCandidatesOutput> => {
  const now = new Date().toISOString();
  const { source, snapshot } = input;

  const candidates =
    source === 'osquery'
      ? await resolveOsqueryHosts({ esClient, logger, candidates: input.candidates })
      : input.candidates;
  const normalized = candidates
    .map((raw) => normalizeCandidate(raw, now, source))
    .filter((candidate): candidate is NormalizedCandidate => candidate !== undefined);
  const skipped = candidates.length - normalized.length;
  if (skipped > 0) {
    logger.debug(
      `Software inventory skipped ${skipped} candidate(s) without a host or name, or with no known mapping`
    );
  }

  const byInstanceId = dedupeCandidates(normalized);
  const instanceIds = [...byInstanceId.keys()];
  const existing = await mgetSources<InstanceDoc>(esClient, INSTANCES_INDEX, instanceIds, true);

  const output: IngestCandidatesOutput = {
    created: 0,
    unchanged: 0,
    patched: 0,
    removed: 0,
    skipped,
  };
  const instanceOperations: object[] = [];
  const catalogCandidates = new Map<string, NormalizedCandidate>();
  const sightings: Array<{
    existing: InstanceDoc | undefined;
    planned: PlannedInstance;
    observedAt: string;
  }> = [];

  for (const [id, candidate] of byInstanceId) {
    const planned = planInstance({
      existing: existing.get(id),
      candidate,
      source,
      now,
    });
    output[planned.outcome] += 1;
    instanceOperations.push({ index: { _index: INSTANCES_INDEX, _id: id } }, planned.doc);
    catalogCandidates.set(catalogIdForCandidate(candidate), candidate);
    sightings.push({ existing: existing.get(id), planned, observedAt: candidate.observed_at });
  }

  const removed = snapshot
    ? await planSnapshotRemovals({
        esClient,
        normalized: [...byInstanceId.values()],
        seenInstanceIds: new Set(instanceIds),
        source,
      })
    : [];
  output.removed = removed.length;
  const removalOperations = removed.flatMap(({ id }) => [
    { update: { _index: INSTANCES_INDEX, _id: id } },
    { doc: { status: 'removed', '@timestamp': now } },
  ]);

  const catalogIds = [...catalogCandidates.keys()];
  const existingCatalog = await mgetSources<CatalogEntry>(
    esClient,
    CATALOG_INDEX,
    catalogIds,
    false
  );
  const catalogOperations = catalogIds
    .filter((id) => !existingCatalog.has(id))
    .flatMap((id) => {
      const candidate = catalogCandidates.get(id);
      return candidate
        ? [{ create: { _index: CATALOG_INDEX, _id: id } }, buildCatalogEntry(candidate, now)]
        : [];
    });

  const postureCatalog = await loadPostureCatalog(esClient, sightings);
  const events = [
    ...sightings.flatMap(({ existing: stored, planned, observedAt }) =>
      planSightingEvents({ existing: stored, planned, source, observedAt, catalog: postureCatalog })
    ),
    ...planStatusEvents({ instances: removed, type: 'removed', source, at: now }),
  ];

  // Catalog first, so an instance never points at a catalog entry that does not exist yet.
  await runBulk(esClient, logger, catalogOperations, 2);
  await runBulk(
    esClient,
    logger,
    [...instanceOperations, ...removalOperations, ...toEventOperations(events)],
    2
  );

  logger.debug(
    `Software inventory ingest from ${source}: ${output.created} created, ${output.unchanged} unchanged, ${output.patched} patched, ${output.removed} removed, ${output.skipped} skipped`
  );
  return output;
};
