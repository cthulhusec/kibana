/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import type { QueryDslQueryContainer, SortResults } from '@elastic/elasticsearch/lib/api/types';
import { DEFAULT_STALE_AFTER_DAYS, INSTANCES_INDEX } from '../../../common/constants';
import { STALE_ELIGIBLE_STATUSES } from './plan_instance';
import { planStatusEvents, type EventInstance } from './plan_events';
import { runBulk, toEventOperations } from './ingest_candidates';

const DAY_MS = 24 * 60 * 60 * 1000;
const SEARCH_PAGE_SIZE = 1000;

export const buildStaleCutoff = (now: Date, staleAfterDays: number): string =>
  new Date(now.getTime() - staleAfterDays * DAY_MS).toISOString();

/** Query for instances that `isStale` accepts. `removed` instances never match. */
export const buildStaleQuery = (cutoff: string): QueryDslQueryContainer => ({
  bool: {
    filter: [
      { terms: { status: [...STALE_ELIGIBLE_STATUSES] } },
      { range: { last_seen: { lt: cutoff } } },
    ],
  },
});

/** Every instance the stale query matches, paged with `search_after`. */
const findStaleInstances = async (
  esClient: ElasticsearchClient,
  query: QueryDslQueryContainer
): Promise<EventInstance[]> => {
  const results: EventInstance[] = [];
  let searchAfter: SortResults | undefined;
  for (;;) {
    const response = await esClient.search<EventInstance>({
      index: INSTANCES_INDEX,
      ignore_unavailable: true,
      size: SEARCH_PAGE_SIZE,
      query,
      sort: [{ id: 'asc' }],
      _source: ['id', 'host.key', 'host.id', 'host.name', 'software_id', 'sources'],
      ...(searchAfter ? { search_after: searchAfter } : {}),
    });
    const { hits } = response.hits;
    for (const hit of hits) {
      if (hit._source) results.push(hit._source);
    }
    const last = hits[hits.length - 1];
    if (hits.length < SEARCH_PAGE_SIZE || !last?.sort) return results;
    searchAfter = last.sort;
  }
};

/**
 * Marks `active` and `patched` instances not seen for `staleAfterDays` as `stale`, and appends a
 * `stale` event for each instance the query matched before the update. An instance that a
 * concurrent ingest revives between the search and the update can get an event without the status
 * change; the next sighting then records `revived`.
 */
export const markStale = async ({
  esClient,
  logger,
  staleAfterDays = DEFAULT_STALE_AFTER_DAYS,
}: {
  esClient: ElasticsearchClient;
  logger: Logger;
  staleAfterDays?: number;
}): Promise<{ marked: number }> => {
  const now = new Date();
  const query = buildStaleQuery(buildStaleCutoff(now, staleAfterDays));
  const candidates = await findStaleInstances(esClient, query);
  if (candidates.length === 0) {
    logger.debug('Software inventory marked 0 instance(s) stale');
    return { marked: 0 };
  }
  const response = await esClient.updateByQuery({
    index: INSTANCES_INDEX,
    query,
    script: {
      source: "ctx._source.status = params.status; ctx._source['@timestamp'] = params.now;",
      lang: 'painless',
      params: { status: 'stale', now: now.toISOString() },
    },
    conflicts: 'proceed',
    refresh: true,
  });
  const marked = response.updated ?? 0;
  // Partial documents (no host or software id) cannot produce a meaningful event.
  const complete = candidates.filter(
    ({ host, software_id: softwareId }) => host?.key && softwareId
  );
  const events = planStatusEvents({ instances: complete, type: 'stale', at: now.toISOString() });
  await runBulk(esClient, logger, toEventOperations(events), 2);
  logger.debug(`Software inventory marked ${marked} instance(s) stale`);
  return { marked };
};
