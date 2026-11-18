/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import { CATALOG_INDEX, INSTANCES_INDEX } from '../../../common/constants';
import type { CatalogEntry, InstanceDoc } from '../../../common/types';
import { buildHostKey, isPolicyHostKey } from '../../lib/instance_identity';
import { combineExposure } from './combine_exposure';
import { isEdgeProduct } from './integration_map';
import { NON_PUBLIC_CIDRS, isPublicIp } from './public_ip';

const LOGS_INDEX = 'logs-*';
const PAGE_SIZE = 500;
const TOP_SOURCES = 3;
/**
 * Only events marked inbound count. An `event.category: network` event without a direction is
 * left out: on a host with a public address, its own outbound flows would look inbound.
 */
const INBOUND_DIRECTIONS = ['inbound', 'ingress'];

interface HostSignal {
  distinct: number;
  samples: string[];
}

interface SourceBucket {
  key: string;
  distinct: { value: number };
  top: { buckets: Array<{ key: string }> };
}

interface HostAggs {
  by_name?: { buckets: Array<SourceBucket> };
  by_id?: { buckets: Array<SourceBucket> };
}

const toSignal = (bucket: SourceBucket): HostSignal => ({
  distinct: bucket.distinct.value,
  samples: bucket.top.buckets.map((b) => b.key).filter(isPublicIp),
});

/** Signals keyed by canonical host key (from log `host.name`) and by log `host.id`. */
export interface InboundSignals {
  byKey: Map<string, HostSignal>;
  byId: Map<string, HostSignal>;
}

const addSignal = (target: Map<string, HostSignal>, key: string, signal: HostSignal): void => {
  const current = target.get(key);
  // Log host names that differ only by case share one key; keep the stronger signal.
  if (!current || signal.distinct > current.distinct) {
    target.set(key, signal);
  }
};

/** Aggregates, in ES, distinct public inbound sources for a set of hosts. */
export const queryInboundSignals = async ({
  esClient,
  names,
  ids,
  lookbackDays,
}: {
  esClient: ElasticsearchClient;
  names: string[];
  ids: string[];
  lookbackDays: number;
}): Promise<InboundSignals> => {
  const byKey = new Map<string, HostSignal>();
  const byId = new Map<string, HostSignal>();
  if (names.length === 0 && ids.length === 0) return { byKey, byId };

  const subAggs = {
    distinct: { cardinality: { field: 'source.ip' } },
    top: { terms: { field: 'source.ip', size: TOP_SOURCES } },
  };
  const response = await esClient.search({
    index: LOGS_INDEX,
    size: 0,
    ignore_unavailable: true,
    allow_no_indices: true,
    query: {
      bool: {
        filter: [
          { range: { '@timestamp': { gte: `now-${lookbackDays}d` } } },
          { exists: { field: 'source.ip' } },
          {
            bool: {
              should: [{ terms: { 'host.name': names } }, { terms: { 'host.id': ids } }],
              minimum_should_match: 1,
            },
          },
          { terms: { 'network.direction': INBOUND_DIRECTIONS } },
        ],
        must_not: NON_PUBLIC_CIDRS.map((cidr) => ({ term: { 'source.ip': cidr } })),
      },
    },
    aggs: {
      by_name: {
        terms: { field: 'host.name', size: Math.max(1, names.length) },
        aggs: subAggs,
      },
      by_id: { terms: { field: 'host.id', size: Math.max(1, ids.length) }, aggs: subAggs },
    },
  });
  const aggs = (response.aggregations ?? {}) as unknown as HostAggs;
  for (const bucket of aggs.by_name?.buckets ?? []) {
    addSignal(byKey, buildHostKey({ hostName: bucket.key, hostId: bucket.key }), toSignal(bucket));
  }
  for (const bucket of aggs.by_id?.buckets ?? []) byId.set(bucket.key, toSignal(bucket));
  return { byKey, byId };
};

/** Canonical key of a stored instance; documents written before `host.key` existed derive it. */
const hostKeyOf = (host: InstanceDoc['host']): string =>
  host.key || buildHostKey({ hostName: host.name, hostId: host.id });

const loadCatalog = async (
  esClient: ElasticsearchClient,
  softwareIds: string[]
): Promise<Map<string, CatalogEntry>> => {
  const result = new Map<string, CatalogEntry>();
  if (softwareIds.length === 0) return result;
  const response = await esClient.search<CatalogEntry>({
    index: CATALOG_INDEX,
    size: softwareIds.length,
    query: { terms: { id: softwareIds } },
    _source: ['id', 'vendor', 'product', 'category'],
  });
  for (const hit of response.hits.hits) {
    if (hit._source) result.set(hit._source.id, hit._source);
  }
  return result;
};

/**
 * Scores every instance that is not removed. Inbound signals are matched on the canonical host
 * key (log `host.name`, lower-cased), then on `host.id`. Fleet policy pseudo-hosts are never
 * matched against logs. Each host is aggregated once per call, even when its instances span
 * several pages.
 */
export const scoreExposure = async ({
  esClient,
  logger,
  lookbackDays,
}: {
  esClient: ElasticsearchClient;
  logger: Logger;
  lookbackDays: number;
}): Promise<{ scored: number }> => {
  let scored = 0;
  let searchAfter: Array<string | number> | undefined;
  const signals: InboundSignals = { byKey: new Map(), byId: new Map() };
  const queriedKeys = new Set<string>();
  const queriedIds = new Set<string>();

  for (;;) {
    const page = await esClient.search<InstanceDoc>({
      index: INSTANCES_INDEX,
      size: PAGE_SIZE,
      query: { bool: { must_not: [{ term: { status: 'removed' } }] } },
      sort: [{ id: 'asc' }],
      ...(searchAfter ? { search_after: searchAfter } : {}),
    });
    const hits = page.hits.hits.filter((hit) => hit._source !== undefined);
    if (hits.length === 0) break;
    searchAfter = page.hits.hits[page.hits.hits.length - 1].sort as Array<string | number>;

    const instances = hits.map((hit) => ({
      id: hit._id as string,
      doc: hit._source as InstanceDoc,
    }));
    const realHosts = instances
      .map(({ doc }) => doc.host)
      .filter((host) => !isPolicyHostKey(hostKeyOf(host)));
    // Log host names are matched exactly, so query both the reported spelling and the key.
    const names = new Set<string>();
    const ids = new Set<string>();
    for (const host of realHosts) {
      const key = hostKeyOf(host);
      if (!queriedKeys.has(key)) {
        queriedKeys.add(key);
        names.add(key);
        if (host.name) names.add(host.name);
      }
      if (host.id && !queriedIds.has(host.id)) {
        queriedIds.add(host.id);
        ids.add(host.id);
      }
    }
    const catalog = await loadCatalog(
      esClient,
      Array.from(new Set(instances.map((i) => i.doc.software_id)))
    );

    try {
      const found = await queryInboundSignals({
        esClient,
        names: [...names],
        ids: [...ids],
        lookbackDays,
      });
      found.byKey.forEach((signal, key) => addSignal(signals.byKey, key, signal));
      found.byId.forEach((signal, id) => signals.byId.set(id, signal));
    } catch (error) {
      logger.warn(`Unable to aggregate inbound traffic signals: ${(error as Error).message}`);
    }

    const operations: Array<Record<string, unknown>> = [];
    for (const { id, doc } of instances) {
      const entry = catalog.get(doc.software_id);
      const isEdge =
        entry !== undefined &&
        (entry.category === 'appliance' || isEdgeProduct(entry.vendor, entry.product));
      const key = hostKeyOf(doc.host);
      const inbound = isPolicyHostKey(key)
        ? undefined
        : signals.byKey.get(key) ?? (doc.host.id ? signals.byId.get(doc.host.id) : undefined);
      const exposure = combineExposure({
        isEdge,
        edgeDetail: entry
          ? `${entry.vendor}/${entry.product} is an edge or internet-facing device`
          : undefined,
        distinctPublicSources: inbound?.distinct ?? 0,
        sampleSources: inbound?.samples,
        lookbackDays,
        existingEvidence: doc.exposure?.evidence,
      });
      operations.push({ update: { _index: INSTANCES_INDEX, _id: id } }, { doc: { exposure } });
      scored++;
    }

    try {
      const bulk = await esClient.bulk({ operations, refresh: false });
      if (bulk.errors) logger.warn('Some instance exposure updates failed');
    } catch (error) {
      logger.warn(`Bulk exposure update failed: ${(error as Error).message}`);
    }

    if (hits.length < PAGE_SIZE) break;
  }
  return { scored };
};
