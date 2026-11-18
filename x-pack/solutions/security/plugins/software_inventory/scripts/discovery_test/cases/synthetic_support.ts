/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Support shared by the DL and SE case modules: write checks scoped to synthetic hosts, a
 * freshness guard for the synthetic logs, and an events check that tolerates timestamp spelling.
 */

import { INSTANCES_INDEX, EVENTS_INDEX } from '../../../common/constants';
import type { InventoryEvent } from '../../../common/history';
import type { InstanceDoc } from '../../../common/types';
import type { ExpectedEvent, LayerResult } from '../assertions';
import { diffEvents, findEvents, layerResult } from '../assertions';
import type { EsClient } from '../clients';
import { syntheticHostKeyQuery } from '../cleanup';
import { instanceIdFor } from '../ids';
import type { CaseResult } from './types';
import { blockedResult } from './types';

/** Blocks a case when the synthetic logs are too old for the window its workflow reads. */
export const blockWhenT0TooOld = (
  t0: Date,
  maxAgeMs: number,
  { now = Date.now(), hint }: { now?: number; hint: string }
): CaseResult | undefined => {
  const ageMs = now - t0.getTime();
  if (ageMs <= maxAgeMs) return undefined;
  return blockedResult(
    `T0 ${t0.toISOString()} is ${Math.round(ageMs / 60_000)} min old (limit ${Math.round(
      maxAgeMs / 60_000
    )} min): ${hint}. Regenerate the logs with a fresh --t0 (cleanup, then logs --phase A).`
  );
};

/**
 * Fails on instance or event writes since `since` on a synthetic host key that the case does not
 * expect. Unlike `checkNoUnexpectedWrites` it ignores demo documents, because `score-exposure`
 * legitimately rewrites them (the regression step restores the demo).
 */
export const checkSyntheticWrites = async (
  es: EsClient,
  { since, allowedHostKeys }: { since: string; allowedHostKeys: readonly string[] }
): Promise<LayerResult> => {
  const query = {
    bool: {
      filter: [{ range: { '@timestamp': { gte: since } } }, syntheticHostKeyQuery()],
      must_not: [{ terms: { 'host.key': [...allowedHostKeys] } }],
    },
  };
  const [instances, events] = await Promise.all([
    es.count(INSTANCES_INDEX, query),
    es.count(EVENTS_INDEX, query),
  ]);
  const diffs = [
    ...(instances > 0
      ? [`${instances} synthetic instance(s) written outside the case's hosts`]
      : []),
    ...(events > 0 ? [`${events} synthetic event(s) written outside the case's hosts`] : []),
  ];
  return layerResult('inventory', diffs, 2, {
    unexpectedSyntheticInstances: instances,
    unexpectedSyntheticEvents: events,
  });
};

const normalizeIso = (value: string): string => {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? value : new Date(parsed).toISOString();
};

/**
 * Compares the exact set of events on `hostKeys` since `since` with `expected`. Timestamps compare
 * as instants, so `...:00Z` and `...:00.000Z` are equal.
 */
export const checkEventSet = async (
  es: EsClient,
  args: {
    hostKeys: readonly string[];
    since: string;
    expected: readonly ExpectedEvent[];
    types?: readonly string[];
  }
): Promise<LayerResult> => {
  const actual: InventoryEvent[] = (await findEvents(es, args)).map((event) => ({
    ...event,
    '@timestamp': normalizeIso(event['@timestamp']),
  }));
  return layerResult(
    'inventory',
    diffEvents(args.expected, actual),
    Math.max(1, args.expected.length),
    { events: actual.map((event) => `${event.type}:${event.host.key}:${event.software_id}`) }
  );
};

/** Instance documents by deterministic id; `undefined` where missing. */
export const fetchInstanceDocs = async (
  es: EsClient,
  items: ReadonlyArray<{ hostKey: string; catalogId: string; installPath?: string }>
): Promise<Array<InstanceDoc | undefined>> => {
  if (items.length === 0) return [];
  const { docs } = await es.mget<InstanceDoc>(
    INSTANCES_INDEX,
    items.map((item) => instanceIdFor(item))
  );
  return items.map((_, index) => (docs[index]?.found ? docs[index]._source : undefined));
};

/** Every non-removed instance on one host key. */
export const findHostInstances = async (es: EsClient, hostKey: string): Promise<InstanceDoc[]> => {
  const response = await es.search<InstanceDoc>(INSTANCES_INDEX, {
    size: 1000,
    query: {
      bool: {
        filter: [{ term: { 'host.key': hostKey } }],
        must_not: [{ term: { status: 'removed' } }],
      },
    },
  });
  return response.hits.hits.flatMap((hit) => (hit._source ? [hit._source] : []));
};
