/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Support for the SE cases: exposure comparison, oracle queries (non-removed, stale-eligible,
 * rollup inputs), the harness writes that set up manual evidence and the stale fixture, and a
 * snapshot of the demo instances' inbound evidence (recorded by SE-1, reported by SE-9).
 *
 * `score-exposure` is not limited to synthetic hosts: a run rewrites demo exposure. Assertions
 * here only cover `synth-` hosts; the regression step restores the demo.
 */

import {
  CATALOG_INDEX,
  EVENTS_INDEX,
  INSTANCES_INDEX,
  ROLLUPS_INDEX,
} from '../../../common/constants';
import type { InstanceDoc } from '../../../common/types';
import type { DailyRollup } from '../../../common/history';
import type { LayerResult } from '../assertions';
import { layerResult } from '../assertions';
import { syntheticHostKeyQuery } from '../cleanup';
import type { EsClient } from '../clients';
import type {
  ExpectedEvidence,
  ExposureExpectation,
  RollupCatalogRow,
  RollupInstanceRow,
} from '../expected/se';
import {
  LOOKBACK_DAYS,
  MANUAL_CATALOG_ID,
  MANUAL_EVIDENCE,
  MANUAL_HOST_KEY,
  STALE_AFTER_DAYS,
  STALE_CATALOG_ID,
  STALE_HOST_KEY,
  staleLastSeen,
} from '../expected/se';
import { R1_MACOS_ROWS } from '../fixtures/osquery';
import { instanceIdFor } from '../ids';
import { fetchInstanceDocs, findHostInstances } from './synthetic_support';

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_ORACLE_DOCS = 10_000;
const NOT_REMOVED = { bool: { must_not: [{ term: { status: 'removed' } }] } };

type Evidence = InstanceDoc['exposure']['evidence'][number];

const diffEvidence = (label: string, expected: ExpectedEvidence, actual: Evidence): string[] => {
  const diffs: string[] = [];
  if (actual.signal !== expected.signal)
    diffs.push(`${label}: signal ${actual.signal} != ${expected.signal}`);
  if (actual.weight !== expected.weight)
    diffs.push(`${label}: weight ${actual.weight} != ${expected.weight}`);
  if (expected.detail !== undefined && actual.detail !== expected.detail) {
    diffs.push(`${label}: detail "${actual.detail}" != "${expected.detail}"`);
  }
  for (const part of expected.detailIncludes ?? []) {
    if (!actual.detail.includes(part))
      diffs.push(`${label}: detail lacks "${part}": ${actual.detail}`);
  }
  for (const part of expected.detailExcludes ?? []) {
    if (actual.detail.includes(part))
      diffs.push(`${label}: detail contains "${part}": ${actual.detail}`);
  }
  return diffs;
};

/** Pure: compares a stored `exposure` with its expectation (level, score, evidence list). */
export const diffExposure = (
  expected: ExposureExpectation,
  doc: InstanceDoc | undefined
): string[] => {
  const label = `${expected.hostKey}/${expected.catalogId}`;
  if (!doc) return [`${label}: missing`];
  const { exposure } = doc;
  const diffs: string[] = [];
  if (exposure.level !== expected.level)
    diffs.push(`${label}: level ${exposure.level} != ${expected.level}`);
  if (exposure.score !== expected.score)
    diffs.push(`${label}: score ${exposure.score} != ${expected.score}`);
  const evidence = exposure.evidence ?? [];
  if (evidence.length !== expected.evidence.length) {
    diffs.push(
      `${label}: expected ${expected.evidence.length} evidence item(s) ` +
        `[${expected.evidence.map(({ signal }) => signal).join(', ')}], got ` +
        `${evidence.length} [${evidence.map(({ signal }) => signal).join(', ')}]`
    );
    return diffs;
  }
  expected.evidence.forEach((item, index) => {
    diffs.push(...diffEvidence(`${label} evidence[${index}]`, item, evidence[index]));
  });
  return diffs;
};

export const checkExposure = async (
  es: EsClient,
  expectations: readonly ExposureExpectation[]
): Promise<LayerResult> => {
  const docs = await fetchInstanceDocs(es, expectations);
  return layerResult(
    'inventory',
    expectations.flatMap((item, index) => diffExposure(item, docs[index])),
    expectations.length
  );
};

/** SE-2: every non-removed instance on a host has no exposure at all. */
export const checkHostExposureNone = async (
  es: EsClient,
  hostKey: string
): Promise<LayerResult> => {
  const instances = await findHostInstances(es, hostKey);
  const diffs =
    instances.length === 0
      ? [`${hostKey}: no instance found`]
      : instances.flatMap(({ software_id: softwareId, exposure }) =>
          exposure.level === 'none' &&
          exposure.score === 0 &&
          (exposure.evidence ?? []).length === 0
            ? []
            : [
                `${hostKey}/${softwareId}: expected none, got ${exposure.level} score ${
                  exposure.score
                } evidence [${(exposure.evidence ?? []).map(({ signal }) => signal).join(', ')}]`,
              ]
        );
  return layerResult('inventory', diffs, Math.max(1, instances.length), {
    instancesChecked: instances.length,
  });
};

// -------------------------------------------------------------------------------------------------
// Oracle queries
// -------------------------------------------------------------------------------------------------

/** Instances `score` visits: every one that is not removed. */
export const countNonRemoved = (es: EsClient): Promise<number> =>
  es.count(INSTANCES_INDEX, NOT_REMOVED);

/** Instances `mark_stale` marks: active or patched, `last_seen` older than the cutoff. */
export const staleEligibleQuery = (now: Date) => ({
  bool: {
    filter: [
      { terms: { status: ['active', 'patched'] } },
      {
        range: {
          last_seen: { lt: new Date(now.getTime() - STALE_AFTER_DAYS * DAY_MS).toISOString() },
        },
      },
    ],
  },
});

export const countStaleEligible = (es: EsClient, now = new Date()): Promise<number> =>
  es.count(INSTANCES_INDEX, staleEligibleQuery(now));

export const countSyntheticStaleEligible = (es: EsClient, now = new Date()): Promise<number> =>
  es.count(INSTANCES_INDEX, {
    bool: { filter: [staleEligibleQuery(now), syntheticHostKeyQuery()] },
  });

export const todayUtc = (now = new Date()): string => now.toISOString().slice(0, 10);

/** The numbers every `score-exposure` run is asserted against, read just before the run. */
export interface ScoreOracle {
  readonly nonRemoved: number;
  readonly staleEligible: number;
}

export const readScoreOracle = async (es: EsClient): Promise<ScoreOracle> => ({
  nonRemoved: await countNonRemoved(es),
  staleEligible: await countStaleEligible(es),
});

export interface RollupInputs {
  readonly instances: RollupInstanceRow[];
  readonly catalog: RollupCatalogRow[];
  readonly events: { first_seen: number; version_changed: number; removed: number };
  readonly truncated: boolean;
}

/** Reads what the rollup aggregates: active and patched instances, the catalog, the day's events. */
export const readRollupInputs = async (
  es: EsClient,
  { dayStart, dayEnd }: { dayStart: string; dayEnd: string }
): Promise<RollupInputs> => {
  const instanceResponse = await es.search<InstanceDoc>(INSTANCES_INDEX, {
    size: MAX_ORACLE_DOCS,
    track_total_hits: true,
    query: { terms: { status: ['active', 'patched'] } },
    _source: ['software_id', 'exposure.level'],
  });
  const catalogResponse = await es.search<RollupCatalogRow>(CATALOG_INDEX, {
    size: MAX_ORACLE_DOCS,
    track_total_hits: true,
    query: { match_all: {} },
    _source: ['id', 'category', 'cve_count', 'max_cvss', 'known_exploited'],
  });
  const eventCount = (type: string) =>
    es.count(EVENTS_INDEX, {
      bool: {
        filter: [{ range: { '@timestamp': { gte: dayStart, lt: dayEnd } } }, { term: { type } }],
      },
    });
  const total = (response: { hits: { total?: { value: number }; hits: readonly unknown[] } }) =>
    response.hits.total?.value ?? response.hits.hits.length;
  return {
    instances: instanceResponse.hits.hits.flatMap((hit) =>
      hit._source
        ? [
            {
              software_id: hit._source.software_id,
              exposureLevel: hit._source.exposure?.level ?? 'none',
            },
          ]
        : []
    ),
    catalog: catalogResponse.hits.hits.flatMap((hit) => (hit._source ? [hit._source] : [])),
    events: {
      first_seen: await eventCount('first_seen'),
      version_changed: await eventCount('version_changed'),
      removed: await eventCount('removed'),
    },
    truncated:
      total(instanceResponse) > MAX_ORACLE_DOCS || total(catalogResponse) > MAX_ORACLE_DOCS,
  };
};

export interface RollupDocResponse {
  readonly found: boolean;
  readonly _version?: number;
  readonly _source?: DailyRollup;
}

export const getRollupDoc = async (es: EsClient, date: string): Promise<RollupDocResponse> => {
  const { status, body } = await es.request<RollupDocResponse>(
    'GET',
    `/${ROLLUPS_INDEX}/_doc/${date}`,
    { allowStatuses: [404] }
  );
  return status === 404 ? { found: false } : body;
};

export const countRollupDocsForDay = (
  es: EsClient,
  { dayStart, dayEnd }: { dayStart: string; dayEnd: string }
): Promise<number> =>
  es.count(ROLLUPS_INDEX, { range: { '@timestamp': { gte: dayStart, lt: dayEnd } } });

// -------------------------------------------------------------------------------------------------
// Harness writes (synthetic documents only)
// -------------------------------------------------------------------------------------------------

const updateInstance = async (es: EsClient, id: string, doc: object): Promise<void> => {
  await es.request('POST', `/${INSTANCES_INDEX}/_update/${id}`, {
    body: { doc },
    query: { refresh: 'true' },
  });
};

/** Sets the manual evidence SE-6 expects on the `synth-web-02` nginx instance. */
export const setManualEvidence = async (es: EsClient): Promise<void> => {
  await updateInstance(
    es,
    instanceIdFor({ hostKey: MANUAL_HOST_KEY, catalogId: MANUAL_CATALOG_ID }),
    {
      exposure: {
        level: 'low',
        score: MANUAL_EVIDENCE.weight,
        evidence: [{ ...MANUAL_EVIDENCE }],
      },
    }
  );
};

export const staleInstanceRef = (): {
  hostKey: string;
  catalogId: string;
  installPath?: string;
} => ({
  hostKey: STALE_HOST_KEY,
  catalogId: STALE_CATALOG_ID,
  installPath: R1_MACOS_ROWS.find(({ catalogId }) => catalogId === STALE_CATALOG_ID)?.installPath,
});

/** SE-10: ages the synthetic Slack instance past the stale cutoff (and makes it `active`). */
export const makeSlackStale = async (es: EsClient, t0: Date): Promise<void> => {
  await updateInstance(es, instanceIdFor(staleInstanceRef()), {
    status: 'active',
    last_seen: staleLastSeen(t0),
  });
};

// -------------------------------------------------------------------------------------------------
// Demo snapshot (recorded, never asserted)
// -------------------------------------------------------------------------------------------------

/** Demo instances (non-synthetic) that carry `inbound_public_ip` evidence, with their level. */
export const snapshotDemoInbound = async (es: EsClient): Promise<Record<string, string>> => {
  const response = await es.search<InstanceDoc>(INSTANCES_INDEX, {
    size: 1000,
    query: {
      bool: {
        filter: [{ term: { 'exposure.evidence.signal': 'inbound_public_ip' } }],
        must_not: [syntheticHostKeyQuery()],
      },
    },
    _source: ['id', 'exposure.level'],
  });
  return Object.fromEntries(
    response.hits.hits.map((hit) => [hit._id, hit._source?.exposure?.level ?? 'none'])
  );
};

/** Current exposure level of the given instance ids (`missing` when absent). */
export const currentLevels = async (
  es: EsClient,
  ids: readonly string[]
): Promise<Record<string, string>> => {
  if (ids.length === 0) return {};
  const { docs } = await es.mget<InstanceDoc>(INSTANCES_INDEX, ids);
  return Object.fromEntries(
    docs.map((doc, index) => [
      ids[index],
      doc.found ? doc._source?.exposure?.level ?? 'none' : 'missing',
    ])
  );
};

/** Step input shared by every `score-exposure` run assertion. */
export const SCORE_STEP_INPUT = {
  score: { lookback_days: LOOKBACK_DAYS },
  mark_stale: { stale_after_days: STALE_AFTER_DAYS },
} as const;
