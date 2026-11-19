/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Expected outcomes of the DE cases (`discover-endpoint`), derived from the generator's documents
 * in `logs/generate_endpoint.ts`. Instance ids come from the plugin's `buildInstanceId` through
 * `ids.ts`; nothing here is a hard-coded hash.
 */

import type { ExpectedEvent, ExpectedInstance } from '../assertions';
import { instanceIdFor, parseCatalogId } from '../ids';

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;

/** `A`: the phase A run (DE-1). `B`: runs after phase B is written (DE-3 and later). */
export type DeStage = 'A' | 'B';

/** The `discover-endpoint` run must start within this age of T0 so the 24 h window keeps its margin. */
export const DE_MAX_T0_AGE_MS = 55 * MINUTE_MS;

/** One ES|QL row the workflow reads, with the instance the ingest step derives from it. */
export interface ExpectedEndpointCandidate {
  /** Plan doc ids that produce this ES|QL row. */
  readonly docIds: readonly string[];
  readonly host_id: string;
  readonly host_name: string;
  /** Raw company, or the code-signature subject when the company is missing. */
  readonly vendor: string;
  readonly name: string;
  readonly version: string;
  /** Offset of the latest sighting from T0 (`observed_at` = T0 - offset). */
  readonly observedOffsetMs: number;
  readonly hostKey: string;
  readonly catalogId: string;
}

export const FIREFOX_HOST_KEY = 'synth-win-01';
export const FIREFOX_FROM_CATALOG_ID = 'mozilla:firefox:124.0.1';
export const FIREFOX_TO_CATALOG_ID = 'mozilla:firefox:125.0.1';
export const SIGNED_HOST_KEY = 'synth-win-02';
export const HOST_NAME_ONLY_HOST_KEY = 'synth-win-03';
export const HOST_NAME_ONLY_CATALOG_ID = 'synth-viewer:synth-viewer:2.1';
export const NOEXE_HOST_KEY = 'synth-win-04';
export const DUAL_HOST_KEY = 'synth-win-07';
export const DUAL_CATALOG_ID = 'synth-dual:synth-dual:3.1';
export const BOTH_HOST_KEY = 'synth-win-08';
export const BOTH_CATALOG_ID = 'synth-both:synth-both:5.0';

/** Hosts whose documents the workflow must leave out, and why. */
export const ABSENT_HOST_KEYS = {
  /** The only candidate document is under `C:\Windows\` or has no file version. */
  excluded: ['synth-win-05'],
  outsideWindow: ['synth-win-06'],
} as const;

const row = (
  docIds: readonly string[],
  hostKey: string,
  vendor: string,
  name: string,
  version: string,
  catalogId: string,
  observedOffsetMs: number,
  hostId = `${hostKey}-id`
): ExpectedEndpointCandidate => ({
  docIds,
  host_id: hostId,
  host_name: hostKey,
  vendor,
  name,
  version,
  observedOffsetMs,
  hostKey,
  catalogId,
});

/** ES|QL rows of the phase A run, in the generator's table order. */
export const EXPECTED_PHASE_A_ROWS: readonly ExpectedEndpointCandidate[] = [
  row(
    ['E1-01', 'E1-02', 'E1-03'],
    FIREFOX_HOST_KEY,
    'Mozilla Corporation',
    'Firefox',
    '124.0.1',
    FIREFOX_FROM_CATALOG_ID,
    HOUR_MS
  ),
  row(
    ['E2'],
    SIGNED_HOST_KEY,
    'Synth-Signer Inc',
    'Synth-Signed',
    '1.0',
    'synth-signer:synth-signed:1.0',
    2 * HOUR_MS
  ),
  // Host name only: the workflow falls back to host.name for host_id.
  row(
    ['E3'],
    HOST_NAME_ONLY_HOST_KEY,
    'Synth-Viewer Corp',
    'Synth-Viewer',
    '2.1',
    HOST_NAME_ONLY_CATALOG_ID,
    3 * HOUR_MS,
    'synth-win-03'
  ),
  row(
    ['E4-NOEXE'],
    NOEXE_HOST_KEY,
    'Synth-NoExe Ltd',
    'Synth-NoExe',
    '1.5',
    'synth-noexe:synth-noexe:1.5',
    90 * MINUTE_MS
  ),
  row(
    ['E7-1'],
    DUAL_HOST_KEY,
    'Synth-Dual Ltd',
    'Synth-Dual',
    '3.0',
    'synth-dual:synth-dual:3.0',
    5 * HOUR_MS
  ),
  row(['E7-2'], DUAL_HOST_KEY, 'Synth-Dual Ltd', 'Synth-Dual', '3.1', DUAL_CATALOG_ID, 2 * HOUR_MS),
  row(
    ['E8'],
    BOTH_HOST_KEY,
    'Synth-Both Inc',
    'Synth-Both',
    '5.0',
    BOTH_CATALOG_ID,
    90 * MINUTE_MS
  ),
];

export const EXPECTED_PHASE_B_ROW: ExpectedEndpointCandidate = row(
  ['E9'],
  FIREFOX_HOST_KEY,
  'Mozilla Corporation',
  'Firefox',
  '125.0.1',
  FIREFOX_TO_CATALOG_ID,
  30 * MINUTE_MS
);

/** The ES|QL rows a run reads at the given stage. */
export const rowsAt = (stage: DeStage): readonly ExpectedEndpointCandidate[] =>
  stage === 'A' ? EXPECTED_PHASE_A_ROWS : [...EXPECTED_PHASE_A_ROWS, EXPECTED_PHASE_B_ROW];

const versionOfCatalogId = (catalogId: string): string => parseCatalogId(catalogId).version;

const instanceKey = ({
  hostKey,
  catalogId,
}: Pick<ExpectedEndpointCandidate, 'hostKey' | 'catalogId'>): string =>
  instanceIdFor({ hostKey, catalogId });

/**
 * Mirrors the ingest dedupe: one row per instance id and the latest observation wins. A smaller
 * offset from T0 is a later observation.
 */
export const dedupeRows = (
  rows: readonly ExpectedEndpointCandidate[]
): Map<string, ExpectedEndpointCandidate> => {
  const byId = new Map<string, ExpectedEndpointCandidate>();
  for (const candidate of rows) {
    const id = instanceKey({
      hostKey: candidate.hostKey,
      // The instance id keys on vendor and product, so the two Synth-Dual versions collapse.
      catalogId: candidate.catalogId,
    });
    const current = byId.get(id);
    if (!current || candidate.observedOffsetMs < current.observedOffsetMs) byId.set(id, candidate);
  }
  return byId;
};

const isFlip = ({ hostKey }: ExpectedEndpointCandidate): boolean => hostKey === FIREFOX_HOST_KEY;

/**
 * Expected instances after the run at `stage`. The run that flips a version leaves the instance
 * `patched`; the next run that sees it unchanged returns it to `active` and keeps the link and
 * history (pass `afterFlipRun`). `osqueryMerged` is true after DE-6 adds an Osquery source.
 */
export const expectedInstancesAt = (
  stage: DeStage,
  {
    afterFlipRun = false,
    osqueryMerged = false,
  }: { afterFlipRun?: boolean; osqueryMerged?: boolean } = {}
): ExpectedInstance[] =>
  [...dedupeRows(rowsAt(stage)).values()].map((candidate) => {
    const flipped = stage === 'B' && isFlip(candidate);
    const both = osqueryMerged && candidate.hostKey === BOTH_HOST_KEY;
    return {
      hostKey: candidate.hostKey,
      catalogId: candidate.catalogId,
      status: flipped && !afterFlipRun ? 'patched' : 'active',
      sources: both ? ['endpoint', 'osquery'] : ['endpoint'],
      hostName: candidate.host_name,
      ...(both ? {} : { hostId: candidate.host_id }),
      versions: flipped
        ? [versionOfCatalogId(FIREFOX_FROM_CATALOG_ID), versionOfCatalogId(candidate.catalogId)]
        : [versionOfCatalogId(candidate.catalogId)],
      ...(flipped ? { previousSoftwareId: FIREFOX_FROM_CATALOG_ID } : {}),
    };
  });

/** Host keys of every instance the endpoint events create, in table order. */
export const deHostKeys = (stage: DeStage): string[] =>
  expectedInstancesAt(stage).map(({ hostKey }) => hostKey);

const isoAt = (t0: Date, offsetMs: number): string =>
  new Date(t0.getTime() - offsetMs).toISOString();

/** Events: a `first_seen` per instance, plus `version_changed` at stage B. */
export const expectedEventsAt = (stage: DeStage, t0: Date): ExpectedEvent[] => {
  const firstSeen = [...dedupeRows(EXPECTED_PHASE_A_ROWS).values()].map(
    (candidate): ExpectedEvent => ({
      type: 'first_seen',
      '@timestamp': isoAt(t0, candidate.observedOffsetMs),
      instance_id: instanceKey(candidate),
      host: { key: candidate.hostKey },
      source: 'endpoint',
      software_id: candidate.catalogId,
      to_version: versionOfCatalogId(candidate.catalogId),
    })
  );
  if (stage === 'A') return firstSeen;
  return [
    ...firstSeen,
    {
      type: 'version_changed',
      '@timestamp': isoAt(t0, EXPECTED_PHASE_B_ROW.observedOffsetMs),
      instance_id: instanceKey(EXPECTED_PHASE_B_ROW),
      host: { key: FIREFOX_HOST_KEY },
      source: 'endpoint',
      software_id: FIREFOX_TO_CATALOG_ID,
      previous_software_id: FIREFOX_FROM_CATALOG_ID,
      from_version: versionOfCatalogId(FIREFOX_FROM_CATALOG_ID),
      to_version: versionOfCatalogId(FIREFOX_TO_CATALOG_ID),
    },
  ];
};

/** First and last sighting (ISO) an instance carries after the run at `stage`. */
export const expectedSightingTimes = (
  stage: DeStage,
  t0: Date
): Array<{ hostKey: string; catalogId: string; firstSeen: string; lastSeen: string }> =>
  [...dedupeRows(rowsAt(stage)).values()].map((candidate) => {
    const lastSeen = isoAt(t0, candidate.observedOffsetMs);
    const flipped = stage === 'B' && isFlip(candidate);
    const firstSeen = flipped
      ? isoAt(t0, EXPECTED_PHASE_A_ROWS.find(isFlip)?.observedOffsetMs ?? 0)
      : lastSeen;
    return { hostKey: candidate.hostKey, catalogId: candidate.catalogId, firstSeen, lastSeen };
  });

/** Catalog ids the instances at `stage` use (the older Synth-Dual version is never created). */
export const expectedCatalogIdsAt = (stage: DeStage): string[] => [
  ...new Set([...dedupeRows(rowsAt(stage)).values()].map(({ catalogId }) => catalogId)),
];

/** Catalog ids the harness may create (cleanup deletes them), including the superseded ones. */
export const ALL_DE_CATALOG_IDS: readonly string[] = [
  ...new Set([...rowsAt('B').map(({ catalogId }) => catalogId)]),
];

/** Ingest outputs. */
export const DE_INGEST = {
  baseline: { created: 6 },
  versionFlip: { unchanged: 5, patched: 1 },
  idempotent: { unchanged: 6 },
  /** DE-4: the Synth-Viewer documents are gone from the window, the other five are unchanged. */
  viewerGone: { unchanged: 5 },
} as const;

/** The Osquery row DE-6 ingests for the host the endpoint events already created. */
export const OSQUERY_MERGE_CANDIDATE = {
  host_id: 'synth-agent-win08',
  host_name: BOTH_HOST_KEY,
  name: 'Synth-Both',
  vendor: 'Synth-Both Inc',
  version: '5.0',
  category: 'application',
} as const;
