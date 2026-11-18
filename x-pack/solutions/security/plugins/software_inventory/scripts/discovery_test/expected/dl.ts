/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Expected outcomes of the DL cases (`discover-logs`), derived from the generator's candidate
 * tables in `logs/generate_logs.ts`. Instance ids come from the plugin's `buildInstanceId` through
 * `ids.ts`; nothing here is a hard-coded hash.
 */

import type { ExpectedEvent, ExpectedInstance } from '../assertions';
import { instanceIdFor, parseCatalogId } from '../ids';
import type { ExpectedLogCandidate } from '../logs/generate_logs';
import {
  EXPECTED_ABSENT_HOST_KEYS,
  EXPECTED_PHASE_A_CANDIDATES,
  EXPECTED_PHASE_B_CANDIDATE,
} from '../logs/generate_logs';

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;

/** `A`: the phase A run (DL-1). `B`: runs after phase B is written (DL-7 and later). */
export type DlStage = 'A' | 'B';

/** The `discover-logs` run must start within this age of T0 so the 24 h window keeps its margin. */
export const DL_MAX_T0_AGE_MS = 55 * MINUTE_MS;

/** Host key of the one instance the Osquery baseline (DO-1) created before the logs run. */
export const SHARED_HOST_KEY = 'synth-lin-01';
export const SHARED_CATALOG_ID = 'f5:nginx:1.18.0';
export const FLIP_HOST_KEY = 'synth-web-02';
export const FLIP_FROM_CATALOG_ID = 'f5:nginx:1.25.2';
export const FLIP_TO_CATALOG_ID = EXPECTED_PHASE_B_CANDIDATE.catalogId;
export const CHECKOUT_HOST_KEY = 'synth-web-01';
export const CHECKOUT_CATALOG_ID = 'synth-checkout:synth-checkout:2.4.0';

/** The ES|QL rows (one per candidate the workflow builds) a run reads at the given stage. */
export const candidatesAt = (stage: DlStage): readonly ExpectedLogCandidate[] =>
  stage === 'A'
    ? EXPECTED_PHASE_A_CANDIDATES
    : [...EXPECTED_PHASE_A_CANDIDATES, EXPECTED_PHASE_B_CANDIDATE];

export const appliancesAt = (stage: DlStage): readonly ExpectedLogCandidate[] =>
  candidatesAt(stage).filter(({ category }) => category === 'appliance');

export const servicesAt = (stage: DlStage): readonly ExpectedLogCandidate[] =>
  candidatesAt(stage).filter(({ category }) => category === 'application');

const compareVersions = (a: string, b: string): number =>
  a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });

const instanceKey = ({ hostKey, catalogId }: Pick<ExpectedLogCandidate, 'hostKey' | 'catalogId'>) =>
  instanceIdFor({ hostKey, catalogId });

/**
 * Mirrors the ingest dedupe: one row per instance id, the latest observation wins, and the highest
 * version wins a tie. A smaller offset from T0 is a later observation.
 */
export const dedupeRows = (
  rows: readonly ExpectedLogCandidate[]
): Map<string, ExpectedLogCandidate> => {
  const byId = new Map<string, ExpectedLogCandidate>();
  for (const row of rows) {
    const id = instanceKey(row);
    const current = byId.get(id);
    const delta = (current?.observedOffsetMs ?? Infinity) - row.observedOffsetMs;
    const preferred =
      !current || delta > 0 || (delta === 0 && compareVersions(row.version, current.version) > 0);
    if (preferred) byId.set(id, row);
  }
  return byId;
};

/** Distinct instances at a stage; 10 for both stages (phase B flips one instance's version). */
export const instanceCountAt = (stage: DlStage): number => dedupeRows(candidatesAt(stage)).size;

const isSharedWithOsquery = ({ hostKey, catalogId }: ExpectedLogCandidate): boolean =>
  hostKey === SHARED_HOST_KEY && catalogId === SHARED_CATALOG_ID;

const isFlip = ({ hostKey }: ExpectedLogCandidate): boolean => hostKey === FLIP_HOST_KEY;

const versionOfCatalogId = (catalogId: string): string => parseCatalogId(catalogId).version;

/**
 * Expected instances after the run at `stage`, for `checkInstances`. The run that flips a version
 * leaves the instance `patched`; the next run that sees it unchanged returns it to `active` and
 * keeps the previous-version link and the history. Pass `afterFlipRun` for runs after the flip.
 */
export const expectedInstancesAt = (
  stage: DlStage,
  { afterFlipRun = false }: { afterFlipRun?: boolean } = {}
): ExpectedInstance[] =>
  [...dedupeRows(candidatesAt(stage)).values()].map((row) => {
    const shared = isSharedWithOsquery(row);
    const flipped = stage === 'B' && isFlip(row);
    return {
      hostKey: row.hostKey,
      catalogId: row.catalogId,
      status: flipped && !afterFlipRun ? 'patched' : 'active',
      sources: shared ? ['osquery', 'logs'] : ['logs'],
      hostName: row.host_name ?? null,
      // The Osquery run reports its own agent id and a different version spelling.
      ...(shared ? {} : { hostId: row.host_id, versions: [versionOfCatalogId(row.catalogId)] }),
      ...(flipped
        ? {
            versions: [versionOfCatalogId(FLIP_FROM_CATALOG_ID), versionOfCatalogId(row.catalogId)],
            previousSoftwareId: FLIP_FROM_CATALOG_ID,
          }
        : {}),
    };
  });

/** Host keys of every instance the logs create or touch, in table order. */
export const dlHostKeys = (stage: DlStage): string[] =>
  expectedInstancesAt(stage).map(({ hostKey }) => hostKey);

/** Host keys whose events come only from the logs (the shared instance has Osquery events too). */
export const dlEventHostKeys = (stage: DlStage): string[] =>
  dlHostKeys(stage).filter((hostKey) => hostKey !== SHARED_HOST_KEY);

const isoAt = (t0: Date, offsetMs: number): string =>
  new Date(t0.getTime() - offsetMs).toISOString();

/** Events on `dlEventHostKeys`: a `first_seen` per instance, plus `version_changed` at stage B. */
export const expectedEventsAt = (stage: DlStage, t0: Date): ExpectedEvent[] => {
  const firstSeen = [...dedupeRows(candidatesAt('A')).values()]
    .filter((row) => !isSharedWithOsquery(row))
    .map(
      (row): ExpectedEvent => ({
        type: 'first_seen',
        '@timestamp': isoAt(t0, row.observedOffsetMs),
        instance_id: instanceKey(row),
        host: { key: row.hostKey },
        source: 'logs',
        software_id: row.catalogId,
        to_version: versionOfCatalogId(row.catalogId),
      })
    );
  if (stage === 'A') return firstSeen;
  return [
    ...firstSeen,
    {
      type: 'version_changed',
      '@timestamp': isoAt(t0, EXPECTED_PHASE_B_CANDIDATE.observedOffsetMs),
      instance_id: instanceKey(EXPECTED_PHASE_B_CANDIDATE),
      host: { key: FLIP_HOST_KEY },
      source: 'logs',
      software_id: FLIP_TO_CATALOG_ID,
      previous_software_id: FLIP_FROM_CATALOG_ID,
      from_version: versionOfCatalogId(FLIP_FROM_CATALOG_ID),
      to_version: versionOfCatalogId(FLIP_TO_CATALOG_ID),
    },
  ];
};

/** First and last sighting (ISO) an instance carries after the run at `stage`. */
export const expectedSightingTimes = (
  stage: DlStage,
  t0: Date
): Array<{ hostKey: string; catalogId: string; firstSeen: string; lastSeen: string }> =>
  [...dedupeRows(candidatesAt(stage)).values()].map((row) => {
    const lastSeen = isoAt(t0, row.observedOffsetMs);
    const flipped = stage === 'B' && isFlip(row);
    const firstSeen = flipped
      ? isoAt(t0, EXPECTED_PHASE_A_CANDIDATES.find(isFlip)?.observedOffsetMs ?? 0)
      : lastSeen;
    return { hostKey: row.hostKey, catalogId: row.catalogId, firstSeen, lastSeen };
  });

/**
 * Catalog entries a run creates or touches, with the category each ends up with. A catalog entry
 * keeps the category of whichever source created it first. DO-1 creates the shared nginx entry
 * from a Debian package row, so it stays `os_package` even though the logs describe it as an
 * `application`; every other entry is created by the logs themselves.
 */
export const expectedCatalogAt = (
  stage: DlStage
): ReadonlyArray<{ id: string; category: ExpectedLogCandidate['category'] | 'os_package' }> => {
  const seen = new Map<string, ExpectedLogCandidate['category'] | 'os_package'>();
  for (const { catalogId, category } of candidatesAt(stage)) {
    if (!seen.has(catalogId)) {
      seen.set(catalogId, catalogId === SHARED_CATALOG_ID ? 'os_package' : category);
    }
  }
  return [...seen.entries()].map(([id, category]) => ({ id, category }));
};

/** Ingest outputs. */
export const DL_INGEST = {
  baselineAfterR1: { created: 9, unchanged: 1 },
  versionFlip: { unchanged: 9, patched: 1 },
  idempotent: { unchanged: 10 },
  /** DL-9: only the four service instances are read. */
  servicesOnly: { unchanged: 4 },
  /** DL-10: ten unchanged instances plus the multi-valued appliance. */
  multiValued: { created: 1, unchanged: 10 },
} as const;

/** DL-10: the doc has `observer.ip: [192.0.2.78, 10.9.9.9]`; doc values sort, so `10.9.9.9` leads. */
export const MULTI_VALUED_EXPECTED_HOST_ID = '10.9.9.9';
export const MULTI_VALUED_OTHER_HOST_ID = '192.0.2.78';
export const MULTI_VALUED_CATALOG_ID = 'f5:big-ip:16.1.4';
export const MULTI_VALUED_OBSERVED_OFFSET_MS = HOUR_MS;

/** Host keys that must not have an instance after the phase A run, and why. */
export const ABSENT_KEYS_BY_REASON = {
  collector: ['synth-collector-01'],
  outsideWindow: ['synth-fw-03'],
  missingVersion: ['synth-fw-04', 'synth-web-03'],
  /** The logs key the shared instance by host name, never by the log host id. */
  hostIdNotAKey: ['synth-hostid-lin01'],
} as const;

export const ALL_ABSENT_HOST_KEYS: readonly string[] = [
  ...EXPECTED_ABSENT_HOST_KEYS,
  ...ABSENT_KEYS_BY_REASON.hostIdNotAKey,
];
