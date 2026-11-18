/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { buildCatalogId, normalizeToken } from '../../../common/normalize';
import type {
  CatalogEntry,
  DiscoverySource,
  InstanceDoc,
  SoftwareCategory,
  VersionHistoryItem,
} from '../../../common/types';
import { buildInstanceId } from '../../lib/instance_identity';
import type { NormalizedCandidate } from './normalize_candidate';

/** Oldest entries are dropped beyond this, so long-lived installs keep a bounded document. */
export const MAX_VERSION_HISTORY = 20;

export type SightingOutcome = 'created' | 'unchanged' | 'patched';

export interface PlannedInstance {
  doc: InstanceDoc;
  outcome: SightingOutcome;
}

export const instanceIdForCandidate = (candidate: NormalizedCandidate): string =>
  buildInstanceId({
    hostKey: candidate.host_key,
    vendor: candidate.vendor,
    product: candidate.product,
    installPath: candidate.install_path,
  });

export const catalogIdForCandidate = (candidate: NormalizedCandidate): string =>
  buildCatalogId(candidate.vendor, candidate.product, candidate.version);

export const buildCatalogEntry = (candidate: NormalizedCandidate, now: string): CatalogEntry => ({
  id: catalogIdForCandidate(candidate),
  vendor: normalizeToken(candidate.vendor),
  product: normalizeToken(candidate.product),
  version: candidate.version,
  display_name: candidate.display_name,
  category: candidate.category,
  cve_count: 0,
  known_exploited: false,
  cve_ids: [],
  '@timestamp': now,
});

const latest = (a: string, b: string): string => (Date.parse(a) >= Date.parse(b) ? a : b);
const earliest = (a: string, b: string): string => (Date.parse(a) <= Date.parse(b) ? a : b);

const unionSources = (
  existing: readonly DiscoverySource[],
  source: DiscoverySource
): DiscoverySource[] => (existing.includes(source) ? [...existing] : [...existing, source]);

/** Refreshes the last entry when the version is unchanged, else appends one. Sets `software_id`. */
const touchHistory = (
  history: readonly VersionHistoryItem[],
  version: string,
  softwareId: string,
  observedAt: string
): VersionHistoryItem[] => {
  const last = history[history.length - 1];
  if (last && last.version === version) {
    return [
      ...history.slice(0, -1),
      {
        ...last,
        software_id: softwareId,
        first_seen: earliest(last.first_seen, observedAt),
        last_seen: latest(last.last_seen, observedAt),
      },
    ];
  }
  return [
    ...history,
    { version, software_id: softwareId, first_seen: observedAt, last_seen: observedAt },
  ].slice(-MAX_VERSION_HISTORY);
};

/** Keeps the stored key and the first non-empty host id; the latest reported name wins. */
const mergeHost = (
  existing: InstanceDoc['host'],
  candidate: NormalizedCandidate
): InstanceDoc['host'] => ({
  ...existing,
  key: existing.key || candidate.host_key,
  id: existing.id || candidate.host_id,
  ...(candidate.host_name ? { name: candidate.host_name } : {}),
});

/**
 * Pure decision for one sighting of an instance.
 *
 * - No stored document: a new `active` instance.
 * - Same version: refresh `last_seen` and return to `active`, which also revives `removed`,
 *   `stale`, and last run's `patched` instances. `version_changed_at` is kept so the UI can still
 *   show a recent patch.
 * - Different version, observed at or after the stored `last_seen`: a patch. The previous version
 *   is kept in `previous_software_id`, and the new one is appended to `version_history`.
 * - Different version, observed before the stored `last_seen`: a late, out-of-order row. Only the
 *   sources are merged, so an old sighting never rolls a patch back.
 *
 * Exposure fields are always preserved; a separate step owns them.
 */
export const planInstance = ({
  existing,
  candidate,
  source,
  now,
}: {
  existing: InstanceDoc | undefined;
  candidate: NormalizedCandidate;
  source: DiscoverySource;
  now: string;
}): PlannedInstance => {
  const softwareId = catalogIdForCandidate(candidate);
  const observedAt = candidate.observed_at;

  if (!existing) {
    return {
      outcome: 'created',
      doc: {
        id: instanceIdForCandidate(candidate),
        host: {
          key: candidate.host_key,
          id: candidate.host_id,
          ...(candidate.host_name ? { name: candidate.host_name } : {}),
        },
        software_id: softwareId,
        version_history: [
          {
            version: candidate.version,
            software_id: softwareId,
            first_seen: observedAt,
            last_seen: observedAt,
          },
        ],
        ...(candidate.install_path ? { install_path: candidate.install_path } : {}),
        sources: [source],
        status: 'active',
        first_seen: observedAt,
        last_seen: observedAt,
        exposure: { level: 'none', score: 0, evidence: [] },
        '@timestamp': now,
      },
    };
  }

  const sources = unionSources(existing.sources ?? [], source);
  const history = existing.version_history ?? [];

  if (existing.software_id === softwareId) {
    return {
      outcome: 'unchanged',
      doc: {
        ...existing,
        host: mergeHost(existing.host, candidate),
        sources,
        status: 'active',
        version_history: touchHistory(history, candidate.version, softwareId, observedAt),
        first_seen: earliest(existing.first_seen, observedAt),
        last_seen: latest(existing.last_seen, observedAt),
        '@timestamp': now,
      },
    };
  }

  if (Date.parse(observedAt) < Date.parse(existing.last_seen)) {
    return {
      outcome: 'unchanged',
      doc: { ...existing, sources, '@timestamp': now },
    };
  }

  return {
    outcome: 'patched',
    doc: {
      ...existing,
      host: mergeHost(existing.host, candidate),
      software_id: softwareId,
      previous_software_id: existing.software_id,
      version_changed_at: observedAt,
      version_history: touchHistory(history, candidate.version, softwareId, observedAt),
      sources,
      status: 'patched',
      last_seen: observedAt,
      '@timestamp': now,
    },
  };
};

const compareVersions = (a: string, b: string): number =>
  a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });

/** True when `candidate` should replace `current`: a later observation, then a higher version. */
const isPreferred = (candidate: NormalizedCandidate, current: NormalizedCandidate): boolean => {
  const delta = Date.parse(candidate.observed_at) - Date.parse(current.observed_at);
  if (delta !== 0) {
    return delta > 0;
  }
  return compareVersions(candidate.version, current.version) > 0;
};

/**
 * Keeps one candidate per instance id: the latest observation, and the highest version when
 * observations tie, so the result does not depend on row order. A snapshot can list the same
 * install twice, for example from two package managers.
 */
export const dedupeCandidates = (
  candidates: readonly NormalizedCandidate[]
): Map<string, NormalizedCandidate> => {
  const byId = new Map<string, NormalizedCandidate>();
  for (const candidate of candidates) {
    const id = instanceIdForCandidate(candidate);
    const current = byId.get(id);
    if (!current || isPreferred(candidate, current)) {
      byId.set(id, candidate);
    }
  }
  return byId;
};

/** Minimal instance fields needed to decide removals. */
export interface RemovalCandidate {
  id: string;
  host: { key: string };
  software_id: string;
  sources: DiscoverySource[];
  status: InstanceDoc['status'];
}

/** Categories each host reported in one call, keyed by host key. */
export const reportedCategoriesByHost = (
  candidates: readonly NormalizedCandidate[]
): Map<string, Set<SoftwareCategory>> => {
  const byHost = new Map<string, Set<SoftwareCategory>>();
  for (const { host_key: hostKey, category } of candidates) {
    byHost.set(hostKey, (byHost.get(hostKey) ?? new Set()).add(category));
  }
  return byHost;
};

/**
 * Pure removal decision for a snapshot, scoped by host and category. Only hosts that reported in
 * this call are considered; a host that did not report is never touched. On a reporting host, an
 * instance becomes `removed` only when this source discovered it, it is absent from the call, and
 * its catalog category is one the host reported in this call. So an OS package snapshot never
 * removes dependencies, and the other way around. An instance whose category is unknown is kept.
 */
export const planRemovals = ({
  existing,
  reportedCategories,
  categoryBySoftwareId,
  seenInstanceIds,
  source,
}: {
  existing: readonly RemovalCandidate[];
  reportedCategories: ReadonlyMap<string, ReadonlySet<SoftwareCategory>>;
  categoryBySoftwareId: ReadonlyMap<string, SoftwareCategory>;
  seenInstanceIds: ReadonlySet<string>;
  source: DiscoverySource;
}): string[] =>
  existing
    .filter(({ id, host, software_id: softwareId, sources, status }) => {
      if (status === 'removed' || seenInstanceIds.has(id) || !(sources ?? []).includes(source)) {
        return false;
      }
      const category = categoryBySoftwareId.get(softwareId);
      return category !== undefined && reportedCategories.get(host.key)?.has(category) === true;
    })
    .map(({ id }) => id);

/** Pure stale decision: `active` or `patched`, and last seen before the cutoff. */
export const isStale = (
  { status, last_seen: lastSeen }: Pick<InstanceDoc, 'status' | 'last_seen'>,
  cutoff: string
): boolean =>
  (status === 'active' || status === 'patched') && Date.parse(lastSeen) < Date.parse(cutoff);

export const STALE_ELIGIBLE_STATUSES: ReadonlyArray<InstanceDoc['status']> = ['active', 'patched'];
