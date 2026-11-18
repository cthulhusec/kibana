/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { InventoryEvent } from '../../../common/history';
import type { CatalogEntry, DiscoverySource, InstanceDoc } from '../../../common/types';
import type { PlannedInstance } from './plan_instance';

/** Catalog fields needed to record vulnerability posture on a `version_changed` event. */
export type PostureEntry = Pick<
  CatalogEntry,
  'cve_count' | 'max_cvss' | 'known_exploited' | 'cve_checked_at'
>;

/** Minimal instance fields needed to emit removal and stale events. */
export interface EventInstance {
  id: string;
  host: { key: string; id?: string; name?: string };
  software_id: string;
  sources?: DiscoverySource[];
}

const eventHost = ({ key, id, name }: EventInstance['host']): InventoryEvent['host'] => ({
  key,
  ...(id ? { id } : {}),
  ...(name ? { name } : {}),
});

/** Version part of a catalog id (`vendor:product:version`). */
export const versionOf = (softwareId: string): string | undefined =>
  softwareId.split(':').slice(2).join(':') || undefined;

/**
 * Posture of a catalog entry, or undefined when it is unknown: the entry is missing, or it was
 * never checked for CVEs (a freshly created entry reports `cve_count: 0` before enrichment).
 */
const posture = (
  entry: PostureEntry | undefined,
  side: 'before' | 'after'
): Partial<InventoryEvent> => {
  if (!entry?.cve_checked_at) return {};
  const knownExploited = entry.known_exploited === true;
  const { cve_count: cveCount, max_cvss: maxCvss } = entry;
  if (side === 'before') {
    return {
      cve_count_before: cveCount,
      ...(maxCvss !== undefined ? { max_cvss_before: maxCvss } : {}),
      known_exploited_before: knownExploited,
    };
  }
  return {
    cve_count_after: cveCount,
    ...(maxCvss !== undefined ? { max_cvss_after: maxCvss } : {}),
    known_exploited_after: knownExploited,
  };
};

const lastVersion = (doc: InstanceDoc): string | undefined =>
  doc.version_history?.[doc.version_history.length - 1]?.version ?? versionOf(doc.software_id);

/**
 * Pure: the events one planned sighting produces.
 * - `created` -> `first_seen`.
 * - `patched` -> `version_changed` with before/after posture from `catalog`.
 * - A removed or stale instance that returns to active or patched -> `revived` (before any
 *   `version_changed` of the same sighting).
 * Late, out-of-order sightings leave the status untouched and produce nothing.
 */
export const planSightingEvents = ({
  existing,
  planned,
  source,
  observedAt,
  catalog,
}: {
  existing: InstanceDoc | undefined;
  planned: PlannedInstance;
  source: DiscoverySource;
  observedAt: string;
  catalog: ReadonlyMap<string, PostureEntry>;
}): InventoryEvent[] => {
  const { doc, outcome } = planned;
  const base = {
    '@timestamp': observedAt,
    instance_id: doc.id,
    host: eventHost(doc.host),
    source,
    software_id: doc.software_id,
  };
  if (!existing || outcome === 'created') {
    return [{ ...base, type: 'first_seen', to_version: lastVersion(doc) }];
  }

  const events: InventoryEvent[] = [];
  const wasClosed = existing.status === 'removed' || existing.status === 'stale';
  if (wasClosed && (doc.status === 'active' || doc.status === 'patched')) {
    events.push({ ...base, type: 'revived' });
  }
  if (outcome === 'patched') {
    events.push({
      ...base,
      type: 'version_changed',
      previous_software_id: existing.software_id,
      ...(lastVersion(existing) !== undefined ? { from_version: lastVersion(existing) } : {}),
      ...(lastVersion(doc) !== undefined ? { to_version: lastVersion(doc) } : {}),
      ...posture(catalog.get(existing.software_id), 'before'),
      ...posture(catalog.get(doc.software_id), 'after'),
    });
  }
  return events;
};

/** Pure: one `removed` or `stale` event per instance. */
export const planStatusEvents = ({
  instances,
  type,
  source,
  at,
}: {
  instances: readonly EventInstance[];
  type: 'removed' | 'stale';
  /** Source that caused the transition; stale events use the instance's first source. */
  source?: DiscoverySource;
  at: string;
}): InventoryEvent[] =>
  instances.map((instance) => {
    const version = versionOf(instance.software_id);
    return {
      '@timestamp': at,
      instance_id: instance.id,
      host: eventHost(instance.host),
      type,
      source: source ?? instance.sources?.[0] ?? 'manual',
      software_id: instance.software_id,
      ...(version !== undefined ? { from_version: version } : {}),
    };
  });
