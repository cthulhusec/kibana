/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { normalizeToken } from '../../../common/normalize';
import type {
  HostTimelineItem,
  HostTimelineResponse,
  InventoryEvent,
  TimelineInterval,
  VulnerableWindow,
} from '../../../common/history';
import type { CatalogEntry, InstanceDoc, SoftwareCategory } from '../../../common/types';

/**
 * Pure history math. See the semantics in `common/history.ts`:
 * - an interval is `[start, end)`; `end` undefined means "still running" and is evaluated as `now`;
 * - a query range is `[from, to]`, inclusive at both ends: a window overlaps it when
 *   `window.start <= to` and `window.end > from`.
 */

/** Epoch milliseconds range; `from <= to`. */
export interface MsRange {
  from: number;
  to: number;
}

export interface VersionInterval {
  /** Catalog id of the version; absent only for a legacy entry whose id cannot be derived. */
  software_id?: string;
  version: string;
  start: number;
  /** Exclusive end; undefined while the interval is still open. */
  end?: number;
  /** Set when the interval ended because the version changed. */
  patched_to_version?: string;
}

/** Window in epoch ms; `end` undefined means still open. */
export interface MsVulnerableWindow {
  start: number;
  end?: number;
  cve_ids: string[];
  max_cvss?: number;
  known_exploited: boolean;
}

export type HistoryInstance = Pick<
  InstanceDoc,
  'software_id' | 'version_history' | 'status' | 'first_seen' | 'last_seen'
>;

const toMs = (value: string | undefined): number | undefined => {
  if (!value) return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : ms;
};

const toIso = (ms: number): string => new Date(ms).toISOString();

/**
 * Derives a history entry's catalog id from the instance's current id (`vendor:product:version`),
 * for legacy entries written before `software_id` was stored on each entry.
 */
export const deriveSoftwareId = (
  currentSoftwareId: string,
  version: string
): string | undefined => {
  const parts = currentSoftwareId.split(':');
  if (parts.length !== 3 || !parts[0] || !parts[1]) return undefined;
  return `${parts[0]}:${parts[1]}:${normalizeToken(version)}`;
};

/** Version part of a catalog id, used when an instance has no history. */
const versionFromSoftwareId = (softwareId: string): string =>
  softwareId.split(':').slice(2).join(':') || 'unknown';

const isClosedStatus = (status: InstanceDoc['status']): boolean =>
  status === 'removed' || status === 'stale';

/**
 * Builds the version intervals of an instance from its `version_history`. Interval `i` runs from
 * `history[i].first_seen` to `history[i + 1].first_seen`. The last interval is open while the
 * instance is active or patched, and ends at `last_seen` when it is removed or stale. Ends are never
 * later than `now`.
 */
export const buildVersionIntervals = (instance: HistoryInstance, now: Date): VersionInterval[] => {
  const nowMs = now.getTime();
  const history = (instance.version_history ?? [])
    .flatMap((entry) => {
      const start = toMs(entry.first_seen);
      return start === undefined ? [] : [{ entry, start }];
    })
    .sort((a, b) => a.start - b.start);

  if (history.length === 0) {
    const start = toMs(instance.first_seen);
    if (start === undefined) return [];
    const end = isClosedStatus(instance.status) ? toMs(instance.last_seen) : undefined;
    return [
      {
        software_id: instance.software_id,
        version: versionFromSoftwareId(instance.software_id),
        start,
        ...(end !== undefined ? { end: Math.min(Math.max(end, start), nowMs) } : {}),
      },
    ];
  }

  return history.map(({ entry, start }, index): VersionInterval => {
    const next = history[index + 1];
    const softwareId = entry.software_id ?? deriveSoftwareId(instance.software_id, entry.version);
    const base = {
      ...(softwareId ? { software_id: softwareId } : {}),
      version: entry.version,
      start,
    };
    if (next) {
      return {
        ...base,
        end: Math.min(Math.max(next.start, start), nowMs),
        ...(next.entry.version !== entry.version ? { patched_to_version: next.entry.version } : {}),
      };
    }
    if (!isClosedStatus(instance.status)) return base;
    const lastSeen = toMs(instance.last_seen) ?? toMs(entry.last_seen) ?? start;
    return { ...base, end: Math.min(Math.max(lastSeen, start), nowMs) };
  });
};

/** True when `[start, end)` (end undefined evaluated as `now`) overlaps the inclusive `[from, to]`. */
export const overlapsRange = (
  { start, end }: { start: number; end?: number },
  range: MsRange,
  nowMs: number
): boolean => start <= range.to && (end ?? nowMs) > range.from;

interface CveStart {
  id?: string;
  start: number;
  cvss?: number;
  knownExploited: boolean;
}

/** Per-CVE starts inside an interval, publish-date aware. */
const cveStarts = (interval: VersionInterval, entry: CatalogEntry): CveStart[] => {
  const details = new Map((entry.cve_details ?? []).map((detail) => [detail.id, detail]));
  const ids = [...new Set([...(entry.cve_ids ?? []), ...details.keys()])];
  if (ids.length === 0) {
    // Counted vulnerable without CVE ids: no publish date is known, so it counts from the start.
    return (entry.cve_count ?? 0) > 0
      ? [
          {
            start: interval.start,
            cvss: entry.max_cvss,
            knownExploited: entry.known_exploited === true,
          },
        ]
      : [];
  }
  const hasDetails = details.size > 0;
  return ids.map((id) => {
    const detail = details.get(id);
    const published = toMs(detail?.published);
    return {
      id,
      start: published === undefined ? interval.start : Math.max(interval.start, published),
      // Without any per-CVE details the entry-level values are the best information available.
      cvss: hasDetails ? detail?.cvss : entry.max_cvss,
      knownExploited: hasDetails
        ? detail?.known_exploited === true
        : entry.known_exploited === true,
    };
  });
};

/**
 * Vulnerable window of one version interval. Each CVE applies from
 * `max(interval.start, cve.published)` to the interval end; CVEs without a publish date apply
 * from the start. Because every CVE window ends at the interval end, overlapping CVE windows merge
 * into at most one window, starting at the earliest CVE start.
 *
 * With `range`, the window is clipped to `[from, to]` and dropped when it does not overlap. An open
 * window is closed at `min(to, now)` when clipped. `cve_ids`, `max_cvss`, and `known_exploited`
 * describe the CVEs that applied inside the returned window.
 */
export const computeVulnerableWindows = (
  interval: VersionInterval,
  entry: CatalogEntry | undefined,
  range?: MsRange,
  now: Date = new Date()
): MsVulnerableWindow[] => {
  if (!entry) return [];
  const nowMs = now.getTime();
  const intervalEnd = interval.end;
  const effectiveEnd = intervalEnd ?? nowMs;

  // A CVE published at or after the interval ended never applied to it.
  const applicable = cveStarts(interval, entry).filter(({ start }) => start < effectiveEnd);
  if (applicable.length === 0) return [];

  let start = Math.min(...applicable.map((cve) => cve.start));
  let end = intervalEnd;
  if (range) {
    if (!overlapsRange({ start, end }, range, nowMs)) return [];
    start = Math.max(start, range.from);
    end = Math.min(effectiveEnd, range.to, nowMs);
  }

  // Only CVEs published before the (clipped) window ends applied inside it.
  const inside = applicable.filter((cve) => cve.start <= (end ?? effectiveEnd));
  const cvss = inside.flatMap(({ cvss: value }) => (value === undefined ? [] : [value]));
  return [
    {
      start,
      ...(end !== undefined ? { end } : {}),
      cve_ids: inside.flatMap(({ id }) => (id ? [id] : [])),
      ...(cvss.length > 0 ? { max_cvss: Math.max(...cvss) } : {}),
      known_exploited: inside.some(({ knownExploited }) => knownExploited),
    },
  ];
};

export interface InstanceRangeVulnerability {
  vulnerable: boolean;
  /** Clipped windows of every interval that overlaps the range. */
  windows: MsVulnerableWindow[];
  /** Intervals that overlap the range, oldest first. */
  intervals: VersionInterval[];
}

/** Evaluates one instance against an inclusive range. */
export const evaluateInstanceInRange = ({
  instance,
  catalog,
  range,
  now,
}: {
  instance: HistoryInstance;
  catalog: ReadonlyMap<string, CatalogEntry>;
  range: MsRange;
  now: Date;
}): InstanceRangeVulnerability => {
  const nowMs = now.getTime();
  const intervals = buildVersionIntervals(instance, now).filter((interval) =>
    overlapsRange(interval, range, nowMs)
  );
  const windows = intervals.flatMap((interval) =>
    computeVulnerableWindows(
      interval,
      interval.software_id ? catalog.get(interval.software_id) : undefined,
      range,
      now
    )
  );
  return { vulnerable: windows.length > 0, windows, intervals };
};

/** True when the instance ran a version affected by a published CVE at any time in `[from, to]`. */
export const vulnerableInRange = (args: {
  instance: HistoryInstance;
  catalog: ReadonlyMap<string, CatalogEntry>;
  range: MsRange;
  now: Date;
}): boolean => evaluateInstanceInRange(args).vulnerable;

/** Catalog id of the latest version that ran during the range, or undefined when none did. */
export const latestSoftwareIdInRange = (
  instance: HistoryInstance,
  range: MsRange,
  now: Date
): string | undefined => {
  const nowMs = now.getTime();
  const overlapping = buildVersionIntervals(instance, now).filter((interval) =>
    overlapsRange(interval, range, nowMs)
  );
  return overlapping[overlapping.length - 1]?.software_id;
};

/** Catalog ids of every interval that overlaps the range (or every interval without a range). */
export const softwareIdsInRange = (
  instance: HistoryInstance,
  now: Date,
  range?: MsRange
): string[] => {
  const nowMs = now.getTime();
  return buildVersionIntervals(instance, now).flatMap((interval) =>
    interval.software_id && (!range || overlapsRange(interval, range, nowMs))
      ? [interval.software_id]
      : []
  );
};

/** Total length of the union of windows, each evaluated with open ends at `nowMs`. */
export const unionDuration = (windows: readonly MsVulnerableWindow[], nowMs: number): number => {
  const sorted = windows
    .map(({ start, end }) => ({ start, end: end ?? nowMs }))
    .filter(({ start, end }) => end > start)
    .sort((a, b) => a.start - b.start);
  let total = 0;
  let currentStart: number | undefined;
  let currentEnd = 0;
  for (const { start, end } of sorted) {
    if (currentStart === undefined || start > currentEnd) {
      if (currentStart !== undefined) total += currentEnd - currentStart;
      currentStart = start;
      currentEnd = end;
    } else {
      currentEnd = Math.max(currentEnd, end);
    }
  }
  if (currentStart !== undefined) total += currentEnd - currentStart;
  return total;
};

const toWindow = ({ start, end, ...rest }: MsVulnerableWindow): VulnerableWindow => ({
  start: toIso(start),
  ...(end !== undefined ? { end: toIso(end) } : {}),
  ...rest,
});

export type TimelineInstance = HistoryInstance &
  Pick<InstanceDoc, 'id' | 'install_path' | 'exposure'>;

const productParts = (
  softwareId: string,
  entry: CatalogEntry | undefined
): { vendor: string; product: string; category: SoftwareCategory } => {
  const [vendor = '', product = ''] = softwareId.split(':');
  return {
    vendor: entry?.vendor ?? vendor,
    product: entry?.product ?? product,
    category: entry?.category ?? 'other',
  };
};

/**
 * Builds the host timeline for `[from, to]`. Items are the instances with at least one interval
 * that overlaps the range; intervals are the overlapping ones, and their `vulnerable_windows` are
 * NOT clipped, so a caller can show the full window. The host-level answer fields
 * (`vulnerable_in_range`, `vulnerable_duration_ms`, `first_vulnerable_at`, `cve_ids`) are computed
 * from windows clipped to the range.
 */
export const buildHostTimeline = ({
  hostKey,
  instances,
  catalog,
  range,
  now,
}: {
  hostKey: string;
  instances: readonly TimelineInstance[];
  catalog: ReadonlyMap<string, CatalogEntry>;
  range: MsRange;
  now: Date;
}): HostTimelineResponse => {
  const nowMs = now.getTime();
  const clippedWindows: MsVulnerableWindow[] = [];
  const items: HostTimelineItem[] = [];

  for (const instance of instances) {
    const evaluation = evaluateInstanceInRange({ instance, catalog, range, now });
    if (evaluation.intervals.length === 0) continue;
    clippedWindows.push(...evaluation.windows);

    const intervals = evaluation.intervals.map((interval): TimelineInterval => {
      const entry = interval.software_id ? catalog.get(interval.software_id) : undefined;
      const { product } = productParts(interval.software_id ?? instance.software_id, entry);
      return {
        software_id: interval.software_id ?? '',
        display_name: entry?.display_name ?? `${product} ${interval.version}`,
        version: interval.version,
        start: toIso(interval.start),
        ...(interval.end !== undefined ? { end: toIso(interval.end) } : {}),
        vulnerable_windows: computeVulnerableWindows(interval, entry, undefined, now).map(toWindow),
        ...(interval.patched_to_version !== undefined
          ? { patched_to_version: interval.patched_to_version }
          : {}),
      };
    });

    const current = catalog.get(instance.software_id);
    items.push({
      instance_id: instance.id,
      ...productParts(instance.software_id, current),
      ...(instance.install_path ? { install_path: instance.install_path } : {}),
      status: instance.status,
      exposure_level: instance.exposure?.level ?? 'none',
      intervals,
      vulnerable_in_range: evaluation.vulnerable,
    });
  }

  const firstVulnerable = clippedWindows.reduce<number | undefined>(
    (earliest, { start }) => (earliest === undefined || start < earliest ? start : earliest),
    undefined
  );
  return {
    host_key: hostKey,
    from: toIso(range.from),
    to: toIso(range.to),
    vulnerable_in_range: clippedWindows.length > 0,
    vulnerable_duration_ms: unionDuration(clippedWindows, nowMs),
    ...(firstVulnerable !== undefined ? { first_vulnerable_at: toIso(firstVulnerable) } : {}),
    cve_ids: [...new Set(clippedWindows.flatMap(({ cve_ids: ids }) => ids))].sort(),
    items: items.sort(
      (a, b) =>
        Number(b.vulnerable_in_range) - Number(a.vulnerable_in_range) ||
        a.product.localeCompare(b.product)
    ),
  };
};

/** Earliest CVE publish date of a catalog entry, from `first_published` or the per-CVE details. */
export const earliestPublished = (entry: CatalogEntry | undefined): number | undefined => {
  if (!entry) return undefined;
  const dates = [
    toMs(entry.first_published),
    ...(entry.cve_details ?? []).map(({ published }) => toMs(published)),
  ].flatMap((ms) => (ms === undefined ? [] : [ms]));
  return dates.length > 0 ? Math.min(...dates) : undefined;
};

const median = (values: readonly number[]): number | undefined => {
  if (values.length === 0) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle];
};

/**
 * Median time to patch: for each `version_changed` event whose previous version had a CVE published
 * at or before the patch, the time from that earliest publish date to the patch. Undefined when no
 * patch qualifies.
 */
export const medianTimeToPatch = (
  events: ReadonlyArray<
    Pick<InventoryEvent, '@timestamp' | 'type' | 'previous_software_id' | 'software_id'>
  >,
  catalog: ReadonlyMap<string, CatalogEntry>
): number | undefined => {
  const durations = events.flatMap((event) => {
    if (event.type !== 'version_changed' || !event.previous_software_id) return [];
    const patchedAt = toMs(event['@timestamp']);
    const published = earliestPublished(catalog.get(event.previous_software_id));
    if (patchedAt === undefined || published === undefined || published > patchedAt) return [];
    return [patchedAt - published];
  });
  return median(durations);
};

/**
 * True when a patch reduced the CVE count. Uses the posture recorded on the event when both sides
 * are known, else the current catalog entries.
 */
export const isRemediatingPatch = (
  event: Pick<
    InventoryEvent,
    'type' | 'previous_software_id' | 'software_id' | 'cve_count_before' | 'cve_count_after'
  >,
  catalog: ReadonlyMap<string, CatalogEntry>
): boolean => {
  if (event.type !== 'version_changed') return false;
  if (event.cve_count_before !== undefined && event.cve_count_after !== undefined) {
    return event.cve_count_after < event.cve_count_before;
  }
  const before = event.previous_software_id
    ? catalog.get(event.previous_software_id)?.cve_count
    : undefined;
  const after = catalog.get(event.software_id)?.cve_count;
  return before !== undefined && after !== undefined && after < before;
};
