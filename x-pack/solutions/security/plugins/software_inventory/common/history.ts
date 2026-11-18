/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { DiscoverySource, ExposureLevel, SoftwareCategory } from './types';

/**
 * ## Semantics (decided with the user; do not change without asking)
 *
 * "Vulnerable at time T" is PUBLISH-DATE AWARE: an instance running version V is vulnerable at T
 * when V is affected by a CVE (that is, the CVE is in the catalog entry of V's `software_id`) AND
 * the CVE was published at or before T. Vulnerable windows for an interval [start, end) are
 * [max(start, cve.published), end) per CVE; CVEs without a `published` date count from `start`.
 *
 * ## Version intervals
 * Built from `InstanceDoc.version_history` (ordered by first_seen):
 * - interval i starts at history[i].first_seen;
 * - it ends at history[i+1].first_seen, which is the patch/change time;
 * - the LAST interval is open-ended (`end` omitted, meaning "now") while status is active/patched,
 *   and ends at `last_seen` when status is removed or stale.
 * Discovery cadence limits precision: boundaries are accurate to the discovery interval, and
 * log-derived sources can never prove absence.
 */

export type InventoryEventType =
  | 'first_seen'
  | 'version_changed'
  | 'removed'
  | 'stale'
  | 'revived';

/** One document per state transition. Append-only; `_id` is generated. */
export interface InventoryEvent {
  '@timestamp': string;
  instance_id: string;
  host: { key: string; id?: string; name?: string };
  type: InventoryEventType;
  source: DiscoverySource;
  /** Catalog id after the transition. */
  software_id: string;
  previous_software_id?: string;
  from_version?: string;
  to_version?: string;
  /** Vulnerability posture before/after, so remediation and regressions are measurable. */
  cve_count_before?: number;
  cve_count_after?: number;
  max_cvss_before?: number;
  max_cvss_after?: number;
  known_exploited_before?: boolean;
  known_exploited_after?: boolean;
}

/** One document per UTC day; `_id` is `YYYY-MM-DD`; `@timestamp` is the start of that UTC day. */
export interface DailyRollup {
  '@timestamp': string;
  /** Instances with status active or patched when the rollup ran. */
  total_instances: number;
  total_software: number;
  /** Instances whose current catalog entry has cve_count > 0. */
  vulnerable_instances: number;
  /** max_cvss >= 9.0 and >= 7.0 (< 9.0) respectively. */
  critical_instances: number;
  high_instances: number;
  /** exposure.level in medium/high. */
  exposed_instances: number;
  known_exploited_instances: number;
  exposed_and_vulnerable_instances: number;
  /** Events of type first_seen / version_changed / removed during that UTC day. */
  new_instances: number;
  patched_instances: number;
  removed_instances: number;
  categories: Record<SoftwareCategory, number>;
}

export interface TrendsResponse {
  from: string;
  to: string;
  /** One bucket per UTC day that has a rollup, ascending. */
  buckets: DailyRollup[];
  /** Over the whole range, from the event log. */
  patch_summary: {
    patches: number;
    /** Patches that reduced cve_count (a real remediation). */
    remediating_patches: number;
    /** Median ms from CVE publish (earliest on the old version) to the patch; absent if unknown. */
    median_time_to_patch_ms?: number;
  };
}

export interface VulnerableWindow {
  start: string;
  /** Omitted when the window is still open. */
  end?: string;
  cve_ids: string[];
  max_cvss?: number;
  known_exploited: boolean;
}

export interface TimelineInterval {
  software_id: string;
  display_name: string;
  version: string;
  start: string;
  /** Omitted when the interval is still open. */
  end?: string;
  /** Windows inside this interval where the version was affected by a published CVE. */
  vulnerable_windows: VulnerableWindow[];
  /** Set on the interval that ended because the version changed. */
  patched_to_version?: string;
}

export interface HostTimelineItem {
  instance_id: string;
  product: string;
  vendor: string;
  category: SoftwareCategory;
  install_path?: string;
  status: string;
  exposure_level: ExposureLevel;
  intervals: TimelineInterval[];
  /** True when any vulnerable window overlaps [from, to]. */
  vulnerable_in_range: boolean;
}

export interface HostTimelineResponse {
  host_key: string;
  from: string;
  to: string;
  /** True when ANY item was vulnerable at any point in [from, to]. */
  vulnerable_in_range: boolean;
  /** Total ms inside [from, to] with at least one vulnerable item. */
  vulnerable_duration_ms: number;
  first_vulnerable_at?: string;
  /** Distinct CVEs that applied inside [from, to]. */
  cve_ids: string[];
  items: HostTimelineItem[];
}
