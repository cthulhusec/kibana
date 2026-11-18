/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z, lazySchema } from '@kbn/zod/v4';
import type { ElasticsearchClient } from '@kbn/core/server';
import { ToolType } from '@kbn/agent-builder-common';
import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import { parse as parseDateMath } from '@kbn/datemath';
import { INSTANCES_INDEX, MAX_HISTORY_RANGE_DAYS } from '../../common/constants';
import type { DailyRollup, HostTimelineItem, VulnerableWindow } from '../../common/history';
import {
  fetchHostEvents,
  getHostTimeline,
  getTrends,
  validateHistoryRange,
} from '../services/history/history_data_access';
import type { MsRange } from '../services/history/history_math';
import { escapeWildcard } from '../routes/query_builders';
import { dataResult, errorResult, withGuard, type SoftwareInventoryToolDeps } from './tool_helpers';

export const HOST_VULNERABILITY_TIMELINE_TOOL_ID =
  'security.software_inventory.host_vulnerability_timeline';
export const INVENTORY_TRENDS_TOOL_ID = 'security.software_inventory.inventory_trends';

export const MAX_TIMELINE_ITEMS_IN_TOOL = 25;
export const MAX_CVE_IDS_IN_TOOL = 50;
export const MAX_WINDOW_CVE_IDS_IN_TOOL = 10;
export const MAX_HOST_EVENTS_IN_TOOL = 25;
export const MAX_HOST_CANDIDATES = 10;
export const MAX_TREND_POINTS_IN_TOOL = 31;

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

const dateInput = (defaultHint: string) =>
  z
    .string()
    .min(1)
    .max(64)
    .optional()
    .describe(
      `ISO 8601 date or date math relative to now, for example "now-3d", "now-1M" or ` +
        `"2026-11-01T00:00:00Z". Defaults to "${defaultHint}".`
    );

/** Resolves ISO or date-math input (`now-3d`) to epoch ms; `roundUp` rounds `/d` style math up. */
export const resolveDateInput = (
  input: string,
  { roundUp, now }: { roundUp: boolean; now: Date }
): number | undefined => {
  const trimmed = input.trim();
  // Only `now`-relative input goes through date math; moment's lenient parsing of free text is
  // avoided, so anything else must be an ISO 8601 date.
  if (!trimmed.startsWith('now')) {
    const ms = Date.parse(trimmed);
    return Number.isNaN(ms) ? undefined : ms;
  }
  const parsed = parseDateMath(trimmed, { roundUp, forceNow: now });
  return parsed?.isValid() ? parsed.valueOf() : undefined;
};

/** Resolves a tool `from`/`to` pair; returns an LLM-readable error when invalid. */
export const resolveToolRange = (
  from: string,
  to: string,
  now: Date
): { range: MsRange } | { error: string } => {
  const fromMs = resolveDateInput(from, { roundUp: false, now });
  const toMs = resolveDateInput(to, { roundUp: true, now });
  if (fromMs === undefined) return { error: `Could not parse from "${from}".` };
  if (toMs === undefined) return { error: `Could not parse to "${to}".` };
  const validation = validateHistoryRange(
    new Date(fromMs).toISOString(),
    new Date(toMs).toISOString()
  );
  if (validation.error !== undefined) {
    return { error: `${validation.error}. At most ${MAX_HISTORY_RANGE_DAYS} days are supported.` };
  }
  return { range: validation.range };
};

export type HostResolution =
  | { hostKey: string }
  | { candidates: Array<{ host_key: string; instances: number }> }
  | { notFound: true };

/**
 * Resolves a host name or key to one `host.key`: an exact key match first, then a partial,
 * case-insensitive match on the host name or key.
 */
export const resolveHost = async (
  esClient: ElasticsearchClient,
  host: string
): Promise<HostResolution> => {
  const key = host.trim().toLowerCase();
  const exact = await esClient.search({
    index: INSTANCES_INDEX,
    ignore_unavailable: true,
    allow_no_indices: true,
    size: 0,
    track_total_hits: 1,
    query: { term: { 'host.key': key } },
  });
  const { total } = exact.hits;
  if ((typeof total === 'number' ? total : total?.value ?? 0) > 0) return { hostKey: key };

  const pattern = `*${escapeWildcard(key)}*`;
  const partial = await esClient.search({
    index: INSTANCES_INDEX,
    ignore_unavailable: true,
    allow_no_indices: true,
    size: 0,
    query: {
      bool: {
        should: [
          { wildcard: { 'host.name': { value: pattern, case_insensitive: true } } },
          { wildcard: { 'host.key': { value: pattern, case_insensitive: true } } },
        ],
        minimum_should_match: 1,
      },
    },
    aggs: { hosts: { terms: { field: 'host.key', size: MAX_HOST_CANDIDATES } } },
  });
  const buckets =
    (
      partial.aggregations?.hosts as
        | { buckets?: Array<{ key: string; doc_count: number }> }
        | undefined
    )?.buckets ?? [];
  if (buckets.length === 0) return { notFound: true };
  if (buckets.length === 1) return { hostKey: buckets[0].key };
  return {
    candidates: buckets.map(({ key: hostKey, doc_count: instances }) => ({
      host_key: hostKey,
      instances,
    })),
  };
};

const clipWindow = (
  { start, end, cve_ids: cveIds, max_cvss: maxCvss, known_exploited: kev }: VulnerableWindow,
  range: MsRange,
  nowMs: number
): Record<string, unknown> | undefined => {
  const startMs = Math.max(Date.parse(start), range.from);
  const endMs = Math.min(end ? Date.parse(end) : range.to, range.to, nowMs);
  if (startMs > range.to || endMs < range.from) return undefined;
  return {
    start: new Date(startMs).toISOString(),
    end: new Date(Math.max(endMs, startMs)).toISOString(),
    still_open: end === undefined,
    cve_ids: cveIds.slice(0, MAX_WINDOW_CVE_IDS_IN_TOOL),
    cve_count: cveIds.length,
    max_cvss: maxCvss,
    known_exploited: kev,
  };
};

const compactItem = (
  item: HostTimelineItem,
  range: MsRange,
  nowMs: number
): Record<string, unknown> => ({
  product: item.product,
  vendor: item.vendor,
  install_path: item.install_path,
  status: item.status,
  exposure_level: item.exposure_level,
  vulnerable_in_range: item.vulnerable_in_range,
  versions: item.intervals.map((interval) => ({
    version: interval.version,
    software_id: interval.software_id,
    running_from: interval.start,
    running_until: interval.end ?? 'still running',
    patched_to_version: interval.patched_to_version,
    vulnerable_windows_in_range: interval.vulnerable_windows.flatMap((window) => {
      const clipped = clipWindow(window, range, nowMs);
      return clipped ? [clipped] : [];
    }),
  })),
});

export const hostVulnerabilityTimelineSchema = lazySchema(() =>
  z.object({
    host: z
      .string()
      .min(1)
      .max(256)
      .describe('Host name or host key, for example "web-1". Partial names are matched.'),
    from: dateInput('now-7d'),
    to: dateInput('now'),
  })
);

export const createHostVulnerabilityTimelineTool = (
  deps: SoftwareInventoryToolDeps
): BuiltinSkillBoundedTool<typeof hostVulnerabilityTimelineSchema> => ({
  id: HOST_VULNERABILITY_TIMELINE_TOOL_ID,
  type: ToolType.builtin,
  description:
    'Answer whether a host ran vulnerable software during a time range, for example ' +
    '"was web-1 vulnerable over the last 3 days?". A version counts as vulnerable from the later of when it ' +
    'started running and when each CVE was published, until it was patched or removed. Returns ' +
    'vulnerable_in_range, vulnerable_hours, first_vulnerable_at, the CVE ids that applied, up to ' +
    `${MAX_TIMELINE_ITEMS_IN_TOOL} affected software items with their versions and vulnerable windows inside ` +
    `the range, and up to ${MAX_HOST_EVENTS_IN_TOOL} patch, removal and revival events in the range. ` +
    'Resolves the host by exact key, then by partial name; returns candidate hosts when the name is ambiguous. ' +
    'Read-only.',
  schema: hostVulnerabilityTimelineSchema,
  handler: async (input, { request }) =>
    withGuard(deps, request, HOST_VULNERABILITY_TIMELINE_TOOL_ID, async () => {
      const now = new Date();
      const resolved = resolveToolRange(input.from ?? 'now-7d', input.to ?? 'now', now);
      if ('error' in resolved) return errorResult(resolved.error);
      const { range } = resolved;

      const esClient = await deps.getEsClient();
      const host = await resolveHost(esClient, input.host);
      if ('notFound' in host) {
        return errorResult(`No host in the software inventory matches "${input.host}".`);
      }
      if ('candidates' in host) {
        return dataResult({
          ambiguous_host: true,
          candidates: host.candidates,
          note: 'Several hosts match. Call the tool again with one host_key as host.',
        });
      }

      const timeline = await getHostTimeline(esClient, host.hostKey, range, now);
      if (!timeline) {
        return errorResult(`No software inventory data for host "${host.hostKey}".`);
      }
      const events = await fetchHostEvents(esClient, host.hostKey, range, MAX_HOST_EVENTS_IN_TOOL);
      const vulnerableItems = timeline.items.filter((item) => item.vulnerable_in_range);
      return dataResult({
        host_key: timeline.host_key,
        from: timeline.from,
        to: timeline.to,
        vulnerable_in_range: timeline.vulnerable_in_range,
        vulnerable_hours: Math.round((timeline.vulnerable_duration_ms / HOUR_MS) * 10) / 10,
        range_hours: Math.round(((range.to - range.from) / HOUR_MS) * 10) / 10,
        first_vulnerable_at: timeline.first_vulnerable_at,
        cve_ids: timeline.cve_ids.slice(0, MAX_CVE_IDS_IN_TOOL),
        cve_count: timeline.cve_ids.length,
        software_in_range: timeline.items.length,
        vulnerable_software_count: vulnerableItems.length,
        vulnerable_software: vulnerableItems
          .slice(0, MAX_TIMELINE_ITEMS_IN_TOOL)
          .map((item) => compactItem(item, range, now.getTime())),
        vulnerable_software_truncated: vulnerableItems.length > MAX_TIMELINE_ITEMS_IN_TOOL,
        events_in_range: events.map((event) => ({
          at: event['@timestamp'],
          type: event.type,
          software_id: event.software_id,
          from_version: event.from_version,
          to_version: event.to_version,
          cve_count_before: event.cve_count_before,
          cve_count_after: event.cve_count_after,
        })),
        note:
          'Boundaries are accurate to the discovery interval. Log-derived sources cannot prove that ' +
          'software was absent.',
      });
    }),
});

export const inventoryTrendsSchema = lazySchema(() =>
  z.object({
    from: dateInput('now-30d'),
    to: dateInput('now'),
  })
);

const TREND_FIELDS = [
  'total_instances',
  'vulnerable_instances',
  'critical_instances',
  'known_exploited_instances',
  'exposed_and_vulnerable_instances',
] as const;

const compactBucket = (bucket: DailyRollup): Record<string, unknown> => ({
  date: bucket['@timestamp'].slice(0, 10),
  ...Object.fromEntries(TREND_FIELDS.map((field) => [field, bucket[field]])),
  new_instances: bucket.new_instances,
  patched_instances: bucket.patched_instances,
  removed_instances: bucket.removed_instances,
});

/** Evenly samples at most `max` buckets, always keeping the first and last. */
export const sampleBuckets = <T>(buckets: readonly T[], max: number): T[] => {
  if (buckets.length <= max) return [...buckets];
  const step = (buckets.length - 1) / (max - 1);
  return Array.from({ length: max }, (_, index) => buckets[Math.round(index * step)]);
};

export const createInventoryTrendsTool = (
  deps: SoftwareInventoryToolDeps
): BuiltinSkillBoundedTool<typeof inventoryTrendsSchema> => ({
  id: INVENTORY_TRENDS_TOOL_ID,
  type: ToolType.builtin,
  description:
    'Get software inventory trends over a time range from daily snapshots: total, vulnerable, critical, ' +
    'known-exploited and exposed-and-vulnerable instance counts per day, the first and last day with the ' +
    'change between them, and a patch summary (patches, patches that reduced CVEs, median days from CVE ' +
    'publication to patch). Use it for "how many vulnerable instances a month ago vs now?" and "how fast do ' +
    `we patch?". Returns at most ${MAX_TREND_POINTS_IN_TOOL} daily points (sampled for long ranges). Read-only.`,
  schema: inventoryTrendsSchema,
  handler: async (input, { request }) =>
    withGuard(deps, request, INVENTORY_TRENDS_TOOL_ID, async () => {
      const resolved = resolveToolRange(input.from ?? 'now-30d', input.to ?? 'now', new Date());
      if ('error' in resolved) return errorResult(resolved.error);
      const trends = await getTrends(await deps.getEsClient(), resolved.range);
      const { buckets, patch_summary: patchSummary } = trends;
      const first = buckets[0];
      const last = buckets[buckets.length - 1];
      const medianMs = patchSummary.median_time_to_patch_ms;
      return dataResult({
        from: trends.from,
        to: trends.to,
        days_with_data: buckets.length,
        first: first ? compactBucket(first) : undefined,
        last: last ? compactBucket(last) : undefined,
        change:
          first && last
            ? Object.fromEntries(TREND_FIELDS.map((field) => [field, last[field] - first[field]]))
            : undefined,
        points: sampleBuckets(buckets, MAX_TREND_POINTS_IN_TOOL).map(compactBucket),
        points_sampled: buckets.length > MAX_TREND_POINTS_IN_TOOL,
        patch_summary: {
          patches: patchSummary.patches,
          remediating_patches: patchSummary.remediating_patches,
          median_days_to_patch:
            medianMs !== undefined ? Math.round((medianMs / DAY_MS) * 10) / 10 : undefined,
        },
        note:
          buckets.length === 0
            ? 'No daily snapshots exist in this range yet; snapshots are written by the score exposure workflow.'
            : undefined,
      });
    }),
});

export const createHistoryTools = (deps: SoftwareInventoryToolDeps): BuiltinSkillBoundedTool[] => [
  createHostVulnerabilityTimelineTool(deps),
  createInventoryTrendsTool(deps),
];
