/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z, lazySchema } from '@kbn/zod/v4';
import { ToolType } from '@kbn/agent-builder-common';
import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import type { CatalogEntry, InstanceRow } from '../../common/types';
import { findInstances, getCatalogDetail, getSummary } from '../routes/data_access';
import type { InstanceFilters } from '../routes/query_builders';
import { dataResult, errorResult, withGuard, type SoftwareInventoryToolDeps } from './tool_helpers';
import { createHistoryTools } from './history_tools';
import {
  buildHuntQueries,
  DEFAULT_LOOKBACK_DAYS,
  MAX_HUNT_HOSTS,
  MAX_LOOKBACK_DAYS,
} from './hunt_queries';

export const FIND_INSTANCES_TOOL_ID = 'security.software_inventory.find_instances';
export const SUMMARY_TOOL_ID = 'security.software_inventory.summary';
export const SOFTWARE_DETAIL_TOOL_ID = 'security.software_inventory.software_detail';
export type { SoftwareInventoryToolDeps } from './tool_helpers';
export {
  HOST_VULNERABILITY_TIMELINE_TOOL_ID,
  INVENTORY_TRENDS_TOOL_ID,
  createHostVulnerabilityTimelineTool,
  createInventoryTrendsTool,
} from './history_tools';
export const BUILD_HUNT_QUERIES_TOOL_ID = 'security.software_inventory.build_hunt_queries';

export const MAX_TOOL_ROWS = 25;
export const MAX_DETAIL_HOSTS_IN_TOOL = 50;
export const MAX_CVE_DETAILS_IN_TOOL = 25;

/**
 * Patch guidance for one catalog entry. `minimal_safe_version` resolves every CVE with a known fix
 * on the current branch; `latest_known_fix` is the newest fixed version NVD lists, not the latest
 * release.
 */
export const toRemediation = ({
  fixed_in: fixedIn,
  latest_known_fix: latestKnownFix,
  fully_remediated: fullyRemediated,
  unfixed_cve_ids: unfixedCveIds,
  remediation_caveat: caveats,
}: CatalogEntry): Record<string, unknown> => ({
  minimal_safe_version: fixedIn,
  latest_known_fix: latestKnownFix,
  fully_remediated: fullyRemediated,
  unfixed_cve_ids: unfixedCveIds?.slice(0, MAX_CVE_DETAILS_IN_TOOL),
  remediation_caveat: caveats,
});

/** Compact projection of an instance row for LLM consumption. */
export const toCompactRow = ({
  host,
  software,
  status,
  exposure,
  install_path: installPath,
  last_seen: lastSeen,
  version_changed_at: versionChangedAt,
  previous_software_id: previousSoftwareId,
  software_id: softwareId,
}: InstanceRow): Record<string, unknown> => ({
  host: host.name ?? host.id,
  host_id: host.id,
  software_id: softwareId,
  product: software.product,
  vendor: software.vendor,
  version: software.version,
  status,
  exposure_level: exposure.level,
  exposure_score: exposure.score,
  cve_count: software.cve_count,
  max_cvss: software.max_cvss,
  known_exploited: software.known_exploited,
  fixed_in: software.fixed_in,
  ...toRemediation(software),
  install_path: installPath,
  last_seen: lastSeen,
  version_changed_at: versionChangedAt,
  previous_software_id: previousSoftwareId,
});

export const findInstancesSchema = lazySchema(() =>
  z.object({
    product: z
      .string()
      .min(1)
      .max(128)
      .optional()
      .describe('Product name, partial and case-insensitive, for example "openssl" or "nginx".'),
    version: z
      .string()
      .min(1)
      .max(128)
      .optional()
      .describe('Exact version string, for example "1.1.1k".'),
    host_name: z
      .string()
      .min(1)
      .max(256)
      .optional()
      .describe('Host name, partial and case-insensitive. Use it to list software on a host.'),
    exposure_level: z
      .array(z.enum(['none', 'low', 'medium', 'high']))
      .max(4)
      .optional()
      .describe('Only instances with one of these exposure levels, for example ["medium","high"].'),
    known_exploited: z
      .boolean()
      .optional()
      .describe('true: only software with a CISA known-exploited vulnerability.'),
    min_cve_count: z
      .number()
      .int()
      .min(0)
      .max(100000)
      .optional()
      .describe('Only software with at least this many known CVEs. Use 1 for "vulnerable".'),
    patched_within_days: z
      .number()
      .int()
      .min(1)
      .max(365)
      .optional()
      .describe('Only instances whose version changed (patched or upgraded) in the last N days.'),
    per_page: z
      .number()
      .int()
      .min(1)
      .max(MAX_TOOL_ROWS)
      .optional()
      .describe(`Rows to return, at most ${MAX_TOOL_ROWS}. Defaults to 10.`),
  })
);

export const createFindInstancesTool = (
  deps: SoftwareInventoryToolDeps
): BuiltinSkillBoundedTool<typeof findInstancesSchema> => ({
  id: FIND_INSTANCES_TOOL_ID,
  type: ToolType.builtin,
  description:
    'Find software instances (one row per host and installed product) in the software inventory. ' +
    'Use it to answer where a product or version runs, which exposed or known-exploited software exists, ' +
    'what was patched recently, and what software a host has. ' +
    'Filters combine with AND. Returns at most 25 rows (newest first) with host, product, version, status, ' +
    'exposure level, CVE count, known-exploited flag, patch guidance (minimal_safe_version, latest_known_fix, ' +
    'fully_remediated, unfixed_cve_ids, remediation_caveat) and the total match count. ' +
    'Read-only. Does not return full CVE lists; use software_detail for that.',
  schema: findInstancesSchema,
  handler: async (input, { request }) =>
    withGuard(deps, request, FIND_INSTANCES_TOOL_ID, async () => {
      const perPage = input.per_page ?? 10;
      const filters: InstanceFilters = {
        product: input.product,
        version: input.version,
        host_name: input.host_name,
        exposure_level: input.exposure_level,
        known_exploited: input.known_exploited,
        min_cve_count: input.min_cve_count,
        patched_within_days: input.patched_within_days,
        // Removed instances are not running anywhere; hide them unless asked via status elsewhere.
        status: ['active', 'patched', 'stale'],
      };
      const result = await findInstances(await deps.getEsClient(), {
        ...filters,
        page: 1,
        per_page: perPage,
        sort_field: 'last_seen',
        sort_order: 'desc',
      });
      return dataResult({
        total: result.total,
        returned: result.items.length,
        truncated: result.total > result.items.length,
        items: result.items.map(toCompactRow),
      });
    }),
});

export const summarySchema = lazySchema(() => z.object({}));

export const createSummaryTool = (
  deps: SoftwareInventoryToolDeps
): BuiltinSkillBoundedTool<typeof summarySchema> => ({
  id: SUMMARY_TOOL_ID,
  type: ToolType.builtin,
  description:
    'Get aggregate software inventory counts: total instances, distinct software, exposed instances, ' +
    'vulnerable instances, known-exploited instances, recently patched instances (last 7 days), and breakdowns by ' +
    'category and discovery source. Read-only. Use it for overview questions; use find_instances for rows.',
  schema: summarySchema,
  handler: async (_input, { request }) =>
    withGuard(deps, request, SUMMARY_TOOL_ID, async () =>
      dataResult({ ...(await getSummary(await deps.getEsClient())) })
    ),
});

export const softwareDetailSchema = lazySchema(() =>
  z.object({
    software_id: z
      .string()
      .min(1)
      .max(512)
      .describe(
        'Catalog id of the software, from the software_id field of find_instances results.'
      ),
  })
);

export const createSoftwareDetailTool = (
  deps: SoftwareInventoryToolDeps
): BuiltinSkillBoundedTool<typeof softwareDetailSchema> => ({
  id: SOFTWARE_DETAIL_TOOL_ID,
  type: ToolType.builtin,
  description:
    'Get one catalog entry (vendor, product, version, CPE, CVE ids, CVSS, known-exploited flag) with patch guidance: ' +
    'minimal_safe_version (lowest version that fixes every CVE with a known fix on the current branch), ' +
    'latest_known_fix (newest fixed version listed, not the latest release), fully_remediated, unfixed_cve_ids, ' +
    `remediation_caveat, and up to ${MAX_CVE_DETAILS_IN_TOOL} per-CVE details (CVSS, published date, fixed-in, KEV). ` +
    `Also returns up to ${MAX_DETAIL_HOSTS_IN_TOOL} hosts that run it. Needs a software_id from find_instances. Read-only.`,
  schema: softwareDetailSchema,
  handler: async ({ software_id: softwareId }, { request }) =>
    withGuard(deps, request, SOFTWARE_DETAIL_TOOL_ID, async () => {
      const detail = await getCatalogDetail(await deps.getEsClient(), softwareId);
      if (!detail) return errorResult(`No software entry found for id "${softwareId}".`);
      const { entry, instances } = detail;
      return dataResult({
        entry: {
          software_id: entry.id,
          vendor: entry.vendor,
          product: entry.product,
          version: entry.version,
          category: entry.category,
          cpe: entry.cpe,
          cve_count: entry.cve_count,
          max_cvss: entry.max_cvss,
          known_exploited: entry.known_exploited,
          fixed_in: entry.fixed_in,
          ...toRemediation(entry),
          first_published: entry.first_published,
          cve_ids: entry.cve_ids.slice(0, 25),
          cve_ids_truncated: entry.cve_ids.length > 25,
          cve_details: (entry.cve_details ?? []).slice(0, MAX_CVE_DETAILS_IN_TOOL),
        },
        host_count: instances.length,
        hosts: instances.slice(0, MAX_DETAIL_HOSTS_IN_TOOL).map((instance) => ({
          host: instance.host.name ?? instance.host.id,
          host_id: instance.host.id,
          status: instance.status,
          exposure_level: instance.exposure.level,
          last_seen: instance.last_seen,
        })),
        hosts_truncated: instances.length > MAX_DETAIL_HOSTS_IN_TOOL,
      });
    }),
});

export const buildHuntQueriesSchema = lazySchema(() =>
  z.object({
    software_id: z
      .string()
      .min(1)
      .max(512)
      .optional()
      .describe(
        'Catalog id of the software (preferred). Takes precedence over product and version.'
      ),
    product: z
      .string()
      .min(1)
      .max(128)
      .optional()
      .describe('Product name when no software_id is known.'),
    version: z.string().min(1).max(128).optional().describe('Exact version, used with product.'),
    lookback_days: z
      .number()
      .int()
      .min(1)
      .max(MAX_LOOKBACK_DAYS)
      .optional()
      .describe(`How far back the queries look. Defaults to ${DEFAULT_LOOKBACK_DAYS} days.`),
  })
);

export const createBuildHuntQueriesTool = (
  deps: SoftwareInventoryToolDeps
): BuiltinSkillBoundedTool<typeof buildHuntQueriesSchema> => ({
  id: BUILD_HUNT_QUERIES_TOOL_ID,
  type: ToolType.builtin,
  description:
    'Build (but do not run) ES|QL hunt queries scoped to the hosts that run an inventory item: host activity, ' +
    'process executions and network connections. Identify the item by software_id, or by product and optional version. ' +
    `Scopes to at most ${MAX_HUNT_HOSTS} hosts and reports when hosts were left out. ` +
    'Returns the host list and query strings the user or another tool can run. Read-only.',
  schema: buildHuntQueriesSchema,
  handler: async (input, { request }) =>
    withGuard(deps, request, BUILD_HUNT_QUERIES_TOOL_ID, async () => {
      const esClient = await deps.getEsClient();
      let hostNames: string[] = [];
      let product = input.product?.toLowerCase();
      let totalHosts = 0;

      if (input.software_id) {
        const detail = await getCatalogDetail(esClient, input.software_id);
        if (!detail) return errorResult(`No software entry found for id "${input.software_id}".`);
        product = detail.entry.product;
        hostNames = detail.instances.flatMap(({ host, status }) =>
          host.name && status !== 'removed' ? [host.name] : []
        );
        totalHosts = hostNames.length;
      } else if (input.product) {
        const result = await findInstances(esClient, {
          product: input.product,
          version: input.version,
          status: ['active', 'patched', 'stale'],
          page: 1,
          per_page: MAX_HUNT_HOSTS,
          sort_field: 'last_seen',
          sort_order: 'desc',
        });
        hostNames = result.items.flatMap(({ host }) => (host.name ? [host.name] : []));
        totalHosts = result.total;
      } else {
        return errorResult('Provide either software_id or product.');
      }

      const queries = buildHuntQueries({
        hostNames,
        product,
        lookbackDays: input.lookback_days,
      });
      if (queries.length === 0) {
        return dataResult({ host_count: 0, queries: [], note: 'No hosts with names found.' });
      }
      const scopedHosts = [...new Set(hostNames)].slice(0, MAX_HUNT_HOSTS);
      return dataResult({
        host_count: totalHosts,
        scoped_hosts: scopedHosts,
        truncated: totalHosts > scopedHosts.length,
        queries,
      });
    }),
});

export const createSoftwareInventoryTools = (
  deps: SoftwareInventoryToolDeps
): BuiltinSkillBoundedTool[] => [
  createFindInstancesTool(deps),
  createSummaryTool(deps),
  createSoftwareDetailTool(deps),
  createBuildHuntQueriesTool(deps),
  ...createHistoryTools(deps),
];
