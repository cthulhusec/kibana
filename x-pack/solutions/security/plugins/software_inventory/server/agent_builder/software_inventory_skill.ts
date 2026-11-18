/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SkillDefinition } from '@kbn/agent-builder-server/skills';
import { defineSkillType } from '@kbn/agent-builder-server/skills/type_definition';
import {
  BUILD_HUNT_QUERIES_TOOL_ID,
  createSoftwareInventoryTools,
  FIND_INSTANCES_TOOL_ID,
  HOST_VULNERABILITY_TIMELINE_TOOL_ID,
  INVENTORY_TRENDS_TOOL_ID,
  SOFTWARE_DETAIL_TOOL_ID,
  SUMMARY_TOOL_ID,
  type SoftwareInventoryToolDeps,
} from './tools';

export const SOFTWARE_INVENTORY_SKILL_ID = 'software-inventory';

export const createSoftwareInventorySkill = (
  deps: SoftwareInventoryToolDeps
): SkillDefinition<'software-inventory', 'skills/security/alerts'> =>
  defineSkillType({
    id: SOFTWARE_INVENTORY_SKILL_ID,
    name: 'software-inventory',
    basePath: 'skills/security/alerts',
    description:
      'Answer questions about discovered software: where a product or version runs, which exposed software has a known-exploited CVE, what was patched recently, what runs on a host, whether a host was vulnerable during a time range, and how vulnerability counts and patch speed trend over time. Builds scoped ES|QL hunt queries around an inventory item. Read-only.',
    availability: {
      cacheMode: 'none',
      handler: async ({ request }) =>
        (await deps.hasReadAccess(request))
          ? { status: 'available' }
          : {
              status: 'unavailable',
              reason: 'Requires the Software inventory read privilege.',
            },
    },
    content: `# Software inventory

## Use this skill

Use it for questions about discovered software across hosts. It is read-only.

## Tools

| Tool | When to use |
|---|---|
| \`${FIND_INSTANCES_TOOL_ID}\` | Rows of software per host. Filter by product, version, host, exposure, known-exploited, CVE count, recent patching. |
| \`${SUMMARY_TOOL_ID}\` | Overview counts. |
| \`${SOFTWARE_DETAIL_TOOL_ID}\` | CVE details, patch guidance and hosts for one software_id. |
| \`${BUILD_HUNT_QUERIES_TOOL_ID}\` | ES|QL hunt queries scoped to hosts that run an item. |
| \`${HOST_VULNERABILITY_TIMELINE_TOOL_ID}\` | Whether one host ran vulnerable software during a time range, with windows, CVEs and patch events. |
| \`${INVENTORY_TRENDS_TOOL_ID}\` | Daily counts over a time range and patch speed. |

## Recipes

- "Where do we run <product> <version>?" -> \`find_instances\` with \`product\` and \`version\`.
- "Which exposed software has a known-exploited CVE?" -> \`find_instances\` with \`known_exploited: true\` and \`exposure_level: ["medium","high"]\`.
- "What was patched recently?" -> \`find_instances\` with \`patched_within_days\`. Rows with \`previous_software_id\` show the prior version.
- "Which version should I patch to?" -> \`software_detail\`. Recommend \`minimal_safe_version\`: the lowest version that fixes every CVE with a known fix on the current release branch. Offer \`latest_known_fix\` only as the newer-branch alternative; it is the highest fixed version NVD lists, not necessarily the latest release. If \`fully_remediated\` is false, list \`unfixed_cve_ids\` and say no fixed version is known for them. If \`remediation_caveat\` contains \`distro_backports\`, say the distribution may have backported fixes into its own package versions, so check the vendor advisory. If it contains \`low_version_confidence\`, say the version string could not be compared reliably.
- "Show software on host X" -> \`find_instances\` with \`host_name\`.
- "Was host X vulnerable over the last 3 days?" -> \`host_vulnerability_timeline\` with \`host: "X"\`, \`from: "now-3d"\`, \`to: "now"\`. Answer with \`vulnerable_in_range\`, then give \`first_vulnerable_at\`, \`vulnerable_hours\` of \`range_hours\`, the affected products and versions, and the CVE ids. If a version was patched inside the range, say when (\`patched_to_version\`, \`events_in_range\`). If the result has \`ambiguous_host\`, ask which of the \`candidates\` the user means.
- "Was host X vulnerable during <dates>?" -> \`host_vulnerability_timeline\` with ISO \`from\` and \`to\` (for example \`2026-11-01T00:00:00Z\`). Software counts as vulnerable from the later of when that version started running and when each CVE was published; a CVE published after the version was replaced never made the host vulnerable.
- "How many vulnerable instances a month ago vs now?" -> \`inventory_trends\` with \`from: "now-1M"\`. Compare \`first\` and \`last\` and report \`change\`. If \`first.date\` is later than the requested start, say the earliest snapshot available is from that date.
- "How fast do we patch?" -> \`inventory_trends\` over the period asked (default \`now-90d\`). Report \`patch_summary.median_days_to_patch\` (median days from CVE publication to the patch), \`patches\`, and \`remediating_patches\` (patches that reduced the CVE count). If the median is absent, say no patch in the range had a known CVE publication date.
- "Hunt around <product>" -> \`build_hunt_queries\` with the \`software_id\` from a prior result. Present the queries in code blocks and explain what each looks for. The tool builds queries but does not run them; use the ES|QL or hunting skills to run them.

## Grounding

Report only values from tool results. If \`truncated\` is true, say that more rows exist and suggest narrowing the filters. If a tool returns no rows, say the inventory has no match; the inventory may not be populated yet.
`,
    getInlineTools: () => createSoftwareInventoryTools(deps),
  });
