/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Expected demo state for the regression cases (RG-1..RG-6). The demo is restored with
 * `seed_demo_data.js --clean`, which regenerates every timestamp relative to the restore time, so
 * the comparison uses projections without the time fields: ids, statuses, versions, CVE posture,
 * exposure levels. `generateSeedData` is deterministic apart from those timestamps.
 */

import type { DailyRollup, InventoryEvent } from '../../../common/history';
import type { CatalogEntry, InstanceDoc } from '../../../common/types';
import { generateSeedData } from '../../seed/generate_seed_data';
import type { JsonObject, JsonValue } from '../clients';
import { E2E3_REPEAT_CATALOG_IDS } from './e2e';
import { EC11_SEED_CATALOG_IDS, EC9_SEED_CATALOG_IDS } from './ec';
import { SC_COPY_IDS, SC9 } from './sc';

/** Counts of the demo seed (see the test plan's verified stack state). */
export const EXPECTED_SEED_COUNTS = {
  catalog: 31,
  instances: 65,
  events: 38,
  rollups: 60,
} as const;

export const MONITORING_DASHBOARD_ID = 'software-inventory-discovery-monitoring';

/** Catalog ids the EC and E2E cases create beyond the shared fixture lists. */
export const EXTRA_SYNTHETIC_CATALOG_IDS: readonly string[] = [
  ...EC9_SEED_CATALOG_IDS,
  ...EC11_SEED_CATALOG_IDS,
  E2E3_REPEAT_CATALOG_IDS.before,
  E2E3_REPEAT_CATALOG_IDS.after,
];

/** Workflows whose scheduled task must not exist after the run. */
export const TASK_FREE_WORKFLOW_IDS: readonly string[] = [
  SC_COPY_IDS.sched,
  SC_COPY_IDS.drop,
  SC9.workflowId,
];

const compact = (value: Readonly<Record<string, JsonValue | undefined>>): JsonObject =>
  Object.fromEntries(
    Object.entries(value).filter((entry): entry is [string, JsonValue] => entry[1] !== undefined)
  );

/** Catalog entry without its time fields; `checked` keeps whether it was ever checked. */
export const projectCatalog = (entry: CatalogEntry): JsonObject =>
  compact({
    id: entry.id,
    vendor: entry.vendor,
    product: entry.product,
    version: entry.version,
    display_name: entry.display_name,
    category: entry.category,
    cpe: entry.cpe,
    cve_count: entry.cve_count,
    max_cvss: entry.max_cvss,
    known_exploited: entry.known_exploited,
    fixed_in: entry.fixed_in,
    latest_known_fix: entry.latest_known_fix,
    fully_remediated: entry.fully_remediated,
    unfixed_cve_ids: entry.unfixed_cve_ids ? [...entry.unfixed_cve_ids] : undefined,
    remediation_caveat: entry.remediation_caveat ? [...entry.remediation_caveat] : undefined,
    cve_details: entry.cve_details?.map((detail) => compact({ ...detail })),
    first_published: entry.first_published,
    cve_ids: [...entry.cve_ids],
    checked: entry.cve_checked_at !== undefined,
    cve_check_failed: entry.cve_check_failed,
    cpe_match_confidence: entry.cpe_match_confidence,
  });

/** Instance without its time fields. */
export const projectInstance = (doc: InstanceDoc): JsonObject =>
  compact({
    id: doc.id,
    host: compact({ key: doc.host.key, id: doc.host.id, name: doc.host.name }),
    software_id: doc.software_id,
    previous_software_id: doc.previous_software_id,
    versions: doc.version_history.map((item) =>
      compact({ version: item.version, software_id: item.software_id })
    ),
    install_path: doc.install_path,
    sources: [...doc.sources].sort(),
    status: doc.status,
    exposure: compact({
      level: doc.exposure.level,
      score: doc.exposure.score,
      signals: doc.exposure.evidence.map(({ signal, weight }) => `${signal}:${weight}`).sort(),
    }),
  });

/** Event identity without its timestamp. */
export const eventKey = (event: InventoryEvent): string =>
  [
    event.instance_id,
    event.type,
    event.software_id,
    event.previous_software_id ?? '',
    event.from_version ?? '',
    event.to_version ?? '',
  ].join('|');

/** Rollup counts that do not depend on where the UTC day boundary falls. */
export const ROLLUP_STABLE_FIELDS = [
  'total_instances',
  'total_software',
  'vulnerable_instances',
  'critical_instances',
  'high_instances',
  'exposed_instances',
  'known_exploited_instances',
  'exposed_and_vulnerable_instances',
  'categories',
] as const;

export const projectRollup = (rollup: DailyRollup): JsonObject =>
  Object.fromEntries(ROLLUP_STABLE_FIELDS.map((field) => [field, { ...rollup }[field]]));

export interface ExpectedDemo {
  readonly catalog: readonly JsonObject[];
  readonly instances: readonly JsonObject[];
  readonly eventKeys: readonly string[];
  readonly rollupCount: number;
  /** Today's rollup as the seed computes it at `now`, keyed by its `_id`. */
  readonly todayRollup: { readonly id: string; readonly counts: JsonObject };
}

const byId = (a: JsonObject, b: JsonObject): number => String(a.id).localeCompare(String(b.id));

export const expectedDemo = (now: Date): ExpectedDemo => {
  const seed = generateSeedData(now);
  const today = seed.rollups[seed.rollups.length - 1];
  return {
    catalog: seed.catalog.map(projectCatalog).sort(byId),
    instances: seed.instances.map(projectInstance).sort(byId),
    eventKeys: seed.events.map(eventKey).sort(),
    rollupCount: seed.rollups.length,
    todayRollup: { id: today['@timestamp'].slice(0, 10), counts: projectRollup(today) },
  };
};

/** Pure: `count` consecutive UTC day ids ending today or yesterday (a restore near midnight). */
export const diffRollupDays = (ids: readonly string[], count: number, now: Date): string[] => {
  const sorted = [...ids].sort();
  const diffs: string[] = [];
  if (sorted.length !== count)
    diffs.push(`rollups: expected ${count} documents, got ${sorted.length}`);
  const day = 86_400_000;
  sorted.slice(1).forEach((id, index) => {
    if (Date.parse(id) - Date.parse(sorted[index]) !== day) {
      diffs.push(`rollups: ${sorted[index]} and ${id} are not consecutive UTC days`);
    }
  });
  const today = now.toISOString().slice(0, 10);
  const yesterday = new Date(now.getTime() - day).toISOString().slice(0, 10);
  const last = sorted[sorted.length - 1];
  if (last !== today && last !== yesterday)
    diffs.push(`rollups: latest day ${last}, expected ${today}`);
  return diffs;
};
