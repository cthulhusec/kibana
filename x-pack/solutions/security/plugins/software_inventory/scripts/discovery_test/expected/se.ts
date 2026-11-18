/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Expected outcomes of the SE cases (`score-exposure`): exposure per synthetic instance (SE-1..7),
 * the stale fixture (SE-10), and the pure rollup oracle (SE-11, SE-12). Instance ids come from
 * the plugin's `buildInstanceId` through `ids.ts`. Weights follow the plan: edge role 50, public
 * inbound 40 plus 2 per extra distinct source up to 10.
 */

import type { InstanceDoc, ExposureLevel, SoftwareCategory } from '../../../common/types';
import type { DailyRollup } from '../../../common/history';
import { parseCatalogId } from '../ids';

export const LOOKBACK_DAYS = 7;
export const STALE_AFTER_DAYS = 30;

export interface ExpectedEvidence {
  readonly signal: InstanceDoc['exposure']['evidence'][number]['signal'];
  readonly weight: number;
  /** Exact `detail`. */
  readonly detail?: string;
  /** Substrings `detail` must contain (the sampled source order is not stable). */
  readonly detailIncludes?: readonly string[];
  readonly detailExcludes?: readonly string[];
}

export interface ExposureExpectation {
  readonly hostKey: string;
  readonly catalogId: string;
  readonly level: ExposureLevel;
  readonly score: number;
  /** Evidence in stored order: kept manual evidence first, then edge, then inbound. */
  readonly evidence: readonly ExpectedEvidence[];
}

/** Detail text `score` writes for an edge instance, from the catalog entry's vendor and product. */
export const edgeDetail = (catalogId: string): string => {
  const { vendor, product } = parseCatalogId(catalogId);
  return `${vendor}/${product} is an edge or internet-facing device`;
};

const edge = (catalogId: string): ExpectedEvidence => ({
  signal: 'edge_device_role',
  weight: 50,
  detail: edgeDetail(catalogId),
});

const inbound = (
  weight: number,
  distinct: number,
  options: { includes?: readonly string[]; excludes?: readonly string[] } = {}
): ExpectedEvidence => ({
  signal: 'inbound_public_ip',
  weight,
  detailIncludes: [
    `${distinct} distinct public IP address(es) in the last ${LOOKBACK_DAYS} day(s)`,
    ...(options.includes ?? []),
  ],
  ...(options.excludes ? { detailExcludes: options.excludes } : {}),
});

const none = (hostKey: string, catalogId: string): ExposureExpectation => ({
  hostKey,
  catalogId,
  level: 'none',
  score: 0,
  evidence: [],
});

/** Manual evidence the harness writes on the `synth-web-02` nginx instance before the first run. */
export const MANUAL_EVIDENCE = {
  signal: 'manual',
  detail: 'synthetic manual',
  weight: 30,
} as const;

export const MANUAL_HOST_KEY = 'synth-web-02';
/** Either version of the flipped instance; the instance id ignores the version. */
export const MANUAL_CATALOG_ID = 'f5:nginx:1.27.4';

const PAN_OS_ID = 'palo_alto_networks:pan-os:10.2.3';

/** SE-1: three public sources, two documents each. */
export const SE1_WEB01: ExposureExpectation = {
  hostKey: 'synth-web-01',
  catalogId: 'synth-checkout:synth-checkout:2.4.0',
  level: 'medium',
  score: 44,
  evidence: [
    inbound(44, 3, {
      includes: ['8.8.8.8', '1.1.1.1', '9.9.9.9'],
      // Private sources and the 8-day-old public source must not be counted or sampled.
      excludes: ['10.1.2.3', '192.168.1.10', '5.5.5.5'],
    }),
  ],
};

/** SE-3: the PAN-OS appliance is an edge device and received 6 distinct public sources. */
export const SE3_FW02: ExposureExpectation = {
  hostKey: 'synth-fw-02',
  catalogId: PAN_OS_ID,
  level: 'high',
  score: 100,
  evidence: [edge(PAN_OS_ID), inbound(50, 6)],
};

/**
 * SE-4: collected appliances get the edge role only; their inbound traffic arrives under the
 * collector's host name (risk R6).
 */
export const SE4_EDGE_ONLY: readonly ExposureExpectation[] = [
  ['synth-fw-01', 'fortinet:fortios:7.2.4'],
  ['synth-fw-05', 'fortinet:fortios:7.0.11'],
  ['synth-sn-0003', 'cisco:adaptive_security_appliance_software:9.16.4'],
  ['192.0.2.77', 'f5:big-ip:16.1.4'],
  ['synth-edge-09', 'synthnet:edgebox:3.1'],
].map(([hostKey, catalogId]) => ({
  hostKey,
  catalogId,
  level: 'medium' as const,
  score: 50,
  evidence: [edge(catalogId)],
}));

/** SE-5: matched by `host.id`, direction `ingress`, one source. */
export const SE5_REDIS: ExposureExpectation = {
  hostKey: 'synth-hostid-0005',
  catalogId: 'redis:redis:7.0.11',
  level: 'medium',
  score: 40,
  evidence: [inbound(40, 1, { includes: ['208.67.222.222'] })],
};

/** SE-6: only the manual evidence the harness wrote; the no-direction document is ignored. */
export const SE6_WEB02: ExposureExpectation = {
  hostKey: MANUAL_HOST_KEY,
  catalogId: MANUAL_CATALOG_ID,
  level: 'low',
  score: 30,
  evidence: [MANUAL_EVIDENCE],
};

/** SE-7: Fleet policy pseudo-hosts ignore logs; the edge integration still counts as edge. */
export const SE7_POLICY: readonly ExposureExpectation[] = [
  {
    hostKey: 'policy:synth-pol-edge',
    catalogId: 'palo_alto_networks:pan-os:unknown',
    level: 'medium',
    score: 50,
    evidence: [edge('palo_alto_networks:pan-os:unknown')],
  },
  none('policy:synth-pol-edge', 'f5:nginx:unknown'),
  none('policy:synth-pol-web', 'f5:nginx:unknown'),
];

/** SE-2: outbound traffic only, so every instance on the host stays at `none`. */
export const SE2_HOST_KEY = 'synth-lin-01';

/** SE-10: the stale fixture. */
export const STALE_HOST_KEY = 'synth-mac-01';
export const STALE_CATALOG_ID = 'slack:slack:4.41.105';
export const STALE_LAST_SEEN_OFFSET_DAYS = 31;

const DAY_MS = 24 * 60 * 60 * 1000;
export const staleLastSeen = (t0: Date): string =>
  new Date(t0.getTime() - STALE_LAST_SEEN_OFFSET_DAYS * DAY_MS).toISOString();

// -------------------------------------------------------------------------------------------------
// Rollup oracle (SE-11, SE-12)
// -------------------------------------------------------------------------------------------------

export interface RollupInstanceRow {
  readonly software_id: string;
  readonly exposureLevel: ExposureLevel;
}

export interface RollupCatalogRow {
  readonly id: string;
  readonly category?: SoftwareCategory;
  readonly cve_count?: number;
  readonly max_cvss?: number;
  readonly known_exploited?: boolean;
}

export interface RollupEventCounts {
  readonly first_seen: number;
  readonly version_changed: number;
  readonly removed: number;
}

const CATEGORIES: readonly SoftwareCategory[] = [
  'application',
  'dependency',
  'appliance',
  'os_package',
  'other',
];

/**
 * The rollup `snapshot_rollup` should write for `dayStart`, computed from the active and patched
 * instances, the catalog, and the day's event counts. Independent of the plugin's aggregations.
 */
export const computeRollupOracle = ({
  dayStart,
  instances,
  catalog,
  events,
}: {
  dayStart: string;
  instances: readonly RollupInstanceRow[];
  catalog: readonly RollupCatalogRow[];
  events: RollupEventCounts;
}): DailyRollup => {
  const byId = new Map(catalog.map((entry) => [entry.id, entry]));
  const count = (
    predicate: (entry: RollupCatalogRow | undefined, row: RollupInstanceRow) => boolean
  ) => instances.filter((row) => predicate(byId.get(row.software_id), row)).length;
  const vulnerable = (entry: RollupCatalogRow | undefined) => (entry?.cve_count ?? 0) > 0;
  const exposed = (row: RollupInstanceRow) =>
    row.exposureLevel === 'medium' || row.exposureLevel === 'high';
  const cvss = (entry: RollupCatalogRow | undefined) => entry?.max_cvss ?? 0;
  return {
    '@timestamp': dayStart,
    total_instances: instances.length,
    total_software: new Set(instances.map(({ software_id: id }) => id)).size,
    vulnerable_instances: count(vulnerable),
    critical_instances: count((entry) => entry !== undefined && cvss(entry) >= 9),
    high_instances: count((entry) => entry !== undefined && cvss(entry) >= 7 && cvss(entry) < 9),
    exposed_instances: count((_, row) => exposed(row)),
    known_exploited_instances: count((entry) => entry?.known_exploited === true),
    exposed_and_vulnerable_instances: count((entry, row) => vulnerable(entry) && exposed(row)),
    new_instances: events.first_seen,
    patched_instances: events.version_changed,
    removed_instances: events.removed,
    categories: Object.fromEntries(
      CATEGORIES.map((category) => [
        category,
        count((entry) => entry !== undefined && (entry.category ?? 'other') === category),
      ])
    ) as Record<SoftwareCategory, number>,
  };
};

/** Start of the UTC day, ISO, for a `YYYY-MM-DD` rollup id. */
export const dayStartOf = (date: string): string => `${date}T00:00:00.000Z`;
export const dayEndOf = (date: string): string =>
  new Date(Date.parse(dayStartOf(date)) + DAY_MS).toISOString();
