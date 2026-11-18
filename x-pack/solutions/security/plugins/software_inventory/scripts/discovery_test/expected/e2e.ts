/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Expected outcomes of the cross-workflow end-to-end cases (E2E-1..E2E-5). Times are relative to
 * the T0 that E2E-1 generates its logs with (recorded as E2E-1 evidence).
 */

import { FLEET_MAPPED_AND_UNMAPPED } from '../fixtures/fleet';
import { R1, R1_DEPENDENCY_ROWS } from '../fixtures/osquery';
import {
  EXPECTED_DL1_INGEST,
  EXPECTED_DL7_INGEST,
  EXPECTED_PHASE_A_CANDIDATES,
  EXPECTED_PHASE_B_CANDIDATE,
} from '../logs/generate_logs';
import { EC_IDS, catalogIdForCandidate } from './ec';

export const HOUR_MS = 3_600_000;
export const DAY_MS = 24 * HOUR_MS;

/** `limit` of the EC run in E2E-1 (raised when more entries are never checked). */
export const E2E_ENRICH_LIMIT = 40;

export const E2E_INGEST = {
  /** Phase A `discover-logs` after `R1` and DI-2. */
  dl1: EXPECTED_DL1_INGEST,
  /** Phase B `discover-logs` (version flip on `synth-web-02`). */
  dl7: EXPECTED_DL7_INGEST,
  di2: FLEET_MAPPED_AND_UNMAPPED.expected.ingest,
} as const;

/** New synthetic instances: 13 (R1) + 3 (Fleet) + 9 (logs; nginx on synth-lin-01 is shared). */
export const E2E_SYNTHETIC_INSTANCES =
  Object.values(R1).reduce((sum, fixture) => sum + (fixture.expected.ingest?.created ?? 0), 0) +
  (FLEET_MAPPED_AND_UNMAPPED.expected.ingest.created ?? 0) +
  EXPECTED_DL1_INGEST.created;

/** Events the pipeline writes on synthetic hosts. */
export const E2E_EVENT_COUNTS = {
  first_seen: E2E_SYNTHETIC_INSTANCES,
  version_changed: 1,
} as const;

/** Catalog entries the EC run of E2E-1 must have checked (everything created before it). */
export const E2E_CHECKED_CATALOG_IDS: readonly string[] = [
  ...new Set([
    ...Object.values(R1).flatMap((fixture) => fixture.expected.catalogIds ?? []),
    ...FLEET_MAPPED_AND_UNMAPPED.expected.instances.map(({ catalogId }) => catalogId),
    ...EXPECTED_PHASE_A_CANDIDATES.map(({ catalogId }) => catalogId),
  ]),
].sort();

/** Created by phase B, after the EC run, so never checked. */
export const E2E_UNCHECKED_CATALOG_ID = EXPECTED_PHASE_B_CANDIDATE.catalogId;

// E2E-2: synth-web-02 ran nginx 1.25.2 (CVE-2023-44487) from T0-20h until the patch at T0-1h.
export const E2E2_HOST = 'synth-web-02';
export const E2E2_CVE_IDS = ['CVE-2023-44487'];
const VULNERABLE_FROM_OFFSET_MS = 20 * HOUR_MS;
const PATCHED_AT_OFFSET_MS = HOUR_MS;
export const E2E2_DURATION_TOLERANCE_MS = 60_000;
/** Tolerance for timestamps that the pipeline derives from log `@timestamp` values. */
export const E2E_TIMESTAMP_TOLERANCE_MS = 1000;

export interface TimelineExpectation {
  readonly label: string;
  readonly from: string;
  readonly to: string;
  readonly vulnerableInRange: boolean;
  readonly firstVulnerableAt?: string;
  readonly cveIds?: readonly string[];
  readonly vulnerableDurationMs?: number;
  /** The instance must not appear in `items`. */
  readonly itemAbsent?: boolean;
}

const iso = (ms: number): string => new Date(ms).toISOString();

/** The three `synth-web-02` timeline queries of E2E-2. */
export const e2e2Expectations = (t0: Date, now: Date): TimelineExpectation[] => {
  const t0Ms = t0.getTime();
  return [
    {
      label: 'from T0-3d to now',
      from: iso(t0Ms - 3 * DAY_MS),
      to: now.toISOString(),
      vulnerableInRange: true,
      firstVulnerableAt: iso(t0Ms - VULNERABLE_FROM_OFFSET_MS),
      cveIds: E2E2_CVE_IDS,
      vulnerableDurationMs: VULNERABLE_FROM_OFFSET_MS - PATCHED_AT_OFFSET_MS,
    },
    {
      label: 'from T0-30m to now',
      from: iso(t0Ms - 30 * 60_000),
      to: now.toISOString(),
      vulnerableInRange: false,
    },
    {
      label: 'from T0-3d to T0-21h',
      from: iso(t0Ms - 3 * DAY_MS),
      to: iso(t0Ms - 21 * HOUR_MS),
      vulnerableInRange: false,
      itemAbsent: true,
    },
  ];
};

// E2E-3: posture on the patch event.
export const E2E3_POSTURE_BEFORE = {
  cve_count_before: 1,
  max_cvss_before: 7.5,
  known_exploited_before: false,
  cve_count_after: undefined,
  max_cvss_after: undefined,
  known_exploited_after: undefined,
} as const;

export const E2E3_NO_POSTURE = {
  cve_count_before: undefined,
  max_cvss_before: undefined,
  known_exploited_before: undefined,
  cve_count_after: undefined,
  max_cvss_after: undefined,
  known_exploited_after: undefined,
} as const;

/**
 * The "EC after phase B" repeat runs on its own host so it does not disturb the E2E-1 state: nginx
 * versions that no other fixture uses, so neither catalog entry is ever checked before the patch.
 */
export const E2E3_REPEAT = {
  hostKey: 'synth-web-04',
  before: '1.25.1',
  after: '1.27.5',
  beforeOffsetMs: 2 * HOUR_MS,
  afterOffsetMs: 60_000,
} as const;

const repeatCatalogId = (version: string): string =>
  catalogIdForCandidate(
    {
      host_id: E2E3_REPEAT.hostKey,
      host_name: E2E3_REPEAT.hostKey,
      name: 'nginx',
      version,
      category: 'application',
    },
    'logs'
  );

export const E2E3_REPEAT_CATALOG_IDS = {
  before: repeatCatalogId(E2E3_REPEAT.before),
  after: repeatCatalogId(E2E3_REPEAT.after),
} as const;

// E2E-4: the log4j host.
export const E2E4_HOST = 'synth-lin-01';
export const E2E4_CVE_IDS = [
  'CVE-2021-44228',
  'CVE-2021-44832',
  'CVE-2021-45046',
  'CVE-2021-45105',
] as const;
const LOG4J_ROW = R1_DEPENDENCY_ROWS.find(({ catalogId }) => catalogId === EC_IDS.log4j2141);
export const E2E4_LOG4J = {
  hostKey: E2E4_HOST,
  catalogId: EC_IDS.log4j2141,
  installPath: LOG4J_ROW?.installPath,
} as const;

// E2E-5: the instances route filtered by the Osquery agent id.
export const E2E5_HOST_ID = 'synth-agent-lin01';
