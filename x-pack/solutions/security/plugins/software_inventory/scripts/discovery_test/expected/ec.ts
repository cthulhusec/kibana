/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Expected outcomes of the enrich-cves cases (EC-1..EC-12), from the "NVD and KEV stub" table of
 * docs/discovery_test_plan.md, with the corrected per-CVE log4j fixes. Catalog ids come from the
 * plugin's own normalization; the CPE strings are the plan's literal values (what the stub must
 * see), and the jest suite proves both against the plugin code.
 */

import type { CatalogEntry, DiscoverySource, RawCandidate } from '../../../common/types';
import { normalizeCandidate } from '../../../server/services/ingest/normalize_candidate';
import { AGENTS, row } from '../fixtures/osquery';
import type { OsqueryRow } from '../fixtures/osquery';
import { buildCatalogId } from '../ids';

/** Catalog id the ingest step derives for a raw candidate of `source`. */
export const catalogIdForCandidate = (raw: RawCandidate, source: DiscoverySource): string => {
  const normalized = normalizeCandidate(raw, new Date(0).toISOString(), source);
  if (!normalized) throw new Error(`Candidate ${raw.name} does not normalize`);
  return buildCatalogId(normalized.vendor, normalized.product, normalized.version);
};

/** Catalog id of an Osquery Linux package row (category `os_package`). */
export const catalogIdForLinuxRow = (osqueryRow: OsqueryRow): string =>
  catalogIdForCandidate(
    {
      host_id: osqueryRow.agent.id,
      ...(osqueryRow.agent.name ? { host_name: osqueryRow.agent.name } : {}),
      name: osqueryRow.columns.name,
      version: osqueryRow.columns.version,
      category: 'os_package',
    },
    'osquery'
  );

export const EC_IDS = {
  log4j2141: buildCatalogId('apache', 'log4j', '2.14.1'),
  log4j2121: buildCatalogId('apache', 'log4j', '2.12.1'),
  synthCheckout: buildCatalogId('synth-checkout', 'synth-checkout', '2.4.0'),
  fortios724: buildCatalogId('fortinet', 'fortios', '7.2.4'),
  panos1023: buildCatalogId('palo_alto_networks', 'pan-os', '10.2.3'),
  nginx1252: buildCatalogId('f5', 'nginx', '1.25.2'),
  slack: buildCatalogId('slack', 'slack', '4.41.105'),
  chrome: buildCatalogId('google', 'chrome', '131.0.6778.86'),
  sevenZip: buildCatalogId('7-zip', '7-zip', '23.01'),
  vscode: buildCatalogId('microsoft', 'visual_studio_code', '1.95.3'),
  panosUnknown: buildCatalogId('palo_alto_networks', 'pan-os', 'unknown'),
  nginxUnknown: buildCatalogId('f5', 'nginx', 'unknown'),
} as const;

/** The `cpeName` values the stub must receive (plan literals). */
export const EC_CPES = {
  log4j2141: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
  log4j2121: 'cpe:2.3:a:apache:log4j:2.12.1:*:*:*:*:*:*:*',
  synthCheckout: 'cpe:2.3:a:synth-checkout:synth-checkout:2.4.0:*:*:*:*:*:*:*',
  fortios724: 'cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*',
  panos1023: 'cpe:2.3:o:paloaltonetworks:pan-os:10.2.3:*:*:*:*:*:*:*',
  nginx1252: 'cpe:2.3:a:f5:nginx:1.25.2:*:*:*:*:*:*:*',
  slack: 'cpe:2.3:a:slack:slack:4.41.105:*:*:*:*:*:*:*',
  chrome: 'cpe:2.3:a:google:chrome:131.0.6778.86:*:*:*:*:*:*:*',
  sevenZip: 'cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*',
  vscode: 'cpe:2.3:a:microsoft:visual_studio_code:1.95.3:*:*:*:*:*:*:*',
} as const;

/**
 * Catalog entries EC-1 needs (created by DO-1, DI-2, and DL-1), every one never checked before the
 * big run.
 */
export const EC_REQUIRED_CATALOG_IDS: readonly string[] = Object.values(EC_IDS);

/** Entries with a version of `unknown` (Fleet): checked without any NVD request (EC-5). */
export const EC_UNKNOWN_VERSION_IDS: readonly string[] = [EC_IDS.panosUnknown, EC_IDS.nginxUnknown];

type ExpectedFields = Readonly<Partial<Record<keyof CatalogEntry, ExpectedValue>>>;
type ExpectedValue =
  | string
  | number
  | boolean
  | null
  | readonly string[]
  | ReadonlyArray<Readonly<Record<string, string | number | boolean>>>;

const LOG4J_CVE_IDS = ['CVE-2021-44228', 'CVE-2021-44832', 'CVE-2021-45046', 'CVE-2021-45105'];
const LOG4J_FIRST_PUBLISHED = '2021-12-10T10:15:09.143Z';

/** EC-1: multi-CVE, safe version on the 2.13+ branch; `cve_details` sorted by CVSS. */
export const EXPECTED_LOG4J_2_14_1: ExpectedFields = {
  cpe: EC_CPES.log4j2141,
  cve_ids: LOG4J_CVE_IDS,
  cve_count: 4,
  max_cvss: 10,
  fixed_in: '2.17.1',
  latest_known_fix: '2.17.1',
  fully_remediated: true,
  unfixed_cve_ids: [],
  known_exploited: true,
  first_published: LOG4J_FIRST_PUBLISHED,
  cve_check_failed: false,
  cve_details: [
    {
      id: 'CVE-2021-44228',
      cvss: 10,
      published: LOG4J_FIRST_PUBLISHED,
      fixed_in: '2.15.0',
      known_exploited: true,
    },
    {
      id: 'CVE-2021-45046',
      cvss: 9,
      published: '2021-12-14T12:15:07.700Z',
      fixed_in: '2.16.0',
      known_exploited: true,
    },
    {
      id: 'CVE-2021-44832',
      cvss: 6.6,
      published: '2021-12-28T21:15:08.150Z',
      fixed_in: '2.17.1',
      known_exploited: false,
    },
    {
      id: 'CVE-2021-45105',
      cvss: 5.9,
      published: '2021-12-18T12:15:07.558Z',
      fixed_in: '2.17.0',
      known_exploited: false,
    },
  ],
};

/** EC-2: multi-branch; the minimal safe version stays on the 2.12 branch. */
export const EXPECTED_LOG4J_2_12_1: ExpectedFields = {
  cpe: EC_CPES.log4j2121,
  cve_count: 4,
  max_cvss: 10,
  fixed_in: '2.12.4',
  latest_known_fix: '2.17.1',
  fully_remediated: true,
  unfixed_cve_ids: [],
  known_exploited: true,
  cve_check_failed: false,
};

/** EC-3: a CVE with no fixed version. */
export const EXPECTED_SYNTH_CHECKOUT: ExpectedFields = {
  cpe: EC_CPES.synthCheckout,
  cve_ids: ['CVE-2099-0001'],
  cve_count: 1,
  max_cvss: 7.5,
  fixed_in: null,
  fully_remediated: false,
  unfixed_cve_ids: ['CVE-2099-0001'],
  known_exploited: false,
  cve_check_failed: false,
};

/** EC-3 companions from the stub table: a single-range fix and a clean product. */
export const EXPECTED_NGINX_1_25_2: ExpectedFields = {
  cpe: EC_CPES.nginx1252,
  cve_ids: ['CVE-2023-44487'],
  cve_count: 1,
  max_cvss: 7.5,
  fixed_in: '1.25.3',
  fully_remediated: true,
  known_exploited: false,
  cve_check_failed: false,
};

export const EXPECTED_SLACK: ExpectedFields = {
  cpe: EC_CPES.slack,
  cve_ids: [],
  cve_count: 0,
  fully_remediated: true,
  known_exploited: false,
  cve_check_failed: false,
};

/** EC-4: appliance OS products use CPE part `o`; PAN-OS uses the NVD vendor alias. */
export const EXPECTED_FORTIOS_7_2_4: ExpectedFields = {
  cpe: EC_CPES.fortios724,
  cve_ids: ['CVE-2023-27997'],
  cve_count: 1,
  max_cvss: 9.8,
  fixed_in: '7.2.5',
  known_exploited: true,
  cve_check_failed: false,
};

export const EXPECTED_PANOS_10_2_3: ExpectedFields = {
  cpe: EC_CPES.panos1023,
  cve_ids: ['CVE-2024-3400'],
  cve_count: 1,
  max_cvss: 10,
  fixed_in: '10.2.9-h1',
  known_exploited: true,
  cve_check_failed: false,
};

/** EC-6: retried twice on 429, then checked with no CVEs. */
export const EXPECTED_CHROME: ExpectedFields = {
  cpe: EC_CPES.chrome,
  cve_count: 0,
  cve_ids: [],
  cve_check_failed: false,
};

/** EC-7 and EC-8: failure marker; the CVE fields keep their ingest defaults. */
export const EXPECTED_FAILURE_MARKER: ExpectedFields = {
  cve_check_failed: true,
  cve_count: 0,
  cve_ids: [],
};

/** Stub responses per CPE that EC-6..EC-8 analyze, with the retries `fetchNvd` makes. */
export const EC_RETRY_EXPECTATIONS = {
  /** 429, 429, then 200: two retries, waits `b` and `2b`. */
  chrome: { cpe: EC_CPES.chrome, statuses: [429, 429, 200], retries: 2, perAttempt: 'none' },
  /** Always 403: three retries, waits `b`, `2b`, `4b`. */
  sevenZip: {
    cpe: EC_CPES.sevenZip,
    statuses: [403, 403, 403, 403],
    retries: 3,
    perAttempt: 'none',
  },
  /** Never answers: four timed-out attempts, request starts `T + b`, `T + 2b`, `T + 4b` apart. */
  vscode: { cpe: EC_CPES.vscode, statuses: [0, 0, 0, 0], retries: 3, perAttempt: 'timeout' },
} as const;

/** Never-checked entries EC-9 seeds (offline network): two real versions on `synth-agent-lin03`. */
export const EC9_SEED_ROWS: readonly OsqueryRow[] = [
  row(AGENTS.lin03, 'synth-ec-offline-a', '1.0.0'),
  row(AGENTS.lin03, 'synth-ec-offline-b', '2.0.0'),
];

/** The never-checked entry EC-11 seeds so the first run shows "never checked first". */
export const EC11_SEED_ROWS: readonly OsqueryRow[] = [
  row(AGENTS.lin03, 'synth-ec-order-a', '1.0.0'),
];

export const EC9_SEED_CATALOG_IDS: readonly string[] = EC9_SEED_ROWS.map(catalogIdForLinuxRow);
export const EC11_SEED_CATALOG_IDS: readonly string[] = EC11_SEED_ROWS.map(catalogIdForLinuxRow);

/** `limit` of the two EC-11 runs. */
export const EC11_LIMIT = 3;

/** Products of the DO-16 bulk generator; the EC cases park them (see `parkBulkEntries`). */
export const BULK_PRODUCT_PREFIX = 'synth-pkg-';

/** Above this many never-checked entries the big EC-1 run is refused as unexpected state. */
export const EC_MAX_NEVER_CHECKED = 200;

/** The plan's `config/kibana.dev.yml` values for the stub. */
export const PLAN_STUB_TIMING = { spacingMs: 100, timeoutMs: 2000, backoffBaseMs: 200 } as const;
