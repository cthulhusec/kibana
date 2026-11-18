/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { buildCatalogId, normalizeToken } from '../../common/normalize';
import { buildHostKey, buildInstanceId } from '../../server/lib/instance_identity';
import { maxVersion } from '../../server/services/enrichment/compare_versions';
import { getRemediationCaveats } from '../../server/services/enrichment/remediation';
import type { DailyRollup, InventoryEvent } from '../../common/history';
import { DEFAULT_STALE_AFTER_DAYS } from '../../common/constants';
import type {
  CatalogEntry,
  CveDetail,
  DiscoverySource,
  ExposureEvidence,
  ExposureLevel,
  InstanceDoc,
  InstanceStatus,
  SoftwareCategory,
} from '../../common/types';

/*
 * SYNTHETIC DEMO DATA. Every host, install path and timestamp generated here is fake. CVE ids
 * come from public advisories but the product-to-host assignments are invented for the demo.
 *
 * Demo scenarios for "was this host vulnerable over this 3-day period?" (all relative to `now`):
 * - web-patched-2d-ago:    vulnerable (Log4j 2.14.1, OpenSSH 9.7p1) until both were patched 2 days
 *                          ago, so a window of the last 3 days straddles the patch.
 * - web-patched-20d-ago:   patched (Log4j, OpenSSL) 20 days ago, so a 3-day window last week is clean.
 * - app-always-vulnerable: Log4j 2.14.1 and lodash 4.17.15 for 150 days, never patched.
 * - app-never-vulnerable:  only patched versions (Log4j 2.17.1, OpenSSL 3.0.13, nginx 1.27.3).
 *
 * Other patches are spread over the last 30 days (web-prod-02, bastion, db and mac hosts).
 * Only instances with status `patched` have a patch within 7 days; older patches keep status
 * `active` and show up through `previous_software_id` / `version_history`.
 *
 * Events cover the last 90 days only. A `stale` event is stamped last_seen + the stale window, the
 * time the mark-stale step would have run. No `revived` events are seeded because no instance
 * status implies one.
 *
 * Rollup simplification: exposure comes from the instance's CURRENT exposure level for every day
 * the instance counts (exposure history is not modelled).
 */

const DAY_MS = 86_400_000;

/** Mulberry32: small deterministic PRNG, so the same `now` always yields the same dataset. */
const createRandom = (seed: number): (() => number) => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

/**
 * One CVE of a seeded entry. Only values from the public advisories are filled in; a field we could
 * not confirm is left out (a missing `fixedIn` reads as "no known fix").
 */
interface SeedCve {
  id: string;
  cvss?: number;
  /** NVD publish date (date only). */
  published?: string;
  /** Nearest fixed version on the entry's release branch. */
  fixedIn?: string;
  kev?: boolean;
}

interface CatalogSpec {
  key: string;
  vendor: string;
  product: string;
  version: string;
  displayName: string;
  category: SoftwareCategory;
  cpe: string;
  cves?: readonly SeedCve[];
  /** Fix on a newer release branch, when higher than the minimal safe version. */
  latestKnownFix?: string;
  /** False leaves `cve_checked_at` unset to show an un-enriched entry. */
  checked?: boolean;
  confidence?: number;
}

const CVE_LOG4SHELL: SeedCve = {
  id: 'CVE-2021-44228',
  cvss: 10,
  published: '2021-12-10',
  fixedIn: '2.15.0',
  kev: true,
};
const CVE_LOG4J_45046: SeedCve = {
  id: 'CVE-2021-45046',
  cvss: 9,
  published: '2021-12-14',
  fixedIn: '2.16.0',
};
const CVE_LOG4J_45105: SeedCve = {
  id: 'CVE-2021-45105',
  cvss: 5.9,
  published: '2021-12-18',
  fixedIn: '2.17.0',
};
const CVE_LOG4J_44832: SeedCve = {
  id: 'CVE-2021-44832',
  cvss: 6.6,
  published: '2021-12-28',
  fixedIn: '2.17.1',
};

const CATALOG_SPECS: readonly CatalogSpec[] = [
  {
    key: 'log4j_2_14_1',
    vendor: 'apache',
    product: 'log4j-core',
    version: '2.14.1',
    displayName: 'Apache Log4j Core 2.14.1',
    category: 'dependency',
    cpe: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
    cves: [CVE_LOG4SHELL, CVE_LOG4J_45046, CVE_LOG4J_45105, CVE_LOG4J_44832],
  },
  {
    key: 'log4j_2_17_1',
    vendor: 'apache',
    product: 'log4j-core',
    version: '2.17.1',
    displayName: 'Apache Log4j Core 2.17.1',
    category: 'dependency',
    cpe: 'cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*',
  },
  {
    key: 'openssl_3_0_2',
    vendor: 'openssl',
    product: 'openssl',
    version: '3.0.2',
    displayName: 'OpenSSL 3.0.2',
    category: 'os_package',
    cpe: 'cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*',
    cves: [
      { id: 'CVE-2022-3602', cvss: 7.5, published: '2022-11-01', fixedIn: '3.0.7' },
      { id: 'CVE-2022-3786', cvss: 7.5, published: '2022-11-01', fixedIn: '3.0.7' },
    ],
  },
  {
    key: 'openssl_3_0_13',
    vendor: 'openssl',
    product: 'openssl',
    version: '3.0.13',
    displayName: 'OpenSSL 3.0.13',
    category: 'os_package',
    cpe: 'cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*',
  },
  {
    key: 'openssh_9_7',
    vendor: 'openbsd',
    product: 'openssh',
    version: '9.7p1',
    displayName: 'OpenSSH 9.7p1',
    category: 'os_package',
    cpe: 'cpe:2.3:a:openbsd:openssh:9.7:p1:*:*:*:*:*:*',
    cves: [{ id: 'CVE-2024-6387', cvss: 8.1, published: '2024-07-01', fixedIn: '9.8p1' }],
  },
  {
    key: 'openssh_9_8',
    vendor: 'openbsd',
    product: 'openssh',
    version: '9.8p1',
    displayName: 'OpenSSH 9.8p1',
    category: 'os_package',
    cpe: 'cpe:2.3:a:openbsd:openssh:9.8:p1:*:*:*:*:*:*',
  },
  // The fixed version for CVE-2024-7347 is not confirmed here, so it is seeded as unfixed.
  {
    key: 'nginx_1_25_3',
    vendor: 'f5',
    product: 'nginx',
    version: '1.25.3',
    displayName: 'nginx 1.25.3',
    category: 'application',
    cpe: 'cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*',
    cves: [{ id: 'CVE-2024-7347', cvss: 4.7, published: '2024-08-14' }],
  },
  {
    key: 'nginx_1_27_3',
    vendor: 'f5',
    product: 'nginx',
    version: '1.27.3',
    displayName: 'nginx 1.27.3',
    category: 'application',
    cpe: 'cpe:2.3:a:f5:nginx:1.27.3:*:*:*:*:*:*:*',
  },
  {
    key: 'httpd_2_4_58',
    vendor: 'apache',
    product: 'http_server',
    version: '2.4.58',
    displayName: 'Apache HTTP Server 2.4.58',
    category: 'application',
    cpe: 'cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*',
    cves: [{ id: 'CVE-2024-38475', cvss: 9.1, published: '2024-07-01', fixedIn: '2.4.60' }],
  },
  {
    key: 'httpd_2_4_49',
    vendor: 'apache',
    product: 'http_server',
    version: '2.4.49',
    displayName: 'Apache HTTP Server 2.4.49',
    category: 'application',
    cpe: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*',
    cves: [
      { id: 'CVE-2021-41773', cvss: 7.5, published: '2021-10-05', fixedIn: '2.4.50', kev: true },
      { id: 'CVE-2021-42013', cvss: 9.8, published: '2021-10-07', fixedIn: '2.4.51', kev: true },
    ],
  },
  {
    key: 'chrome_120',
    vendor: 'google',
    product: 'chrome',
    version: '120.0.6099.109',
    displayName: 'Google Chrome 120.0.6099.109',
    category: 'application',
    cpe: 'cpe:2.3:a:google:chrome:120.0.6099.109:*:*:*:*:*:*:*',
    cves: [
      {
        id: 'CVE-2023-7024',
        cvss: 8.8,
        published: '2023-12-21',
        fixedIn: '120.0.6099.129',
        kev: true,
      },
    ],
  },
  {
    key: 'chrome_131',
    vendor: 'google',
    product: 'chrome',
    version: '131.0.6778.85',
    displayName: 'Google Chrome 131.0.6778.85',
    category: 'application',
    cpe: 'cpe:2.3:a:google:chrome:131.0.6778.85:*:*:*:*:*:*:*',
    confidence: 0.55,
  },
  {
    key: '7zip_22_01',
    vendor: '7-zip',
    product: '7-zip',
    version: '22.01',
    displayName: '7-Zip 22.01',
    category: 'application',
    cpe: 'cpe:2.3:a:7-zip:7-zip:22.01:*:*:*:*:*:*:*',
    cves: [{ id: 'CVE-2023-31102', cvss: 7.8, fixedIn: '23.01' }],
  },
  {
    key: '7zip_24_09',
    vendor: '7-zip',
    product: '7-zip',
    version: '24.09',
    displayName: '7-Zip 24.09',
    category: 'application',
    cpe: 'cpe:2.3:a:7-zip:7-zip:24.09:*:*:*:*:*:*:*',
  },
  {
    key: 'notepadpp_8_6_2',
    vendor: 'notepad-plus-plus',
    product: 'notepad++',
    version: '8.6.2',
    displayName: 'Notepad++ 8.6.2',
    category: 'application',
    cpe: 'cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.6.2:*:*:*:*:*:*:*',
    checked: false,
    confidence: 0.5,
  },
  {
    key: 'jackson_2_13_1',
    vendor: 'fasterxml',
    product: 'jackson-databind',
    version: '2.13.1',
    displayName: 'jackson-databind 2.13.1',
    category: 'dependency',
    cpe: 'cpe:2.3:a:fasterxml:jackson-databind:2.13.1:*:*:*:*:*:*:*',
    cves: [{ id: 'CVE-2020-36518', cvss: 7.5, published: '2022-03-11', fixedIn: '2.13.2.1' }],
  },
  {
    key: 'jackson_2_15_2',
    vendor: 'fasterxml',
    product: 'jackson-databind',
    version: '2.15.2',
    displayName: 'jackson-databind 2.15.2',
    category: 'dependency',
    cpe: 'cpe:2.3:a:fasterxml:jackson-databind:2.15.2:*:*:*:*:*:*:*',
  },
  {
    key: 'spring_5_3_17',
    vendor: 'vmware',
    product: 'spring-framework',
    version: '5.3.17',
    displayName: 'Spring Framework 5.3.17',
    category: 'dependency',
    cpe: 'cpe:2.3:a:vmware:spring_framework:5.3.17:*:*:*:*:*:*:*',
    cves: [
      { id: 'CVE-2022-22965', cvss: 9.8, published: '2022-04-01', fixedIn: '5.3.18', kev: true },
    ],
  },
  {
    key: 'spring_6_1_14',
    vendor: 'vmware',
    product: 'spring-framework',
    version: '6.1.14',
    displayName: 'Spring Framework 6.1.14',
    category: 'dependency',
    cpe: 'cpe:2.3:a:vmware:spring_framework:6.1.14:*:*:*:*:*:*:*',
  },
  {
    key: 'lodash_4_17_15',
    vendor: 'lodash',
    product: 'lodash',
    version: '4.17.15',
    displayName: 'lodash 4.17.15',
    category: 'dependency',
    cpe: 'cpe:2.3:a:lodash:lodash:4.17.15:*:*:*:*:node.js:*:*',
    cves: [
      { id: 'CVE-2020-8203', cvss: 7.4, published: '2020-07-15', fixedIn: '4.17.19' },
      { id: 'CVE-2021-23337', cvss: 7.2, published: '2021-02-15', fixedIn: '4.17.21' },
    ],
  },
  {
    key: 'lodash_4_17_21',
    vendor: 'lodash',
    product: 'lodash',
    version: '4.17.21',
    displayName: 'lodash 4.17.21',
    category: 'dependency',
    cpe: 'cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:node.js:*:*',
  },
  {
    key: 'express_4_17_1',
    vendor: 'expressjs',
    product: 'express',
    version: '4.17.1',
    displayName: 'Express 4.17.1',
    category: 'dependency',
    cpe: 'cpe:2.3:a:expressjs:express:4.17.1:*:*:*:*:node.js:*:*',
    cves: [
      { id: 'CVE-2024-29041', cvss: 6.1, published: '2024-03-25', fixedIn: '4.19.2' },
      { id: 'CVE-2024-43796', published: '2024-09-10', fixedIn: '4.20.0' },
    ],
  },
  {
    key: 'django_3_2_12',
    vendor: 'djangoproject',
    product: 'django',
    version: '3.2.12',
    displayName: 'Django 3.2.12',
    category: 'dependency',
    cpe: 'cpe:2.3:a:djangoproject:django:3.2.12:*:*:*:*:*:*:*',
    cves: [
      { id: 'CVE-2022-28346', cvss: 9.8, published: '2022-04-12', fixedIn: '3.2.13' },
      { id: 'CVE-2022-28347', cvss: 9.8, published: '2022-04-12', fixedIn: '3.2.13' },
    ],
    latestKnownFix: '4.0.4',
  },
  {
    key: 'django_4_2_16',
    vendor: 'djangoproject',
    product: 'django',
    version: '4.2.16',
    displayName: 'Django 4.2.16',
    category: 'dependency',
    cpe: 'cpe:2.3:a:djangoproject:django:4.2.16:*:*:*:*:*:*:*',
    checked: false,
  },
  {
    key: 'curl_7_81_0',
    vendor: 'haxx',
    product: 'curl',
    version: '7.81.0',
    displayName: 'curl 7.81.0',
    category: 'os_package',
    cpe: 'cpe:2.3:a:haxx:curl:7.81.0:*:*:*:*:*:*:*',
    cves: [{ id: 'CVE-2023-38545', cvss: 9.8, published: '2023-10-18', fixedIn: '8.4.0' }],
  },
  {
    key: 'sudo_1_9_5p1',
    vendor: 'sudo_project',
    product: 'sudo',
    version: '1.9.5p1',
    displayName: 'sudo 1.9.5p1',
    category: 'os_package',
    cpe: 'cpe:2.3:a:sudo_project:sudo:1.9.5:p1:*:*:*:*:*:*',
    cves: [
      { id: 'CVE-2021-3156', cvss: 7.8, published: '2021-01-26', fixedIn: '1.9.5p2', kev: true },
    ],
  },
  {
    key: 'postgres_15_3',
    vendor: 'postgresql',
    product: 'postgresql',
    version: '15.3',
    displayName: 'PostgreSQL 15.3',
    category: 'application',
    cpe: 'cpe:2.3:a:postgresql:postgresql:15.3:*:*:*:*:*:*:*',
    cves: [{ id: 'CVE-2023-39417', cvss: 8.8, fixedIn: '15.4' }],
  },
  {
    key: 'panos_10_2_8',
    vendor: 'paloaltonetworks',
    product: 'pan-os',
    version: '10.2.8',
    displayName: 'Palo Alto PAN-OS 10.2.8',
    category: 'appliance',
    cpe: 'cpe:2.3:o:paloaltonetworks:pan-os:10.2.8:*:*:*:*:*:*:*',
    cves: [
      { id: 'CVE-2024-3400', cvss: 10, published: '2024-04-12', fixedIn: '10.2.9-h1', kev: true },
    ],
  },
  {
    key: 'fortios_7_0_6',
    vendor: 'fortinet',
    product: 'fortios',
    version: '7.0.6',
    displayName: 'Fortinet FortiOS 7.0.6',
    category: 'appliance',
    cpe: 'cpe:2.3:o:fortinet:fortios:7.0.6:*:*:*:*:*:*:*',
    cves: [
      { id: 'CVE-2022-42475', cvss: 9.8, published: '2023-01-02', fixedIn: '7.0.9', kev: true },
    ],
  },
  // The fixed release for CVE-2024-20353 on this train is not confirmed here, so it is seeded as unfixed.
  {
    key: 'asa_9_18_3',
    vendor: 'cisco',
    product: 'adaptive_security_appliance_software',
    version: '9.18.3',
    displayName: 'Cisco ASA Software 9.18.3',
    category: 'appliance',
    cpe: 'cpe:2.3:o:cisco:adaptive_security_appliance_software:9.18.3:*:*:*:*:*:*:*',
    cves: [{ id: 'CVE-2024-20353', cvss: 8.6, published: '2024-04-24', kev: true }],
    confidence: 0.7,
  },
  {
    key: 'bigip_15_1_5',
    vendor: 'f5',
    product: 'big-ip',
    version: '15.1.5',
    displayName: 'F5 BIG-IP 15.1.5',
    category: 'appliance',
    cpe: 'cpe:2.3:a:f5:big-ip_local_traffic_manager:15.1.5:*:*:*:*:*:*:*',
    cves: [
      { id: 'CVE-2022-1388', cvss: 9.8, published: '2022-05-05', fixedIn: '15.1.5.1', kev: true },
    ],
  },
];

type HostKind = 'linux' | 'windows' | 'macos' | 'appliance';

interface HostSpec {
  key: string;
  name: string;
  kind: HostKind;
}

const HOST_SPECS: readonly HostSpec[] = [
  { key: 'web1', name: 'web-prod-01', kind: 'linux' },
  { key: 'web2', name: 'web-prod-02', kind: 'linux' },
  { key: 'bastion', name: 'bastion-01', kind: 'linux' },
  { key: 'db1', name: 'db-prod-01', kind: 'linux' },
  { key: 'db2', name: 'db-prod-02', kind: 'linux' },
  { key: 'win1', name: 'WIN-WS-0142', kind: 'windows' },
  { key: 'win2', name: 'WIN-WS-0217', kind: 'windows' },
  { key: 'win3', name: 'WIN-WS-0388', kind: 'windows' },
  { key: 'mac1', name: 'mbp-ajohnson', kind: 'macos' },
  { key: 'mac2', name: 'mbp-rpatel', kind: 'macos' },
  { key: 'mac3', name: 'mbp-lchen', kind: 'macos' },
  { key: 'pan', name: 'fw-edge-paloalto-01', kind: 'appliance' },
  { key: 'forti', name: 'fw-edge-fortigate-01', kind: 'appliance' },
  { key: 'asa', name: 'fw-dc-cisco-asa-01', kind: 'appliance' },
  { key: 'f5', name: 'lb-edge-bigip-01', kind: 'appliance' },
  { key: 'patched2d', name: 'web-patched-2d-ago', kind: 'linux' },
  { key: 'patched20d', name: 'web-patched-20d-ago', kind: 'linux' },
  { key: 'alwaysvuln', name: 'app-always-vulnerable', kind: 'linux' },
  { key: 'nevervuln', name: 'app-never-vulnerable', kind: 'linux' },
];

type Lifecycle = 'active' | 'patched' | 'removed' | 'stale';
type ExposureKind = 'none' | 'edge' | 'public_high' | 'public_medium';

interface InstanceSpec {
  host: string;
  sw: string;
  path: string;
  state?: Lifecycle;
  /** Catalog key of the version this instance ran before it was patched. */
  prev?: string;
  sources?: readonly DiscoverySource[];
  exposure?: ExposureKind;
  /** Days before `now` that the instance was first seen; random when unset. */
  ageDays?: number;
  /** Days before `now` that `prev` was replaced by `sw`; random (1 to 6.5) when unset. */
  patchDaysAgo?: number;
}

const OS: readonly DiscoverySource[] = ['osquery'];
const OS_LOGS: readonly DiscoverySource[] = ['osquery', 'logs'];
const OS_FLEET: readonly DiscoverySource[] = ['osquery', 'fleet_integration'];
const LOGS: readonly DiscoverySource[] = ['logs'];

const INSTANCE_SPECS: readonly InstanceSpec[] = [
  // web-prod-01: public nginx plus a vulnerable Java/Node stack
  {
    host: 'web1',
    sw: 'nginx_1_25_3',
    path: '/usr/sbin/nginx',
    sources: OS_LOGS,
    exposure: 'public_high',
  },
  { host: 'web1', sw: 'openssl_3_0_2', path: '/usr/lib/x86_64-linux-gnu/libssl.so.3' },
  { host: 'web1', sw: 'openssh_9_7', path: '/usr/sbin/sshd' },
  { host: 'web1', sw: 'curl_7_81_0', path: '/usr/bin/curl' },
  { host: 'web1', sw: 'sudo_1_9_5p1', path: '/usr/bin/sudo' },
  {
    host: 'web1',
    sw: 'log4j_2_14_1',
    path: '/opt/orders-api/lib/log4j-core-2.14.1.jar',
    sources: OS_LOGS,
  },
  { host: 'web1', sw: 'spring_5_3_17', path: '/opt/orders-api/lib/spring-core-5.3.17.jar' },
  { host: 'web1', sw: 'jackson_2_13_1', path: '/opt/orders-api/lib/jackson-databind-2.13.1.jar' },
  { host: 'web1', sw: 'lodash_4_17_15', path: '/srv/storefront/node_modules/lodash' },
  { host: 'web1', sw: 'express_4_17_1', path: '/srv/storefront/node_modules/express' },
  // web-prod-02: recently patched, plus public Apache httpd
  {
    host: 'web2',
    sw: 'nginx_1_27_3',
    path: '/usr/sbin/nginx',
    state: 'patched',
    prev: 'nginx_1_25_3',
    patchDaysAgo: 5.5,
    sources: OS_LOGS,
  },
  {
    host: 'web2',
    sw: 'openssl_3_0_13',
    path: '/usr/lib/x86_64-linux-gnu/libssl.so.3',
    state: 'patched',
    prev: 'openssl_3_0_2',
    patchDaysAgo: 4,
  },
  {
    host: 'web2',
    sw: 'openssh_9_8',
    path: '/usr/sbin/sshd',
    state: 'patched',
    prev: 'openssh_9_7',
    patchDaysAgo: 3.5,
  },
  {
    host: 'web2',
    sw: 'httpd_2_4_58',
    path: '/usr/sbin/httpd',
    sources: OS_LOGS,
    exposure: 'public_medium',
  },
  { host: 'web2', sw: 'curl_7_81_0', path: '/usr/bin/curl' },
  {
    host: 'web2',
    sw: 'log4j_2_17_1',
    path: '/opt/orders-api/lib/log4j-core-2.17.1.jar',
    state: 'patched',
    prev: 'log4j_2_14_1',
    patchDaysAgo: 6,
    sources: OS_LOGS,
  },
  {
    host: 'web2',
    sw: 'spring_6_1_14',
    path: '/opt/orders-api/lib/spring-core-6.1.14.jar',
    state: 'patched',
    prev: 'spring_5_3_17',
    patchDaysAgo: 0.8,
  },
  { host: 'web2', sw: 'jackson_2_15_2', path: '/opt/orders-api/lib/jackson-databind-2.15.2.jar' },
  {
    host: 'web2',
    sw: 'django_3_2_12',
    path: '/srv/portal/venv/lib/python3.10/site-packages/django',
  },
  { host: 'web2', sw: 'lodash_4_17_21', path: '/srv/storefront/node_modules/lodash' },
  // bastion
  { host: 'bastion', sw: 'openssh_9_7', path: '/usr/sbin/sshd', exposure: 'public_medium' },
  {
    host: 'bastion',
    sw: 'openssl_3_0_13',
    path: '/usr/lib/x86_64-linux-gnu/libssl.so.3',
    prev: 'openssl_3_0_2',
    patchDaysAgo: 9,
  },
  { host: 'bastion', sw: 'sudo_1_9_5p1', path: '/usr/bin/sudo', state: 'removed' },
  { host: 'bastion', sw: 'curl_7_81_0', path: '/usr/bin/curl' },
  // database servers
  { host: 'db1', sw: 'postgres_15_3', path: '/usr/lib/postgresql/15/bin/postgres' },
  { host: 'db1', sw: 'openssl_3_0_2', path: '/usr/lib/x86_64-linux-gnu/libssl.so.3' },
  { host: 'db1', sw: 'openssh_9_8', path: '/usr/sbin/sshd', prev: 'openssh_9_7', patchDaysAgo: 12 },
  { host: 'db1', sw: 'sudo_1_9_5p1', path: '/usr/bin/sudo' },
  { host: 'db2', sw: 'postgres_15_3', path: '/usr/lib/postgresql/15/bin/postgres' },
  {
    host: 'db2',
    sw: 'openssl_3_0_13',
    path: '/usr/lib/x86_64-linux-gnu/libssl.so.3',
    prev: 'openssl_3_0_2',
    patchDaysAgo: 17,
  },
  { host: 'db2', sw: 'log4j_2_14_1', path: '/opt/etl/lib/log4j-core-2.14.1.jar', sources: OS_LOGS },
  {
    host: 'db2',
    sw: 'jackson_2_13_1',
    path: '/opt/etl/lib/jackson-databind-2.13.1.jar',
    state: 'stale',
  },
  { host: 'db2', sw: 'httpd_2_4_49', path: '/opt/legacy-admin/httpd', state: 'stale' },
  // Windows workstations
  {
    host: 'win1',
    sw: 'chrome_120',
    path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    sources: OS_FLEET,
  },
  {
    host: 'win1',
    sw: '7zip_24_09',
    path: 'C:\\Program Files\\7-Zip\\7z.exe',
    state: 'patched',
    prev: '7zip_22_01',
    patchDaysAgo: 1.5,
    sources: OS_FLEET,
  },
  {
    host: 'win1',
    sw: 'notepadpp_8_6_2',
    path: 'C:\\Program Files\\Notepad++\\notepad++.exe',
    sources: OS_FLEET,
  },
  {
    host: 'win2',
    sw: 'chrome_131',
    path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    sources: OS_FLEET,
  },
  { host: 'win2', sw: '7zip_22_01', path: 'C:\\Program Files\\7-Zip\\7z.exe', sources: OS_FLEET },
  {
    host: 'win2',
    sw: 'notepadpp_8_6_2',
    path: 'C:\\Program Files\\Notepad++\\notepad++.exe',
    state: 'removed',
    sources: OS_FLEET,
  },
  {
    host: 'win3',
    sw: 'chrome_131',
    path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    sources: OS_FLEET,
  },
  {
    host: 'win3',
    sw: '7zip_22_01',
    path: 'C:\\Program Files\\7-Zip\\7z.exe',
    state: 'stale',
    sources: OS,
  },
  {
    host: 'win3',
    sw: 'notepadpp_8_6_2',
    path: 'C:\\Program Files\\Notepad++\\notepad++.exe',
    sources: OS,
  },
  // macOS laptops
  { host: 'mac1', sw: 'chrome_131', path: '/Applications/Google Chrome.app', sources: OS },
  {
    host: 'mac1',
    sw: 'openssl_3_0_13',
    path: '/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib',
    prev: 'openssl_3_0_2',
    patchDaysAgo: 25,
    sources: OS,
  },
  {
    host: 'mac1',
    sw: 'openssh_9_8',
    path: '/opt/homebrew/sbin/sshd',
    prev: 'openssh_9_7',
    patchDaysAgo: 28,
    sources: OS,
  },
  {
    host: 'mac1',
    sw: 'lodash_4_17_15',
    path: '/Users/ajohnson/dev/app/node_modules/lodash',
    sources: OS,
  },
  { host: 'mac2', sw: 'chrome_131', path: '/Applications/Google Chrome.app', sources: OS },
  {
    host: 'mac2',
    sw: 'django_4_2_16',
    path: '/Users/rpatel/dev/site/.venv/lib/python3.12/site-packages/django',
    sources: OS,
  },
  {
    host: 'mac2',
    sw: 'express_4_17_1',
    path: '/Users/rpatel/dev/api/node_modules/express',
    sources: OS,
  },
  {
    host: 'mac3',
    sw: 'chrome_120',
    path: '/Applications/Google Chrome.app',
    state: 'stale',
    sources: OS,
  },
  {
    host: 'mac3',
    sw: 'openssl_3_0_2',
    path: '/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib',
    state: 'removed',
    sources: OS,
  },
  { host: 'mac3', sw: 'curl_7_81_0', path: '/usr/local/bin/curl', sources: OS },
  // edge appliances
  { host: 'pan', sw: 'panos_10_2_8', path: 'firmware', sources: LOGS, exposure: 'edge' },
  { host: 'forti', sw: 'fortios_7_0_6', path: 'firmware', sources: LOGS, exposure: 'edge' },
  { host: 'asa', sw: 'asa_9_18_3', path: 'firmware', sources: LOGS, exposure: 'edge' },
  { host: 'f5', sw: 'bigip_15_1_5', path: 'firmware', sources: LOGS, exposure: 'edge' },
  // Scenario hosts, see the comment block at the top of this file.
  {
    host: 'patched2d',
    sw: 'log4j_2_17_1',
    path: '/opt/billing/lib/log4j-core-2.17.1.jar',
    state: 'patched',
    prev: 'log4j_2_14_1',
    patchDaysAgo: 2,
    ageDays: 120,
    exposure: 'public_medium',
  },
  {
    host: 'patched2d',
    sw: 'openssh_9_8',
    path: '/usr/sbin/sshd',
    state: 'patched',
    prev: 'openssh_9_7',
    patchDaysAgo: 2,
    ageDays: 120,
  },
  {
    host: 'patched20d',
    sw: 'log4j_2_17_1',
    path: '/opt/search/lib/log4j-core-2.17.1.jar',
    prev: 'log4j_2_14_1',
    patchDaysAgo: 20,
    ageDays: 85,
  },
  {
    host: 'patched20d',
    sw: 'openssl_3_0_13',
    path: '/usr/lib/x86_64-linux-gnu/libssl.so.3',
    prev: 'openssl_3_0_2',
    patchDaysAgo: 20,
    ageDays: 85,
  },
  {
    host: 'alwaysvuln',
    sw: 'log4j_2_14_1',
    path: '/opt/legacy-batch/lib/log4j-core-2.14.1.jar',
    ageDays: 150,
    exposure: 'public_high',
  },
  {
    host: 'alwaysvuln',
    sw: 'lodash_4_17_15',
    path: '/srv/legacy-batch/node_modules/lodash',
    ageDays: 150,
  },
  {
    host: 'nevervuln',
    sw: 'log4j_2_17_1',
    path: '/opt/reports/lib/log4j-core-2.17.1.jar',
    ageDays: 100,
  },
  {
    host: 'nevervuln',
    sw: 'openssl_3_0_13',
    path: '/usr/lib/x86_64-linux-gnu/libssl.so.3',
    ageDays: 100,
  },
  { host: 'nevervuln', sw: 'nginx_1_27_3', path: '/usr/sbin/nginx', ageDays: 100 },
];

const toIso = (ms: number): string => new Date(Math.round(ms)).toISOString();

const hex = (random: () => number, length: number): string =>
  Array.from({ length }, () => Math.floor(random() * 16).toString(16)).join('');

const buildExposure = (
  kind: ExposureKind,
  host: HostSpec,
  random: () => number
): InstanceDoc['exposure'] => {
  if (kind === 'none') {
    return { level: 'none', score: 0, evidence: [] };
  }
  // 198.51.100.0/24 and 203.0.113.0/24 are reserved documentation ranges.
  const publicIp = `${random() < 0.5 ? '203.0.113' : '198.51.100'}.${
    1 + Math.floor(random() * 253)
  }`;
  const publicIpEvidence = (weight: number): ExposureEvidence => ({
    signal: 'inbound_public_ip',
    detail: `Inbound connections accepted from public IP ${publicIp}`,
    weight,
  });
  if (kind === 'edge') {
    return {
      level: 'high',
      score: 90,
      evidence: [
        {
          signal: 'edge_device_role',
          detail: `${host.name} is an internet-facing edge device`,
          weight: 0.6,
        },
        publicIpEvidence(0.4),
      ],
    };
  }
  const level: ExposureLevel = kind === 'public_high' ? 'high' : 'medium';
  return {
    level,
    score: kind === 'public_high' ? 75 : 55,
    evidence: [publicIpEvidence(kind === 'public_high' ? 0.75 : 0.55)],
  };
};

type SeedRemediationFields = Pick<
  CatalogEntry,
  | 'cve_count'
  | 'max_cvss'
  | 'known_exploited'
  | 'fixed_in'
  | 'latest_known_fix'
  | 'fully_remediated'
  | 'unfixed_cve_ids'
  | 'remediation_caveat'
  | 'cve_details'
  | 'first_published'
  | 'cve_ids'
>;

/**
 * Seeded CVEs carry one fix per CVE on the entry's branch, so the minimal safe version is the
 * highest of those fixes. Enrichment derives the same fields from the full NVD ranges.
 */
const buildSeedRemediation = ({
  cves = [],
  version,
  category,
  latestKnownFix,
  checked,
}: CatalogSpec): SeedRemediationFields => {
  const base = {
    cve_count: cves.length,
    known_exploited: cves.some(({ kev }) => kev === true),
    cve_ids: cves.map(({ id }) => id).sort(),
  };
  if (checked === false) return base;
  const scores = cves.flatMap(({ cvss }) => (cvss !== undefined ? [cvss] : []));
  const minimalSafe = maxVersion(cves.flatMap(({ fixedIn }) => (fixedIn ? [fixedIn] : [])));
  const latest = maxVersion([
    ...(minimalSafe ? [minimalSafe] : []),
    ...(latestKnownFix ? [latestKnownFix] : []),
  ]);
  const unfixed = cves.filter(({ fixedIn }) => !fixedIn).map(({ id }) => id);
  const published = cves.flatMap((cve) => (cve.published ? [cve.published] : [])).sort();
  const details: CveDetail[] = [...cves]
    .sort((a, b) => (b.cvss ?? -1) - (a.cvss ?? -1) || a.id.localeCompare(b.id))
    .map(({ id, cvss, published: date, fixedIn, kev }) => ({
      id,
      ...(cvss !== undefined ? { cvss } : {}),
      ...(date !== undefined ? { published: date } : {}),
      ...(fixedIn !== undefined ? { fixed_in: fixedIn } : {}),
      known_exploited: kev === true,
    }));
  return {
    ...base,
    ...(scores.length > 0 ? { max_cvss: Math.max(...scores) } : {}),
    ...(minimalSafe ? { fixed_in: minimalSafe } : {}),
    ...(latest ? { latest_known_fix: latest } : {}),
    fully_remediated: unfixed.length === 0,
    unfixed_cve_ids: unfixed.sort(),
    remediation_caveat: getRemediationCaveats({ version, category }),
    cve_details: details,
    ...(published.length > 0 ? { first_published: published[0] } : {}),
  };
};

const EVENT_DAYS = 90;
const ROLLUP_DAYS = 60;

interface Interval {
  softwareId: string;
  start: number;
  /** Exclusive; undefined means still running. */
  end?: number;
}

/** Interval rules from `common/history.ts`: entry i ends where i+1 starts; the last is open or ends at last_seen. */
const toIntervals = ({
  version_history: history,
  status,
  last_seen: lastSeen,
}: InstanceDoc): Interval[] =>
  history.map((item, index) => {
    const next = history[index + 1];
    const open = status === 'active' || status === 'patched';
    return {
      softwareId: item.software_id ?? '',
      start: Date.parse(item.first_seen),
      ...(next ? { end: Date.parse(next.first_seen) } : open ? {} : { end: Date.parse(lastSeen) }),
    };
  });

const buildEvents = (
  instances: readonly InstanceDoc[],
  catalog: readonly CatalogEntry[],
  nowMs: number
): InventoryEvent[] => {
  const cutoff = nowMs - EVENT_DAYS * DAY_MS;
  const byId = new Map(catalog.map((entry) => [entry.id, entry]));
  const events: InventoryEvent[] = [];

  instances.forEach((instance) => {
    const { host, id, sources, version_history: history } = instance;
    const base = { instance_id: id, host, source: sources[0] ?? ('manual' as const) };
    const push = (
      ms: number,
      event: Omit<InventoryEvent, '@timestamp' | 'instance_id' | 'host' | 'source'>
    ) => {
      if (ms >= cutoff && ms <= nowMs) {
        events.push({ '@timestamp': toIso(ms), ...base, ...event });
      }
    };

    const [first] = history;
    push(Date.parse(first.first_seen), {
      type: 'first_seen',
      software_id: first.software_id ?? '',
    });

    history.slice(1).forEach((item, index) => {
      const from = history[index];
      const before = byId.get(from.software_id ?? '');
      const after = byId.get(item.software_id ?? '');
      push(Date.parse(item.first_seen), {
        type: 'version_changed',
        software_id: item.software_id ?? '',
        previous_software_id: from.software_id,
        from_version: from.version,
        to_version: item.version,
        ...(before
          ? {
              cve_count_before: before.cve_count,
              ...(before.max_cvss !== undefined ? { max_cvss_before: before.max_cvss } : {}),
              known_exploited_before: before.known_exploited,
            }
          : {}),
        ...(after
          ? {
              cve_count_after: after.cve_count,
              ...(after.max_cvss !== undefined ? { max_cvss_after: after.max_cvss } : {}),
              known_exploited_after: after.known_exploited,
            }
          : {}),
      });
    });

    const lastSeenMs = Date.parse(instance.last_seen);
    if (instance.status === 'removed') {
      push(lastSeenMs, { type: 'removed', software_id: instance.software_id });
    }
    if (instance.status === 'stale') {
      push(lastSeenMs + DEFAULT_STALE_AFTER_DAYS * DAY_MS, {
        type: 'stale',
        software_id: instance.software_id,
      });
    }
  });

  return events.sort(
    (a, b) =>
      a['@timestamp'].localeCompare(b['@timestamp']) ||
      a.instance_id.localeCompare(b.instance_id) ||
      a.type.localeCompare(b.type)
  );
};

const startOfUtcDay = (ms: number): number => Math.floor(ms / DAY_MS) * DAY_MS;

/**
 * Replays the instance histories for each of the last 60 UTC days. A day is evaluated at its end
 * (or `now` for today). CVEs count once published on or before that instant.
 */
const buildRollups = (
  instances: readonly InstanceDoc[],
  catalog: readonly CatalogEntry[],
  events: readonly InventoryEvent[],
  nowMs: number
): DailyRollup[] => {
  const byId = new Map(catalog.map((entry) => [entry.id, entry]));
  const intervals = instances.map((instance) => ({ instance, intervals: toIntervals(instance) }));
  const today = startOfUtcDay(nowMs);

  return Array.from({ length: ROLLUP_DAYS }, (_, index) => {
    const dayStart = today - (ROLLUP_DAYS - 1 - index) * DAY_MS;
    const asOf = Math.min(dayStart + DAY_MS - 1, nowMs);
    const categories: DailyRollup['categories'] = {
      application: 0,
      dependency: 0,
      appliance: 0,
      os_package: 0,
      other: 0,
    };
    const software = new Set<string>();
    let total = 0;
    let vulnerable = 0;
    let critical = 0;
    let high = 0;
    let exposed = 0;
    let exploited = 0;
    let exposedAndVulnerable = 0;

    intervals.forEach(({ instance, intervals: list }) => {
      const current = list.find(
        ({ start, end }) => start <= asOf && (end === undefined || asOf < end)
      );
      const entry = current ? byId.get(current.softwareId) : undefined;
      if (!current || !entry) return;
      total++;
      software.add(entry.id);
      categories[entry.category]++;
      const published = (entry.cve_details ?? []).filter(
        ({ published: date }) => date === undefined || Date.parse(date) <= asOf
      );
      const scores = published.flatMap(({ cvss }) => (cvss !== undefined ? [cvss] : []));
      const maxScore = scores.length > 0 ? Math.max(...scores) : 0;
      const isVulnerable = published.length > 0;
      const isExposed = instance.exposure.level === 'medium' || instance.exposure.level === 'high';
      if (isVulnerable) vulnerable++;
      if (maxScore >= 9) critical++;
      else if (maxScore >= 7) high++;
      if (isExposed) exposed++;
      if (published.some(({ known_exploited: kev }) => kev)) exploited++;
      if (isExposed && isVulnerable) exposedAndVulnerable++;
    });

    const dayEvents = events.filter(
      ({ '@timestamp': at }) => startOfUtcDay(Date.parse(at)) === dayStart
    );
    const countOf = (type: InventoryEvent['type']): number =>
      dayEvents.filter((event) => event.type === type).length;

    return {
      '@timestamp': toIso(dayStart),
      total_instances: total,
      total_software: software.size,
      vulnerable_instances: vulnerable,
      critical_instances: critical,
      high_instances: high,
      exposed_instances: exposed,
      known_exploited_instances: exploited,
      exposed_and_vulnerable_instances: exposedAndVulnerable,
      new_instances: countOf('first_seen'),
      patched_instances: countOf('version_changed'),
      removed_instances: countOf('removed'),
      categories,
    };
  });
};

export const generateSeedData = (
  now: Date
): {
  catalog: CatalogEntry[];
  instances: InstanceDoc[];
  events: InventoryEvent[];
  rollups: DailyRollup[];
} => {
  const nowMs = now.getTime();
  const random = createRandom(20240601);
  const between = (min: number, max: number): number => min + random() * (max - min);

  const catalog: CatalogEntry[] = CATALOG_SPECS.map((spec) => ({
    id: buildCatalogId(spec.vendor, spec.product, spec.version),
    vendor: normalizeToken(spec.vendor),
    product: normalizeToken(spec.product),
    version: spec.version,
    display_name: spec.displayName,
    category: spec.category,
    cpe: spec.cpe,
    ...buildSeedRemediation(spec),
    ...(spec.checked === false ? {} : { cve_checked_at: toIso(nowMs - between(0.1, 3) * DAY_MS) }),
    ...(spec.confidence !== undefined ? { cpe_match_confidence: spec.confidence } : {}),
    '@timestamp': toIso(nowMs - between(0.1, 3) * DAY_MS),
  }));
  const idByKey = new Map(CATALOG_SPECS.map((spec, index) => [spec.key, catalog[index]]));
  const getEntry = (key: string): CatalogEntry => {
    const entry = idByKey.get(key);
    if (!entry) {
      throw new Error(`Unknown catalog key: ${key}`);
    }
    return entry;
  };

  const hostIds = new Map(
    HOST_SPECS.map((host) => [
      host.key,
      `${hex(random, 8)}-${hex(random, 4)}-4${hex(random, 3)}-a${hex(random, 3)}-${hex(
        random,
        12
      )}`,
    ])
  );

  const instances: InstanceDoc[] = INSTANCE_SPECS.map((spec) => {
    const host = HOST_SPECS.find(({ key }) => key === spec.host);
    const hostId = hostIds.get(spec.host);
    if (!host || !hostId) {
      throw new Error(`Unknown host key: ${spec.host}`);
    }
    const entry = getEntry(spec.sw);
    const state: InstanceStatus = spec.state ?? 'active';

    const previous = spec.prev ? getEntry(spec.prev) : undefined;
    let firstSeen: number;
    let lastSeen: number;
    switch (state) {
      case 'removed':
        lastSeen = nowMs - between(3, 18) * DAY_MS;
        firstSeen = lastSeen - between(40, 200) * DAY_MS;
        break;
      case 'stale':
        lastSeen = nowMs - between(35, 90) * DAY_MS;
        firstSeen = lastSeen - between(60, 200) * DAY_MS;
        break;
      case 'patched':
        lastSeen = nowMs - between(0.05, 0.5) * DAY_MS;
        firstSeen = nowMs - between(60, 220) * DAY_MS;
        break;
      default:
        lastSeen = nowMs - between(0.02, 1.5) * DAY_MS;
        firstSeen = nowMs - between(previous ? 60 : 20, 220) * DAY_MS;
    }
    if (spec.ageDays !== undefined) {
      firstSeen = nowMs - spec.ageDays * DAY_MS;
    }

    const changedAt = previous
      ? nowMs - (spec.patchDaysAgo ?? between(1, 6.5)) * DAY_MS
      : undefined;
    const versionHistory =
      previous && changedAt !== undefined
        ? [
            {
              version: previous.version,
              software_id: previous.id,
              first_seen: toIso(firstSeen),
              last_seen: toIso(changedAt),
            },
            {
              version: entry.version,
              software_id: entry.id,
              first_seen: toIso(changedAt),
              last_seen: toIso(lastSeen),
            },
          ]
        : [
            {
              version: entry.version,
              software_id: entry.id,
              first_seen: toIso(firstSeen),
              last_seen: toIso(lastSeen),
            },
          ];

    // Same derivation as ingest, so a later discovery run updates these documents in place.
    const hostKey = buildHostKey({ hostName: host.name, hostId });
    return {
      id: buildInstanceId({
        hostKey,
        vendor: entry.vendor,
        product: entry.product,
        installPath: spec.path,
      }),
      host: { key: hostKey, id: hostId, name: host.name },
      software_id: entry.id,
      ...(previous && changedAt !== undefined
        ? { previous_software_id: previous.id, version_changed_at: toIso(changedAt) }
        : {}),
      version_history: versionHistory,
      install_path: spec.path,
      sources: [...(spec.sources ?? OS)],
      status: state,
      first_seen: toIso(firstSeen),
      last_seen: toIso(lastSeen),
      exposure: buildExposure(spec.exposure ?? 'none', host, random),
      '@timestamp': toIso(lastSeen),
    };
  });

  const events = buildEvents(instances, catalog, nowMs);
  const rollups = buildRollups(instances, catalog, events, nowMs);
  return { catalog, instances, events, rollups };
};
