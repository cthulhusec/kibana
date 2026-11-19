/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export type SoftwareCategory = 'application' | 'dependency' | 'appliance' | 'os_package' | 'other';
export type DiscoverySource = 'osquery' | 'fleet_integration' | 'logs' | 'endpoint' | 'manual';
export type InstanceStatus = 'active' | 'patched' | 'removed' | 'stale';
export type ExposureLevel = 'none' | 'low' | 'medium' | 'high';

/**
 * Why a remediation answer may be inaccurate:
 * - `distro_backports`: OS packages often carry backported fixes that NVD ranges do not reflect.
 * - `low_version_confidence`: the version is not purely numeric (`9.8p1`, epochs, `~`).
 */
export type RemediationCaveat = 'distro_backports' | 'low_version_confidence';

/** Per-CVE detail kept on the catalog entry. */
export interface CveDetail {
  id: string;
  cvss?: number;
  /** ISO date the CVE was published in NVD. */
  published?: string;
  /** Nearest fixed version on the current release branch; absent when no fix is known. */
  fixed_in?: string;
  known_exploited: boolean;
}

/** One document per vendor:product:version. Shared by every host that runs it. */
export interface CatalogEntry {
  id: string; // buildCatalogId(vendor, product, version)
  vendor: string; // normalized, lower-case
  product: string; // normalized, lower-case
  version: string;
  display_name: string;
  category: SoftwareCategory;
  cpe?: string; // cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
  cve_count: number;
  max_cvss?: number;
  known_exploited: boolean; // CISA KEV
  /**
   * Minimal safe version: the lowest version that resolves every CVE with a known fix on the
   * current release branch.
   */
  fixed_in?: string;
  /** Highest fixed version NVD lists for the product (newest branch). Not the latest release. */
  latest_known_fix?: string;
  /** False when some CVEs have no known fix, so `fixed_in` does not resolve everything. */
  fully_remediated?: boolean;
  unfixed_cve_ids?: string[];
  remediation_caveat?: RemediationCaveat[];
  /** At most 100 CVEs, highest CVSS first. */
  cve_details?: CveDetail[];
  /** Earliest `published` date across all CVEs of this entry. */
  first_published?: string;
  cve_ids: string[];
  cve_checked_at?: string; // ISO; drives re-check ordering
  /** True when the last CVE lookup failed. `cve_checked_at` is still bumped, so it retries last. */
  cve_check_failed?: boolean;
  cpe_match_confidence?: number; // 0..1
  '@timestamp': string;
}

export interface VersionHistoryItem {
  version: string;
  /** Catalog id of this version. Needed to resolve the CVEs that applied while it ran. */
  software_id?: string;
  first_seen: string;
  last_seen: string;
}

export interface ExposureEvidence {
  signal: 'inbound_public_ip' | 'edge_device_role' | 'manual';
  detail: string;
  weight: number;
}

/**
 * One document per host + vendor + product + install path. Version is an attribute, so a patch
 * updates the document in place instead of creating a new one.
 */
export interface InstanceDoc {
  id: string; // deterministic from host.key + vendor + product + install_path
  /**
   * `key` is the canonical host identity: the lower-cased host name, else the host id. `id` is
   * informational (the first non-empty id a source reported).
   */
  host: { key: string; id: string; name?: string };
  software_id: string; // current CatalogEntry.id
  previous_software_id?: string;
  version_changed_at?: string;
  version_history: VersionHistoryItem[];
  install_path?: string;
  sources: DiscoverySource[];
  status: InstanceStatus;
  first_seen: string;
  last_seen: string;
  exposure: { level: ExposureLevel; score: number; evidence: ExposureEvidence[] };
  '@timestamp': string;
}

/** Raw row produced by a discovery workflow, before normalization. */
export interface RawCandidate {
  host_id: string;
  host_name?: string;
  name: string;
  version?: string;
  vendor?: string;
  install_path?: string;
  category?: SoftwareCategory;
  observed_at?: string; // ISO; defaults to now
}

export interface IngestCandidatesInput {
  source: DiscoverySource;
  /** True when each reported host sent its COMPLETE list, so absent items can be marked removed. */
  snapshot: boolean;
  candidates: RawCandidate[];
}

export interface IngestCandidatesOutput {
  created: number;
  unchanged: number;
  patched: number;
  removed: number;
  /** Rows dropped as invalid, without a host or name, or with no known mapping. */
  skipped: number;
}

/**
 * Row returned by the instances list route: instance joined with its catalog entry.
 *
 * When the request carries `as_of_from`/`as_of_to` (ISO timestamps), the route scopes the inventory
 * to that period: it returns instances whose version interval overlaps the period, `software` is the
 * catalog entry of the LATEST version that ran during the period (not necessarily the current one),
 * and `vulnerable_in_range` is set per the publish-date-aware rules in `./history.ts`.
 * The request may also pass `vulnerable_in_range=true` to keep only vulnerable rows.
 */
export interface InstanceRow extends InstanceDoc {
  software: CatalogEntry;
  vulnerable_in_range?: boolean;
}

export interface FindInstancesResponse {
  total: number;
  page: number;
  per_page: number;
  items: InstanceRow[];
}

export interface SummaryResponse {
  total_instances: number;
  total_software: number;
  exposed_instances: number;
  vulnerable_instances: number;
  known_exploited_instances: number;
  recently_patched_instances: number; // status patched within 7d
  by_category: Array<{ key: SoftwareCategory; count: number }>;
  by_source: Array<{ key: DiscoverySource; count: number }>;
}

export interface CatalogDetailResponse {
  entry: CatalogEntry;
  instances: InstanceDoc[];
}
