/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import { CATALOG_INDEX } from '../../../common/constants';
import type { CatalogEntry, CveDetail, RemediationCaveat } from '../../../common/types';
import { UNKNOWN_VERSION } from '../ingest/normalize_candidate';
import { buildCpe, toNvdVendor } from './build_cpe';
import { isKnownVendorProduct } from './integration_map';
import type { KevResponse, NvdResponse, ParsedNvd } from './nvd_parse';
import { intersectKev, parseKevCveIds, parseNvdResponse } from './nvd_parse';

const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const SPACING_NO_KEY_MS = 6000;
const SPACING_WITH_KEY_MS = 700;
const REQUEST_TIMEOUT_MS = 30000;
const MAX_RETRIES = 3;
const BACKOFF_BASE_MS = 2000;
const RETRYABLE_STATUS = (status: number): boolean =>
  status === 403 || status === 429 || status >= 500;

const CONFIDENCE_KNOWN = 0.9;
const CONFIDENCE_HEURISTIC = 0.4;

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

class NetworkUnavailableError extends Error {}

const fetchWithTimeout = async (
  fetchFn: typeof fetch,
  url: string,
  headers: Record<string, string>
): Promise<Response> => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetchFn(url, { headers, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
};

const isAbortError = (error: unknown): boolean =>
  error instanceof Error && error.name === 'AbortError';

/** Fetches a JSON document from NVD with retries on 403/429/5xx and timeouts. */
const fetchNvd = async (
  fetchFn: typeof fetch,
  cpe: string,
  apiKey: string | undefined
): Promise<NvdResponse> => {
  const url = `${NVD_URL}?cpeName=${encodeURIComponent(cpe)}&noRejected`;
  const headers: Record<string, string> = apiKey ? { apiKey } : {};
  for (let attempt = 0; ; attempt++) {
    let response: Response;
    try {
      response = await fetchWithTimeout(fetchFn, url, headers);
    } catch (error) {
      if (!isAbortError(error)) {
        throw new NetworkUnavailableError('NVD is not reachable');
      }
      if (attempt >= MAX_RETRIES) throw new Error('NVD request timed out');
      await sleep(BACKOFF_BASE_MS * 2 ** attempt);
      continue;
    }
    if (response.ok) return (await response.json()) as NvdResponse;
    if (!RETRYABLE_STATUS(response.status) || attempt >= MAX_RETRIES) {
      throw new Error(`NVD responded with status ${response.status}`);
    }
    await sleep(BACKOFF_BASE_MS * 2 ** attempt);
  }
};

const loadKev = async (fetchFn: typeof fetch, logger: Logger): Promise<Set<string> | undefined> => {
  try {
    const response = await fetchWithTimeout(fetchFn, KEV_URL, {});
    if (!response.ok) {
      logger.warn(`CISA KEV catalog responded with status ${response.status}`);
      return undefined;
    }
    return parseKevCveIds((await response.json()) as KevResponse);
  } catch (error) {
    logger.warn(`Unable to fetch the CISA KEV catalog: ${(error as Error).message}`);
    return undefined;
  }
};

export const MAX_CVE_DETAILS = 100;

type NullableField =
  | 'max_cvss'
  | 'fixed_in'
  | 'latest_known_fix'
  | 'fully_remediated'
  | 'first_published';

/** `null` clears a field on partial update; `undefined` would be dropped and leave stale data. */
export type CatalogUpdate = Omit<
  Partial<CatalogEntry>,
  NullableField | 'cve_details' | 'unfixed_cve_ids' | 'remediation_caveat'
> & {
  [K in NullableField]-?: NonNullable<CatalogEntry[K]> | null;
} & {
  cve_details: CveDetail[];
  unfixed_cve_ids: string[];
  remediation_caveat: RemediationCaveat[];
};

/**
 * Per-CVE details, highest CVSS first. Without a KEV catalog, the flag recorded by an earlier run
 * is kept.
 */
const buildCveDetails = (
  entry: CatalogEntry,
  parsed: ParsedNvd,
  kev: ReadonlySet<string> | undefined
): CveDetail[] => {
  const previous = new Map((entry.cve_details ?? []).map((d) => [d.id, d.known_exploited]));
  return (parsed.cves ?? []).slice(0, MAX_CVE_DETAILS).map(({ id, cvss, published, fixedIn }) => ({
    id,
    ...(cvss !== undefined ? { cvss } : {}),
    ...(published !== undefined ? { published } : {}),
    ...(fixedIn !== undefined ? { fixed_in: fixedIn } : {}),
    known_exploited: kev ? kev.has(id) : previous.get(id) ?? false,
  }));
};

export const buildCatalogUpdate = ({
  entry,
  parsed,
  kev,
  now,
}: {
  entry: CatalogEntry;
  parsed: ParsedNvd;
  kev: ReadonlySet<string> | undefined;
  now: string;
}): CatalogUpdate => ({
  cpe: buildCpe(entry),
  cpe_match_confidence: isKnownVendorProduct(entry.vendor, entry.product)
    ? CONFIDENCE_KNOWN
    : CONFIDENCE_HEURISTIC,
  cve_ids: parsed.cveIds,
  cve_count: parsed.cveIds.length,
  max_cvss: parsed.maxCvss ?? null,
  fixed_in: parsed.fixedIn ?? null,
  latest_known_fix: parsed.latestKnownFix ?? null,
  fully_remediated: parsed.fullyRemediated ?? null,
  unfixed_cve_ids: parsed.unfixedCveIds ?? [],
  remediation_caveat: parsed.caveats ?? [],
  cve_details: buildCveDetails(entry, parsed, kev),
  first_published: parsed.firstPublished ?? null,
  ...(kev ? { known_exploited: intersectKev(parsed.cveIds, kev) } : {}),
  cve_checked_at: now,
  cve_check_failed: false,
});

/** True when the version cannot be matched to CPE ranges, so an NVD lookup would be noise. */
export const hasUnknownVersion = ({ version }: Pick<CatalogEntry, 'version'>): boolean => {
  const trimmed = version?.trim() ?? '';
  return trimmed === '' || trimmed.toLowerCase() === UNKNOWN_VERSION;
};

/**
 * Written when a lookup fails for this entry. Bumping `cve_checked_at` moves the entry behind the
 * healthy ones in the next run's oldest-first order, so persistent failures cannot block the
 * queue. CVE fields are left as they were.
 */
const failedCheckUpdate = (now: string): Partial<CatalogEntry> => ({
  cve_checked_at: now,
  cve_check_failed: true,
});

/** Written for an entry with no usable version: no lookup, and no CPE or CVE data. */
const unknownVersionUpdate = (now: string): Partial<CatalogEntry> => ({
  cve_checked_at: now,
  cve_check_failed: false,
});

export const enrichCatalogEntries = async ({
  esClient,
  logger,
  limit,
  fetchFn = fetch,
}: {
  esClient: ElasticsearchClient;
  logger: Logger;
  limit: number;
  fetchFn?: typeof fetch;
}): Promise<{ checked: number; updated: number; failed: number }> => {
  const apiKey = process.env.NVD_API_KEY || undefined;
  const spacing = apiKey ? SPACING_WITH_KEY_MS : SPACING_NO_KEY_MS;

  const search = await esClient.search<CatalogEntry>({
    index: CATALOG_INDEX,
    size: limit,
    query: { match_all: {} },
    sort: [{ cve_checked_at: { order: 'asc', missing: '_first' } }],
  });
  const hits = search.hits.hits.filter((hit) => hit._source !== undefined);
  if (hits.length === 0) return { checked: 0, updated: 0, failed: 0 };

  const kev = await loadKev(fetchFn, logger);

  const operations: Array<Record<string, unknown>> = [];
  const pushUpdate = (id: string, doc: object): void => {
    operations.push({ update: { _index: CATALOG_INDEX, _id: id } }, { doc });
  };
  let checked = 0;
  let failed = 0;
  let requests = 0;
  let failureMarkers = 0;

  for (const hit of hits) {
    const entry = hit._source as CatalogEntry;
    const id = hit._id as string;
    checked++;
    if (hasUnknownVersion(entry)) {
      pushUpdate(id, unknownVersionUpdate(new Date().toISOString()));
      continue;
    }
    if (requests > 0) await sleep(spacing);
    requests++;
    try {
      const cpe = buildCpe(entry);
      const response = await fetchNvd(fetchFn, cpe, apiKey);
      const parsed = parseNvdResponse(response, {
        nvdVendor: toNvdVendor(entry.vendor),
        product: entry.product,
        version: entry.version,
        category: entry.category,
      });
      pushUpdate(id, buildCatalogUpdate({ entry, parsed, kev, now: new Date().toISOString() }));
    } catch (error) {
      failed++;
      if (error instanceof NetworkUnavailableError) {
        // Transient: leave the entry unchecked so it is first in line next run.
        logger.warn('NVD is not reachable; remaining catalog entries stay unchecked');
        break;
      }
      pushUpdate(id, failedCheckUpdate(new Date().toISOString()));
      failureMarkers++;
      logger.debug(`CVE enrichment failed for ${entry.id}: ${(error as Error).message}`);
    }
  }

  // Failure markers are written but are not enrichment updates.
  let updated = operations.length / 2 - failureMarkers;
  if (operations.length > 0) {
    try {
      const bulk = await esClient.bulk({ operations, refresh: false });
      if (bulk.errors) {
        const errorCount = bulk.items.filter((item) => item.update?.error).length;
        updated = Math.max(0, updated - errorCount);
        failed += errorCount;
        logger.warn(`${errorCount} catalog updates failed during CVE enrichment`);
      }
    } catch (error) {
      logger.warn(`Bulk catalog update failed: ${(error as Error).message}`);
      failed += updated;
      updated = 0;
    }
  }

  return { checked, updated, failed };
};
