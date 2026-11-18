/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { normalizeToken } from '../../../common/normalize';
import type { DiscoverySource, RawCandidate, SoftwareCategory } from '../../../common/types';
import { buildHostKey } from '../../lib/instance_identity';
import { resolveIntegration, resolveObserver } from '../enrichment/integration_map';

export const UNKNOWN_VERSION = 'unknown';

export interface NormalizedSoftware {
  vendor: string;
  product: string;
  version: string;
  display_name: string;
  category: SoftwareCategory;
}

export interface NormalizedCandidate extends NormalizedSoftware {
  /** Canonical host identity; see `buildHostKey`. */
  host_key: string;
  host_id: string;
  host_name?: string;
  install_path?: string;
  observed_at: string;
}

interface KnownProduct {
  pattern: RegExp;
  vendor: string;
  product: string;
  category?: SoftwareCategory;
}

/**
 * Small heuristic table for well-known software whose name does not carry its vendor. Vendor and
 * product follow NVD CPE naming where one exists. The first match wins, so specific patterns come
 * before generic ones.
 */
const KNOWN_PRODUCTS: readonly KnownProduct[] = [
  { pattern: /^google chrome\b/, vendor: 'google', product: 'chrome' },
  { pattern: /^chromium\b/, vendor: 'google', product: 'chromium' },
  { pattern: /^(mozilla )?firefox\b/, vendor: 'mozilla', product: 'firefox' },
  { pattern: /^(mozilla )?thunderbird\b/, vendor: 'mozilla', product: 'thunderbird' },
  { pattern: /^microsoft edge\b/, vendor: 'microsoft', product: 'edge_chromium' },
  {
    pattern: /^(microsoft )?visual studio code\b|^code$/,
    vendor: 'microsoft',
    product: 'visual_studio_code',
  },
  { pattern: /^(microsoft )?teams\b/, vendor: 'microsoft', product: 'teams' },
  { pattern: /^(microsoft )?office\b/, vendor: 'microsoft', product: 'office' },
  {
    pattern: /^adobe acrobat reader\b|^adobe reader\b/,
    vendor: 'adobe',
    product: 'acrobat_reader',
  },
  { pattern: /^7-zip\b/, vendor: '7-zip', product: '7-zip' },
  { pattern: /^zoom\b/, vendor: 'zoom', product: 'zoom' },
  { pattern: /^slack\b/, vendor: 'slack', product: 'slack' },
  { pattern: /^docker( desktop| engine| ce|\.io)?\b/, vendor: 'docker', product: 'docker' },
  { pattern: /^openssl\b|^libssl/, vendor: 'openssl', product: 'openssl', category: 'dependency' },
  { pattern: /^openssh\b|^openssh-(server|client)/, vendor: 'openbsd', product: 'openssh' },
  { pattern: /^nginx\b/, vendor: 'f5', product: 'nginx' },
  {
    pattern: /^apache( http server|2)?$|^httpd\b|^apache2\b/,
    vendor: 'apache',
    product: 'http_server',
  },
  { pattern: /^(apache )?tomcat\b/, vendor: 'apache', product: 'tomcat' },
  {
    pattern: /^(apache )?log4j\b|^log4j-core/,
    vendor: 'apache',
    product: 'log4j',
    category: 'dependency',
  },
  { pattern: /^python\b|^python3\b/, vendor: 'python', product: 'python' },
  { pattern: /^node(\.js|js)?$/, vendor: 'nodejs', product: 'node.js' },
  { pattern: /^(openjdk|java)\b/, vendor: 'oracle', product: 'openjdk' },
  { pattern: /^curl\b|^libcurl/, vendor: 'haxx', product: 'curl' },
  { pattern: /^postgres(ql)?\b/, vendor: 'postgresql', product: 'postgresql' },
  { pattern: /^mysql\b/, vendor: 'oracle', product: 'mysql' },
  { pattern: /^redis\b/, vendor: 'redis', product: 'redis' },
  { pattern: /^sudo$/, vendor: 'sudo_project', product: 'sudo', category: 'os_package' },
  { pattern: /^bash$/, vendor: 'gnu', product: 'bash', category: 'os_package' },
  { pattern: /^(glibc|libc6|libc-bin)$/, vendor: 'gnu', product: 'glibc', category: 'os_package' },
  { pattern: /^xz(-utils)?$|^liblzma/, vendor: 'tukaani', product: 'xz', category: 'os_package' },
  { pattern: /^git$/, vendor: 'git-scm', product: 'git' },
];

const CORPORATE_SUFFIX =
  /[\s,]+(corporation|corp\.?|incorporated|inc\.?|llc|ltd\.?|limited|gmbh|co\.?|s\.a\.|ag|foundation)$/i;

/** Strips the bitness, locale, and trailing version that installers append to display names. */
const cleanProductName = (name: string): string =>
  name
    .replace(/\((x64|x86|64-bit|32-bit|amd64|arm64|[a-z]{2}-[a-z]{2})\)/gi, ' ')
    .replace(/\s+v?\d+(\.\d+)*([-_.][0-9a-z]+)*\s*$/i, '')
    .replace(/\s+/g, ' ')
    .trim();

const cleanVendor = (vendor: string): string => {
  let cleaned = vendor.trim();
  // Remove repeated suffixes such as "Foo Software, Inc.".
  while (CORPORATE_SUFFIX.test(cleaned)) {
    cleaned = cleaned.replace(CORPORATE_SUFFIX, '');
  }
  return cleaned;
};

/**
 * Debian and RPM release suffixes that do not change the upstream version. Kept narrow on
 * purpose: removing too much would merge distinct upstream versions.
 */
const DISTRO_REVISION =
  /-[0-9a-z.~+]*(ubuntu|deb|debian|el\d|fc\d|amzn|build|mga\d|suse)[0-9a-z.~+_]*$/i;

/** Returns a comparable version string, or `UNKNOWN_VERSION` when none was reported. */
export const cleanVersion = (version: string | undefined | null): string => {
  if (version == null) {
    return UNKNOWN_VERSION;
  }
  const cleaned = version
    .trim()
    // Debian epoch, for example `1:1.2.11`.
    .replace(/^\d+:/, '')
    // Leading `v` only when a digit follows, so `v1.2.3` changes and `very` does not.
    .replace(/^v(?=\d)/i, '')
    .replace(DISTRO_REVISION, '')
    .trim();
  return cleaned.length > 0 ? cleaned : UNKNOWN_VERSION;
};

const findKnownProduct = (name: string): KnownProduct | undefined => {
  const lower = name.toLowerCase();
  return KNOWN_PRODUCTS.find(({ pattern }) => pattern.test(lower));
};

const stripVendorPrefix = (product: string, vendor: string): string => {
  if (!vendor) {
    return product;
  }
  const prefix = `${vendor}_`;
  return product.startsWith(prefix) && product.length > prefix.length
    ? product.slice(prefix.length)
    : product;
};

/** Resolves vendor, product, version, display name, and category for one raw row. */
export const normalizeSoftware = (raw: {
  name: string;
  version?: string | null;
  vendor?: string | null;
  category?: SoftwareCategory | null;
}): NormalizedSoftware | undefined => {
  const displayName = raw.name.trim();
  const productName = cleanProductName(displayName);
  if (!productName) {
    return undefined;
  }
  const version = cleanVersion(raw.version);
  const known = findKnownProduct(productName);
  if (known) {
    return {
      vendor: known.vendor,
      product: known.product,
      version,
      display_name: displayName,
      category: raw.category ?? known.category ?? 'application',
    };
  }

  const vendor = raw.vendor ? normalizeToken(cleanVendor(raw.vendor)) : '';
  const product = stripVendorPrefix(normalizeToken(productName), vendor);
  if (!product) {
    return undefined;
  }
  return {
    // Many open source projects use the same CPE vendor and product, such as `zlib:zlib`.
    vendor: vendor || product,
    product,
    version,
    display_name: displayName,
    category: raw.category ?? 'application',
  };
};

const toIsoTimestamp = (value: string | undefined | null, fallback: string): string => {
  if (!value) {
    return fallback;
  }
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? fallback : new Date(parsed).toISOString();
};

/**
 * A Fleet package version is the integration's version, not the version of the software it
 * monitors, so Fleet candidates use the unknown version. Packages without a mapping are dropped:
 * a package name is not software.
 */
const normalizeFleetPackage = (name: string): NormalizedSoftware | undefined => {
  const resolved = resolveIntegration(name);
  if (!resolved) {
    return undefined;
  }
  return {
    vendor: resolved.vendor,
    product: resolved.product,
    version: UNKNOWN_VERSION,
    display_name: name.trim(),
    category: resolved.category,
  };
};

/** Maps a log `observer.vendor` / `observer.product` pair to its known identity when one exists. */
const normalizeObserver = (raw: RawCandidate): NormalizedSoftware | undefined => {
  const resolved = resolveObserver(raw.vendor ?? undefined, raw.name);
  if (!resolved) {
    return undefined;
  }
  return {
    vendor: resolved.vendor,
    product: resolved.product,
    version: cleanVersion(raw.version),
    display_name: raw.name.trim(),
    category: 'appliance',
  };
};

const normalizeForSource = (
  raw: RawCandidate,
  source: DiscoverySource
): NormalizedSoftware | undefined => {
  if (source === 'fleet_integration') {
    return normalizeFleetPackage(raw.name);
  }
  if (source === 'logs' && raw.category === 'appliance') {
    return normalizeObserver(raw) ?? normalizeSoftware(raw);
  }
  return normalizeSoftware(raw);
};

/**
 * Normalizes one raw candidate. Returns `undefined` for rows without a usable host or name, and
 * for Fleet packages with no known mapping. Fleet candidates are policy-level pseudo-hosts, so
 * their key is the `policy:<id>` host id; every other source keys on the host name.
 */
export const normalizeCandidate = (
  raw: RawCandidate,
  now: string,
  source: DiscoverySource = 'manual'
): NormalizedCandidate | undefined => {
  const hostId = raw.host_id?.trim();
  if (!hostId || !raw.name?.trim()) {
    return undefined;
  }
  const software = normalizeForSource(raw, source);
  if (!software) {
    return undefined;
  }
  const hostName = raw.host_name?.trim();
  const installPath = raw.install_path?.trim();
  return {
    ...software,
    host_key:
      source === 'fleet_integration'
        ? buildHostKey({ hostId })
        : buildHostKey({ hostName, hostId }),
    host_id: hostId,
    ...(hostName ? { host_name: hostName } : {}),
    ...(installPath ? { install_path: installPath } : {}),
    observed_at: toIsoTimestamp(raw.observed_at, now),
  };
};
