/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { buildCatalogId } from '../../common/normalize';
import { buildHostKey, buildInstanceId } from '../../server/lib/instance_identity';

export { buildCatalogId, buildHostKey, buildInstanceId };

/** Every synthetic host key starts with one of these prefixes (see the test plan's Safety section). */
export const SYNTHETIC_HOST_KEY_PREFIXES = ['synth-', 'policy:synth-'] as const;

/**
 * Synthetic host keys that cannot carry the prefix: IP-keyed appliances from TEST-NET-1. DL-10 writes
 * a multi-valued `observer.ip` whose sorted first doc value (`10.9.9.9`) becomes the key.
 */
export const SYNTHETIC_EXACT_HOST_KEYS = ['192.0.2.77', '192.0.2.78', '10.9.9.9'] as const;

/** Synthetic catalog entries whose vendor or product is invented start with this prefix. */
export const SYNTHETIC_CATALOG_TOKEN_PREFIX = 'synth-';

/** Throwaway saved workflows use this id prefix; never `system-`. */
export const TEST_WORKFLOW_ID_PREFIX = 'si-test-';

/** Helper steps that a variant inserts (for example a bulk row generator) use this name prefix. */
export const HELPER_STEP_PREFIX = 'si_test_';

export const isSyntheticHostKey = (hostKey: string): boolean =>
  SYNTHETIC_HOST_KEY_PREFIXES.some((prefix) => hostKey.startsWith(prefix)) ||
  (SYNTHETIC_EXACT_HOST_KEYS as readonly string[]).includes(hostKey);

export interface CatalogIdParts {
  readonly vendor: string;
  readonly product: string;
  readonly version: string;
}

/** Splits `vendor:product:version`; the version may itself contain colons. */
export const parseCatalogId = (catalogId: string): CatalogIdParts => {
  const [vendor, product, ...rest] = catalogId.split(':');
  if (!vendor || !product || rest.length === 0) {
    throw new Error(`Not a catalog id (vendor:product:version): "${catalogId}"`);
  }
  return { vendor, product, version: rest.join(':') };
};

/** Instance id for a host key and the catalog id of the software it runs. */
export const instanceIdFor = ({
  hostKey,
  catalogId,
  installPath,
}: {
  hostKey: string;
  catalogId: string;
  installPath?: string;
}): string => {
  const { vendor, product } = parseCatalogId(catalogId);
  return buildInstanceId({ hostKey, vendor, product, installPath });
};
