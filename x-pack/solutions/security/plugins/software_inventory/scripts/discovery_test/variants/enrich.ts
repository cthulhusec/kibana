/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { VariantOptions } from './build_variant';
import { buildVariant, getProductionYaml } from './build_variant';

export const ENRICH_STEP = 'enrich';
/** The production `limit` of the `enrich` step. */
export const PRODUCTION_ENRICH_LIMIT = 25;

export interface EnrichVariantSpec extends VariantOptions {
  /** Number of catalog entries the `enrich` step checks (oldest `cve_checked_at` first). */
  readonly limit: number;
}

/** `enrich-cves` with only `enrich.with.limit` changed. */
export const buildEnrichVariant = ({ limit, ...options }: EnrichVariantSpec): string => {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new Error(`limit must be a positive integer, got ${limit}`);
  }
  return buildVariant(
    getProductionYaml('enrichCves'),
    { [ENRICH_STEP]: { kind: 'with', with: { limit } } },
    options
  );
};
