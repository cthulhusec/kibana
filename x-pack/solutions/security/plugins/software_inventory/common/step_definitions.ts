/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { i18n } from '@kbn/i18n';
import { StepCategory } from '@kbn/workflows';
import type { CommonStepDefinition } from '@kbn/workflows-extensions/common';
import { z, lazySchema } from '@kbn/zod/v4';
import {
  DEFAULT_STALE_AFTER_DAYS,
  MAX_CANDIDATES_PER_CALL,
  STEP_ENRICH_CVES,
  STEP_INGEST_CANDIDATES,
  STEP_MARK_STALE,
  STEP_SCORE_EXPOSURE,
  STEP_SNAPSHOT_ROLLUP,
} from './constants';

const MAX_ID_LENGTH = 256;
const MAX_NAME_LENGTH = 512;
const MAX_PATH_LENGTH = 2048;
const MAX_TIMESTAMP_LENGTH = 64;

// ES|QL and osquery rows carry `null` for missing columns, so optional fields accept it.
const optionalString = (max: number) => z.string().max(max).nullish();

/** One row. Rows that fail this schema are skipped by the handler, not the whole batch. */
export const rawCandidateSchema = lazySchema(() =>
  z.object({
    host_id: z.string().trim().min(1).max(MAX_ID_LENGTH),
    host_name: optionalString(MAX_ID_LENGTH),
    name: z.string().trim().min(1).max(MAX_NAME_LENGTH),
    version: optionalString(MAX_ID_LENGTH),
    vendor: optionalString(MAX_ID_LENGTH),
    install_path: optionalString(MAX_PATH_LENGTH),
    category: z.enum(['application', 'dependency', 'appliance', 'os_package', 'other']).nullish(),
    observed_at: optionalString(MAX_TIMESTAMP_LENGTH),
  })
);

const ingestCandidatesInputSchema = lazySchema(() =>
  z.object({
    source: z.enum(['osquery', 'fleet_integration', 'logs', 'endpoint', 'manual']),
    snapshot: z
      .boolean()
      .default(false)
      .describe('True when each reported host sent its complete list of software.'),
    // A malformed row (for example an empty name) must not reject the whole batch, so each element
    // falls back to `unknown`; the handler re-validates every row and counts the invalid ones.
    candidates: z
      .array(z.union([rawCandidateSchema, z.unknown()]))
      .max(MAX_CANDIDATES_PER_CALL)
      .describe('Raw software rows. Invalid rows are skipped and counted in `skipped`.'),
  })
);

const ingestCandidatesOutputSchema = lazySchema(() =>
  z.object({
    created: z.number(),
    unchanged: z.number(),
    patched: z.number(),
    removed: z.number(),
    skipped: z.number(),
  })
);

const enrichCvesInputSchema = lazySchema(() =>
  z.object({
    limit: z.number().int().min(1).max(1000).default(100),
  })
);

const enrichCvesOutputSchema = lazySchema(() =>
  z.object({
    checked: z.number(),
    updated: z.number(),
    failed: z.number(),
  })
);

const scoreExposureInputSchema = lazySchema(() =>
  z.object({
    lookback_days: z.number().int().min(1).max(90).default(7),
  })
);

const scoreExposureOutputSchema = lazySchema(() =>
  z.object({
    scored: z.number(),
  })
);

const markStaleInputSchema = lazySchema(() =>
  z.object({
    stale_after_days: z.number().int().min(1).max(365).default(DEFAULT_STALE_AFTER_DAYS),
  })
);

const markStaleOutputSchema = lazySchema(() =>
  z.object({
    marked: z.number(),
  })
);

const snapshotRollupInputSchema = lazySchema(() => z.object({}));

const snapshotRollupOutputSchema = lazySchema(() =>
  z.object({
    date: z.string().describe('UTC day of the rollup, as YYYY-MM-DD.'),
    total_instances: z.number(),
    vulnerable_instances: z.number(),
  })
);

export type IngestCandidatesStepInput = z.infer<typeof ingestCandidatesInputSchema>;
export type RawCandidateStepRow = z.infer<typeof rawCandidateSchema>;

export const ingestCandidatesStepCommonDefinition: CommonStepDefinition<
  typeof ingestCandidatesInputSchema,
  typeof ingestCandidatesOutputSchema
> = {
  id: STEP_INGEST_CANDIDATES,
  label: i18n.translate('xpack.softwareInventory.steps.ingestCandidates.label', {
    defaultMessage: 'Ingest software candidates',
  }),
  description: i18n.translate('xpack.softwareInventory.steps.ingestCandidates.description', {
    defaultMessage:
      'Normalizes raw software rows and upserts them into the software inventory, tracking patches and removals.',
  }),
  category: StepCategory.KibanaSecurity,
  stability: 'tech_preview',
  inputSchema: ingestCandidatesInputSchema,
  outputSchema: ingestCandidatesOutputSchema,
};

export const enrichCvesStepCommonDefinition: CommonStepDefinition<
  typeof enrichCvesInputSchema,
  typeof enrichCvesOutputSchema
> = {
  id: STEP_ENRICH_CVES,
  label: i18n.translate('xpack.softwareInventory.steps.enrichCves.label', {
    defaultMessage: 'Enrich software with CVEs',
  }),
  description: i18n.translate('xpack.softwareInventory.steps.enrichCves.description', {
    defaultMessage: 'Looks up known vulnerabilities for software catalog entries.',
  }),
  category: StepCategory.KibanaSecurity,
  stability: 'tech_preview',
  inputSchema: enrichCvesInputSchema,
  outputSchema: enrichCvesOutputSchema,
};

export const scoreExposureStepCommonDefinition: CommonStepDefinition<
  typeof scoreExposureInputSchema,
  typeof scoreExposureOutputSchema
> = {
  id: STEP_SCORE_EXPOSURE,
  label: i18n.translate('xpack.softwareInventory.steps.scoreExposure.label', {
    defaultMessage: 'Score software exposure',
  }),
  description: i18n.translate('xpack.softwareInventory.steps.scoreExposure.description', {
    defaultMessage: 'Scores how exposed each software instance is from network and role signals.',
  }),
  category: StepCategory.KibanaSecurity,
  stability: 'tech_preview',
  inputSchema: scoreExposureInputSchema,
  outputSchema: scoreExposureOutputSchema,
};

export const markStaleStepCommonDefinition: CommonStepDefinition<
  typeof markStaleInputSchema,
  typeof markStaleOutputSchema
> = {
  id: STEP_MARK_STALE,
  label: i18n.translate('xpack.softwareInventory.steps.markStale.label', {
    defaultMessage: 'Mark stale software',
  }),
  description: i18n.translate('xpack.softwareInventory.steps.markStale.description', {
    defaultMessage: 'Marks software instances that have not been seen recently as stale.',
  }),
  category: StepCategory.KibanaSecurity,
  stability: 'tech_preview',
  inputSchema: markStaleInputSchema,
  outputSchema: markStaleOutputSchema,
};

export const snapshotRollupStepCommonDefinition: CommonStepDefinition<
  typeof snapshotRollupInputSchema,
  typeof snapshotRollupOutputSchema
> = {
  id: STEP_SNAPSHOT_ROLLUP,
  label: i18n.translate('xpack.softwareInventory.steps.snapshotRollup.label', {
    defaultMessage: 'Snapshot software inventory trends',
  }),
  description: i18n.translate('xpack.softwareInventory.steps.snapshotRollup.description', {
    defaultMessage:
      "Writes today's software inventory counts for trend charts. Re-running on the same day overwrites them.",
  }),
  category: StepCategory.KibanaSecurity,
  stability: 'tech_preview',
  inputSchema: snapshotRollupInputSchema,
  outputSchema: snapshotRollupOutputSchema,
};
