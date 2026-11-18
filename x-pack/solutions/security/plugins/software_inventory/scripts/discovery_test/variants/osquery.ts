/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { BulkOsqueryFixture, OsqueryFixture, OsqueryQueryStep } from '../fixtures/osquery';
import { F_EMPTY, OSQUERY_QUERY_STEPS, bulkRowsTemplate } from '../fixtures/osquery';
import type { Replacements, StepReplacement, VariantOptions } from './build_variant';
import { buildVariant, getProductionYaml } from './build_variant';

/** What replaces one `query_*` step. */
export type OsqueryStepInput =
  | OsqueryFixture
  | BulkOsqueryFixture
  | { readonly kind: 'throw' }
  /** Arbitrary step body, for example a `wait` with a step `timeout` (SC-6). */
  | { readonly kind: 'step'; readonly step: object };

const toReplacement = (input: OsqueryStepInput): StepReplacement => {
  if ('kind' in input) return input;
  if ('rows' in input) {
    return { kind: 'generated', output: input.output, rowsTemplate: bulkRowsTemplate(input.rows) };
  }
  return { kind: 'fixture', output: input.output };
};

export interface OsqueryVariantSpec extends Omit<VariantOptions, 'label'> {
  readonly label: string;
  /** Steps left out get `F-empty`, so a variant never dispatches a real Osquery query. */
  readonly steps: Partial<Readonly<Record<OsqueryQueryStep, OsqueryStepInput>>>;
}

/** Replacements for all four query steps, defaulting unspecified ones to `F-empty`. */
export const osqueryReplacements = (
  steps: OsqueryVariantSpec['steps']
): Readonly<Record<OsqueryQueryStep, StepReplacement>> =>
  Object.fromEntries(
    OSQUERY_QUERY_STEPS.map((step) => [step, toReplacement(steps[step] ?? F_EMPTY)])
  ) as Record<OsqueryQueryStep, StepReplacement>;

/** `discover-osquery` with its four `osquery.runQuery` steps replaced by fixtures. */
export const buildOsqueryVariant = ({ steps, ...options }: OsqueryVariantSpec): string => {
  const replacements: Replacements = osqueryReplacements(steps);
  return buildVariant(getProductionYaml('discoverOsquery'), replacements, options);
};
