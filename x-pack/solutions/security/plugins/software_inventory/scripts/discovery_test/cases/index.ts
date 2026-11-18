/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { cases as t0 } from './t0';
import { cases as discoverOsquery } from './do';
import { cases as discoverIntegrations } from './di';
import { cases as discoverLogs } from './dl';
import { cases as enrichCves } from './ec';
import { cases as scoreExposure } from './se';
import { cases as endToEnd } from './e2e';
import { cases as scheduling } from './sc';
import { cases as regression } from './rg';
import type { CaseFamily, TestCase } from './types';
import { CASE_FAMILIES } from './types';

/**
 * DO-15..DO-18 run after the log cases, as the plan's runbook orders them: DO-15 writes synthetic
 * logs, and DL-0 needs a cluster without any. The numeric suffix of the id decides.
 */
const LATE_OSQUERY_CASE_FROM = 15;
const isLateOsqueryCase = ({ id }: TestCase): boolean =>
  Number(id.split('-')[1]) >= LATE_OSQUERY_CASE_FROM;

/** Every registered case, in the plan's execution order (families in this order, then file order). */
export const ALL_CASES: readonly TestCase[] = [
  ...t0,
  ...discoverOsquery.filter((testCase) => !isLateOsqueryCase(testCase)),
  ...discoverIntegrations,
  ...discoverLogs,
  ...discoverOsquery.filter(isLateOsqueryCase),
  ...enrichCves,
  ...scoreExposure,
  ...endToEnd,
  ...scheduling,
  ...regression,
];

/** Throws on duplicate ids, family mismatches, or `requires` that name unknown cases. */
export const validateRegistry = (registry: readonly TestCase[]): void => {
  const ids = new Set<string>();
  const problems: string[] = [];
  for (const testCase of registry) {
    if (ids.has(testCase.id)) problems.push(`duplicate case id ${testCase.id}`);
    ids.add(testCase.id);
    if (!testCase.id.startsWith(`${testCase.family}-`)) {
      problems.push(`case ${testCase.id} is registered under family ${testCase.family}`);
    }
  }
  for (const testCase of registry) {
    for (const required of testCase.requires ?? []) {
      if (!ids.has(required))
        problems.push(`case ${testCase.id} requires unknown case ${required}`);
    }
  }
  if (problems.length > 0) throw new Error(`Invalid case registry:\n- ${problems.join('\n- ')}`);
};

/**
 * Resolves a selector: `all` (every family except RG), a family (`DO`), case ids (`DO-1`), or a comma-separated mix. Keeps
 * registry order and drops duplicates; throws on an unknown selector.
 */
export const selectCases = (
  selector: string,
  registry: readonly TestCase[] = ALL_CASES
): TestCase[] => {
  const tokens = selector
    .split(',')
    .map((token) => token.trim())
    .filter((token) => token !== '');
  if (tokens.length === 0) throw new Error('Select cases with ids, a family, or "all"');
  const selected = new Set<TestCase>();
  for (const token of tokens) {
    const upper = token.toUpperCase();
    if (upper === 'ALL') {
      // The RG family checks the stack after cleanup and restore, so `all` leaves it out: run the
      // `regression` command (cleanup, restore, then RG) as the last step.
      registry.filter(({ family }) => family !== 'RG').forEach((testCase) => selected.add(testCase));
      continue;
    }
    if ((CASE_FAMILIES as readonly string[]).includes(upper)) {
      registry
        .filter(({ family }) => family === (upper as CaseFamily))
        .forEach((testCase) => selected.add(testCase));
      continue;
    }
    const match = registry.find(({ id }) => id.toUpperCase() === upper);
    if (!match) throw new Error(`Unknown case or family "${token}"`);
    selected.add(match);
  }
  return registry.filter((testCase) => selected.has(testCase));
};
