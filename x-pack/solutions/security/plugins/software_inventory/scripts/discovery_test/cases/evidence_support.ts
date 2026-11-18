/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Helpers shared by the EC, E2E, SC, and RG cases: typed access to the evidence an earlier case
 * recorded (in this invocation or in the results file), and small JSON guards.
 */

import type { JsonObject, JsonValue } from '../clients';
import type { CaseRecord } from './types';

export const isJsonObject = (value: JsonValue | undefined): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

export const readString = (value: JsonValue | undefined): string | undefined =>
  typeof value === 'string' ? value : undefined;

export const readNumber = (value: JsonValue | undefined): number | undefined =>
  typeof value === 'number' && Number.isFinite(value) ? value : undefined;

/** The first layer evidence value stored under `key` by case `caseId`, if it passed. */
export const readEvidence = (
  prior: ReadonlyMap<string, CaseRecord>,
  caseId: string,
  key: string
): JsonValue | undefined => {
  const record = prior.get(caseId);
  if (!record || record.status !== 'pass') return undefined;
  for (const layer of record.layers) {
    const value = layer.evidence?.[key];
    if (value !== undefined) return value;
  }
  return undefined;
};

/** Milliseconds between two ISO timestamps (`b - a`); NaN when either is missing or invalid. */
export const msBetween = (a: string | undefined, b: string | undefined): number =>
  a === undefined || b === undefined ? Number.NaN : Date.parse(b) - Date.parse(a);
