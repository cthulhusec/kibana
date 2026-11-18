/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import dateMath from '@kbn/datemath';
import { MAX_HISTORY_RANGE_DAYS } from '../../common/constants';

/** Raw picker value: date math strings such as `now-30d`, or absolute ISO strings. */
export interface TimeRangeInput {
  start: string;
  end: string;
}

/** A resolved range as ISO timestamps. */
export interface ResolvedPeriod {
  from: string;
  to: string;
}

export type RangeResolution =
  | { status: 'ok'; period: ResolvedPeriod; clamped: boolean }
  | { status: 'invalid' };

export const DEFAULT_TIME_RANGE: TimeRangeInput = { start: 'now-30d', end: 'now' };

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Resolves picker input to ISO timestamps. Returns `invalid` when either side does not parse or
 * the range is empty or inverted, and shortens ranges longer than `MAX_HISTORY_RANGE_DAYS` to the
 * most recent that many days (`clamped: true`).
 */
export const resolveTimeRange = (
  { start, end }: TimeRangeInput,
  now: Date = new Date()
): RangeResolution => {
  const from = dateMath.parse(start, { forceNow: now });
  const to = dateMath.parse(end, { roundUp: true, forceNow: now });
  if (!from || !to || !from.isValid() || !to.isValid()) return { status: 'invalid' };

  const toMs = to.valueOf();
  const fromMs = from.valueOf();
  if (fromMs >= toMs) return { status: 'invalid' };

  const maxMs = MAX_HISTORY_RANGE_DAYS * DAY_MS;
  const clamped = toMs - fromMs > maxMs;
  return {
    status: 'ok',
    clamped,
    period: {
      from: new Date(clamped ? toMs - maxMs : fromMs).toISOString(),
      to: new Date(toMs).toISOString(),
    },
  };
};

/** Query params for the instances route; empty when the current inventory is requested. */
export const toAsOfParams = (
  period: ResolvedPeriod | undefined
): { as_of_from?: string; as_of_to?: string } =>
  period ? { as_of_from: period.from, as_of_to: period.to } : {};
