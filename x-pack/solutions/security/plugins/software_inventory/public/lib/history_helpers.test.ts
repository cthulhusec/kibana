/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { formatDuration } from './duration';
import { resolveTimeRange, toAsOfParams } from './time_range';
import { makeRollup } from './history_fixtures';
import { toTrendRows } from './trends';
import { MAX_HISTORY_RANGE_DAYS } from '../../common/constants';

const MIN = 60 * 1000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

describe('formatDuration', () => {
  it.each([
    [0, '0m'],
    [30_000, '<1m'],
    [45 * MIN, '45m'],
    [3 * HOUR + 20 * MIN, '3h 20m'],
    [3 * HOUR, '3h'],
    [2 * DAY + 4 * HOUR + 30 * MIN, '2d 4h'],
    [2 * DAY, '2d'],
  ])('formats %d ms as %s', (ms, expected) => {
    expect(formatDuration(ms)).toBe(expected);
  });
});

describe('resolveTimeRange', () => {
  const now = new Date('2026-06-30T12:00:00.000Z');

  it('resolves relative ranges to ISO timestamps', () => {
    expect(resolveTimeRange({ start: 'now-30d', end: 'now' }, now)).toEqual({
      status: 'ok',
      clamped: false,
      period: { from: '2026-05-31T12:00:00.000Z', to: '2026-06-30T12:00:00.000Z' },
    });
  });

  it('resolves absolute ranges', () => {
    const result = resolveTimeRange(
      { start: '2026-01-01T00:00:00.000Z', end: '2026-01-10T00:00:00.000Z' },
      now
    );
    expect(result).toMatchObject({
      status: 'ok',
      period: { from: '2026-01-01T00:00:00.000Z', to: '2026-01-10T00:00:00.000Z' },
    });
  });

  it('clamps ranges longer than the maximum to the most recent days', () => {
    const result = resolveTimeRange({ start: 'now-2y', end: 'now' }, now);
    if (result.status !== 'ok') throw new Error('expected ok');
    expect(result.clamped).toBe(true);
    expect(result.period.to).toBe('2026-06-30T12:00:00.000Z');
    expect(Date.parse(result.period.to) - Date.parse(result.period.from)).toBe(
      MAX_HISTORY_RANGE_DAYS * DAY
    );
  });

  it('accepts a range exactly at the maximum without clamping', () => {
    const result = resolveTimeRange({ start: `now-${MAX_HISTORY_RANGE_DAYS}d`, end: 'now' }, now);
    expect(result).toMatchObject({ status: 'ok', clamped: false });
  });

  it('reports invalid, inverted and empty ranges', () => {
    expect(resolveTimeRange({ start: 'now-5x', end: 'now' }, now)).toEqual({ status: 'invalid' });
    expect(resolveTimeRange({ start: 'now', end: 'now-1d' }, now)).toEqual({ status: 'invalid' });
    expect(resolveTimeRange({ start: 'now', end: 'now' }, now)).toEqual({ status: 'invalid' });
  });
});

describe('toAsOfParams', () => {
  it('omits the params for the current inventory', () => {
    expect(toAsOfParams(undefined)).toEqual({});
  });

  it('maps a period to both params', () => {
    expect(toAsOfParams({ from: 'a', to: 'b' })).toEqual({ as_of_from: 'a', as_of_to: 'b' });
  });
});

describe('toTrendRows', () => {
  it('flattens rollups into chart rows', () => {
    const rows = toTrendRows([
      makeRollup({
        vulnerable_instances: 5,
        exposed_instances: 3,
        known_exploited_instances: 1,
        new_instances: 2,
        patched_instances: 4,
        removed_instances: 0,
      }),
    ]);
    expect(rows).toEqual([
      {
        x: Date.parse('2026-06-01T00:00:00.000Z'),
        vulnerable: 5,
        exposed: 3,
        knownExploited: 1,
        added: 2,
        patched: 4,
        removed: 0,
      },
    ]);
  });
});
