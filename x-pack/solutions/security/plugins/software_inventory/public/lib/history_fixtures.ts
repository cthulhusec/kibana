/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  DailyRollup,
  HostTimelineResponse,
  TimelineInterval,
  TrendsResponse,
} from '../../common/history';

/** Typed builders for tests. */
export const makeRollup = (overrides: Partial<DailyRollup> = {}): DailyRollup => ({
  '@timestamp': '2026-06-01T00:00:00.000Z',
  total_instances: 10,
  total_software: 8,
  vulnerable_instances: 5,
  critical_instances: 1,
  high_instances: 2,
  exposed_instances: 3,
  known_exploited_instances: 1,
  exposed_and_vulnerable_instances: 1,
  new_instances: 2,
  patched_instances: 4,
  removed_instances: 0,
  categories: { application: 5, dependency: 3, appliance: 0, os_package: 2, other: 0 },
  ...overrides,
});

export const makeTrends = (overrides: Partial<TrendsResponse> = {}): TrendsResponse => ({
  from: '2026-06-01T00:00:00.000Z',
  to: '2026-06-30T00:00:00.000Z',
  buckets: [makeRollup()],
  patch_summary: { patches: 7, remediating_patches: 5, median_time_to_patch_ms: 2 * 86_400_000 },
  ...overrides,
});

export const makeInterval = (overrides: Partial<TimelineInterval> = {}): TimelineInterval => ({
  software_id: 'apache:log4j:2.14.0',
  display_name: 'Log4j',
  version: '2.14.0',
  start: '2026-06-01T00:00:00.000Z',
  vulnerable_windows: [],
  ...overrides,
});

export const makeTimeline = (
  overrides: Partial<HostTimelineResponse> = {}
): HostTimelineResponse => ({
  host_key: 'web-1',
  from: '2026-06-01T00:00:00.000Z',
  to: '2026-06-30T00:00:00.000Z',
  vulnerable_in_range: false,
  vulnerable_duration_ms: 0,
  cve_ids: [],
  items: [],
  ...overrides,
});
