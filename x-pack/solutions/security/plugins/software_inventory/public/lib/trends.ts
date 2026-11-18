/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { DailyRollup } from '../../common/history';

export interface TrendRow {
  /** Start of the UTC day, in epoch ms. */
  x: number;
  vulnerable: number;
  exposed: number;
  knownExploited: number;
  added: number;
  patched: number;
  removed: number;
}

/** Flattens daily rollups into one row per UTC day for the charts. */
export const toTrendRows = (buckets: readonly DailyRollup[]): TrendRow[] =>
  buckets.map((bucket) => ({
    x: Date.parse(bucket['@timestamp']),
    vulnerable: bucket.vulnerable_instances,
    exposed: bucket.exposed_instances,
    knownExploited: bucket.known_exploited_instances,
    added: bucket.new_instances,
    patched: bucket.patched_instances,
    removed: bucket.removed_instances,
  }));
