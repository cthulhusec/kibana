/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ExposureEvidence, ExposureLevel } from '../../../common/types';

export const EDGE_ROLE_WEIGHT = 50;
export const INBOUND_PUBLIC_WEIGHT = 40;
export const MAX_EXTRA_SOURCES_WEIGHT = 10;

export const levelFromScore = (score: number): ExposureLevel => {
  if (score < 1) return 'none';
  if (score < 40) return 'low';
  if (score < 70) return 'medium';
  return 'high';
};

export interface ExposureSignals {
  isEdge: boolean;
  edgeDetail?: string;
  /** Number of distinct public source IPs observed, 0 when none. */
  distinctPublicSources: number;
  sampleSources?: string[];
  lookbackDays: number;
  existingEvidence?: ExposureEvidence[];
}

export interface ExposureResult {
  level: ExposureLevel;
  score: number;
  evidence: ExposureEvidence[];
}

/** Combines signals into a 0-100 score. Manual evidence is always kept and never reduced. */
export const combineExposure = (signals: ExposureSignals): ExposureResult => {
  const evidence: ExposureEvidence[] = (signals.existingEvidence ?? []).filter(
    (item) => item.signal === 'manual'
  );

  if (signals.isEdge) {
    evidence.push({
      signal: 'edge_device_role',
      detail: signals.edgeDetail ?? 'Software runs on an edge or internet-facing device',
      weight: EDGE_ROLE_WEIGHT,
    });
  }

  if (signals.distinctPublicSources > 0) {
    const extra = Math.min(MAX_EXTRA_SOURCES_WEIGHT, (signals.distinctPublicSources - 1) * 2);
    const samples = signals.sampleSources?.length
      ? ` (for example ${signals.sampleSources.join(', ')})`
      : '';
    evidence.push({
      signal: 'inbound_public_ip',
      detail: `Received inbound connections from ${signals.distinctPublicSources} distinct public IP address(es) in the last ${signals.lookbackDays} day(s)${samples}`,
      weight: INBOUND_PUBLIC_WEIGHT + extra,
    });
  }

  const score = Math.min(
    100,
    evidence.reduce((sum, item) => sum + Math.max(0, item.weight), 0)
  );
  return { level: levelFromScore(score), score, evidence };
};
