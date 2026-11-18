/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Deterministic synthetic log documents for `discover-logs` and `score-exposure` (see "Generator
 * specification" in docs/discovery_test_plan.md). Every timestamp is `T0 - offset`, every document
 * id is derived from T0 and the plan's doc id, and every host uses the `synth-` prefix (except the
 * TEST-NET-1 appliance `192.0.2.77`). Run each workflow within 60 minutes of T0.
 */

import type { EsClient } from '../clients';
import type { SoftwareCategory } from '../../../common/types';
import { SYNTHETIC_DATASET, SYNTHETIC_DATA_STREAM } from './template';

export type LogPhase = 'A' | 'B';
export const LOG_PHASES: readonly LogPhase[] = ['A', 'B'];

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

export interface LogFields {
  readonly host?: { readonly name?: string; readonly id?: string };
  readonly observer?: {
    readonly hostname?: string;
    readonly serial_number?: string;
    readonly ip?: string | readonly string[];
    readonly vendor?: string;
    readonly product?: string;
    readonly version?: string;
  };
  readonly service?: { readonly name?: string; readonly version?: string };
  readonly source?: { readonly ip: string };
  readonly network?: { readonly direction: string };
}

export interface SyntheticLogSpec {
  /** Plan doc id, with a `-NN` suffix for repeated documents (`A1-01`). */
  readonly docId: string;
  readonly phase: LogPhase;
  readonly offsetMs: number;
  readonly purpose: string;
  readonly fields: LogFields;
}

export interface SyntheticLogDoc {
  readonly _id: string;
  readonly spec: SyntheticLogSpec;
  readonly _source: LogFields & {
    readonly '@timestamp': string;
    readonly event: { readonly dataset: string };
    readonly message: string;
  };
}

const repeat = (
  baseId: string,
  count: number,
  build: (index: number) => Omit<SyntheticLogSpec, 'docId'>
): SyntheticLogSpec[] =>
  Array.from({ length: count }, (_, index) => ({
    docId: `${baseId}-${String(index + 1).padStart(2, '0')}`,
    ...build(index),
  }));

const fortigate = (hostname: string, version: string) => ({
  hostname,
  vendor: 'Fortinet',
  product: 'FortiGate',
  version,
});

const inbound = (ip: string) => ({ source: { ip }, network: { direction: 'inbound' } });

const X1_SOURCES = ['8.8.8.8', '8.8.8.8', '1.1.1.1', '1.1.1.1', '9.9.9.9', '9.9.9.9'];
const X4_SOURCES = ['4.2.2.1', '4.2.2.2', '64.6.64.6', '64.6.65.6', '76.76.2.0', '94.140.14.14'];

/** Every document of the plan's generator table, in table order. */
export const SYNTHETIC_LOG_SPECS: readonly SyntheticLogSpec[] = [
  ...repeat('A1', 10, (index) => ({
    phase: 'A',
    offsetMs: (120 - index * 10) * MINUTE_MS,
    purpose: 'Collector vs appliance; 10 duplicates collapse to 1 row (observed_at T0-30m)',
    fields: {
      host: { name: 'synth-collector-01' },
      observer: fortigate('synth-fw-01', '7.2.4'),
    },
  })),
  {
    docId: 'A2',
    phase: 'A',
    offsetMs: HOUR_MS,
    purpose: 'Second appliance behind the same collector',
    fields: {
      host: { name: 'synth-collector-01' },
      observer: {
        hostname: 'synth-fw-02',
        vendor: 'Palo Alto Networks',
        product: 'PAN-OS',
        version: '10.2.3',
      },
    },
  },
  {
    docId: 'A3',
    phase: 'A',
    offsetMs: 3 * HOUR_MS,
    purpose: 'Serial fallback, no host_name',
    fields: {
      observer: {
        serial_number: 'SYNTH-SN-0003',
        vendor: 'Cisco',
        product: 'ASA',
        version: '9.16.4',
      },
    },
  },
  {
    docId: 'A4',
    phase: 'A',
    offsetMs: 4 * HOUR_MS,
    purpose: 'IP fallback',
    fields: { observer: { ip: '192.0.2.77', vendor: 'F5', product: 'BIG-IP', version: '16.1.4' } },
  },
  {
    docId: 'A5',
    phase: 'A',
    offsetMs: 5 * HOUR_MS,
    purpose: 'Unmapped observer vendor',
    fields: {
      observer: {
        hostname: 'synth-edge-09',
        vendor: 'SynthNet',
        product: 'EdgeBox',
        version: '3.1',
      },
    },
  },
  {
    docId: 'A6',
    phase: 'A',
    offsetMs: HOUR_MS,
    purpose: 'Excluded (observer.version IS NOT NULL)',
    fields: { observer: { hostname: 'synth-fw-04', product: 'FortiGate' } },
  },
  {
    docId: 'A7',
    phase: 'A',
    offsetMs: 26 * HOUR_MS,
    purpose: 'Excluded (outside 24 h)',
    fields: { observer: fortigate('synth-fw-03', '7.2.4') },
  },
  {
    docId: 'A8',
    phase: 'A',
    offsetMs: 23 * HOUR_MS,
    purpose: 'Included (inside 24 h)',
    fields: { observer: fortigate('synth-fw-05', '7.0.11') },
  },
  {
    docId: 'S1',
    phase: 'A',
    offsetMs: 2 * HOUR_MS,
    purpose: 'Same instance as the Osquery nginx row',
    fields: {
      host: { name: 'synth-lin-01', id: 'synth-hostid-lin01' },
      service: { name: 'nginx', version: '1.18.0' },
    },
  },
  {
    docId: 'S2',
    phase: 'A',
    offsetMs: 3 * HOUR_MS,
    purpose: 'host_id falls back to the host name',
    fields: {
      host: { name: 'synth-web-01' },
      service: { name: 'synth-checkout', version: '2.4.0' },
    },
  },
  {
    docId: 'S2b',
    phase: 'A',
    offsetMs: HOUR_MS,
    purpose: 'Second ES|QL row, same instance key: dedupe',
    fields: {
      host: { name: 'SYNTH-Web-01' },
      service: { name: 'synth-checkout', version: '2.4.0' },
    },
  },
  {
    docId: 'S3a',
    phase: 'A',
    offsetMs: 20 * HOUR_MS,
    purpose: 'Version flip, before',
    fields: { host: { name: 'synth-web-02' }, service: { name: 'nginx', version: '1.25.2' } },
  },
  {
    docId: 'S3b',
    phase: 'B',
    offsetMs: HOUR_MS,
    purpose: 'Version flip, after',
    fields: { host: { name: 'synth-web-02' }, service: { name: 'nginx', version: '1.27.4' } },
  },
  {
    docId: 'S4',
    phase: 'A',
    offsetMs: 2 * HOUR_MS,
    purpose: 'Key on host id',
    fields: { host: { id: 'synth-hostid-0005' }, service: { name: 'redis', version: '7.0.11' } },
  },
  {
    docId: 'S5',
    phase: 'A',
    offsetMs: 2 * HOUR_MS,
    purpose: 'Excluded (no version)',
    fields: { host: { name: 'synth-web-03' }, service: { name: 'synth-api' } },
  },
  ...repeat('X1', 6, (index) => ({
    phase: 'A',
    offsetMs: DAY_MS,
    purpose: '3 distinct public sources',
    fields: { host: { name: 'synth-web-01' }, ...inbound(X1_SOURCES[index]) },
  })),
  ...repeat('X2', 2, (index) => ({
    phase: 'A',
    offsetMs: DAY_MS,
    purpose: 'Private, ignored',
    fields: { host: { name: 'synth-web-01' }, ...inbound(['10.1.2.3', '192.168.1.10'][index]) },
  })),
  {
    docId: 'X3',
    phase: 'A',
    offsetMs: DAY_MS,
    purpose: 'Outbound, ignored',
    fields: {
      host: { name: 'synth-lin-01' },
      source: { ip: '8.8.4.4' },
      network: { direction: 'outbound' },
    },
  },
  ...repeat('X4', 6, (index) => ({
    phase: 'A',
    offsetMs: 2 * DAY_MS,
    purpose: 'Edge plus inbound',
    fields: { host: { name: 'synth-fw-02' }, ...inbound(X4_SOURCES[index]) },
  })),
  {
    docId: 'X5',
    phase: 'A',
    offsetMs: DAY_MS,
    purpose: 'No direction, ignored',
    fields: { host: { name: 'synth-web-02' }, source: { ip: '1.0.0.1' } },
  },
  {
    docId: 'X6',
    phase: 'A',
    offsetMs: DAY_MS,
    purpose: 'Matched by host id, ingress',
    fields: {
      host: { id: 'synth-hostid-0005' },
      source: { ip: '208.67.222.222' },
      network: { direction: 'ingress' },
    },
  },
  {
    docId: 'X7',
    phase: 'A',
    offsetMs: 8 * DAY_MS,
    purpose: 'Outside 7 d',
    fields: { host: { name: 'synth-web-01' }, ...inbound('5.5.5.5') },
  },
  {
    docId: 'X8',
    phase: 'A',
    offsetMs: DAY_MS,
    purpose: 'Policy pseudo-hosts ignore logs',
    fields: { host: { name: 'policy:synth-pol-edge' }, ...inbound('8.8.8.8') },
  },
];

const compactTimestamp = (t0: Date): string => t0.toISOString().replace(/[-:.]/g, '');

/** Parses `--t0`; throws on anything that is not an ISO timestamp. */
export const parseT0 = (value: string): Date => {
  const parsed = Date.parse(value);
  if (!/^\d{4}-\d{2}-\d{2}T/.test(value) || Number.isNaN(parsed)) {
    throw new Error(`--t0 must be an ISO timestamp such as 2026-11-18T10:00:00Z, got "${value}"`);
  }
  return new Date(parsed);
};

export const toLogDoc = (spec: SyntheticLogSpec, t0: Date): SyntheticLogDoc => ({
  _id: `synth-${compactTimestamp(t0)}-${spec.docId}`,
  spec,
  _source: {
    '@timestamp': new Date(t0.getTime() - spec.offsetMs).toISOString(),
    event: { dataset: SYNTHETIC_DATASET },
    message: `software inventory synthetic log ${spec.docId}: ${spec.purpose}`,
    ...spec.fields,
  },
});

/** The documents of one phase; deterministic for a given T0. */
export const buildPhaseDocs = (phase: LogPhase, t0: Date): SyntheticLogDoc[] =>
  SYNTHETIC_LOG_SPECS.filter((spec) => spec.phase === phase).map((spec) => toLogDoc(spec, t0));

/** DL-10: an appliance with a multi-valued `observer.ip` (doc values sort `10.9.9.9` first). */
export const MULTI_VALUED_OBSERVER_SPEC: SyntheticLogSpec = {
  docId: 'DL10',
  phase: 'A',
  offsetMs: HOUR_MS,
  purpose: 'Multi-valued observer.ip',
  fields: {
    observer: {
      ip: ['192.0.2.78', '10.9.9.9'],
      vendor: 'F5',
      product: 'BIG-IP',
      version: '16.1.4',
    },
  },
};

/** A one-off service document, for cases such as DO-15 (`synth-svc` on `synth-lin-01`). */
export const serviceLogSpec = ({
  docId,
  hostName,
  hostId,
  service,
  version,
  offsetMs = HOUR_MS,
}: {
  docId: string;
  hostName?: string;
  hostId?: string;
  service: string;
  version: string;
  offsetMs?: number;
}): SyntheticLogSpec => ({
  docId,
  phase: 'A',
  offsetMs,
  purpose: `Service ${service} ${version}`,
  fields: {
    host: { ...(hostName ? { name: hostName } : {}), ...(hostId ? { id: hostId } : {}) },
    service: { name: service, version },
  },
});

/**
 * Writes documents with `create` and fixed ids, so re-writing a phase for the same T0 is a no-op
 * (conflicts are counted, not failed).
 */
export const writeLogDocs = async (
  es: EsClient,
  docs: readonly SyntheticLogDoc[]
): Promise<{ written: number; existing: number }> => {
  const summary = await es.bulk(
    docs.flatMap((doc) => [
      { create: { _index: SYNTHETIC_DATA_STREAM, _id: doc._id } },
      doc._source,
    ]),
    { refresh: 'true' }
  );
  if (summary.failed > 0) {
    throw new Error(
      `Writing synthetic logs failed for ${summary.failed} doc(s): ${summary.firstError}`
    );
  }
  return { written: summary.total - summary.conflicts, existing: summary.conflicts };
};

// -------------------------------------------------------------------------------------------------
// Expected `discover-logs` candidates (one per ES|QL row) and instances.
// -------------------------------------------------------------------------------------------------

export interface ExpectedLogCandidate {
  /** Plan doc ids that produce this ES|QL row. */
  readonly docIds: readonly string[];
  readonly category: Extract<SoftwareCategory, 'appliance' | 'application'>;
  readonly host_id: string;
  readonly host_name?: string;
  readonly vendor?: string;
  readonly name: string;
  readonly version: string;
  /** Offset of the latest sighting from T0 (`observed_at` = T0 - offset). */
  readonly observedOffsetMs: number;
  /** Canonical host key and normalized catalog id the ingest step derives. */
  readonly hostKey: string;
  readonly catalogId: string;
}

/** ES|QL rows of the phase A run, appliances first, in the plan's table order. */
export const EXPECTED_PHASE_A_CANDIDATES: readonly ExpectedLogCandidate[] = [
  {
    docIds: ['A1'],
    category: 'appliance',
    host_id: 'synth-fw-01',
    host_name: 'synth-fw-01',
    vendor: 'Fortinet',
    name: 'FortiGate',
    version: '7.2.4',
    observedOffsetMs: 30 * MINUTE_MS,
    hostKey: 'synth-fw-01',
    catalogId: 'fortinet:fortios:7.2.4',
  },
  {
    docIds: ['A2'],
    category: 'appliance',
    host_id: 'synth-fw-02',
    host_name: 'synth-fw-02',
    vendor: 'Palo Alto Networks',
    name: 'PAN-OS',
    version: '10.2.3',
    observedOffsetMs: HOUR_MS,
    hostKey: 'synth-fw-02',
    catalogId: 'palo_alto_networks:pan-os:10.2.3',
  },
  {
    docIds: ['A3'],
    category: 'appliance',
    host_id: 'SYNTH-SN-0003',
    vendor: 'Cisco',
    name: 'ASA',
    version: '9.16.4',
    observedOffsetMs: 3 * HOUR_MS,
    hostKey: 'synth-sn-0003',
    catalogId: 'cisco:adaptive_security_appliance_software:9.16.4',
  },
  {
    docIds: ['A4'],
    category: 'appliance',
    host_id: '192.0.2.77',
    vendor: 'F5',
    name: 'BIG-IP',
    version: '16.1.4',
    observedOffsetMs: 4 * HOUR_MS,
    hostKey: '192.0.2.77',
    catalogId: 'f5:big-ip:16.1.4',
  },
  {
    docIds: ['A5'],
    category: 'appliance',
    host_id: 'synth-edge-09',
    host_name: 'synth-edge-09',
    vendor: 'SynthNet',
    name: 'EdgeBox',
    version: '3.1',
    observedOffsetMs: 5 * HOUR_MS,
    hostKey: 'synth-edge-09',
    catalogId: 'synthnet:edgebox:3.1',
  },
  {
    docIds: ['A8'],
    category: 'appliance',
    host_id: 'synth-fw-05',
    host_name: 'synth-fw-05',
    vendor: 'Fortinet',
    name: 'FortiGate',
    version: '7.0.11',
    observedOffsetMs: 23 * HOUR_MS,
    hostKey: 'synth-fw-05',
    catalogId: 'fortinet:fortios:7.0.11',
  },
  {
    docIds: ['S1'],
    category: 'application',
    host_id: 'synth-hostid-lin01',
    host_name: 'synth-lin-01',
    name: 'nginx',
    version: '1.18.0',
    observedOffsetMs: 2 * HOUR_MS,
    hostKey: 'synth-lin-01',
    catalogId: 'f5:nginx:1.18.0',
  },
  {
    docIds: ['S2'],
    category: 'application',
    host_id: 'synth-web-01',
    host_name: 'synth-web-01',
    name: 'synth-checkout',
    version: '2.4.0',
    observedOffsetMs: 3 * HOUR_MS,
    hostKey: 'synth-web-01',
    catalogId: 'synth-checkout:synth-checkout:2.4.0',
  },
  {
    docIds: ['S2b'],
    category: 'application',
    host_id: 'SYNTH-Web-01',
    host_name: 'SYNTH-Web-01',
    name: 'synth-checkout',
    version: '2.4.0',
    observedOffsetMs: HOUR_MS,
    hostKey: 'synth-web-01',
    catalogId: 'synth-checkout:synth-checkout:2.4.0',
  },
  {
    docIds: ['S3a'],
    category: 'application',
    host_id: 'synth-web-02',
    host_name: 'synth-web-02',
    name: 'nginx',
    version: '1.25.2',
    observedOffsetMs: 20 * HOUR_MS,
    hostKey: 'synth-web-02',
    catalogId: 'f5:nginx:1.25.2',
  },
  {
    docIds: ['S4'],
    category: 'application',
    host_id: 'synth-hostid-0005',
    name: 'redis',
    version: '7.0.11',
    observedOffsetMs: 2 * HOUR_MS,
    hostKey: 'synth-hostid-0005',
    catalogId: 'redis:redis:7.0.11',
  },
];

/** The ES|QL row phase B adds (the version flip on `synth-web-02`). */
export const EXPECTED_PHASE_B_CANDIDATE: ExpectedLogCandidate = {
  docIds: ['S3b'],
  category: 'application',
  host_id: 'synth-web-02',
  host_name: 'synth-web-02',
  name: 'nginx',
  version: '1.27.4',
  observedOffsetMs: HOUR_MS,
  hostKey: 'synth-web-02',
  catalogId: 'f5:nginx:1.27.4',
};

export interface ExpectedLogInstance {
  readonly hostKey: string;
  readonly catalogId: string;
  readonly category: 'appliance' | 'application';
  /** Stored `host.name`, or null when the instance has none. */
  readonly hostName: string | null;
  /** Outcome of the first `discover-logs` run when `R1` (DO-1) ran before it. */
  readonly outcomeAfterR1: 'created' | 'unchanged';
}

/** Instances of the phase A run: 10, one per instance key. */
export const EXPECTED_PHASE_A_INSTANCES: readonly ExpectedLogInstance[] = [
  ...new Map(
    EXPECTED_PHASE_A_CANDIDATES.map((candidate) => [
      `${candidate.hostKey}|${candidate.catalogId}`,
      {
        hostKey: candidate.hostKey,
        catalogId: candidate.catalogId,
        category: candidate.category,
        hostName: candidate.host_name ?? null,
        outcomeAfterR1:
          candidate.hostKey === 'synth-lin-01' && candidate.catalogId === 'f5:nginx:1.18.0'
            ? ('unchanged' as const)
            : ('created' as const),
      },
    ])
  ).values(),
];

/** `ingest` output of the phase A run after `R1` (DL-1) and of the phase B re-run (DL-7). */
export const EXPECTED_DL1_INGEST = { created: 9, unchanged: 1, patched: 0, removed: 0, skipped: 0 };
export const EXPECTED_DL7_INGEST = { created: 0, unchanged: 9, patched: 1, removed: 0, skipped: 0 };

/** Host keys that must never get an instance from the synthetic logs. */
export const EXPECTED_ABSENT_HOST_KEYS = [
  'synth-collector-01',
  'synth-fw-03',
  'synth-fw-04',
  'synth-web-03',
] as const;

/** Distinct public inbound sources `score` sees within 7 days, by log `host.name` / `host.id`. */
export const EXPECTED_INBOUND_SOURCES = {
  byHostName: { 'synth-web-01': 3, 'synth-fw-02': 6, 'policy:synth-pol-edge': 1 },
  byHostId: { 'synth-hostid-0005': 1 },
} as const;
