/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Deterministic synthetic Elastic Defend process events for `discover-endpoint` (see the DE
 * section of docs/discovery_test_plan.md). Every timestamp is `T0 - offset`, every document id is
 * derived from T0 and the plan's doc id, and every host uses the `synth-win-` prefix. Run each
 * workflow within 55 minutes of T0.
 */

import type { EsClient } from '../clients';
import { ENDPOINT_DATASET, ENDPOINT_DATA_STREAM } from './endpoint_template';

export type EndpointPhase = 'A' | 'B';

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;

export interface EndpointFields {
  readonly host: { readonly id?: string; readonly name?: string };
  readonly process: {
    readonly name: string;
    readonly executable?: string;
    readonly pe?: {
      readonly company?: string;
      readonly product?: string;
      readonly file_version?: string;
    };
    readonly code_signature?: { readonly subject_name: string };
  };
}

export interface SyntheticEndpointSpec {
  /** Plan doc id, with a `-NN` suffix for repeated documents (`E1-01`). */
  readonly docId: string;
  readonly phase: EndpointPhase;
  readonly offsetMs: number;
  readonly purpose: string;
  readonly fields: EndpointFields;
}

export interface SyntheticEndpointDoc {
  readonly _id: string;
  readonly spec: SyntheticEndpointSpec;
  readonly _source: EndpointFields & {
    readonly '@timestamp': string;
    readonly event: { readonly dataset: string; readonly action: string };
    readonly message: string;
  };
}

const FIREFOX_EXE = 'C:\\Program Files\\Mozilla Firefox\\firefox.exe';

const spec = (
  docId: string,
  offsetMs: number,
  purpose: string,
  fields: EndpointFields,
  phase: EndpointPhase = 'A'
): SyntheticEndpointSpec => ({ docId, phase, offsetMs, purpose, fields });

const firefox = (version: string): EndpointFields => ({
  host: { id: 'synth-win-01-id', name: 'synth-win-01' },
  process: {
    name: 'firefox.exe',
    executable: FIREFOX_EXE,
    pe: { company: 'Mozilla Corporation', product: 'Firefox', file_version: version },
  },
});

/** Every document of the DE generator table, in table order. */
export const SYNTHETIC_ENDPOINT_SPECS: readonly SyntheticEndpointSpec[] = [
  spec('E1-01', 3 * HOUR_MS, 'Firefox 124.0.1, duplicate 1 of 3', firefox('124.0.1')),
  spec('E1-02', 2 * HOUR_MS, 'Firefox 124.0.1, duplicate 2 of 3', firefox('124.0.1')),
  spec(
    'E1-03',
    HOUR_MS,
    'Firefox 124.0.1, duplicate 3 of 3 (observed_at T0-1h)',
    firefox('124.0.1')
  ),
  spec('E2', 2 * HOUR_MS, 'No company: the vendor comes from the code signature', {
    host: { id: 'synth-win-02-id', name: 'synth-win-02' },
    process: {
      name: 'signed.exe',
      executable: 'C:\\Program Files\\Synth-Signed\\signed.exe',
      pe: { product: 'Synth-Signed', file_version: '1.0' },
      code_signature: { subject_name: 'Synth-Signer Inc' },
    },
  }),
  spec('E3', 3 * HOUR_MS, 'Host name only: no host.id', {
    host: { name: 'synth-win-03' },
    process: {
      name: 'viewer.exe',
      executable: 'C:\\Program Files\\Synth-Viewer\\viewer.exe',
      pe: { company: 'Synth-Viewer Corp', product: 'Synth-Viewer', file_version: '2.1' },
    },
  }),
  spec('E4-SVC', 2 * HOUR_MS, 'Excluded: executable under C:\\Windows\\', {
    host: { id: 'synth-win-04-id', name: 'synth-win-04' },
    process: {
      name: 'svchost.exe',
      executable: 'C:\\Windows\\System32\\svchost.exe',
      pe: {
        company: 'Microsoft Corporation',
        product: 'Microsoft Windows Operating System',
        file_version: '10.0.19041.1',
      },
    },
  }),
  spec('E4-NOTEPAD', 2 * HOUR_MS, 'Excluded: upper-case C:\\WINDOWS\\ path', {
    host: { id: 'synth-win-04-id', name: 'synth-win-04' },
    process: {
      name: 'notepad.exe',
      executable: 'c:\\WINDOWS\\system32\\notepad.exe',
      pe: {
        company: 'Microsoft Corporation',
        product: 'Microsoft Windows Operating System',
        file_version: '10.0.19041.2',
      },
    },
  }),
  spec('E4-NOEXE', 90 * MINUTE_MS, 'Kept: no process.executable at all', {
    host: { id: 'synth-win-04-id', name: 'synth-win-04' },
    process: {
      name: 'noexe',
      pe: { company: 'Synth-NoExe Ltd', product: 'Synth-NoExe', file_version: '1.5' },
    },
  }),
  spec('E5', 2 * HOUR_MS, 'Excluded: PE product without a file version', {
    host: { id: 'synth-win-05-id', name: 'synth-win-05' },
    process: {
      name: 'noversion.exe',
      executable: 'C:\\Program Files\\Synth-NoVersion\\noversion.exe',
      pe: { company: 'Synth-NoVersion Ltd', product: 'Synth-NoVersion' },
    },
  }),
  spec('E6', 26 * HOUR_MS, 'Excluded: outside the 24 h window', {
    host: { id: 'synth-win-06-id', name: 'synth-win-06' },
    process: {
      name: 'old.exe',
      executable: 'C:\\Program Files\\Synth-Old\\old.exe',
      pe: { company: 'Synth-Old Ltd', product: 'Synth-Old', file_version: '2.0' },
    },
  }),
  ...['3.0', '3.1'].map((version, index) =>
    spec(`E7-${index + 1}`, (index === 0 ? 5 : 2) * HOUR_MS, `Synth-Dual ${version}`, {
      host: { id: 'synth-win-07-id', name: 'synth-win-07' },
      process: {
        name: 'dual.exe',
        executable: 'C:\\Program Files\\Synth-Dual\\dual.exe',
        pe: { company: 'Synth-Dual Ltd', product: 'Synth-Dual', file_version: version },
      },
    })
  ),
  spec('E8', 90 * MINUTE_MS, 'Synth-Both, also reported by Osquery in DE-6', {
    host: { id: 'synth-win-08-id', name: 'synth-win-08' },
    process: {
      name: 'both.exe',
      executable: 'C:\\Program Files\\Synth-Both\\both.exe',
      pe: { company: 'Synth-Both Inc', product: 'Synth-Both', file_version: '5.0' },
    },
  }),
  spec(
    'E9',
    30 * MINUTE_MS,
    'Firefox 125.0.1 on the same host: the patch',
    firefox('125.0.1'),
    'B'
  ),
];

const compactTimestamp = (t0: Date): string => t0.toISOString().replace(/[-:.]/g, '');

export const toEndpointDoc = (item: SyntheticEndpointSpec, t0: Date): SyntheticEndpointDoc => ({
  _id: `synth-${compactTimestamp(t0)}-${item.docId}`,
  spec: item,
  _source: {
    '@timestamp': new Date(t0.getTime() - item.offsetMs).toISOString(),
    event: { dataset: ENDPOINT_DATASET, action: 'start' },
    message: `software inventory synthetic endpoint event ${item.docId}: ${item.purpose}`,
    ...item.fields,
  },
});

/** The documents of one phase; deterministic for a given T0. */
export const buildEndpointDocs = (phase: EndpointPhase, t0: Date): SyntheticEndpointDoc[] =>
  SYNTHETIC_ENDPOINT_SPECS.filter((item) => item.phase === phase).map((item) =>
    toEndpointDoc(item, t0)
  );

/** Writes documents with `create` and fixed ids, so re-writing a phase for one T0 is a no-op. */
export const writeEndpointDocs = async (
  es: EsClient,
  docs: readonly SyntheticEndpointDoc[]
): Promise<{ written: number; existing: number }> => {
  const summary = await es.bulk(
    docs.flatMap((doc) => [
      { create: { _index: ENDPOINT_DATA_STREAM, _id: doc._id } },
      doc._source,
    ]),
    { refresh: 'true' }
  );
  if (summary.failed > 0) {
    throw new Error(
      `Writing synthetic endpoint events failed for ${summary.failed} doc(s): ${summary.firstError}`
    );
  }
  return { written: summary.total - summary.conflicts, existing: summary.conflicts };
};
