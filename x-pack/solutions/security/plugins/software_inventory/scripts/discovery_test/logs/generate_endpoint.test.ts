/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * @jest-environment node
 */

import { normalizeCandidate } from '../../../server/services/ingest/normalize_candidate';
import {
  ABSENT_HOST_KEYS,
  EXPECTED_PHASE_A_ROWS,
  EXPECTED_PHASE_B_ROW,
  dedupeRows,
  rowsAt,
} from '../expected/de';
import { isSyntheticHostKey } from '../ids';
import type { SyntheticEndpointDoc } from './generate_endpoint';
import {
  SYNTHETIC_ENDPOINT_SPECS,
  buildEndpointDocs,
  toEndpointDoc,
  writeEndpointDocs,
} from './generate_endpoint';
import {
  ENDPOINT_DATA_STREAM,
  ENDPOINT_PACKAGE_TEMPLATE_NAME,
  ENDPOINT_PATTERN,
  ENDPOINT_TEMPLATE,
  ENDPOINT_TEMPLATE_NAME,
  deleteEndpointDataStream,
  ensureEndpointDataStream,
  listEndpointDataStreams,
} from './endpoint_template';
import { buildFakeStack } from '../cases/fake_stack';

const T0 = new Date('2026-11-18T10:00:00.000Z');
const HOUR_MS = 3_600_000;
const RUN_AT = T0.getTime() + 30 * 60_000;

interface Row {
  host_id: string;
  host_name?: string;
  vendor?: string;
  name: string;
  version: string;
  observed_at: string;
}

/** In-memory model of the production ES|QL query of `discover-endpoint`. */
const emulateDiscoverEndpoint = (docs: readonly SyntheticEndpointDoc[], now: number): Row[] => {
  const groups = new Map<string, Row>();
  for (const { _source: source } of docs) {
    const { process, host } = source;
    if (Date.parse(source['@timestamp']) <= now - 24 * HOUR_MS) continue;
    if (!process.pe?.product || !process.pe.file_version) continue;
    if ((process.executable ?? '').toLowerCase().startsWith('c:\\windows\\')) continue;
    const hostId = host.id ?? host.name;
    if (!hostId) continue;
    const vendor = process.pe.company ?? process.code_signature?.subject_name;
    const key = [hostId, host.name, vendor, process.pe.product, process.pe.file_version].join('|');
    const row: Row = {
      host_id: hostId,
      ...(host.name ? { host_name: host.name } : {}),
      ...(vendor ? { vendor } : {}),
      name: process.pe.product,
      version: process.pe.file_version,
      observed_at: source['@timestamp'],
    };
    const current = groups.get(key);
    if (!current || row.observed_at > current.observed_at) groups.set(key, row);
  }
  return [...groups.values()];
};

const allDocs = (): SyntheticEndpointDoc[] => [
  ...buildEndpointDocs('A', T0),
  ...buildEndpointDocs('B', T0),
];

describe('synthetic endpoint documents', () => {
  it('derive ids and timestamps from T0 and are unique', () => {
    const docs = allDocs();
    expect(new Set(docs.map(({ _id }) => _id)).size).toBe(docs.length);
    expect(docs.length).toBe(SYNTHETIC_ENDPOINT_SPECS.length);
    expect(buildEndpointDocs('A', T0)).toEqual(buildEndpointDocs('A', T0));
    const doc = toEndpointDoc(SYNTHETIC_ENDPOINT_SPECS[0], T0);
    expect(doc._id).toBe('synth-20261118T100000000Z-E1-01');
    expect(doc._source['@timestamp']).toBe(new Date(T0.getTime() - 3 * HOUR_MS).toISOString());
  });

  it('use only synthetic host names', () => {
    for (const { _source: source } of allDocs()) {
      expect(isSyntheticHostKey(source.host.name ?? '')).toBe(true);
    }
  });

  it('produce the expected ES|QL rows at each stage', () => {
    const expected = (stage: 'A' | 'B') =>
      rowsAt(stage).map(
        ({ host_id: id, host_name: name, vendor, version, observedOffsetMs, ...rest }) => ({
          host_id: id,
          host_name: name,
          vendor,
          name: rest.name,
          version,
          observed_at: new Date(T0.getTime() - observedOffsetMs).toISOString(),
        })
      );
    const sorted = (rows: readonly Row[]) =>
      [...rows].sort((a, b) =>
        `${a.host_id}${a.version}`.localeCompare(`${b.host_id}${b.version}`)
      );
    expect(sorted(emulateDiscoverEndpoint(buildEndpointDocs('A', T0), RUN_AT))).toEqual(
      sorted(expected('A'))
    );
    expect(sorted(emulateDiscoverEndpoint(allDocs(), RUN_AT))).toEqual(sorted(expected('B')));
  });

  it('leave the excluded hosts without a row', () => {
    const hosts = emulateDiscoverEndpoint(allDocs(), RUN_AT).map(({ host_name: name }) => name);
    for (const hostKey of [...ABSENT_HOST_KEYS.excluded, ...ABSENT_HOST_KEYS.outsideWindow]) {
      expect(hosts).not.toContain(hostKey);
    }
    expect(emulateDiscoverEndpoint(allDocs(), RUN_AT).map(({ name }) => name)).not.toContain(
      'Microsoft Windows Operating System'
    );
  });

  it('normalize to the expected catalog ids and host keys', () => {
    for (const candidate of [...EXPECTED_PHASE_A_ROWS, EXPECTED_PHASE_B_ROW]) {
      const normalized = normalizeCandidate(
        {
          host_id: candidate.host_id,
          host_name: candidate.host_name,
          name: candidate.name,
          vendor: candidate.vendor,
          version: candidate.version,
          category: 'application',
        },
        T0.toISOString(),
        'endpoint'
      );
      expect(normalized?.host_key).toBe(candidate.hostKey);
      const [vendor, product, version] = candidate.catalogId.split(':');
      expect(normalized).toMatchObject({ vendor, product, version, category: 'application' });
    }
  });

  it('dedupe to six instances at both stages', () => {
    expect(dedupeRows(rowsAt('A')).size).toBe(6);
    expect(dedupeRows(rowsAt('B')).size).toBe(6);
    const dual = [...dedupeRows(rowsAt('A')).values()].find(
      ({ hostKey }) => hostKey === 'synth-win-07'
    );
    expect(dual?.version).toBe('3.1');
  });
});

describe('endpoint data stream and template', () => {
  it('maps every field the workflow reads', () => {
    const { properties } = ENDPOINT_TEMPLATE.template.mappings;
    expect(Object.keys(properties.host.properties)).toEqual(['id', 'name']);
    expect(Object.keys(properties.process.properties.pe.properties)).toEqual([
      'company',
      'product',
      'file_version',
    ]);
    expect(properties.process.properties.code_signature.properties.subject_name.type).toBe(
      'keyword'
    );
    expect(properties.process.properties.executable.type).toBe('keyword');
    expect(ENDPOINT_TEMPLATE.priority).toBeGreaterThan(200);
    expect(ENDPOINT_TEMPLATE.index_patterns).toEqual([`${ENDPOINT_DATA_STREAM}*`]);
    expect(ENDPOINT_DATA_STREAM.startsWith(ENDPOINT_PATTERN.replace('*', ''))).toBe(true);
  });

  it('installs its own template only when the Endpoint package template is missing', async () => {
    const stack = buildFakeStack();
    const created = await ensureEndpointDataStream(stack.es);
    expect(created).toEqual({
      templateCreated: true,
      dataStreamCreated: true,
      usedPackageTemplate: false,
    });
    expect(stack.templates.has(ENDPOINT_TEMPLATE_NAME)).toBe(true);
    expect(stack.dataStreams.has(ENDPOINT_DATA_STREAM)).toBe(true);
    expect(await listEndpointDataStreams(stack.es)).toEqual([ENDPOINT_DATA_STREAM]);

    const withPackage = buildFakeStack();
    withPackage.templates.add(ENDPOINT_PACKAGE_TEMPLATE_NAME);
    expect(await ensureEndpointDataStream(withPackage.es)).toEqual({
      templateCreated: false,
      dataStreamCreated: true,
      usedPackageTemplate: true,
    });
    expect(withPackage.templates.has(ENDPOINT_TEMPLATE_NAME)).toBe(false);
  });

  it('deletes the data stream and the harness template, never the package template', async () => {
    const stack = buildFakeStack();
    stack.templates.add(ENDPOINT_PACKAGE_TEMPLATE_NAME);
    stack.templates.add(ENDPOINT_TEMPLATE_NAME);
    stack.dataStreams.add(ENDPOINT_DATA_STREAM);
    expect(await deleteEndpointDataStream(stack.es)).toEqual({
      dataStreamDeleted: true,
      templateDeleted: true,
    });
    expect(stack.templates.has(ENDPOINT_PACKAGE_TEMPLATE_NAME)).toBe(true);
    expect(await deleteEndpointDataStream(stack.es)).toEqual({
      dataStreamDeleted: false,
      templateDeleted: false,
    });
  });

  it('writes with create and fixed ids, so a second write is a no-op', async () => {
    const stack = buildFakeStack();
    const docs = buildEndpointDocs('A', T0);
    expect(await writeEndpointDocs(stack.es, docs)).toEqual({ written: docs.length, existing: 0 });
    expect(await writeEndpointDocs(stack.es, docs)).toEqual({ written: 0, existing: docs.length });
  });
});
