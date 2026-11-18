/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { normalizeCandidate } from '../../../server/services/ingest/normalize_candidate';
import { isPublicIp } from '../../../server/services/enrichment/public_ip';
import { isSyntheticHostKey } from '../ids';
import type { ExpectedLogCandidate, SyntheticLogDoc } from './generate_logs';
import {
  EXPECTED_ABSENT_HOST_KEYS,
  EXPECTED_INBOUND_SOURCES,
  EXPECTED_PHASE_A_CANDIDATES,
  EXPECTED_PHASE_A_INSTANCES,
  EXPECTED_PHASE_B_CANDIDATE,
  MULTI_VALUED_OBSERVER_SPEC,
  SYNTHETIC_LOG_SPECS,
  buildPhaseDocs,
  parseT0,
  toLogDoc,
} from './generate_logs';
import { REQUIRED_MAPPED_FIELDS, SYNTHETIC_TEMPLATE, evaluateSimulation } from './template';

const T0 = new Date('2026-11-18T10:00:00.000Z');
const HOUR_MS = 3_600_000;
/** The workflow runs within 60 minutes of T0, as the plan requires. */
const RUN_AT = T0.getTime() + 30 * 60_000;

interface EsqlRow {
  host_id: string;
  host_name?: string;
  vendor?: string;
  name: string;
  version: string;
  observed_at: string;
  category: 'appliance' | 'application';
}

const firstIp = (ip: string | readonly string[] | undefined): string | undefined => {
  if (ip === undefined) return undefined;
  if (typeof ip === 'string') return ip;
  // MV_FIRST reads doc values, which Elasticsearch stores sorted.
  return [...ip].sort()[0];
};

/** In-memory model of the two production ES|QL queries of `discover-logs`. */
const emulateDiscoverLogs = (docs: readonly SyntheticLogDoc[], now: number): EsqlRow[] => {
  const inWindow = docs.filter((doc) => Date.parse(doc._source['@timestamp']) > now - 24 * HOUR_MS);
  const groups = new Map<string, EsqlRow>();
  const keep = (key: string, row: EsqlRow) => {
    const current = groups.get(key);
    if (!current || row.observed_at > current.observed_at) groups.set(key, row);
  };
  for (const { _source: source } of inWindow) {
    const { observer, service, host } = source;
    if (observer?.product && observer.version) {
      const hostId = observer.hostname ?? observer.serial_number ?? firstIp(observer.ip);
      if (hostId) {
        keep(
          `a|${hostId}|${observer.hostname}|${observer.vendor}|${observer.product}|${observer.version}`,
          {
            host_id: hostId,
            ...(observer.hostname ? { host_name: observer.hostname } : {}),
            ...(observer.vendor ? { vendor: observer.vendor } : {}),
            name: observer.product,
            version: observer.version,
            observed_at: source['@timestamp'],
            category: 'appliance',
          }
        );
      }
    }
    if (service?.name && service.version) {
      const hostId = host?.id ?? host?.name;
      if (hostId) {
        keep(`s|${host?.id}|${host?.name}|${service.name}|${service.version}`, {
          host_id: hostId,
          ...(host?.name ? { host_name: host.name } : {}),
          name: service.name,
          version: service.version,
          observed_at: source['@timestamp'],
          category: 'application',
        });
      }
    }
  }
  return [...groups.values()];
};

const toRow = (candidate: ExpectedLogCandidate): EsqlRow => ({
  host_id: candidate.host_id,
  ...(candidate.host_name ? { host_name: candidate.host_name } : {}),
  ...(candidate.vendor ? { vendor: candidate.vendor } : {}),
  name: candidate.name,
  version: candidate.version,
  observed_at: new Date(T0.getTime() - candidate.observedOffsetMs).toISOString(),
  category: candidate.category,
});

const sortRows = (rows: EsqlRow[]) =>
  [...rows].sort((a, b) =>
    `${a.host_id}|${a.name}|${a.version}`.localeCompare(`${b.host_id}|${b.name}|${b.version}`)
  );

describe('generate_logs', () => {
  it('is deterministic for a given T0 and changes ids with T0', () => {
    expect(buildPhaseDocs('A', T0)).toEqual(buildPhaseDocs('A', new Date(T0.getTime())));
    const other = buildPhaseDocs('A', new Date(T0.getTime() + 1000));
    expect(other.map((doc) => doc._id)).not.toEqual(buildPhaseDocs('A', T0).map((doc) => doc._id));
  });

  it('gives every document a unique id and the synthetic dataset', () => {
    const docs = [...buildPhaseDocs('A', T0), ...buildPhaseDocs('B', T0)];
    expect(new Set(docs.map((doc) => doc._id)).size).toBe(docs.length);
    expect(docs).toHaveLength(SYNTHETIC_LOG_SPECS.length);
    for (const doc of docs) expect(doc._source.event.dataset).toBe('softwareinventory.synthetic');
    expect(buildPhaseDocs('B', T0).map((doc) => doc.spec.docId)).toEqual(['S3b']);
  });

  it('timestamps every document at T0 minus its offset', () => {
    const a1 = buildPhaseDocs('A', T0).filter((doc) => doc.spec.docId.startsWith('A1-'));
    expect(a1).toHaveLength(10);
    expect(
      a1
        .map((doc) => doc._source['@timestamp'])
        .sort()
        .at(-1)
    ).toBe('2026-11-18T09:30:00.000Z');
    expect(a1.map((doc) => doc._source['@timestamp']).sort()[0]).toBe('2026-11-18T08:00:00.000Z');
  });

  it('uses only synthetic hosts (synth- prefix or the TEST-NET appliance)', () => {
    for (const { fields } of [...SYNTHETIC_LOG_SPECS, MULTI_VALUED_OBSERVER_SPEC]) {
      const names = [
        fields.host?.name,
        fields.host?.id,
        fields.observer?.hostname,
        fields.observer?.serial_number,
      ]
        .filter((value): value is string => value !== undefined)
        .map((value) => value.toLowerCase().replace(/^policy:/, ''));
      for (const name of names) expect(name.startsWith('synth-')).toBe(true);
      const ips = fields.observer?.ip;
      if (ips)
        for (const ip of typeof ips === 'string' ? [ips] : ips)
          expect(isSyntheticHostKey(ip)).toBe(true);
    }
  });

  it('phase A yields exactly the expected discover-logs rows (ES|QL model)', () => {
    const rows = emulateDiscoverLogs(buildPhaseDocs('A', T0), RUN_AT);
    expect(sortRows(rows)).toEqual(sortRows(EXPECTED_PHASE_A_CANDIDATES.map(toRow)));
    const hostKeys = rows.map((row) => (row.host_name ?? row.host_id).toLowerCase());
    for (const absent of EXPECTED_ABSENT_HOST_KEYS) expect(hostKeys).not.toContain(absent);
  });

  it('phase B adds only the version flip on synth-web-02', () => {
    const docs = [...buildPhaseDocs('A', T0), ...buildPhaseDocs('B', T0)];
    const rows = emulateDiscoverLogs(docs, RUN_AT);
    expect(sortRows(rows)).toEqual(
      sortRows([...EXPECTED_PHASE_A_CANDIDATES, EXPECTED_PHASE_B_CANDIDATE].map(toRow))
    );
  });

  it('DL-10 multi-valued observer.ip keys on the sorted first value', () => {
    const rows = emulateDiscoverLogs([toLogDoc(MULTI_VALUED_OBSERVER_SPEC, T0)], RUN_AT);
    expect(rows.map((row) => row.host_id)).toEqual(['10.9.9.9']);
  });

  it.each(
    [...EXPECTED_PHASE_A_CANDIDATES, EXPECTED_PHASE_B_CANDIDATE].map(
      (c) => [c.docIds.join(','), c] as const
    )
  )('%s normalizes to its documented host key and catalog id', (_docIds, candidate) => {
    const normalized = normalizeCandidate(
      {
        host_id: candidate.host_id,
        ...(candidate.host_name ? { host_name: candidate.host_name } : {}),
        ...(candidate.vendor ? { vendor: candidate.vendor } : {}),
        name: candidate.name,
        version: candidate.version,
        category: candidate.category,
      },
      T0.toISOString(),
      'logs'
    );
    expect(normalized).toBeDefined();
    expect(normalized?.host_key).toBe(candidate.hostKey);
    expect(`${normalized?.vendor}:${normalized?.product}:${normalized?.version}`).toBe(
      candidate.catalogId
    );
    expect(isSyntheticHostKey(candidate.hostKey)).toBe(true);
  });

  it('expects 10 phase A instances, one unchanged after R1 (DL-1: created 9, unchanged 1)', () => {
    expect(EXPECTED_PHASE_A_INSTANCES).toHaveLength(10);
    expect(EXPECTED_PHASE_A_INSTANCES.filter((i) => i.outcomeAfterR1 === 'unchanged')).toEqual([
      expect.objectContaining({ hostKey: 'synth-lin-01', catalogId: 'f5:nginx:1.18.0' }),
    ]);
  });

  it('network documents yield the expected inbound public sources within 7 days', () => {
    const docs = buildPhaseDocs('A', T0).filter(
      (doc) =>
        Date.parse(doc._source['@timestamp']) >= RUN_AT - 7 * 24 * HOUR_MS &&
        doc._source.source !== undefined &&
        ['inbound', 'ingress'].includes(doc._source.network?.direction ?? '') &&
        isPublicIp(doc._source.source.ip)
    );
    const distinct = (key: (doc: SyntheticLogDoc) => string | undefined) => {
      const result: Record<string, number> = {};
      const sets = new Map<string, Set<string>>();
      for (const doc of docs) {
        const k = key(doc);
        if (!k || !doc._source.source) continue;
        sets.set(k, (sets.get(k) ?? new Set()).add(doc._source.source.ip));
      }
      sets.forEach((set, k) => {
        result[k] = set.size;
      });
      return result;
    };
    expect(distinct((doc) => doc._source.host?.name)).toEqual(EXPECTED_INBOUND_SOURCES.byHostName);
    expect(distinct((doc) => doc._source.host?.id)).toEqual(EXPECTED_INBOUND_SOURCES.byHostId);
  });

  it('parses --t0 strictly', () => {
    expect(parseT0('2026-11-18T10:00:00Z').toISOString()).toBe('2026-11-18T10:00:00.000Z');
    expect(() => parseT0('yesterday')).toThrow(/ISO timestamp/);
    expect(() => parseT0('')).toThrow(/ISO timestamp/);
  });
});

describe('template', () => {
  it('maps every field the workflows read', () => {
    const { properties } = SYNTHETIC_TEMPLATE.template.mappings;
    const response = {
      template: { settings: { index: { mode: 'logsdb' } }, mappings: { properties } },
    };
    expect(evaluateSimulation(response)).toEqual({ indexMode: 'logsdb', missingFields: [] });
    expect(REQUIRED_MAPPED_FIELDS).toContain('observer.serial_number');
  });

  it('reports unmapped fields from a simulation', () => {
    const response = { template: { settings: { index: {} }, mappings: { properties: {} } } };
    expect(evaluateSimulation(response).missingFields).toEqual([...REQUIRED_MAPPED_FIELDS]);
  });
});
