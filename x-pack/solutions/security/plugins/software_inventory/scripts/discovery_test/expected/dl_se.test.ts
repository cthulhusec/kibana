/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { combineExposure } from '../../../server/services/enrichment/combine_exposure';
import { isEdgeProduct } from '../../../server/services/enrichment/integration_map';
import { isPublicIp } from '../../../server/services/enrichment/public_ip';
import { buildHostKey, buildInstanceId } from '../../../server/lib/instance_identity';
import { instanceIdFor, parseCatalogId } from '../ids';
import {
  EXPECTED_DL1_INGEST,
  EXPECTED_DL7_INGEST,
  SYNTHETIC_LOG_SPECS,
} from '../logs/generate_logs';
import {
  DL_INGEST,
  appliancesAt,
  candidatesAt,
  dedupeRows,
  dlEventHostKeys,
  expectedCatalogAt,
  expectedEventsAt,
  expectedInstancesAt,
  expectedSightingTimes,
  instanceCountAt,
  servicesAt,
} from './dl';
import type { ExposureExpectation } from './se';
import {
  LOOKBACK_DAYS,
  SE1_WEB01,
  SE3_FW02,
  SE4_EDGE_ONLY,
  SE5_REDIS,
  SE6_WEB02,
  SE7_POLICY,
  computeRollupOracle,
  edgeDetail,
  staleLastSeen,
} from './se';

const T0 = new Date('2026-11-18T10:00:00.000Z');
const HOUR_MS = 3_600_000;
const sum = (counts: Record<string, number>) => Object.values(counts).reduce((a, b) => a + b, 0);

describe('expected DL outcomes', () => {
  it('derives 11 rows (6 appliances, 5 services) and 10 instances for phase A', () => {
    expect(candidatesAt('A')).toHaveLength(11);
    expect(appliancesAt('A')).toHaveLength(6);
    expect(servicesAt('A')).toHaveLength(5);
    expect(instanceCountAt('A')).toBe(10);
    expect(expectedInstancesAt('A')).toHaveLength(10);
  });

  it('adds only the phase B row, which still yields 10 instances', () => {
    expect(candidatesAt('B')).toHaveLength(12);
    expect(instanceCountAt('B')).toBe(10);
  });

  it('keeps the ingest outputs equal to the instance count', () => {
    expect(sum(DL_INGEST.baselineAfterR1)).toBe(instanceCountAt('A'));
    expect(sum(DL_INGEST.versionFlip)).toBe(instanceCountAt('B'));
    expect(sum(DL_INGEST.idempotent)).toBe(instanceCountAt('B'));
    expect(sum(DL_INGEST.multiValued)).toBe(instanceCountAt('B') + 1);
    expect(DL_INGEST.baselineAfterR1).toEqual(expect.objectContaining(pick(EXPECTED_DL1_INGEST)));
    expect(DL_INGEST.versionFlip).toEqual(expect.objectContaining(pick(EXPECTED_DL7_INGEST)));
  });

  it('lets the later observation win a duplicate instance (S2b over S2) and uses its host name', () => {
    const winner = [...dedupeRows(candidatesAt('A')).values()].find(
      ({ hostKey, name }) => hostKey === 'synth-web-01' && name === 'synth-checkout'
    );
    expect(winner?.docIds).toEqual(['S2b']);
    const instance = expectedInstancesAt('A').find(({ hostKey }) => hostKey === 'synth-web-01');
    expect(instance).toEqual(expect.objectContaining({ hostName: 'SYNTH-Web-01' }));
    const times = expectedSightingTimes('A', T0).find(({ hostKey }) => hostKey === 'synth-web-01');
    expect(times).toEqual(
      expect.objectContaining({
        firstSeen: new Date(T0.getTime() - HOUR_MS).toISOString(),
        lastSeen: new Date(T0.getTime() - HOUR_MS).toISOString(),
      })
    );
  });

  it('collapses the A1 duplicates to one sighting at T0-30m', () => {
    const times = expectedSightingTimes('A', T0).find(({ hostKey }) => hostKey === 'synth-fw-01');
    expect(times?.lastSeen).toBe(new Date(T0.getTime() - 30 * 60_000).toISOString());
    expect(times?.firstSeen).toBe(times?.lastSeen);
  });

  it('marks the version flip as patched with history from T0-20h to T0-1h', () => {
    const flipA = expectedInstancesAt('A').find(({ hostKey }) => hostKey === 'synth-web-02');
    const flipB = expectedInstancesAt('B').find(({ hostKey }) => hostKey === 'synth-web-02');
    expect(flipA).toEqual(
      expect.objectContaining({
        status: 'active',
        catalogId: 'f5:nginx:1.25.2',
        versions: ['1.25.2'],
      })
    );
    expect(flipB).toEqual(
      expect.objectContaining({
        status: 'patched',
        catalogId: 'f5:nginx:1.27.4',
        previousSoftwareId: 'f5:nginx:1.25.2',
        versions: ['1.25.2', '1.27.4'],
      })
    );
    const times = expectedSightingTimes('B', T0).find(({ hostKey }) => hostKey === 'synth-web-02');
    expect(times).toEqual({
      hostKey: 'synth-web-02',
      catalogId: 'f5:nginx:1.27.4',
      firstSeen: new Date(T0.getTime() - 20 * HOUR_MS).toISOString(),
      lastSeen: new Date(T0.getTime() - HOUR_MS).toISOString(),
    });
  });

  it('expects first_seen events for the nine log-only instances and a version_changed at B', () => {
    const a = expectedEventsAt('A', T0);
    const b = expectedEventsAt('B', T0);
    expect(a).toHaveLength(9);
    expect(a.every(({ type }) => type === 'first_seen')).toBe(true);
    expect(b).toHaveLength(10);
    expect(b.filter(({ type }) => type === 'version_changed')).toHaveLength(1);
    expect(dlEventHostKeys('A')).not.toContain('synth-lin-01');
    expect(dlEventHostKeys('A')).toHaveLength(9);
  });

  it('shares the Osquery nginx instance with sources osquery and logs', () => {
    expect(expectedInstancesAt('A').find(({ hostKey }) => hostKey === 'synth-lin-01')).toEqual(
      expect.objectContaining({ sources: ['osquery', 'logs'], catalogId: 'f5:nginx:1.18.0' })
    );
  });

  it('keeps the serial and IP fallback instances without a host name', () => {
    const byKey = new Map(expectedInstancesAt('A').map((item) => [item.hostKey, item]));
    expect(byKey.get('synth-sn-0003')).toEqual(
      expect.objectContaining({ hostName: null, hostId: 'SYNTH-SN-0003' })
    );
    expect(byKey.get('192.0.2.77')).toEqual(
      expect.objectContaining({ hostName: null, hostId: '192.0.2.77' })
    );
  });

  it('creates catalog entries with the candidate category', () => {
    const catalog = new Map(expectedCatalogAt('B').map(({ id, category }) => [id, category]));
    expect(catalog.get('fortinet:fortios:7.2.4')).toBe('appliance');
    expect(catalog.get('f5:nginx:1.27.4')).toBe('application');
    expect(catalog.size).toBe(new Set(candidatesAt('B').map(({ catalogId }) => catalogId)).size);
  });

  it('computes instance ids with the plugin function, never a literal hash', () => {
    expect(instanceIdFor({ hostKey: 'synth-fw-01', catalogId: 'fortinet:fortios:7.2.4' })).toBe(
      buildInstanceId({ hostKey: 'synth-fw-01', vendor: 'fortinet', product: 'fortios' })
    );
    // The version is not part of the id, so a patch updates the same instance.
    expect(instanceIdFor({ hostKey: 'synth-web-02', catalogId: 'f5:nginx:1.25.2' })).toBe(
      instanceIdFor({ hostKey: 'synth-web-02', catalogId: 'f5:nginx:1.27.4' })
    );
  });
});

const pick = (counts: Record<string, number>) =>
  Object.fromEntries(Object.entries(counts).filter(([, value]) => value !== 0));

/** Emulates `score`: public inbound sources per log host name and host id within the window. */
const emulateInbound = () => {
  const byKey = new Map<string, Set<string>>();
  const byId = new Map<string, Set<string>>();
  for (const spec of SYNTHETIC_LOG_SPECS) {
    const { source, network, host } = spec.fields;
    const inWindow = spec.offsetMs <= LOOKBACK_DAYS * 24 * HOUR_MS;
    if (!inWindow || !source || !network) continue;
    if (!['inbound', 'ingress'].includes(network.direction) || !isPublicIp(source.ip)) continue;
    if (host?.name) {
      const key = buildHostKey({ hostName: host.name, hostId: host.name });
      byKey.set(key, (byKey.get(key) ?? new Set()).add(source.ip));
    }
    if (host?.id) byId.set(host.id, (byId.get(host.id) ?? new Set()).add(source.ip));
  }
  return { byKey, byId };
};

describe('expected SE exposure', () => {
  const inbound = emulateInbound();
  const category = (catalogId: string) =>
    candidatesAt('B').find((candidate) => candidate.catalogId === catalogId)?.category;

  const emulate = (expectation: ExposureExpectation, hostId?: string) => {
    const { vendor, product } = parseCatalogId(expectation.catalogId);
    const isPolicy = expectation.hostKey.startsWith('policy:');
    const isEdge =
      category(expectation.catalogId) === 'appliance' ||
      (expectation.catalogId.endsWith(':unknown') && vendor === 'palo_alto_networks') ||
      isEdgeProduct(vendor, product);
    const sources = isPolicy
      ? undefined
      : inbound.byKey.get(expectation.hostKey) ?? (hostId ? inbound.byId.get(hostId) : undefined);
    return combineExposure({
      isEdge,
      edgeDetail: edgeDetail(expectation.catalogId),
      distinctPublicSources: sources?.size ?? 0,
      lookbackDays: LOOKBACK_DAYS,
    });
  };

  const expectations: Array<[string, ExposureExpectation, string | undefined]> = [
    ['SE-1 web-01', SE1_WEB01, undefined],
    ['SE-3 fw-02', SE3_FW02, undefined],
    ...SE4_EDGE_ONLY.map((item): [string, ExposureExpectation, string | undefined] => [
      `SE-4 ${item.hostKey}`,
      item,
      undefined,
    ]),
    ['SE-5 redis', SE5_REDIS, 'synth-hostid-0005'],
    ...SE7_POLICY.map((item): [string, ExposureExpectation, string | undefined] => [
      `SE-7 ${item.hostKey}/${item.catalogId}`,
      item,
      undefined,
    ]),
  ];

  it.each(expectations)(
    '%s matches combineExposure over the generated traffic',
    (_, item, hostId) => {
      const result = emulate(item, hostId);
      expect(result.level).toBe(item.level);
      expect(result.score).toBe(item.score);
      expect(result.evidence.map(({ signal, weight }) => ({ signal, weight }))).toEqual(
        item.evidence.map(({ signal, weight }) => ({ signal, weight }))
      );
    }
  );

  it('keeps the manual evidence and ignores the no-direction document for synth-web-02', () => {
    expect(inbound.byKey.get('synth-web-02')).toBeUndefined();
    expect(SE6_WEB02).toEqual(expect.objectContaining({ level: 'low', score: 30 }));
  });

  it('counts only three public sources for synth-web-01 (private and 8-day-old excluded)', () => {
    expect([...(inbound.byKey.get('synth-web-01') ?? [])].sort()).toEqual([
      '1.1.1.1',
      '8.8.8.8',
      '9.9.9.9',
    ]);
  });

  it('places the stale fixture 31 days before T0', () => {
    expect(Date.parse(staleLastSeen(T0))).toBe(T0.getTime() - 31 * 24 * HOUR_MS);
  });
});

describe('computeRollupOracle', () => {
  it('counts active and patched instances against the catalog and the day events', () => {
    const rollup = computeRollupOracle({
      dayStart: '2026-11-18T00:00:00.000Z',
      instances: [
        { software_id: 'a:a:1', exposureLevel: 'high' },
        { software_id: 'a:a:1', exposureLevel: 'none' },
        { software_id: 'b:b:2', exposureLevel: 'medium' },
        { software_id: 'c:c:3', exposureLevel: 'low' },
        { software_id: 'missing:x:1', exposureLevel: 'high' },
      ],
      catalog: [
        {
          id: 'a:a:1',
          category: 'application',
          cve_count: 2,
          max_cvss: 9.8,
          known_exploited: true,
        },
        { id: 'b:b:2', category: 'appliance', cve_count: 1, max_cvss: 7.5 },
        { id: 'c:c:3', category: 'dependency', cve_count: 0 },
      ],
      events: { first_seen: 4, version_changed: 1, removed: 2 },
    });
    expect(rollup).toEqual({
      '@timestamp': '2026-11-18T00:00:00.000Z',
      total_instances: 5,
      total_software: 4,
      vulnerable_instances: 3,
      critical_instances: 2,
      high_instances: 1,
      exposed_instances: 3,
      known_exploited_instances: 2,
      exposed_and_vulnerable_instances: 2,
      new_instances: 4,
      patched_instances: 1,
      removed_instances: 2,
      categories: { application: 2, dependency: 1, appliance: 1, os_package: 0, other: 0 },
    });
  });
});
