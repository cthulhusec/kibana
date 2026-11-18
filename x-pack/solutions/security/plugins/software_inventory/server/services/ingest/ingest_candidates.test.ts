/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { loggingSystemMock } from '@kbn/core-logging-server-mocks';
import { CATALOG_INDEX, EVENTS_INDEX, INSTANCES_INDEX } from '../../../common/constants';
import type { InventoryEvent } from '../../../common/history';
import type {
  CatalogEntry,
  DiscoverySource,
  InstanceDoc,
  RawCandidate,
} from '../../../common/types';
import { createFakeEsClient } from './fake_es_client';
import { ingestCandidates } from './ingest_candidates';
import { markStale } from './mark_stale';
import { FLEET_AGENTS_INDEX } from './resolve_osquery_hosts';

const DAY_MS = 24 * 60 * 60 * 1000;
const daysAgo = (days: number): string => new Date(Date.now() - days * DAY_MS).toISOString();

const row = (overrides: Partial<RawCandidate> = {}): RawCandidate => ({
  host_id: 'host-1',
  host_name: 'web-1',
  name: 'OpenSSL',
  version: '3.0.2',
  install_path: '/usr/lib/libssl.so',
  category: 'os_package',
  ...overrides,
});

describe('ingestCandidates', () => {
  const logger = loggingSystemMock.createLogger();
  let fake: ReturnType<typeof createFakeEsClient>;

  const ingest = (
    candidates: RawCandidate[],
    snapshot = true,
    source: DiscoverySource = 'osquery'
  ) =>
    ingestCandidates({ esClient: fake.esClient, logger, input: { source, snapshot, candidates } });

  const instances = () => fake.getAll<InstanceDoc>(INSTANCES_INDEX);
  const byProduct = (product: string) =>
    instances().find(({ software_id: softwareId }) => softwareId.split(':')[1] === product);

  beforeEach(() => {
    fake = createFakeEsClient();
  });

  it('creates instances and catalog entries for new software', async () => {
    const result = await ingest([
      row(),
      row({ name: 'nginx', version: '1.24.0', install_path: '/usr/sbin/nginx' }),
    ]);
    expect(result).toEqual({ created: 2, unchanged: 0, patched: 0, removed: 0, skipped: 0 });
    expect(instances()).toHaveLength(2);
    expect(fake.getDoc<CatalogEntry>(CATALOG_INDEX, 'openssl:openssl:3.0.2')).toMatchObject({
      vendor: 'openssl',
      product: 'openssl',
      version: '3.0.2',
      cve_count: 0,
      known_exploited: false,
      cve_ids: [],
    });
    expect(fake.getDoc<CatalogEntry>(CATALOG_INDEX, 'f5:nginx:1.24.0')).toBeDefined();
  });

  it('counts an unchanged sighting and does not overwrite catalog enrichment', async () => {
    await ingest([row()]);
    const entry = fake.getDoc<CatalogEntry>(CATALOG_INDEX, 'openssl:openssl:3.0.2');
    fake.putDoc(CATALOG_INDEX, 'openssl:openssl:3.0.2', {
      ...entry,
      cve_count: 4,
      cve_ids: ['CVE-1'],
    });

    expect(await ingest([row()])).toEqual({
      created: 0,
      unchanged: 1,
      patched: 0,
      removed: 0,
      skipped: 0,
    });
    expect(fake.getDoc<CatalogEntry>(CATALOG_INDEX, 'openssl:openssl:3.0.2')?.cve_count).toBe(4);
  });

  it('patches the instance in place and then returns it to active', async () => {
    await ingest([row({ observed_at: daysAgo(2) })]);
    const [original] = instances();

    expect(await ingest([row({ version: '3.0.13', observed_at: daysAgo(1) })])).toEqual({
      created: 0,
      unchanged: 0,
      patched: 1,
      removed: 0,
      skipped: 0,
    });
    expect(instances()).toHaveLength(1);
    const patched = instances()[0];
    expect(patched).toMatchObject({
      id: original.id,
      status: 'patched',
      software_id: 'openssl:openssl:3.0.13',
      previous_software_id: 'openssl:openssl:3.0.2',
    });
    expect(fake.getDoc(CATALOG_INDEX, 'openssl:openssl:3.0.13')).toBeDefined();

    expect(await ingest([row({ version: '3.0.13' })])).toMatchObject({ unchanged: 1 });
    expect(instances()[0]).toMatchObject({
      status: 'active',
      version_changed_at: patched.version_changed_at,
    });
  });

  it('marks software missing from a host snapshot as removed', async () => {
    await ingest([row(), row({ name: 'nginx', version: '1.24.0' })]);
    expect(await ingest([row()])).toEqual({
      created: 0,
      unchanged: 1,
      patched: 0,
      removed: 1,
      skipped: 0,
    });
    expect(byProduct('nginx')?.status).toBe('removed');
    expect(byProduct('openssl')?.status).toBe('active');
  });

  it('never removes software on hosts that did not report', async () => {
    await ingest([
      row(),
      row({ host_id: 'host-2', host_name: 'web-2', name: 'nginx', version: '1.24.0' }),
    ]);
    expect(await ingest([row()])).toMatchObject({ removed: 0 });
    expect(byProduct('nginx')?.status).toBe('active');
  });

  it('does not remove anything for non-snapshot sources', async () => {
    await ingest([row(), row({ name: 'nginx', version: '1.24.0' })]);
    expect(await ingest([row()], false)).toMatchObject({ removed: 0 });
    expect(byProduct('nginx')?.status).toBe('active');
  });

  it('does not remove instances that only another source discovered', async () => {
    await ingest([row({ name: 'nginx', version: '1.24.0' })], false, 'logs');
    expect(await ingest([row()])).toMatchObject({ created: 1, removed: 0 });
    expect(byProduct('nginx')?.status).toBe('active');
  });

  it('revives a removed instance when it is seen again', async () => {
    await ingest([row(), row({ name: 'nginx', version: '1.24.0' })]);
    await ingest([row()]);
    expect(await ingest([row(), row({ name: 'nginx', version: '1.24.0' })])).toMatchObject({
      unchanged: 2,
      removed: 0,
    });
    expect(byProduct('nginx')?.status).toBe('active');
  });

  it('merges sources across discovery paths', async () => {
    await ingest([row()]);
    await ingest([row()], false, 'logs');
    expect(instances()[0].sources).toEqual(['osquery', 'logs']);
  });

  it('skips rows without a host id and counts them', async () => {
    expect(await ingest([row({ host_id: '' })])).toEqual({
      created: 0,
      unchanged: 0,
      patched: 0,
      removed: 0,
      skipped: 1,
    });
    expect(fake.esClient.bulk).not.toHaveBeenCalled();
  });

  describe('snapshot removal scoping', () => {
    const dependency = (overrides: Partial<RawCandidate> = {}) =>
      row({
        name: 'requests',
        version: '2.31.0',
        install_path: '/usr/lib/python3/requests',
        category: 'dependency',
        ...overrides,
      });

    it('never lets a dependencies snapshot remove OS packages, or the other way around', async () => {
      await ingest([row(), row({ name: 'nginx', version: '1.24.0' })]);
      await ingest([dependency(), dependency({ name: 'flask', install_path: '/srv/flask' })]);

      // A dependencies call that lists only `requests` removes `flask`, never the OS packages.
      expect(await ingest([dependency()])).toMatchObject({ removed: 1 });
      expect(byProduct('flask')?.status).toBe('removed');
      expect(byProduct('openssl')?.status).toBe('active');
      expect(byProduct('nginx')?.status).toBe('active');

      // An OS package call that lists only openssl removes nginx, never `requests`.
      expect(await ingest([row()])).toMatchObject({ removed: 1 });
      expect(byProduct('nginx')?.status).toBe('removed');
      expect(byProduct('requests')?.status).toBe('active');
    });

    it('leaves a host untouched when its query sent no rows in this call', async () => {
      await ingest([
        row(),
        row({ host_id: 'host-2', host_name: 'web-2', name: 'curl', version: '8' }),
      ]);
      // Only web-1 reported OS packages; web-2 failed or timed out.
      expect(await ingest([row()])).toMatchObject({ removed: 0 });
      expect(byProduct('curl')?.status).toBe('active');
    });

    it('removes nothing from an incomplete (non-snapshot) result', async () => {
      await ingest([row(), row({ name: 'nginx', version: '1.24.0' })]);
      // A truncated or failed query result is ingested with snapshot false.
      expect(await ingest([row()], false)).toMatchObject({ removed: 0, unchanged: 1 });
      expect(byProduct('nginx')?.status).toBe('active');
    });
  });

  describe('host identity', () => {
    it('unions sources for one machine reported with different ids per source', async () => {
      await ingest([row({ host_id: 'agent-uuid', host_name: 'WEB-1' })]);
      await ingest([row({ host_id: 'host-uuid', host_name: 'web-1' })], false, 'logs');
      expect(instances()).toHaveLength(1);
      expect(instances()[0]).toMatchObject({
        host: { key: 'web-1', id: 'agent-uuid' },
        sources: ['osquery', 'logs'],
      });
    });

    it('resolves osquery agent ids to the Fleet host name and id', async () => {
      fake.putDoc(FLEET_AGENTS_INDEX, 'agent-1', {
        local_metadata: { host: { hostname: 'Web-1', id: 'host-uuid' } },
      });
      await ingest([row({ host_id: 'agent-1', host_name: undefined })]);
      await ingest([row({ host_id: 'host-uuid', host_name: 'web-1' })], false, 'logs');
      expect(instances()).toHaveLength(1);
      expect(instances()[0]).toMatchObject({
        host: { key: 'web-1', id: 'host-uuid', name: 'web-1' },
        sources: ['osquery', 'logs'],
      });
    });

    it('falls back to the agent name, then the agent id, when Fleet has no agent', async () => {
      await ingest([
        row({ host_id: 'agent-1', host_name: 'Mac-1' }),
        row({ host_id: 'Agent-2', host_name: undefined }),
      ]);
      expect(
        instances()
          .map(({ host }) => host.key)
          .sort()
      ).toEqual(['agent-2', 'mac-1']);
    });

    it('falls back to the reported values when the Fleet lookup fails', async () => {
      const { mget } = fake.esClient;
      const fallback = mget.getMockImplementation();
      mget.mockImplementation(((request: { index: string }) =>
        request.index === FLEET_AGENTS_INDEX
          ? Promise.reject(new Error('forbidden'))
          : fallback?.(request as never)) as never);
      expect(await ingest([row({ host_id: 'agent-1', host_name: 'web-1' })])).toMatchObject({
        created: 1,
      });
      expect(instances()[0].host.key).toBe('web-1');
      expect(logger.warn).toHaveBeenCalled();
    });

    it('keeps Fleet policy pseudo-hosts separate from real hosts', async () => {
      await ingest(
        [{ host_id: 'policy:p1', host_name: 'web-1', name: 'nginx', version: '1.2.3' }],
        false,
        'fleet_integration'
      );
      expect(instances()[0].host.key).toBe('policy:p1');
    });
  });

  describe('events', () => {
    const events = () => fake.getAll<InventoryEvent>(EVENTS_INDEX);
    const ofType = (type: InventoryEvent['type']) => events().filter((e) => e.type === type);

    it('writes software_id on every history entry', async () => {
      await ingest([row({ observed_at: daysAgo(2) })]);
      await ingest([row({ version: '3.0.13', observed_at: daysAgo(1) })]);
      expect(instances()[0].version_history.map(({ software_id: id }) => id)).toEqual([
        'openssl:openssl:3.0.2',
        'openssl:openssl:3.0.13',
      ]);
    });

    it('emits first_seen, version_changed with posture, removed and revived', async () => {
      await ingest([
        row({ observed_at: daysAgo(3) }),
        row({ name: 'nginx', version: '1.24.0', observed_at: daysAgo(3) }),
      ]);
      expect(ofType('first_seen')).toHaveLength(2);
      expect(ofType('first_seen')[0]).toMatchObject({
        host: { key: 'web-1', id: 'host-1', name: 'web-1' },
        source: 'osquery',
      });

      const old = fake.getDoc<CatalogEntry>(CATALOG_INDEX, 'openssl:openssl:3.0.2');
      fake.putDoc(CATALOG_INDEX, 'openssl:openssl:3.0.2', {
        ...old,
        cve_count: 3,
        max_cvss: 9.8,
        known_exploited: true,
        cve_checked_at: daysAgo(3),
      });
      fake.putDoc(CATALOG_INDEX, 'openssl:openssl:3.0.13', {
        ...old,
        id: 'openssl:openssl:3.0.13',
        version: '3.0.13',
        cve_count: 0,
        known_exploited: false,
        cve_checked_at: daysAgo(3),
      });

      const patchedAt = daysAgo(2);
      await ingest([
        row({ version: '3.0.13', observed_at: patchedAt }),
        row({ name: 'nginx', version: '1.24.0', observed_at: patchedAt }),
      ]);
      expect(ofType('version_changed')).toEqual([
        expect.objectContaining({
          '@timestamp': patchedAt,
          software_id: 'openssl:openssl:3.0.13',
          previous_software_id: 'openssl:openssl:3.0.2',
          from_version: '3.0.2',
          to_version: '3.0.13',
          cve_count_before: 3,
          cve_count_after: 0,
          max_cvss_before: 9.8,
          known_exploited_before: true,
          known_exploited_after: false,
        }),
      ]);

      await ingest([row({ version: '3.0.13' })]);
      expect(ofType('removed')).toEqual([
        expect.objectContaining({ software_id: 'f5:nginx:1.24.0', from_version: '1.24.0' }),
      ]);

      await ingest([row({ version: '3.0.13' }), row({ name: 'nginx', version: '1.24.0' })]);
      expect(ofType('revived')).toEqual([
        expect.objectContaining({ software_id: 'f5:nginx:1.24.0' }),
      ]);
    });

    it('leaves posture out when the new version was never checked for CVEs', async () => {
      await ingest([row({ observed_at: daysAgo(2) })]);
      await ingest([row({ version: '3.0.13', observed_at: daysAgo(1) })]);
      const [event] = ofType('version_changed');
      expect(event).not.toHaveProperty('cve_count_after');
      expect(event).not.toHaveProperty('cve_count_before');
    });

    it('writes events for many instances in chunked bulk calls', async () => {
      const many = Array.from({ length: 1500 }, (_, index) =>
        row({ name: `pkg-${index}`, install_path: `/opt/${index}` })
      );
      await ingest(many);
      expect(ofType('first_seen')).toHaveLength(1500);
      expect(fake.esClient.bulk.mock.calls.length).toBeGreaterThan(2);
    });

    it('emits a stale event per instance markStale marks', async () => {
      await ingest([row({ observed_at: daysAgo(40) })]);
      await markStale({ esClient: fake.esClient, logger, staleAfterDays: 30 });
      expect(ofType('stale')).toEqual([
        expect.objectContaining({ software_id: 'openssl:openssl:3.0.2', source: 'osquery' }),
      ]);
    });
  });

  it('drops Fleet packages with no software mapping and counts them as skipped', async () => {
    expect(
      await ingest(
        [
          { host_id: 'policy:p1', name: 'system', version: '1.60.0' },
          { host_id: 'policy:p1', name: 'panw', version: '5.3.0' },
        ],
        false,
        'fleet_integration'
      )
    ).toMatchObject({ created: 1, skipped: 1 });
    expect(instances()[0].software_id).toBe('palo_alto_networks:pan-os:unknown');
  });
});

describe('markStale', () => {
  const logger = loggingSystemMock.createLogger();

  it('marks active and patched instances older than the threshold, never removed ones', async () => {
    const fake = createFakeEsClient();
    const put = (id: string, status: InstanceDoc['status'], lastSeen: string) =>
      fake.putDoc(INSTANCES_INDEX, id, { id, status, last_seen: lastSeen });
    put('old-active', 'active', daysAgo(40));
    put('old-patched', 'patched', daysAgo(40));
    put('old-removed', 'removed', daysAgo(40));
    put('recent', 'active', daysAgo(2));

    expect(await markStale({ esClient: fake.esClient, logger, staleAfterDays: 30 })).toEqual({
      marked: 2,
    });
    const status = (id: string) => fake.getDoc<InstanceDoc>(INSTANCES_INDEX, id)?.status;
    expect(status('old-active')).toBe('stale');
    expect(status('old-patched')).toBe('stale');
    expect(status('old-removed')).toBe('removed');
    expect(status('recent')).toBe('active');
  });

  it('honors a shorter threshold', async () => {
    const fake = createFakeEsClient();
    fake.putDoc(INSTANCES_INDEX, 'a', { id: 'a', status: 'active', last_seen: daysAgo(2) });
    expect(await markStale({ esClient: fake.esClient, logger, staleAfterDays: 1 })).toEqual({
      marked: 1,
    });
  });
});
