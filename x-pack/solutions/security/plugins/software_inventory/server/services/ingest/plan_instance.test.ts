/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createHash } from 'crypto';
import type { InstanceDoc, SoftwareCategory } from '../../../common/types';
import { buildHostKey, buildInstanceId } from '../../lib/instance_identity';
import type { NormalizedCandidate } from './normalize_candidate';
import {
  MAX_VERSION_HISTORY,
  dedupeCandidates,
  isStale,
  planInstance,
  planRemovals,
  reportedCategoriesByHost,
} from './plan_instance';

const T1 = '2026-11-01T00:00:00.000Z';
const T2 = '2026-11-08T00:00:00.000Z';
const T3 = '2026-11-15T00:00:00.000Z';
const NOW = '2026-11-18T00:00:00.000Z';

const candidate = (overrides: Partial<NormalizedCandidate> = {}): NormalizedCandidate => ({
  host_key: 'web-1',
  host_id: 'host-1',
  host_name: 'web-1',
  vendor: 'openssl',
  product: 'openssl',
  version: '3.0.2',
  display_name: 'OpenSSL',
  category: 'dependency',
  install_path: '/usr/lib/libssl.so',
  observed_at: T1,
  ...overrides,
});

const created = (overrides: Partial<NormalizedCandidate> = {}): InstanceDoc =>
  planInstance({
    existing: undefined,
    candidate: candidate(overrides),
    source: 'osquery',
    now: NOW,
  }).doc;

describe('buildHostKey', () => {
  it('is the lower-cased host name, else the host id', () => {
    expect(buildHostKey({ hostName: ' WEB-1 ', hostId: 'agent-1' })).toBe('web-1');
    expect(buildHostKey({ hostName: '', hostId: 'Agent-1' })).toBe('agent-1');
    expect(buildHostKey({ hostId: 'policy:p1' })).toBe('policy:p1');
  });
});

describe('buildInstanceId', () => {
  // Hyphens are kept by normalizeToken (they used to become underscores).
  it('is the sha256 hex of the normalized host key, vendor, product, and path', () => {
    const expected = createHash('sha256')
      .update('host-1|openssl|openssl|usr_lib_libssl.so')
      .digest('hex');
    expect(
      buildInstanceId({
        hostKey: 'HOST-1',
        vendor: ' OpenSSL ',
        product: 'openssl',
        installPath: '/usr/lib/libssl.so',
      })
    ).toBe(expected);
  });

  it('does not depend on the version', () => {
    expect(
      planInstance({
        existing: undefined,
        candidate: candidate({ version: '1' }),
        source: 'osquery',
        now: NOW,
      }).doc.id
    ).toBe(created({ version: '2' }).id);
  });

  it('derives from the host key, not the host id, so sources share one instance', () => {
    expect(created({ host_id: 'agent-uuid' }).id).toBe(created({ host_id: 'host-uuid' }).id);
    expect(created({ host_key: 'web-2' }).id).not.toBe(created().id);
  });

  it('stores the key and keeps the first non-empty host id on later sightings', () => {
    const first = created({ host_id: 'agent-uuid' });
    expect(first.host).toEqual({ key: 'web-1', id: 'agent-uuid', name: 'web-1' });
    const { doc } = planInstance({
      existing: first,
      candidate: candidate({ host_id: 'other-id', host_name: 'WEB-1', observed_at: T2 }),
      source: 'logs',
      now: NOW,
    });
    expect(doc.host).toEqual({ key: 'web-1', id: 'agent-uuid', name: 'WEB-1' });
    expect(doc.sources).toEqual(['osquery', 'logs']);
  });

  it('separates installs at different paths', () => {
    expect(created({ install_path: '/a' }).id).not.toBe(created({ install_path: '/b' }).id);
  });
});

describe('planInstance', () => {
  it('creates a new active instance', () => {
    const { outcome, doc } = planInstance({
      existing: undefined,
      candidate: candidate(),
      source: 'osquery',
      now: NOW,
    });
    expect(outcome).toBe('created');
    expect(doc).toEqual({
      id: expect.any(String),
      host: { key: 'web-1', id: 'host-1', name: 'web-1' },
      software_id: 'openssl:openssl:3.0.2',
      version_history: [
        { version: '3.0.2', software_id: 'openssl:openssl:3.0.2', first_seen: T1, last_seen: T1 },
      ],
      install_path: '/usr/lib/libssl.so',
      sources: ['osquery'],
      status: 'active',
      first_seen: T1,
      last_seen: T1,
      exposure: { level: 'none', score: 0, evidence: [] },
      '@timestamp': NOW,
    });
  });

  it('refreshes last_seen on an unchanged sighting and keeps exposure', () => {
    const existing: InstanceDoc = {
      ...created(),
      exposure: {
        level: 'high',
        score: 90,
        evidence: [{ signal: 'inbound_public_ip', detail: '1.2.3.4', weight: 1 }],
      },
    };
    const { outcome, doc } = planInstance({
      existing,
      candidate: candidate({ observed_at: T2 }),
      source: 'osquery',
      now: NOW,
    });
    expect(outcome).toBe('unchanged');
    expect(doc.last_seen).toBe(T2);
    expect(doc.first_seen).toBe(T1);
    expect(doc.status).toBe('active');
    expect(doc.version_history).toEqual([
      { version: '3.0.2', software_id: 'openssl:openssl:3.0.2', first_seen: T1, last_seen: T2 },
    ]);
    expect(doc.exposure).toEqual(existing.exposure);
  });

  it('adds software_id to a legacy history entry when it is touched', () => {
    const legacy: InstanceDoc = {
      ...created(),
      version_history: [{ version: '3.0.2', first_seen: T1, last_seen: T1 }],
    };
    const { doc } = planInstance({
      existing: legacy,
      candidate: candidate({ observed_at: T2 }),
      source: 'osquery',
      now: NOW,
    });
    expect(doc.version_history).toEqual([
      { version: '3.0.2', software_id: 'openssl:openssl:3.0.2', first_seen: T1, last_seen: T2 },
    ]);
  });

  it('records a patch when the version changes', () => {
    const existing = created();
    const { outcome, doc } = planInstance({
      existing,
      candidate: candidate({ version: '3.0.13', observed_at: T2 }),
      source: 'osquery',
      now: NOW,
    });
    expect(outcome).toBe('patched');
    expect(doc).toMatchObject({
      id: existing.id,
      software_id: 'openssl:openssl:3.0.13',
      previous_software_id: 'openssl:openssl:3.0.2',
      version_changed_at: T2,
      status: 'patched',
      first_seen: T1,
      last_seen: T2,
      version_history: [
        { version: '3.0.2', software_id: 'openssl:openssl:3.0.2', first_seen: T1, last_seen: T1 },
        {
          version: '3.0.13',
          software_id: 'openssl:openssl:3.0.13',
          first_seen: T2,
          last_seen: T2,
        },
      ],
    });
  });

  it('returns a patched instance to active on the next unchanged sighting', () => {
    const patched = planInstance({
      existing: created(),
      candidate: candidate({ version: '3.0.13', observed_at: T2 }),
      source: 'osquery',
      now: NOW,
    }).doc;
    const { outcome, doc } = planInstance({
      existing: patched,
      candidate: candidate({ version: '3.0.13', observed_at: T3 }),
      source: 'osquery',
      now: NOW,
    });
    expect(outcome).toBe('unchanged');
    expect(doc.status).toBe('active');
    expect(doc.version_changed_at).toBe(T2);
    expect(doc.previous_software_id).toBe('openssl:openssl:3.0.2');
    expect(doc.version_history).toHaveLength(2);
    expect(doc.version_history[1]).toEqual({
      version: '3.0.13',
      software_id: 'openssl:openssl:3.0.13',
      first_seen: T2,
      last_seen: T3,
    });
  });

  it.each(['removed', 'stale'] as const)('revives a %s instance seen again', (status) => {
    const { outcome, doc } = planInstance({
      existing: { ...created(), status },
      candidate: candidate({ observed_at: T2 }),
      source: 'osquery',
      now: NOW,
    });
    expect(outcome).toBe('unchanged');
    expect(doc.status).toBe('active');
    expect(doc.last_seen).toBe(T2);
  });

  it('merges sources as a union', () => {
    const existing = created();
    const fromLogs = planInstance({
      existing,
      candidate: candidate({ observed_at: T2 }),
      source: 'logs',
      now: NOW,
    }).doc;
    expect(fromLogs.sources).toEqual(['osquery', 'logs']);
    const again = planInstance({
      existing: fromLogs,
      candidate: candidate({ observed_at: T3 }),
      source: 'osquery',
      now: NOW,
    }).doc;
    expect(again.sources).toEqual(['osquery', 'logs']);
  });

  it('ignores a late row with an older, different version', () => {
    const existing = planInstance({
      existing: created(),
      candidate: candidate({ version: '3.0.13', observed_at: T3 }),
      source: 'osquery',
      now: NOW,
    }).doc;
    const { outcome, doc } = planInstance({
      existing,
      candidate: candidate({ version: '3.0.2', observed_at: T2 }),
      source: 'logs',
      now: NOW,
    });
    expect(outcome).toBe('unchanged');
    expect(doc.software_id).toBe('openssl:openssl:3.0.13');
    expect(doc.last_seen).toBe(T3);
    expect(doc.sources).toEqual(['osquery', 'logs']);
  });

  it('keeps the version history bounded', () => {
    let doc = created({ version: '0' });
    for (let version = 1; version <= MAX_VERSION_HISTORY + 5; version++) {
      doc = planInstance({
        existing: doc,
        candidate: candidate({
          version: String(version),
          observed_at: new Date(Date.parse(T1) + version * 1000).toISOString(),
        }),
        source: 'osquery',
        now: NOW,
      }).doc;
    }
    expect(doc.version_history).toHaveLength(MAX_VERSION_HISTORY);
    expect(doc.version_history[MAX_VERSION_HISTORY - 1].version).toBe(
      String(MAX_VERSION_HISTORY + 5)
    );
  });
});

describe('dedupeCandidates', () => {
  it('keeps the latest observation per instance', () => {
    const result = dedupeCandidates([
      candidate({ version: '1', observed_at: T2 }),
      candidate({ version: '2', observed_at: T1 }),
      candidate({ host_key: 'web-2', host_id: 'host-2' }),
    ]);
    expect(result.size).toBe(2);
    expect([...result.values()].map(({ version }) => version)).toEqual(['1', '3.0.2']);
  });

  it('keeps the highest version when observations tie, regardless of row order', () => {
    const rows = [
      candidate({ version: '7.0.10', observed_at: T1 }),
      candidate({ version: '7.0.9', observed_at: T1 }),
    ];
    expect([...dedupeCandidates(rows).values()][0].version).toBe('7.0.10');
    expect([...dedupeCandidates([...rows].reverse()).values()][0].version).toBe('7.0.10');
  });
});

describe('planRemovals', () => {
  const instance = (
    id: string,
    hostKey: string,
    softwareId = 'os',
    overrides: Partial<InstanceDoc> = {}
  ) => ({
    id,
    host: { key: hostKey },
    software_id: softwareId,
    sources: ['osquery' as const],
    status: 'active' as const,
    ...overrides,
  });
  const categories = new Map<string, SoftwareCategory>([
    ['os', 'os_package'],
    ['dep', 'dependency'],
  ]);
  const reported = (entries: Array<[string, SoftwareCategory[]]>) =>
    new Map(entries.map(([key, list]) => [key, new Set(list)]));

  it('removes absent instances only on hosts that reported', () => {
    expect(
      planRemovals({
        existing: [
          instance('a', 'host-1'),
          instance('b', 'host-1'),
          instance('c', 'host-2'),
          instance('d', 'host-1', 'os', { sources: ['logs'] }),
          instance('e', 'host-1', 'os', { status: 'removed' }),
        ],
        reportedCategories: reported([['host-1', ['os_package']]]),
        categoryBySoftwareId: categories,
        seenInstanceIds: new Set(['a']),
        source: 'osquery',
      })
    ).toEqual(['b']);
  });

  it('only removes instances in a category the host reported in this call', () => {
    expect(
      planRemovals({
        existing: [instance('pkg', 'host-1', 'os'), instance('lib', 'host-1', 'dep')],
        reportedCategories: reported([['host-1', ['dependency']]]),
        categoryBySoftwareId: categories,
        seenInstanceIds: new Set(),
        source: 'osquery',
      })
    ).toEqual(['lib']);
  });

  it('keeps instances whose catalog category is unknown', () => {
    expect(
      planRemovals({
        existing: [instance('a', 'host-1', 'missing')],
        reportedCategories: reported([['host-1', ['os_package']]]),
        categoryBySoftwareId: categories,
        seenInstanceIds: new Set(),
        source: 'osquery',
      })
    ).toEqual([]);
  });

  it('removes nothing when no host reported', () => {
    expect(
      planRemovals({
        existing: [instance('a', 'host-1')],
        reportedCategories: new Map(),
        categoryBySoftwareId: categories,
        seenInstanceIds: new Set(),
        source: 'osquery',
      })
    ).toEqual([]);
  });
});

describe('reportedCategoriesByHost', () => {
  it('groups categories by host key', () => {
    expect(
      reportedCategoriesByHost([
        candidate({ host_key: 'a', category: 'os_package' }),
        candidate({ host_key: 'a', category: 'dependency' }),
        candidate({ host_key: 'b', category: 'os_package' }),
      ])
    ).toEqual(
      new Map([
        ['a', new Set(['os_package', 'dependency'])],
        ['b', new Set(['os_package'])],
      ])
    );
  });
});

describe('isStale', () => {
  const cutoff = T2;
  it.each([
    ['active', T1, true],
    ['patched', T1, true],
    ['active', T3, false],
    ['removed', T1, false],
    ['stale', T1, false],
  ] as const)('%s last seen %s is stale: %s', (status, lastSeen, expected) => {
    expect(isStale({ status, last_seen: lastSeen }, cutoff)).toBe(expected);
  });
});
