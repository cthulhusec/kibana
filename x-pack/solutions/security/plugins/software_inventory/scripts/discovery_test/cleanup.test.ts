/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { generateSeedData } from '../seed/generate_seed_data';
import {
  KNOWN_SYNTHETIC_CATALOG_IDS,
  collectSoftwareIds,
  isResidueEmpty,
  seedCatalogIds,
  selectCatalogIdsToDelete,
  syntheticCatalogTokenQuery,
  syntheticHostKeyQuery,
} from './cleanup';
import { AGENTS } from './fixtures/osquery';
import { ALL_FLEET_FIXTURES } from './fixtures/fleet';
import { EXPECTED_PHASE_A_CANDIDATES } from './logs/generate_logs';
import { instanceIdFor, isSyntheticHostKey, parseCatalogId } from './ids';

describe('cleanup selection', () => {
  const seed = generateSeedData(new Date('2026-11-18T10:00:00Z'));

  it('never selects a demo host key', () => {
    for (const instance of seed.instances)
      expect(isSyntheticHostKey(instance.host.key)).toBe(false);
  });

  it('selects every synthetic host key the fixtures and logs produce', () => {
    const keys = [
      ...Object.values(AGENTS)
        .map(({ hostKey }) => hostKey)
        .filter((key) => key !== ''),
      ...ALL_FLEET_FIXTURES.flatMap((fixture) => fixture.expected.instances.map((i) => i.hostKey)),
      ...EXPECTED_PHASE_A_CANDIDATES.map(({ hostKey }) => hostKey),
    ];
    for (const key of keys) expect(isSyntheticHostKey(key)).toBe(true);
  });

  it('builds the host-key query from prefixes and exact keys', () => {
    expect(syntheticHostKeyQuery()).toEqual({
      bool: {
        should: [
          { prefix: { 'host.key': 'synth-' } },
          { prefix: { 'host.key': 'policy:synth-' } },
          { terms: { 'host.key': ['192.0.2.77', '192.0.2.78', '10.9.9.9'] } },
        ],
        minimum_should_match: 1,
      },
    });
    expect(syntheticCatalogTokenQuery().bool.should).toEqual([
      { prefix: { vendor: 'synth-' } },
      { prefix: { product: 'synth-' } },
    ]);
  });

  it('keeps known synthetic catalog ids disjoint from the demo seed', () => {
    const seedIds = new Set(seedCatalogIds());
    expect(KNOWN_SYNTHETIC_CATALOG_IDS.filter((id) => seedIds.has(id))).toEqual([]);
    expect(KNOWN_SYNTHETIC_CATALOG_IDS).toEqual(
      expect.arrayContaining(['openssl:openssl:3.0.7', 'apache:log4j:2.14.1', 'f5:nginx:1.27.4'])
    );
  });

  it('removes protected ids and deduplicates', () => {
    expect(
      selectCatalogIdsToDelete({
        candidates: ['b:b:1', 'a:a:1', 'b:b:1', 'demo:demo:1', 'shared:x:1'],
        protectedIds: ['demo:demo:1', 'shared:x:1'],
      })
    ).toEqual(['a:a:1', 'b:b:1']);
  });

  it('collects current, previous, and history software ids', () => {
    expect(
      collectSoftwareIds({
        software_id: 'openssl:openssl:3.0.14',
        previous_software_id: 'openssl:openssl:3.0.7',
        version_history: [
          {
            version: '3.0.7',
            software_id: 'openssl:openssl:3.0.7',
            first_seen: 'x',
            last_seen: 'x',
          },
          { version: '3.0.14', first_seen: 'x', last_seen: 'x' },
        ],
      })
    ).toEqual(['openssl:openssl:3.0.14', 'openssl:openssl:3.0.7', 'openssl:openssl:3.0.7']);
  });

  it('reports an empty residue only when nothing is left', () => {
    const empty = {
      syntheticInstances: 0,
      syntheticEvents: 0,
      syntheticCatalogIds: [],
      dataStreamExists: false,
      templateExists: false,
      testWorkflows: [],
    };
    expect(isResidueEmpty(empty)).toBe(true);
    expect(isResidueEmpty({ ...empty, testWorkflows: ['si-test-x'] })).toBe(false);
    expect(isResidueEmpty({ ...empty, syntheticCatalogIds: ['synth-tool:synth-tool:2.0.0'] })).toBe(
      false
    );
  });
});

describe('expected ids', () => {
  it('splits catalog ids whose version contains colons', () => {
    expect(parseCatalogId('a:b:1:2')).toEqual({ vendor: 'a', product: 'b', version: '1:2' });
    expect(() => parseCatalogId('a:b')).toThrow(/Not a catalog id/);
  });

  it('computes the same instance id as the seed for a demo instance', () => {
    const seed = generateSeedData(new Date('2026-11-18T10:00:00Z'));
    const instance = seed.instances[0];
    expect(
      instanceIdFor({
        hostKey: instance.host.key,
        catalogId: instance.software_id,
        installPath: instance.install_path,
      })
    ).toBe(instance.id);
  });

  it('ignores the version: patched instances keep their id', () => {
    const before = instanceIdFor({ hostKey: 'synth-lin-01', catalogId: 'openssl:openssl:3.0.7' });
    const after = instanceIdFor({ hostKey: 'synth-lin-01', catalogId: 'openssl:openssl:3.0.14' });
    expect(after).toBe(before);
  });
});
