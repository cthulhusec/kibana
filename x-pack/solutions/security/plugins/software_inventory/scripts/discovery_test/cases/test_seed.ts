/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Builders that put plugin documents into the fake stack (`./fake_stack.ts`) for the DL and SE
 * case tests. They derive every value from the expected-outcome modules, so the tests prove that
 * the cases accept the state their own expectations describe and reject deviations.
 */

import { CATALOG_INDEX, EVENTS_INDEX, INSTANCES_INDEX } from '../../../common/constants';
import type { InventoryEvent } from '../../../common/history';
import type { ExposureLevel, InstanceDoc } from '../../../common/types';
import type { ExpectedEvent } from '../assertions';
import type { JsonValue } from '../clients';
import type { DlStage } from '../expected/dl';
import {
  expectedCatalogAt,
  expectedEventsAt,
  expectedInstancesAt,
  expectedSightingTimes,
} from '../expected/dl';
import type { ExposureExpectation } from '../expected/se';
import { instanceIdFor, parseCatalogId } from '../ids';
import type { Doc, FakeStack } from './fake_stack';
import type { ExpectedEsqlRow } from './dl_support';

const toDoc = (value: InstanceDoc | InventoryEvent | object): Doc =>
  JSON.parse(JSON.stringify(value)) as Doc;

export const instanceDoc = (
  stack: FakeStack,
  item: {
    hostKey: string;
    catalogId: string;
    installPath?: string;
    status?: InstanceDoc['status'];
    sources?: InstanceDoc['sources'];
    hostName?: string | null;
    hostId?: string;
    versionHistory?: InstanceDoc['version_history'];
    previousSoftwareId?: string;
    firstSeen?: string;
    lastSeen?: string;
    exposure?: InstanceDoc['exposure'];
    /** `@timestamp` of the write; defaults to now. */
    writtenAt?: string;
  }
): InstanceDoc => {
  const now = new Date().toISOString();
  const { version } = parseCatalogId(item.catalogId);
  const id = instanceIdFor(item);
  const doc: InstanceDoc = {
    id,
    host: {
      key: item.hostKey,
      id: item.hostId ?? item.hostKey,
      ...(item.hostName ? { name: item.hostName } : {}),
    },
    software_id: item.catalogId,
    ...(item.previousSoftwareId ? { previous_software_id: item.previousSoftwareId } : {}),
    version_history: item.versionHistory ?? [
      {
        version,
        software_id: item.catalogId,
        first_seen: item.firstSeen ?? now,
        last_seen: item.lastSeen ?? now,
      },
    ],
    ...(item.installPath ? { install_path: item.installPath } : {}),
    sources: item.sources ?? ['logs'],
    status: item.status ?? 'active',
    first_seen: item.firstSeen ?? now,
    last_seen: item.lastSeen ?? now,
    exposure: item.exposure ?? { level: 'none', score: 0, evidence: [] },
    '@timestamp': item.writtenAt ?? now,
  };
  stack.put(INSTANCES_INDEX, id, toDoc(doc));
  return doc;
};

export const putEvent = (stack: FakeStack, event: ExpectedEvent | InventoryEvent): void => {
  stack.put(
    EVENTS_INDEX,
    `${event.type}-${String(event.instance_id)}-${String(event['@timestamp'])}`,
    toDoc(event)
  );
};

/** Seeds the instances, catalog entries, and events the logs run at `stage` leaves behind. */
export const seedDlState = (
  stack: FakeStack,
  stage: DlStage,
  t0: Date,
  { writtenAt, afterFlipRun = false }: { writtenAt?: string; afterFlipRun?: boolean } = {}
): void => {
  const times = expectedSightingTimes(stage, t0);
  const flipFirstSeen = new Date(t0.getTime() - 20 * 3_600_000).toISOString();
  for (const expected of expectedInstancesAt(stage, { afterFlipRun })) {
    const sighting = times.find(
      ({ hostKey, catalogId }) => hostKey === expected.hostKey && catalogId === expected.catalogId
    );
    // The flipped instance keeps its previous-version link and history after it returns to active.
    const flipped = expected.previousSoftwareId !== undefined;
    instanceDoc(stack, {
      hostKey: expected.hostKey,
      catalogId: expected.catalogId,
      status: expected.status,
      sources: expected.sources ? [...expected.sources] : ['logs'],
      hostName: expected.hostName ?? null,
      hostId: expected.hostId ?? 'synth-agent-lin01',
      writtenAt,
      previousSoftwareId: expected.previousSoftwareId,
      firstSeen: sighting?.firstSeen,
      lastSeen: sighting?.lastSeen,
      versionHistory: flipped
        ? [
            {
              version: '1.25.2',
              software_id: 'f5:nginx:1.25.2',
              first_seen: flipFirstSeen,
              last_seen: flipFirstSeen,
            },
            {
              version: '1.27.4',
              software_id: 'f5:nginx:1.27.4',
              first_seen: sighting?.lastSeen ?? flipFirstSeen,
              last_seen: sighting?.lastSeen ?? flipFirstSeen,
            },
          ]
        : undefined,
    });
  }
  for (const { id, category } of expectedCatalogAt(stage)) {
    const { vendor, product, version } = parseCatalogId(id);
    stack.put(CATALOG_INDEX, id, toDoc({ id, vendor, product, version, category }));
  }
  for (const event of expectedEventsAt(stage, t0)) putEvent(stack, event);
  // The Osquery baseline (DO-1) wrote the first_seen event of the shared nginx instance.
  putEvent(stack, {
    type: 'first_seen',
    '@timestamp': '2026-11-18T00:00:00.000Z',
    instance_id: instanceIdFor({ hostKey: 'synth-lin-01', catalogId: 'f5:nginx:1.18.0' }),
    host: { key: 'synth-lin-01' },
    source: 'osquery',
    software_id: 'f5:nginx:1.18.0',
  });
};

/** `query_*` ES|QL step output for expected rows. */
export const esqlOutput = (rows: readonly ExpectedEsqlRow[]): JsonValue => ({
  columns: ['host_id', 'host_name', 'vendor', 'name', 'version', 'observed_at'].map((name) => ({
    name,
    type: 'keyword',
  })),
  values: rows.map((row) => [
    row.host_id,
    row.host_name ?? null,
    row.vendor ?? null,
    row.name,
    row.version,
    row.observedAt,
  ]),
});

export const seedExposure = (
  stack: FakeStack,
  expectation: ExposureExpectation,
  overrides: { installPath?: string; writtenAt?: string } = {}
): void => {
  instanceDoc(stack, {
    writtenAt: overrides.writtenAt,
    hostKey: expectation.hostKey,
    catalogId: expectation.catalogId,
    installPath: overrides.installPath,
    exposure: {
      level: expectation.level as ExposureLevel,
      score: expectation.score,
      evidence: expectation.evidence.map((item) => ({
        signal: item.signal,
        weight: item.weight,
        detail: item.detail ?? [...(item.detailIncludes ?? [])].join(' '),
      })),
    },
  });
};
