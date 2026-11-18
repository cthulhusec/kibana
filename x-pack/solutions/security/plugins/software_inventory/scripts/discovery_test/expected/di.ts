/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Expected outcomes of the DISCOVER-INTEGRATIONS cases (DI-1..DI-5 in docs/discovery_test_plan.md).
 * Instances and catalog ids derive from the Fleet fixtures: mapped packages become instances on
 * `policy:<agent policy id>` pseudo-hosts with the `unknown` version, unmapped packages are
 * skipped, and package policies without a name or without agent policies produce no candidate.
 */

import type { ExpectedCatalogEntry, ExpectedEvent, ExpectedInstance } from '../assertions';
import type { FleetFixture } from '../fixtures/fleet';
import {
  FLEET_MAPPED_AND_UNMAPPED,
  FLEET_WITHOUT_NGINX_ON_EDGE,
  SYNTH_POLICY_EDGE,
  SYNTH_POLICY_WEB,
  oversizedFleetFixture,
  policyHostKey,
} from '../fixtures/fleet';
import type { IngestCounts } from './do';

/** Fleet candidates carry no real version: the server stores this one. */
export const UNKNOWN_VERSION = 'unknown';
export const FLEET_SOURCE = 'fleet_integration';

export interface DiIngestExpectation {
  readonly output: IngestCounts;
  /** The workflow never takes a snapshot of package policies. */
  readonly snapshot: false;
  /** Candidates `build_candidates` hands to `ingest`. */
  readonly candidates: number;
}

export const instancesOfFleetFixture = (fixture: FleetFixture): ExpectedInstance[] =>
  fixture.expected.instances.map(({ hostKey, hostName, catalogId }) => ({
    hostKey,
    catalogId,
    status: 'active',
    sources: [FLEET_SOURCE],
    hostId: hostKey,
    hostName,
    versions: [UNKNOWN_VERSION],
  }));

export const catalogOfFleetFixture = (fixture: FleetFixture): ExpectedCatalogEntry[] => [
  ...new Map(
    fixture.expected.instances.map(({ catalogId, category }) => [
      catalogId,
      { id: catalogId, fields: { category, version: UNKNOWN_VERSION } },
    ])
  ).values(),
];

export const firstSeenEventsOfFleetFixture = (fixture: FleetFixture): ExpectedEvent[] =>
  fixture.expected.instances.map(({ hostKey, hostName, catalogId }) => ({
    type: 'first_seen',
    source: FLEET_SOURCE,
    software_id: catalogId,
    host: { key: hostKey, id: hostKey, name: hostName },
    to_version: UNKNOWN_VERSION,
  }));

export const DI_HOST_KEYS: readonly string[] = [
  policyHostKey(SYNTH_POLICY_EDGE),
  policyHostKey(SYNTH_POLICY_WEB),
];

/** DI-1: the real Fleet on the test stack has no package policies. */
export const DI1_INGEST: DiIngestExpectation = { output: {}, snapshot: false, candidates: 0 };

export const DI2 = {
  fixture: FLEET_MAPPED_AND_UNMAPPED,
  ingest: {
    output: FLEET_MAPPED_AND_UNMAPPED.expected.ingest,
    snapshot: false,
    candidates: FLEET_MAPPED_AND_UNMAPPED.expected.buildCandidates,
  } as DiIngestExpectation,
  instances: instancesOfFleetFixture(FLEET_MAPPED_AND_UNMAPPED),
  catalog: catalogOfFleetFixture(FLEET_MAPPED_AND_UNMAPPED),
  events: firstSeenEventsOfFleetFixture(FLEET_MAPPED_AND_UNMAPPED),
};

/** DI-3: instances per policy pseudo-host after DI-2. */
export const DI3_INSTANCE_COUNTS: Readonly<Record<string, number>> = {
  [policyHostKey(SYNTH_POLICY_EDGE)]: 2,
  [policyHostKey(SYNTH_POLICY_WEB)]: 1,
};

export const DI4 = {
  fixture: FLEET_WITHOUT_NGINX_ON_EDGE,
  ingest: {
    output: FLEET_WITHOUT_NGINX_ON_EDGE.expected.ingest,
    snapshot: false,
    candidates: FLEET_WITHOUT_NGINX_ON_EDGE.expected.buildCandidates,
  } as DiIngestExpectation,
  /** Without a snapshot, nginx on the edge policy stays active. */
  instances: instancesOfFleetFixture(FLEET_MAPPED_AND_UNMAPPED),
};

export const DI5_CANDIDATE_LIMIT = 5000;
export const DI5_FIXTURE = oversizedFleetFixture(DI5_CANDIDATE_LIMIT + 1);
