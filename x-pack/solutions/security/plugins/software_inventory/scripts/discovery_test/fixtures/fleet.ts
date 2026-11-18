/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Fleet package policy fixtures for the `discover-integrations` variants. The variant replaces
 * `list_package_policies` with a `data.set` whose output is the Fleet response body
 * (`GET /api/fleet/package_policies`), so `build_candidates` reads `output.items` as in production.
 * See "Fleet fixtures" in docs/discovery_test_plan.md.
 */

import type { IngestCandidatesOutput } from '../../../common/types';

/** The fields of a package policy that `build_candidates` reads, plus realistic identity fields. */
export interface FleetPackagePolicy {
  readonly id: string;
  readonly name: string;
  readonly namespace: string;
  readonly enabled: boolean;
  readonly package: { readonly name: string; readonly title: string; readonly version: string };
  readonly policy_ids: readonly string[];
}

export interface FleetPackagePoliciesResponse {
  readonly items: readonly FleetPackagePolicy[];
  readonly total: number;
  readonly page: number;
  readonly perPage: number;
}

export interface ExpectedFleetInstance {
  /** `policy:<agent policy id>`; also the stored `host.id`. */
  readonly hostKey: string;
  /** The agent policy id without the prefix. */
  readonly hostName: string;
  readonly catalogId: string;
  readonly category: 'appliance' | 'application';
}

export interface FleetFixture {
  readonly id: string;
  readonly description: string;
  readonly response: FleetPackagePoliciesResponse;
  readonly expected: {
    readonly buildCandidates: number;
    readonly ingest: Partial<IngestCandidatesOutput>;
    readonly instances: readonly ExpectedFleetInstance[];
  };
}

export const SYNTH_POLICY_EDGE = 'synth-pol-edge';
export const SYNTH_POLICY_WEB = 'synth-pol-web';
export const policyHostKey = (agentPolicyId: string): string => `policy:${agentPolicyId}`;

const packagePolicy = (
  id: string,
  packageName: string,
  version: string,
  policyIds: readonly string[]
): FleetPackagePolicy => ({
  id,
  name: `synth-${id}`,
  namespace: 'default',
  enabled: true,
  package: { name: packageName, title: packageName, version },
  policy_ids: policyIds,
});

const response = (items: readonly FleetPackagePolicy[]): FleetPackagePoliciesResponse => ({
  items,
  total: items.length,
  page: 1,
  perPage: 1000,
});

/** The real, empty Fleet response on the test stack (DI-1). */
export const EMPTY_FLEET_RESPONSE: FleetPackagePoliciesResponse = response([]);

const PANW_EDGE: ExpectedFleetInstance = {
  hostKey: policyHostKey(SYNTH_POLICY_EDGE),
  hostName: SYNTH_POLICY_EDGE,
  catalogId: 'palo_alto_networks:pan-os:unknown',
  category: 'appliance',
};
const NGINX_EDGE: ExpectedFleetInstance = {
  hostKey: policyHostKey(SYNTH_POLICY_EDGE),
  hostName: SYNTH_POLICY_EDGE,
  catalogId: 'f5:nginx:unknown',
  category: 'application',
};
const NGINX_WEB: ExpectedFleetInstance = {
  hostKey: policyHostKey(SYNTH_POLICY_WEB),
  hostName: SYNTH_POLICY_WEB,
  catalogId: 'f5:nginx:unknown',
  category: 'application',
};

/** DI-2: mapped (`panw`, `nginx`), unmapped (`system`, `osquery_manager`), blank, and orphan. */
export const FLEET_MAPPED_AND_UNMAPPED: FleetFixture = {
  id: 'FLEET-mapped-unmapped',
  description: 'pp-1..pp-6 of the Fleet fixtures table',
  response: response([
    packagePolicy('pp-1', 'panw', '5.3.0', [SYNTH_POLICY_EDGE]),
    packagePolicy('pp-2', 'nginx', '1.20.0', [SYNTH_POLICY_WEB, SYNTH_POLICY_EDGE]),
    packagePolicy('pp-3', 'system', '1.60.0', [SYNTH_POLICY_WEB]),
    packagePolicy('pp-4', 'osquery_manager', '1.14.0', [SYNTH_POLICY_WEB]),
    packagePolicy('pp-5', '', '1.0.0', [SYNTH_POLICY_WEB]),
    packagePolicy('pp-6', 'fortinet_fortigate', '', []),
  ]),
  expected: {
    buildCandidates: 5,
    ingest: { created: 3, skipped: 2 },
    instances: [PANW_EDGE, NGINX_WEB, NGINX_EDGE],
  },
};

/** DI-4: the DI-2 fixture minus `nginx` on `synth-pol-edge`; no snapshot, so nothing is removed. */
export const FLEET_WITHOUT_NGINX_ON_EDGE: FleetFixture = {
  id: 'FLEET-without-nginx-edge',
  description: 'DI-2 fixture with pp-2 attached to synth-pol-web only',
  response: response([
    packagePolicy('pp-1', 'panw', '5.3.0', [SYNTH_POLICY_EDGE]),
    packagePolicy('pp-2', 'nginx', '1.20.0', [SYNTH_POLICY_WEB]),
    packagePolicy('pp-3', 'system', '1.60.0', [SYNTH_POLICY_WEB]),
    packagePolicy('pp-4', 'osquery_manager', '1.14.0', [SYNTH_POLICY_WEB]),
  ]),
  expected: {
    buildCandidates: 4,
    ingest: { unchanged: 2, skipped: 2, removed: 0 },
    instances: [PANW_EDGE, NGINX_WEB, NGINX_EDGE],
  },
};

/** DI-5: one `panw` policy on `count` agent policies, above the 5000-candidate limit by default. */
export const oversizedFleetFixture = (count = 5001): FleetFixture => ({
  id: `FLEET-oversized-${count}`,
  description: `One panw package policy attached to ${count} synthetic agent policies`,
  response: response([
    packagePolicy(
      'pp-big',
      'panw',
      '5.3.0',
      Array.from({ length: count }, (_, index) => `synth-pol-bulk-${index + 1}`)
    ),
  ]),
  expected: { buildCandidates: count, ingest: {}, instances: [] },
});

export const ALL_FLEET_FIXTURES: readonly FleetFixture[] = [
  FLEET_MAPPED_AND_UNMAPPED,
  FLEET_WITHOUT_NGINX_ON_EDGE,
];
