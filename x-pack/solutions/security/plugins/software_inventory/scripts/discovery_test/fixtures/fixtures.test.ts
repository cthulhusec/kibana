/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { parse } from 'yaml';
import { createWorkflowLiquidEngine } from '@kbn/workflows/common/utils';
import { runQueryOutputSchema } from '@kbn/osquery-plugin/common/workflows/step_types/run_query/run_query_common';
import type { DiscoverySource, RawCandidate } from '../../../common/types';
import { normalizeCandidate } from '../../../server/services/ingest/normalize_candidate';
import { getProductionYaml } from '../variants/build_variant';
import { isSyntheticHostKey } from '../ids';
import type { ExpectedRow, OsqueryFixture, OsqueryQueryStep } from './osquery';
import {
  ALL_OSQUERY_FIXTURES,
  R1,
  R1_DEPENDENCY_ROWS,
  R1_EXPECTED_TOTALS,
  R1_LINUX_ROWS,
  R1_MACOS_ROWS,
  R1_WINDOWS_ROWS,
  R2_LINUX,
} from './osquery';
import type { FleetFixture } from './fleet';
import { ALL_FLEET_FIXTURES, oversizedFleetFixture } from './fleet';

interface Step {
  name: string;
  with?: Record<string, string | number | boolean>;
}
const engine = createWorkflowLiquidEngine();
const NOW = '2026-11-18T10:00:00.000Z';

const renderCandidates = async (
  workflow: 'discoverOsquery' | 'discoverIntegrations',
  buildStep: string,
  context: object
): Promise<RawCandidate[]> => {
  const { steps } = parse(getProductionYaml(workflow)) as { steps: Step[] };
  const template = String(steps.find(({ name }) => name === buildStep)?.with?.candidates_json);
  return JSON.parse(await engine.parseAndRender(template, context));
};

const BUILD_STEP: Record<OsqueryQueryStep, string> = {
  query_linux: 'build_linux',
  query_windows: 'build_windows',
  query_macos: 'build_macos',
  query_dependencies: 'build_dependencies',
};

/** Mirrors the ingest step's dedupe: one instance per host key, vendor, product, install path. */
const normalizeAll = (candidates: readonly RawCandidate[], source: DiscoverySource) => {
  const normalized = candidates.map((candidate) => normalizeCandidate(candidate, NOW, source));
  const valid = normalized.flatMap((item) => (item ? [item] : []));
  const unique = new Map(
    valid.map((item) => [
      `${item.host_key}|${item.vendor}|${item.product}|${item.install_path ?? ''}`,
      `${item.host_key} ${item.vendor}:${item.product}:${item.version}`,
    ])
  );
  return { skipped: normalized.length - valid.length, instances: [...unique.values()].sort() };
};

describe('Osquery fixtures', () => {
  it.each(ALL_OSQUERY_FIXTURES.map((fixture) => [fixture.id, fixture] as const))(
    '%s parses with the real runQueryOutputSchema and has string columns',
    (_id, fixture: OsqueryFixture) => {
      expect(runQueryOutputSchema.safeParse(fixture.output).success).toBe(true);
      for (const row of fixture.output.rows) {
        expect(Object.values(row.columns).every((value) => typeof value === 'string')).toBe(true);
        expect(row.ecs).toEqual({});
        expect(typeof row['@timestamp']).toBe('string');
      }
      expect(fixture.output.row_count).toBeGreaterThanOrEqual(fixture.output.rows.length);
    }
  );

  it('rejects a malformed row, so the contract check is meaningful', () => {
    const broken = {
      ...R1.query_linux.output,
      rows: [{ agent: { id: 'x' }, columns: { version: 1 }, ecs: {} }],
    };
    expect(runQueryOutputSchema.safeParse(broken).success).toBe(false);
  });

  const DOCUMENTED: Record<OsqueryQueryStep, readonly ExpectedRow[]> = {
    query_linux: R1_LINUX_ROWS,
    query_windows: R1_WINDOWS_ROWS,
    query_macos: R1_MACOS_ROWS,
    query_dependencies: R1_DEPENDENCY_ROWS,
  };

  it.each(Object.keys(R1) as OsqueryQueryStep[])(
    'R1 %s normalizes to the documented host keys and catalog ids',
    async (query) => {
      const candidates = await renderCandidates('discoverOsquery', BUILD_STEP[query], {
        steps: { [query]: { output: R1[query].output } },
      });
      const { skipped, instances } = normalizeAll(candidates, 'osquery');
      const created = DOCUMENTED[query].filter(({ outcome }) => outcome === 'created');
      expect(instances).toEqual(created.map((row) => `${row.hostKey} ${row.catalogId}`).sort());
      expect(skipped).toBe(R1[query].expected.ingest?.skipped ?? 0);
      expect(instances).toHaveLength(R1[query].expected.ingest?.created ?? 0);
      for (const { hostKey } of created) expect(isSyntheticHostKey(hostKey ?? '')).toBe(true);
    }
  );

  it('R1 totals match the plan (13 instances)', () => {
    const created = Object.values(R1).reduce(
      (sum, fixture) => sum + (fixture.expected.ingest?.created ?? 0),
      0
    );
    expect(created).toBe(R1_EXPECTED_TOTALS.instances);
  });

  it('R2 patches openssl to 3.0.14 on synth-lin-01', async () => {
    const candidates = await renderCandidates('discoverOsquery', 'build_linux', {
      steps: { query_linux: { output: R2_LINUX.output } },
    });
    expect(normalizeAll(candidates, 'osquery').instances).toContain(
      'synth-lin-01 openssl:openssl:3.0.14'
    );
  });

  it('every created catalog id of every fixture matches normalizeCandidate', async () => {
    for (const fixture of ALL_OSQUERY_FIXTURES) {
      const candidates = await renderCandidates('discoverOsquery', 'build_dependencies', {
        steps: { query_dependencies: { output: fixture.output } },
      });
      const ids = normalizeAll(candidates, 'osquery').instances.map((line) => line.split(' ')[1]);
      for (const id of fixture.expected.catalogIds ?? []) expect(ids).toContain(id);
    }
  });
});

describe('Fleet fixtures', () => {
  it.each(ALL_FLEET_FIXTURES.map((fixture) => [fixture.id, fixture] as const))(
    '%s yields the documented candidates, instances, and skipped count',
    async (_id, fixture: FleetFixture) => {
      const candidates = await renderCandidates('discoverIntegrations', 'build_candidates', {
        steps: { list_package_policies: { output: fixture.response } },
      });
      expect(candidates).toHaveLength(fixture.expected.buildCandidates);
      const { skipped, instances } = normalizeAll(candidates, 'fleet_integration');
      expect(skipped).toBe(fixture.expected.ingest.skipped ?? 0);
      const expected = fixture.expected.instances.map((i) => `${i.hostKey} ${i.catalogId}`);
      expect(expected).toEqual(expect.arrayContaining(instances));
      const { created = 0, unchanged = 0 } = fixture.expected.ingest;
      expect(instances).toHaveLength(created + unchanged);
      for (const candidate of candidates) {
        expect(candidate.host_id).toBe(`policy:${candidate.host_name}`);
      }
    }
  );

  it('DI-2 creates exactly the three mapped instances', async () => {
    const [fixture] = ALL_FLEET_FIXTURES;
    const candidates = await renderCandidates('discoverIntegrations', 'build_candidates', {
      steps: { list_package_policies: { output: fixture.response } },
    });
    expect(normalizeAll(candidates, 'fleet_integration').instances).toEqual(
      fixture.expected.instances.map((i) => `${i.hostKey} ${i.catalogId}`).sort()
    );
  });

  it('builds an oversized fixture above the 5000-candidate limit', async () => {
    const fixture = oversizedFleetFixture();
    const candidates = await renderCandidates('discoverIntegrations', 'build_candidates', {
      steps: { list_package_policies: { output: fixture.response } },
    });
    expect(candidates).toHaveLength(5001);
  });
});
