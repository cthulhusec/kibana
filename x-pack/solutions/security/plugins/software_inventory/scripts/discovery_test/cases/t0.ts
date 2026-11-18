/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * T0: harness self-checks. Owned by the harness; this module is also the reference implementation
 * of the case contract in `./types.ts`. T0-4 (preflight) is the `preflight` CLI command.
 */

import { isDeepStrictEqual } from 'util';
import { parse } from 'yaml';
import { runQueryOutputSchema } from '@kbn/osquery-plugin/common/workflows/step_types/run_query/run_query_common';
import type { LayerResult } from '../assertions';
import {
  checkEngine,
  checkNoUnexpectedWrites,
  checkSteps,
  ingestOutput,
  layerResult,
} from '../assertions';
import { HttpError } from '../clients';
import {
  ALL_BULK_FIXTURES,
  ALL_OSQUERY_FIXTURES,
  F_EMPTY,
  FIXTURE_ROW_TIMESTAMP,
  OSQUERY_QUERY_STEPS,
  R1,
} from '../fixtures/osquery';
import { FLEET_MAPPED_AND_UNMAPPED } from '../fixtures/fleet';
import { assertFidelity, getProductionYaml, getWorkflowId } from '../variants/build_variant';
import { buildOsqueryVariant, osqueryReplacements } from '../variants/osquery';
import { buildIntegrationsVariant } from '../variants/integrations';
import { buildEnrichVariant } from '../variants/enrich';
import type { CaseResult, TestCase } from './types';
import { caseResult } from './types';

interface NamedStep {
  name: string;
}

/** Names of the steps whose parsed form differs between two workflow YAML files. */
const changedSteps = (productionYaml: string, variantYaml: string): string[] => {
  const production = (parse(productionYaml) as { steps: NamedStep[] }).steps;
  const variant = (parse(variantYaml) as { steps: NamedStep[] }).steps;
  return production
    .filter(
      (step) =>
        !isDeepStrictEqual(
          step,
          variant.find(({ name }) => name === step.name)
        )
    )
    .map(({ name }) => name);
};

const t0VariantFidelity = async (): Promise<CaseResult> => {
  const diffs: string[] = [];
  let checks = 0;
  const expectChanged = (label: string, actual: string[], expected: string[]) => {
    checks++;
    if (!isDeepStrictEqual(actual, expected)) {
      diffs.push(
        `${label}: changed steps ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`
      );
    }
  };

  const osqueryProduction = getProductionYaml('discoverOsquery');
  const osquery = buildOsqueryVariant({ label: 'T0-1', steps: R1 });
  expectChanged('discover-osquery', changedSteps(osqueryProduction, osquery), [
    ...OSQUERY_QUERY_STEPS,
  ]);

  expectChanged(
    'discover-integrations',
    changedSteps(
      getProductionYaml('discoverIntegrations'),
      buildIntegrationsVariant({ label: 'T0-1', response: FLEET_MAPPED_AND_UNMAPPED.response })
    ),
    ['list_package_policies']
  );
  expectChanged(
    'enrich-cves',
    changedSteps(getProductionYaml('enrichCves'), buildEnrichVariant({ label: 'T0-1', limit: 3 })),
    ['enrich']
  );

  // The invariant must also reject a tampered variant, or the check above proves nothing.
  checks++;
  const tampered = osquery.replace('source: osquery', 'source: logs');
  try {
    assertFidelity(osqueryProduction, tampered, osqueryReplacements(R1), { label: 'T0-1' });
    diffs.push('assertFidelity accepted a variant with a modified ingest step');
  } catch {
    // Expected.
  }

  return caseResult([layerResult('harness', diffs, checks)]);
};

const t0FixtureContract = async (): Promise<CaseResult> => {
  const diffs: string[] = [];
  const outputs = [
    ...ALL_OSQUERY_FIXTURES.map((fixture) => ({ id: fixture.id, output: fixture.output })),
    ...ALL_BULK_FIXTURES.map((fixture) => ({
      id: fixture.id,
      output: {
        ...fixture.output,
        rows: [
          {
            agent: { id: fixture.rows.agent.id, name: fixture.rows.agent.name },
            '@timestamp': FIXTURE_ROW_TIMESTAMP,
            columns: { name: 'synth-pkg-1', version: '1.0.1', install_path: '' },
            ecs: {},
          },
        ],
      },
    })),
  ];
  for (const { id, output } of outputs) {
    const parsed = runQueryOutputSchema.safeParse(output);
    if (!parsed.success) {
      diffs.push(
        `${id}: ${parsed.error.issues
          .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
          .join('; ')}`
      );
    }
    if ('rows' in output) {
      for (const row of output.rows) {
        const nonString = Object.entries(row.columns).filter(
          ([, value]) => typeof value !== 'string'
        );
        if (nonString.length > 0)
          diffs.push(`${id}: non-string columns ${nonString.map(([k]) => k).join(', ')}`);
      }
    }
  }
  return caseResult([layerResult('harness', diffs, outputs.length)]);
};

const t0ManagedIdTestRun: TestCase['run'] = async (ctx) => {
  const workflowId = getWorkflowId('discoverOsquery');
  const since = new Date().toISOString();
  const yaml = buildOsqueryVariant({
    label: 'T0-3 no-op',
    steps: Object.fromEntries(OSQUERY_QUERY_STEPS.map((step) => [step, F_EMPTY])),
  });
  let run;
  try {
    run = await ctx.runWorkflow({ workflow: 'discoverOsquery', yaml });
  } catch (error) {
    if (error instanceof HttpError && error.status >= 400 && error.status < 500) {
      return caseResult(
        [layerResult('engine', [`managed-id test run refused: ${error.message}`], 1)],
        ['Switch to the si-test- fallback: a saved copy plus a dashboard filter (risk R2).']
      );
    }
    throw error;
  }
  const engine = checkEngine(run.execution, { workflowId, isTestRun: true });
  const ingestSteps = ['ingest_linux', 'ingest_windows', 'ingest_macos', 'ingest_dependencies'];
  const step = await checkSteps(
    run,
    Object.fromEntries(
      ingestSteps.map((name) => [
        name,
        { output: ingestOutput({}), input: { snapshot: true, candidates: [] } },
      ])
    )
  );
  const inventory: LayerResult = await checkNoUnexpectedWrites(ctx.es, {
    since,
    allowedHostKeys: [],
  });
  return caseResult([engine, step, inventory]);
};

export const cases: TestCase[] = [
  {
    id: 'T0-1',
    family: 'T0',
    title: 'Variant fidelity: builders change only the replaced steps',
    run: t0VariantFidelity,
  },
  {
    id: 'T0-2',
    family: 'T0',
    title: 'Fixture contract: every Osquery fixture parses with runQueryOutputSchema',
    run: t0FixtureContract,
  },
  {
    id: 'T0-3',
    family: 'T0',
    title: 'Managed-id test run accepted (no-op discover-osquery variant)',
    requires: ['T0-1'],
    run: t0ManagedIdTestRun,
  },
];
