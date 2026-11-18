/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * DI: discover-integrations (DI-1..DI-5 in docs/discovery_test_plan.md). DI-6 is a read-only code
 * review (the Fleet path lacks the space prefix, risk R3) and has no executable check here.
 * DI-1 reads the real Fleet and is blocked when it holds package policies, because the stored
 * YAML would then ingest real policies.
 */

import type { LayerResult, StepExpectation } from '../assertions';
import {
  checkCatalogEntries,
  checkEngine,
  checkEvents,
  checkInstances,
  checkNoUnexpectedWrites,
  checkSteps,
  ingestOutput,
  layerResult,
  mergeLayer,
} from '../assertions';
import type { CompletedRun } from '../clients';
import { HttpError } from '../clients';
import {
  DI1_INGEST,
  DI2,
  DI3_INSTANCE_COUNTS,
  DI4,
  DI5_CANDIDATE_LIMIT,
  DI5_FIXTURE,
  DI_HOST_KEYS,
  FLEET_SOURCE,
} from '../expected/di';
import type { DiIngestExpectation } from '../expected/di';
import { buildIntegrationsVariant } from '../variants/integrations';
import { getWorkflowId } from '../variants/build_variant';
import {
  candidateCountOf,
  checkCandidateCounts,
  countHostInstances,
  expectCount,
  stepErrorText,
} from './do_support';
import type { CaseContext, TestCase } from './types';
import { blockedResult, caseResult } from './types';

const WORKFLOW_ID = getWorkflowId('discoverIntegrations');

const ingestExpectation = ({ output, snapshot }: DiIngestExpectation): StepExpectation => ({
  output: ingestOutput(output),
  input: { source: FLEET_SOURCE, snapshot },
});

/** Engine and step layers of a finished `discover-integrations` run. */
const checkIntegrationsRun = async (
  run: CompletedRun,
  ingest: DiIngestExpectation,
  { runStatus = 'completed', ingestStatus }: { runStatus?: string; ingestStatus?: string } = {}
): Promise<{ engine: LayerResult; step: LayerResult }> => ({
  engine: checkEngine(run.execution, {
    workflowId: WORKFLOW_ID,
    isTestRun: true,
    status: runStatus,
    ...(ingestStatus ? { steps: { ingest: ingestStatus } } : {}),
  }),
  step: await checkCandidateCounts(run, { ingest: ingest.candidates }),
});

const di1: TestCase['run'] = async (ctx: CaseContext) => {
  let total: number | undefined;
  try {
    const { body } = await ctx.kibana.request<{ total?: number }>(
      'GET',
      '/api/fleet/package_policies',
      { query: { perPage: 1, page: 1 } }
    );
    total = body?.total;
  } catch (error) {
    if (error instanceof HttpError) {
      return blockedResult(`The Fleet package policies API is not readable: ${error.message}`);
    }
    throw error;
  }
  if (total !== 0) {
    return blockedResult(
      `Fleet has ${String(
        total
      )} package policies; the stored YAML would ingest real policies. DI-1 needs an empty Fleet.`
    );
  }

  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({ workflow: 'discoverIntegrations' });
  const { engine, step: counts } = await checkIntegrationsRun(run, DI1_INGEST);
  const step = mergeLayer('step', [
    counts,
    await checkSteps(run, {
      list_package_policies: { output: { items: [] } },
      ingest: ingestExpectation(DI1_INGEST),
    }),
  ]);
  const inventory = await checkNoUnexpectedWrites(ctx.es, { since, allowedHostKeys: [] });
  return caseResult([engine, step, inventory]);
};

const di2: TestCase['run'] = async (ctx) => {
  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({
    workflow: 'discoverIntegrations',
    yaml: buildIntegrationsVariant({ label: 'DI-2', response: DI2.fixture.response }),
  });
  const { engine, step: counts } = await checkIntegrationsRun(run, DI2.ingest);
  const step = mergeLayer('step', [
    counts,
    await checkSteps(run, { ingest: ingestExpectation(DI2.ingest) }),
  ]);
  const inventory = mergeLayer('inventory', [
    await checkInstances(ctx.es, DI2.instances),
    await checkCatalogEntries(ctx.es, DI2.catalog),
    await checkEvents(ctx.es, { hostKeys: DI_HOST_KEYS, since, expected: DI2.events }),
    await checkNoUnexpectedWrites(ctx.es, { since, allowedHostKeys: DI_HOST_KEYS }),
  ]);
  return caseResult([engine, step, inventory]);
};

const di3: TestCase['run'] = async (ctx) => {
  const counts = await Promise.all(
    Object.entries(DI3_INSTANCE_COUNTS).map(async ([hostKey, expected]) =>
      expectCount(`instances on ${hostKey}`, expected, await countHostInstances(ctx.es, hostKey))
    )
  );
  // `checkInstances` also asserts `host.id` = `host.key` and `host.name` without the prefix.
  const inventory = mergeLayer('inventory', [
    ...counts,
    await checkInstances(ctx.es, DI2.instances),
  ]);
  return caseResult([inventory]);
};

const di4: TestCase['run'] = async (ctx) => {
  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({
    workflow: 'discoverIntegrations',
    yaml: buildIntegrationsVariant({ label: 'DI-4', response: DI4.fixture.response }),
  });
  const { engine, step: counts } = await checkIntegrationsRun(run, DI4.ingest);
  const step = mergeLayer('step', [
    counts,
    await checkSteps(run, { ingest: ingestExpectation(DI4.ingest) }),
  ]);
  const inventory = mergeLayer('inventory', [
    await checkInstances(ctx.es, DI4.instances),
    await checkEvents(ctx.es, { hostKeys: DI_HOST_KEYS, since, expected: [] }),
    await checkNoUnexpectedWrites(ctx.es, { since, allowedHostKeys: DI_HOST_KEYS }),
  ]);
  return caseResult([engine, step, inventory]);
};

const di5: TestCase['run'] = async (ctx) => {
  const since = new Date().toISOString();
  const run = await ctx.runWorkflow({
    workflow: 'discoverIntegrations',
    yaml: buildIntegrationsVariant({ label: 'DI-5', response: DI5_FIXTURE.response }),
    wait: { timeoutMs: 10 * 60 * 1000 },
  });
  const { engine } = await checkIntegrationsRun(
    run,
    { output: {}, snapshot: false, candidates: DI5_CANDIDATE_LIMIT + 1 },
    { runStatus: 'failed', ingestStatus: 'failed' }
  );
  const errorText = await stepErrorText(run, 'ingest');
  const detail = await run.step('ingest');
  const candidates = candidateCountOf(detail.input);
  const diffs = [
    ...(/candidates|5000/.test(errorText)
      ? []
      : [`ingest error does not name candidates or the 5000 limit: ${errorText.slice(0, 300)}`]),
    ...(candidates === DI5_CANDIDATE_LIMIT + 1
      ? []
      : [`ingest.input.candidates: expected ${DI5_CANDIDATE_LIMIT + 1}, got ${candidates}`]),
  ];
  const step = layerResult('step', diffs, 2, { ingestError: errorText.slice(0, 500) });
  // The validation fails before any write.
  const inventory = await checkNoUnexpectedWrites(ctx.es, { since, allowedHostKeys: [] });
  return caseResult([engine, step, inventory]);
};

export const cases: TestCase[] = [
  {
    id: 'DI-1',
    family: 'DI',
    title: 'Real Fleet, empty: no package policies, ingest all zeros',
    run: di1,
  },
  {
    id: 'DI-2',
    family: 'DI',
    title: 'Mapped vs unmapped packages: created 3, skipped 2, versions unknown',
    run: di2,
  },
  {
    id: 'DI-3',
    family: 'DI',
    title: 'Policy pseudo-hosts: policy:<id> keys, names without the prefix',
    requires: ['DI-2'],
    run: di3,
  },
  {
    id: 'DI-4',
    family: 'DI',
    title: 'Re-run without nginx on the edge policy: no snapshot, nothing removed',
    requires: ['DI-2'],
    run: di4,
  },
  {
    id: 'DI-5',
    family: 'DI',
    title: 'Ingest failure (5001 candidates) fails the run',
    run: di5,
  },
];
