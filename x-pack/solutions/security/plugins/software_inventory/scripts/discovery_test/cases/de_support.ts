/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Support for the DE cases: ES|QL row checks against the generator's rows, the step-contract check
 * of a `discover-endpoint` run, and the inline Osquery ingest DE-6 uses.
 */

import type { LayerResult } from '../assertions';
import { checkSteps, ingestOutput, layerResult, mergeLayer } from '../assertions';
import type { CompletedRun } from '../clients';
import type { DeStage, ExpectedEndpointCandidate } from '../expected/de';
import { OSQUERY_MERGE_CANDIDATE, rowsAt } from '../expected/de';
import { diffEsqlRows } from './dl_support';
import type { ExpectedEsqlRow } from './dl_support';

export const toEndpointEsqlRow = (
  candidate: ExpectedEndpointCandidate,
  t0: Date
): ExpectedEsqlRow => ({
  host_id: candidate.host_id,
  host_name: candidate.host_name,
  vendor: candidate.vendor,
  name: candidate.name,
  version: candidate.version,
  observedAt: new Date(t0.getTime() - candidate.observedOffsetMs).toISOString(),
});

export const endpointRowsAt = (stage: DeStage, t0: Date): ExpectedEsqlRow[] =>
  rowsAt(stage).map((candidate) => toEndpointEsqlRow(candidate, t0));

export interface DiscoverEndpointStepExpectation {
  /** Rows `query_processes` returns, or `failed` when it fails with `failedPattern`. */
  readonly rows: readonly ExpectedEsqlRow[] | 'failed';
  readonly ingest: Partial<
    Record<'created' | 'unchanged' | 'patched' | 'removed' | 'skipped', number>
  >;
  /** Candidates the YAML passes to `ingest`. */
  readonly candidateCount: number;
  readonly failedPattern?: RegExp;
}

/** Step-contract layer of a `discover-endpoint` run: query rows, ingest input and output. */
export const checkDiscoverEndpointSteps = async (
  run: CompletedRun,
  {
    rows,
    ingest,
    candidateCount,
    failedPattern = /Unknown index/i,
  }: DiscoverEndpointStepExpectation
): Promise<LayerResult> => {
  const diffs: string[] = [];
  let checks = 1;
  if (rows === 'failed') {
    const error = JSON.stringify(run.stepsByName.get('query_processes')?.error ?? null);
    if (!failedPattern.test(error)) {
      diffs.push(`query_processes: error does not match ${failedPattern}: ${error}`);
    }
  } else {
    const detail = await run.step('query_processes');
    checks += rows.length;
    diffs.push(...diffEsqlRows('query_processes', detail.output, rows));
  }
  const { input } = await run.step('ingest');
  const candidates =
    typeof input === 'object' && input !== null && !Array.isArray(input) ? input.candidates : null;
  checks++;
  if (!Array.isArray(candidates) || candidates.length !== candidateCount) {
    diffs.push(
      `ingest.input.candidates: expected ${candidateCount} item(s), got ${
        Array.isArray(candidates) ? candidates.length : JSON.stringify(candidates)
      }`
    );
  }
  const contract = await checkSteps(run, {
    ingest: { output: ingestOutput(ingest), input: { source: 'endpoint', snapshot: false } },
  });
  return mergeLayer('step', [layerResult('step', diffs, checks), contract]);
};

/** A one-step workflow that ingests the Osquery row for the DE-6 host (JSON is valid YAML). */
export const buildOsqueryMergeYaml = (): string =>
  JSON.stringify(
    {
      version: '1',
      name: 'Software inventory - DE-6 Osquery row [test: de-6]',
      enabled: false,
      triggers: [{ type: 'manual' }],
      steps: [
        {
          name: 'ingest',
          type: 'softwareInventory.ingestCandidates',
          with: { source: 'osquery', snapshot: false, candidates: [OSQUERY_MERGE_CANDIDATE] },
        },
      ],
    },
    null,
    2
  );
