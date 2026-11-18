/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { loggingSystemMock } from '@kbn/core-logging-server-mocks';
import { elasticsearchServiceMock } from '@kbn/core-elasticsearch-server-mocks';
import type { WorkflowsExtensionsServerPluginSetup } from '@kbn/workflows-extensions/server';
import {
  MAX_CANDIDATES_PER_CALL,
  STEP_ENRICH_CVES,
  STEP_INGEST_CANDIDATES,
  STEP_MARK_STALE,
  STEP_SCORE_EXPOSURE,
  STEP_SNAPSHOT_ROLLUP,
} from '../../common/constants';
import { ingestCandidatesStepCommonDefinition } from '../../common/step_definitions';
import { createFakeEsClient } from '../services/ingest/fake_es_client';
import { registerSoftwareInventorySteps, toIngestInput } from './register_steps';

jest.mock('../services/enrichment/enrich_catalog_entries', () => ({
  enrichCatalogEntries: jest.fn(),
}));
jest.mock('../services/enrichment/score_exposure', () => ({ scoreExposure: jest.fn() }));

describe('software inventory steps', () => {
  it('registers all five steps', () => {
    const registerStepDefinition = jest.fn();
    registerSoftwareInventorySteps({
      workflowsExtensions: {
        registerStepDefinition,
      } as unknown as WorkflowsExtensionsServerPluginSetup,
      getEsClient: async () => elasticsearchServiceMock.createElasticsearchClient(),
      logger: loggingSystemMock.createLogger(),
    });
    expect(registerStepDefinition.mock.calls.map(([definition]) => definition.id)).toEqual([
      STEP_INGEST_CANDIDATES,
      STEP_ENRICH_CVES,
      STEP_SCORE_EXPOSURE,
      STEP_MARK_STALE,
      STEP_SNAPSHOT_ROLLUP,
    ]);
  });

  it('accepts null row fields and drops them before ingest', () => {
    const parsed = ingestCandidatesStepCommonDefinition.inputSchema.parse({
      source: 'osquery',
      candidates: [{ host_id: 'h1', name: 'nginx', version: null, vendor: null }],
    });
    expect(toIngestInput(parsed)).toEqual({
      input: {
        source: 'osquery',
        snapshot: false,
        candidates: [{ host_id: 'h1', name: 'nginx' }],
      },
      invalid: 0,
    });
  });

  it('accepts a batch with malformed rows and drops only those rows', () => {
    const parsed = ingestCandidatesStepCommonDefinition.inputSchema.safeParse({
      source: 'osquery',
      snapshot: true,
      candidates: [
        { host_id: 'h1', name: 'nginx' },
        { host_id: 'h1', name: '' },
        { host_id: '', name: 'Safari' },
        { host_id: 'h1', name: 'x'.repeat(10_000) },
        { host_id: 'h1', name: 'curl', category: 'not-a-category' },
        'not an object',
        null,
      ],
    });
    expect(parsed.success).toBe(true);
    expect(parsed.success && toIngestInput(parsed.data)).toEqual({
      input: { source: 'osquery', snapshot: true, candidates: [{ host_id: 'h1', name: 'nginx' }] },
      invalid: 6,
    });
  });

  it('reports invalid rows in the step output as skipped', async () => {
    const registerStepDefinition = jest.fn();
    registerSoftwareInventorySteps({
      workflowsExtensions: {
        registerStepDefinition,
      } as unknown as WorkflowsExtensionsServerPluginSetup,
      getEsClient: async () => createFakeEsClient().esClient,
      logger: loggingSystemMock.createLogger(),
    });
    const [[definition]] = registerStepDefinition.mock.calls;
    const input = ingestCandidatesStepCommonDefinition.inputSchema.parse({
      source: 'osquery',
      snapshot: true,
      candidates: [
        { host_id: 'h1', host_name: 'web-1', name: 'nginx' },
        { host_id: 'h1', name: '' },
      ],
    });
    const { output } = await definition.handler({ input });
    expect(output).toEqual({ created: 1, unchanged: 0, patched: 0, removed: 0, skipped: 1 });
    expect(ingestCandidatesStepCommonDefinition.outputSchema.safeParse(output).success).toBe(true);
  });

  it('bounds the number of candidates', () => {
    const candidates = Array.from({ length: MAX_CANDIDATES_PER_CALL + 1 }, () => ({
      host_id: 'h1',
      name: 'nginx',
    }));
    expect(
      ingestCandidatesStepCommonDefinition.inputSchema.safeParse({ source: 'osquery', candidates })
        .success
    ).toBe(false);
  });
});
