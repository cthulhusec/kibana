/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import type { Duration } from 'moment';
import {
  createServerStepDefinition,
  type WorkflowsExtensionsServerPluginSetup,
} from '@kbn/workflows-extensions/server';
import {
  enrichCvesStepCommonDefinition,
  ingestCandidatesStepCommonDefinition,
  markStaleStepCommonDefinition,
  rawCandidateSchema,
  scoreExposureStepCommonDefinition,
  snapshotRollupStepCommonDefinition,
  type IngestCandidatesStepInput,
  type RawCandidateStepRow,
} from '../../common/step_definitions';
import { MAX_CANDIDATES_PER_CALL } from '../../common/constants';
import type { IngestCandidatesInput, RawCandidate } from '../../common/types';
import { ingestCandidates, markStale } from '../services/ingest';
import { enrichCatalogEntries } from '../services/enrichment/enrich_catalog_entries';
import { scoreExposure } from '../services/enrichment/score_exposure';
import { snapshotRollup } from '../services/rollup/snapshot_rollup';

export interface RegisterStepsDeps {
  workflowsExtensions: WorkflowsExtensionsServerPluginSetup;
  /** Internal-user client: the inventory indices are plugin-owned and hidden. */
  getEsClient: () => Promise<ElasticsearchClient>;
  logger: Logger;
  /** Optional endpoint overrides for CVE enrichment; unset values use the live services. */
  enrichment?: {
    nvdBaseUrl?: string;
    kevUrl?: string;
    requestSpacing?: Duration;
    requestTimeout?: Duration;
    backoffBase?: Duration;
  };
}

/** Converts the step's nullable row fields into the optional fields `RawCandidate` uses. */
const toRawCandidate = (row: RawCandidateStepRow): RawCandidate => ({
  host_id: row.host_id,
  name: row.name,
  ...(row.host_name != null && { host_name: row.host_name }),
  ...(row.version != null && { version: row.version }),
  ...(row.vendor != null && { vendor: row.vendor }),
  ...(row.install_path != null && { install_path: row.install_path }),
  ...(row.category != null && { category: row.category }),
  ...(row.observed_at != null && { observed_at: row.observed_at }),
});

/** Validates each row on its own; `invalid` counts the rows that were dropped. */
export const toIngestInput = ({
  source,
  snapshot,
  candidates,
}: IngestCandidatesStepInput): { input: IngestCandidatesInput; invalid: number } => {
  // The step's input schema declares this bound, but the workflow engine does not enforce a step
  // input schema's array limit at run time, so the handler enforces it itself.
  if (candidates.length > MAX_CANDIDATES_PER_CALL) {
    throw new Error(
      `Too many candidates: received ${candidates.length}, the limit is ${MAX_CANDIDATES_PER_CALL} candidates per call. Split the rows across several calls.`
    );
  }
  const valid = candidates.flatMap((row) => {
    const parsed = rawCandidateSchema.safeParse(row);
    return parsed.success ? [toRawCandidate(parsed.data)] : [];
  });
  return {
    input: { source, snapshot, candidates: valid },
    invalid: candidates.length - valid.length,
  };
};

/** Registers the software inventory custom workflow steps. Handlers resolve ES lazily. */
export const registerSoftwareInventorySteps = ({
  workflowsExtensions,
  getEsClient,
  logger,
  enrichment,
}: RegisterStepsDeps): void => {
  workflowsExtensions.registerStepDefinition(
    createServerStepDefinition({
      ...ingestCandidatesStepCommonDefinition,
      handler: async ({ input }) => {
        const { input: ingestInput, invalid } = toIngestInput(input);
        if (invalid > 0) {
          logger.debug(`Software inventory skipped ${invalid} invalid candidate row(s)`);
        }
        const output = await ingestCandidates({
          esClient: await getEsClient(),
          logger,
          input: ingestInput,
        });
        return { output: { ...output, skipped: output.skipped + invalid } };
      },
    })
  );

  workflowsExtensions.registerStepDefinition(
    createServerStepDefinition({
      ...enrichCvesStepCommonDefinition,
      handler: async ({ input }) => {
        const output = await enrichCatalogEntries({
          esClient: await getEsClient(),
          logger,
          limit: input.limit,
          ...(enrichment?.nvdBaseUrl ? { nvdBaseUrl: enrichment.nvdBaseUrl } : {}),
          ...(enrichment?.kevUrl ? { kevUrl: enrichment.kevUrl } : {}),
          ...(enrichment?.requestSpacing
            ? { requestSpacingMs: enrichment.requestSpacing.asMilliseconds() }
            : {}),
          ...(enrichment?.requestTimeout
            ? { requestTimeoutMs: enrichment.requestTimeout.asMilliseconds() }
            : {}),
          ...(enrichment?.backoffBase
            ? { backoffBaseMs: enrichment.backoffBase.asMilliseconds() }
            : {}),
        });
        return { output };
      },
    })
  );

  workflowsExtensions.registerStepDefinition(
    createServerStepDefinition({
      ...scoreExposureStepCommonDefinition,
      handler: async ({ input }) => {
        const output = await scoreExposure({
          esClient: await getEsClient(),
          logger,
          lookbackDays: input.lookback_days,
        });
        return { output };
      },
    })
  );

  workflowsExtensions.registerStepDefinition(
    createServerStepDefinition({
      ...markStaleStepCommonDefinition,
      handler: async ({ input }) => {
        const output = await markStale({
          esClient: await getEsClient(),
          logger,
          staleAfterDays: input.stale_after_days,
        });
        return { output };
      },
    })
  );

  workflowsExtensions.registerStepDefinition(
    createServerStepDefinition({
      ...snapshotRollupStepCommonDefinition,
      handler: async () => {
        const { date, rollup } = await snapshotRollup({ esClient: await getEsClient(), logger });
        return {
          output: {
            date,
            total_instances: rollup.total_instances,
            vulnerable_instances: rollup.vulnerable_instances,
          },
        };
      },
    })
  );
};
