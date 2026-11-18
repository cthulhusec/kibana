/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Expected outcomes and manual procedures of the scheduling, concurrency, and failure-injection
 * cases (SC-1..SC-9). Saved copies use the `si-test-` id prefix and are always deleted with
 * `force=true` at the end of their case.
 */

import { TEST_WORKFLOW_ID_PREFIX } from '../ids';
import { getWorkflowId } from '../variants/build_variant';

export const SC_COPY_IDS = {
  sched: `${TEST_WORKFLOW_ID_PREFIX}discover-osquery-sched`,
  drop: `${TEST_WORKFLOW_ID_PREFIX}discover-osquery-drop`,
} as const;

/** The production concurrency key of `discover-osquery` (SC-3 and SC-4 share it on purpose). */
export const OSQUERY_CONCURRENCY_KEY = 'software-inventory-discover-osquery';

export const SC1 = {
  every: '1m',
  concurrencyKey: `${TEST_WORKFLOW_ID_PREFIX}discover-osquery-sched`,
  runs: 3,
  /** Enabling schedules a task without `runAt`, so the first run starts within seconds. */
  firstRunWithinMs: 90_000,
  gapMinMs: 45_000,
  gapMaxMs: 90_000,
  timeoutMs: 6 * 60_000,
} as const;

export const SC3 = {
  every: '1m',
  waitDuration: '90s',
  waitMs: 90_000,
  timeoutMs: 5 * 60_000,
} as const;

export const SC4 = {
  holderWaitDuration: '45s',
  otherConcurrencyKey: `${TEST_WORKFLOW_ID_PREFIX}sc4-other-key`,
  holderStartTimeoutMs: 60_000,
} as const;

export const SC6 = {
  waitDuration: '30s',
  stepTimeout: '5s',
  acceptedStepStatuses: ['timed_out', 'failed'],
  acceptedRunStatuses: ['completed', 'failed', 'timed_out'],
} as const;

export const SC9 = {
  workflowId: getWorkflowId('discoverIntegrations'),
  firstRunWithinMs: 120_000,
  taskRemovedWithinMs: 30_000,
} as const;

export const SCHEDULED_TASK_INDEX = '.kibana_task_manager';
export const WORKFLOW_EXECUTIONS_INDEX = '.workflows-executions';
export const WORKFLOWS_INDEX = '.workflows-workflows';

/** Task Manager document of a workflow's scheduled trigger (`workflow_task_scheduler.ts`). */
export const scheduledTaskDocPath = (workflowId: string): string =>
  `/${SCHEDULED_TASK_INDEX}/_doc/${encodeURIComponent(`task:workflow:${workflowId}:scheduled`)}`;

const RUNNER =
  'node x-pack/solutions/security/plugins/software_inventory/scripts/run_discovery_tests.js';
const KBN_HELPERS =
  'Shell helpers: see "Environment and prerequisites" in docs/discovery_test_plan.md (kbn, es, $KBN, $ES, $WF).';

/** SC-7 needs a Kibana restart while a run is in flight; the lead runs it by hand. */
export const SC7_PROCEDURE: readonly string[] = [
  'BLOCKED BY DESIGN: needs a Kibana restart in the middle of a run. Manual procedure:',
  KBN_HELPERS,
  `1. In shell A: ${RUNNER} run DO-16 --verbose (prints the execution id; or test-run the F-bulk-5000 variant with curl).`,
  '2. In shell B, poll: kbn "$KBN/api/workflows/executions/<id>" | jq -c \'.stepExecutions[]|{stepId,status}\' until ingest_linux is "running".',
  '3. Stop Kibana (Ctrl+C in its terminal) and start it again (yarn start); wait for "Kibana is now available".',
  '4. Poll the execution until it is terminal or 10 minutes pass; record the final status: resumed (completed), failed, or stuck "running".',
  '5. Oracle: es "$ES/.kibana-software-inventory-instances/_count" -d \'{"query":{"term":{"host.key":"synth-bulk-01"}}}\' must be 5000 (ids are deterministic: no duplicates).',
  '6. Record duplicate events: es "$ES/.kibana-software-inventory-events/_count" -d \'{"query":{"bool":{"filter":[{"term":{"host.key":"synth-bulk-01"}},{"term":{"type":"first_seen"}}]}}}\' (5000 means none were replayed).',
  '7. Check the dashboard: WH "Currently running" returns to 0. Record the outcome in the results table as SC-7.',
];

/** SC-8 changes a managed workflow's YAML and needs a restart and explicit approval. */
export const SC8_PROCEDURE: readonly string[] = [
  'BLOCKED BY DESIGN: needs explicit approval and a Kibana restart. Manual procedure (discover-integrations, harmless):',
  KBN_HELPERS,
  '1. Record: kbn "$KBN/api/workflows/workflow/$WF-discover-integrations" | jq \'{enabled,definitionHash}\' (expect enabled false).',
  '2. Save the YAML with every "12h" replaced by "1m": kbn "$KBN/api/workflows/workflow/$WF-discover-integrations" | jq -r .yaml | sed \'s/every: "12h"/every: "1m"/\' > /tmp/si-sc8.yaml',
  '3. jq -n --rawfile y /tmp/si-sc8.yaml \'{yaml: $y}\' > /tmp/si-sc8.json; kbn -X PUT "$KBN/api/workflows/managed/workflow/$WF-discover-integrations" -d @/tmp/si-sc8.json',
  '4. Confirm the stored YAML now has every "1m" and enabled is still false (no run must appear: the workflow is disabled).',
  '5. Restart Kibana and wait until it is available.',
  '6. Expect: the stored YAML has every "12h" again (versionStrategy auto re-applies on a definitionHash mismatch), enabled false, definitionHash equal to step 1.',
];
