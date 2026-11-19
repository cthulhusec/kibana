# Software inventory discovery workflows: test plan

This plan tests the six managed software inventory workflows end to end on a live stack. It
runs the production workflow YAML through the real workflow engine, the real custom steps, and
real Elasticsearch writes. Only the external inputs are replaced:

- Osquery results come from fixtures with the exact `osquery.runQuery` output shape.
- Log discovery and exposure scoring read synthetic documents in a dedicated `logs-*` data stream.
- Endpoint discovery reads synthetic Elastic Defend process events in a dedicated
  `logs-endpoint.events.process-*` data stream.
- The Fleet package policy response comes from fixtures (or a real, empty Fleet).
- NVD and CISA KEV responses come from a local stub server.

The plan is executable: each test case lists its setup, trigger, and exact expected outcome. The
harness that automates it does not exist yet; [Harness to build](#harness-to-build) specifies it.

Verified on 2026-11-18 against Elasticsearch `9.7.0-SNAPSHOT` and Kibana at
`http://localhost:5601/tdy`, with the six workflows installed (managed, disabled) in the default
space and the demo seed loaded (65 instances, 31 catalog entries, 38 events, 60 rollups).

## Contents

- [Purpose, scope, and non-goals](#purpose-scope-and-non-goals)
- [Verified engine behavior](#verified-engine-behavior)
- [Environment and prerequisites](#environment-and-prerequisites)
- [Safety](#safety)
- [Observability with the monitoring dashboard](#observability-with-the-monitoring-dashboard)
- [Test data design](#test-data-design) (including [Synthetic Defend events](#synthetic-defend-process-events))
- [Test matrix](#test-matrix)
- [Execution procedure](#execution-procedure)
- [Harness to build](#harness-to-build)
- [Risks and open questions](#risks-and-open-questions)
- [Phased rollout](#phased-rollout)

## Purpose, scope, and non-goals

### Purpose

The jest suites prove the pure logic. This plan proves the parts that only exist when a workflow
runs: engine rendering and step chaining, typed values passed between steps, the custom step
registration and its input validation, Elasticsearch mappings and refresh behavior, the ES|QL
queries against real `logs-*` mappings, the Fleet agent lookup, HTTP retries against a real
socket, the scheduler, concurrency, and what the monitoring dashboard shows for each outcome.

### Scope

The plan covers these workflows (ids prefixed with `system-security-software-inventory-`):

| Workflow | Steps under test | External input and its replacement |
|---|---|---|
| `discover-osquery` | `query_*` (4), `build_*` (4), `ingest_*` (4) | `osquery.runQuery` replaced by `data.set` fixtures |
| `discover-integrations` | `list_package_policies`, `build_candidates`, `ingest` | Fleet response replaced by a `data.set` fixture, or real empty Fleet |
| `discover-logs` | `query_appliances`, `query_services`, `build_candidates`, `ingest` | Synthetic documents in `logs-softwareinventory.synthetic-default` |
| `discover-endpoint` | `query_processes`, `build_candidates`, `ingest` | Synthetic Defend process events in `logs-endpoint.events.process-sisynthetic` |
| `enrich-cves` | `enrich` | NVD and KEV served by a local stub |
| `score-exposure` | `score`, `mark_stale`, `snapshot_rollup` | Synthetic network documents in the same data stream |

### Non-goals

- Re-testing the pure functions that jest already covers (see the next table).
- UI tests. The plan checks API routes and the monitoring dashboard, not the plugin UI.
- Load testing beyond the 5000-candidate per-call limit.
- Real Osquery agents and live NVD in phase 1 (they are phases 3 and 2).

### What the existing unit tests already cover

About 330 jest tests exist. The plan does not repeat them.

| Area | Test files | Already proven |
|---|---|---|
| YAML contract | `kbn-workflows/managed/definitions/software_inventory/software_inventory.test.ts` (9 tests) | Ids, custom step inputs, snapshot gate for each `status`/`truncated`/`error_code` combination, row mapping liquid with blank fields, Fleet one-candidate-per-policy, ES\|QL column mapping, appliance keyed on observer. Rendered with `createWorkflowLiquidEngine`, not the engine |
| Ingest | `ingest_candidates.test.ts` (26), `plan_instance.test.ts` (23), `normalize_candidate.test.ts` (16) | Created/unchanged/patched/late-row outcomes, dedupe, category-scoped removals, events, normalization tables, against `fake_es_client.ts` |
| Enrichment | `enrich_catalog_entries.test.ts` (12), `enrichment_pure.test.ts` (22), `remediation.test.ts` (17) | Retries, failure markers, network-unavailable break, KEV merge, multi-branch remediation, with an injected `fetchFn` |
| Exposure | `score_exposure.test.ts` (4) | Combination of edge and inbound signals, manual evidence kept, policy hosts skipped, against a mocked client |
| Rollup, history | `snapshot_rollup.test.ts` (5), `history_math.test.ts` (36), `history_data_access.test.ts` (6) | Rollup shaping, interval and vulnerable-window math |
| Steps | `register_steps.test.ts` (5) | Row-level validation and the `skipped` count |

Only a live run proves the following:

| Claim | Why jest cannot prove it |
|---|---|
| The engine renders `data.set` output into `steps.<name>.output.*` with the same types the YAML expects (booleans stay booleans, arrays stay arrays) | Jest renders liquid without the engine's context manager |
| A failed `on-failure: continue` step leaves `output` empty and downstream liquid yields `[]` and `snapshot: false` | Requires the engine's failure handling |
| `softwareInventory.*` steps validate input at runtime (for example `candidates` max 5000) and fail the step, not the run | Requires the step registry and zod at execution time |
| ES\|QL over `logs-*` works against logsdb mappings from `ecs@mappings` | Requires real mappings |
| `.fleet-agents` resolution falls back correctly when the index is missing or the agent is unknown | Requires the internal user and real indices |
| `refresh: 'wait_for'` makes a second ingest call see the first call's writes | Requires Elasticsearch |
| NVD retry and timeout behavior over a real socket | `fetchFn` mocks skip sockets and `AbortController` timing |
| Scheduler, concurrency `drop`, restart behavior, and the dashboard signals | Engine and Task Manager only |

## Verified engine behavior

Every statement below comes from a read-only probe or a throwaway workflow run on the live stack,
unless marked **code-read**. The probe workflows were named `zz-probe-*` and are deleted.

### Running workflows on demand

| Question | Answer | Evidence |
|---|---|---|
| Run a saved workflow | `POST /api/workflows/workflow/{id}/run` with body `{"inputs":{}}` | `run_workflow.ts` |
| Run a disabled workflow with `/run` | No. Returns `400 "Workflow is disabled. Enable it to run it."` for any disabled workflow, managed or not | Probe on `zz-probe-concurrency`; the check is `if (!workflow.enabled)` in the route, so managed workflows get the same 400 |
| Test-run without saving | `POST /api/workflows/test` with `{"workflowYaml": "...", "inputs": {}}`. Runs disabled or unsaved YAML | Probe: status `completed`, `workflowId: "internal-test-workflow"`, `isTestRun: true`, `isEphemeral: true` |
| Test-run a saved workflow as stored | `{"workflowId": "<id>", "inputs": {}}` | Probe: execution keeps `workflowId: <id>`, `isTestRun: true`, `isEphemeral: false`, ran while disabled |
| Test-run modified YAML for a saved id | `{"workflowId": "<id>", "workflowYaml": "...", "inputs": {}}`; needs `edit` access | Probe: execution attributed to `<id>`, `isEphemeral: true`, only the override steps ran |
| Effect of `isTestRun` | The execution and step documents are written to `.workflows-executions` and `.workflows-step-executions` like any run, with `isTestRun: true`. The enabled check is skipped, and failed-execution events and identity-failure events are not emitted. The run holds the concurrency slot of its YAML's `settings.concurrency.key` | Probe docs; **code-read** `plugin.ts` `ensureWorkflowEnabled`, `emit_workflow_execution_failed_event.ts`, `workflows_management_api.ts` `testWorkflow` |
| Poll status | `GET /api/workflows/executions/{executionId}`. Terminal statuses: `completed`, `failed`, `cancelled`, `timed_out`, `skipped` | Probe; `ExecutionStatus` in `kbn-workflows/types/v1.ts` |
| Per-step status | Same response, `stepExecutions[].{id, stepId, stepType, status, error}`. `output` is `null` in this response | Probe |
| Per-step output | `GET /api/workflows/executions/{executionId}/step/{stepExecutionId}` returns `output` and `input` | Probe |
| List a workflow's runs | `GET /api/workflows/workflow/{id}/executions` (includes test runs) | Probe |
| List managed workflows | `GET /api/workflows?size=100&managed=managed`. The default filter hides managed workflows | Probe: default list returned 0 of the 5, `managed=managed` returned all 5 |
| Change only `enabled` of a managed workflow | `PUT /api/workflows/workflow/{id}` with `{"enabled": true}` (enablement-only updates are allowed) | **code-read** `updateWorkflow`, `isEnablementOnlyUpdate` |
| Change a managed workflow's YAML (for example `every`) | `PUT /api/workflows/managed/workflow/{id}` (elevated). The next Kibana start reinstalls the registered YAML because `versionStrategy: auto` re-applies on a `definitionHash` mismatch; `enablement: restorable` keeps the enabled state | **code-read** `update_workflow.ts`, `MANAGED_WORKFLOWS.md` |
| Delete a throwaway workflow | `DELETE /api/workflows/workflow/{id}` soft-deletes (a tombstone with `deleted_at` stays). Add `?force=true` to hard-delete; that also removed the workflow's execution documents | Probe |
| Internal plugin routes | Need `elastic-api-version: 1` and `x-elastic-internal-origin: kibana`; without the origin header the timeline route returns 400 | Probe on `/internal/software_inventory/hosts/web-prod-01/timeline` |

### Mocking Osquery with `data.set`

The production `osquery.runQuery` output contract (`osquery/common/workflows/contract/schemas.ts`
and `run_query_common.ts`) is:

```ts
{
  status: 'success' | 'partial' | 'failed' | 'timed_out';
  agents: { total: number; responded: number; pending: number; failed: number };
  rows: Array<{
    agent: { id: string; name?: string };      // name omitted when the result doc has none
    '@timestamp'?: string;
    columns: Record<string, string>;           // every value is a string (build_rows.ts String())
    ecs: Record<string, unknown>;
  }>;
  row_count: number;
  truncated: boolean;
  error_code?: 'DISPATCH_UNCONFIRMED' | 'ACTION_NOT_VISIBLE' | 'STATUS_UNREADABLE_FORBIDDEN' | 'RESULTS_UNREADABLE';
  action_id?: string;
}
```

A `data.set` step's output is exactly its rendered `with` object (`data_set_step_impl.ts`). The
probe replaced the four query steps with `data.set` fixtures in that shape and kept the
production `build_*` steps and `snapshot` expressions verbatim (copied programmatically from
`discover_osquery.yaml`). Observed results:

| Fixture | `build_*` output | `snapshot` | Notes |
|---|---|---|---|
| `status: success`, `truncated: false`, 5 rows: 1 valid, 1 blank `columns.name`, 1 blank `agent.id`, 1 without `version`, 1 with `"` and `\` in the name and empty `version` | 3 candidates; blank-name and blank-agent rows dropped; empty `version` and `install_path` omitted; `"host_name"` omitted when `agent.name` is absent; quotes and backslashes escaped | `true` | `truncated` arrived as boolean `false`, `rows[0].agent.id` addressable |
| `status: failed`, `error_code: DISPATCH_UNCONFIRMED`, `rows: []` | `[]` | `false` | |
| Step replaced by a failing `elasticsearch.request` (`GET /zz-probe-missing-index/_doc/1`) with `on-failure: continue` | `[]` | `false` | Step `failed`, `output: null`, run `completed` |
| `status: success`, `truncated: true` | `[]` | `false` | |
| Liquid generator: `{% for i in (1..5001) %}` building JSON, parsed with `${{ ... \| json_parse }}` into `rows` | 5001 rows, `rows \| size` = 5001 | | 0.8 s to render; the whole run took 3 s |

Liquid detail (**code-read**, `liquidjs` 10.28.0 `BlankDrop`): `blank` matches `null`, `undefined`,
`false`, and whitespace-only strings. A whitespace-only name is therefore dropped by the YAML
before ingest and never counted in `skipped`.

Conclusion: a test variant that swaps only the four `osquery.runQuery` steps for `data.set`
fixtures exercises every downstream step exactly as production does.

### ES|QL and Fleet step shapes

| Probe | Result |
|---|---|
| `elasticsearch.esql.query` with `format: json` (`ROW ...`) | `output.columns[] = {name, type}` and `output.values[][]` (row arrays); ES\|QL `null` is `blank` in liquid |
| `FROM logs-* \| WHERE observer.product IS NOT NULL` on this stack (no `logs-*` data) | Step fails: `verification_exception: Unknown column [observer.product]` |
| `kibana.request GET /api/fleet/package_policies?perPage=1000&page=1` | `output` is the response body: `{"items":[],"total":0,"page":1,"perPage":1000}` |

### Stack state that shapes the plan

| Probe | Result | Consequence |
|---|---|---|
| Fleet package policies, agent policies, agents | All 0; installed packages: `endpoint`, `security_ai_prompts`, `security_detection_engine`, `synthetics` | `osquery_manager` is not installed; real Osquery cannot run (phase 3). Real `discover-integrations` returns 0 candidates |
| `.fleet-agents` | Does not exist; `elastic` has no `write` on it even with `allow_restricted_indices` | The "agent found" resolution path cannot be faked; phase 1 tests the fallback, phase 3 the real path |
| Osquery saved queries | All four `software_inventory_*` saved queries exist | Ready for phase 3 |
| `logs-*` | No data streams; the `logs` template (`logs-*-*`, priority 100, `logsdb`, composed of `logs@mappings`, `logs@settings`, `logs@custom`, `ecs@mappings`) applies to `logs-softwareinventory.synthetic-default` (`_simulate_index`) | `*.ip` maps to `ip`, strings to `keyword`; fields exist only after a document carries them |
| Write privileges (`_has_privileges`) | `elastic` can write `logs-softwareinventory.synthetic-default` and `.kibana-software-inventory-*` | Harness writes are possible (they need your approval, see [Safety](#safety)) |
| Demo instances | 65 instances; exposure `none` 56, `medium` 3, `high` 6; 9 have `inbound_public_ip` evidence and 4 `edge_device_role`; 0 are eligible for stale | `score-exposure` will rewrite demo exposure (no logs back the seeded evidence) |
| Demo catalog | 31 entries, 2 never checked (`djangoproject:django:4.2.16`, `notepad-plus-plus:notepad++:8.6.2`) | `enrich-cves` will touch those 2 demo entries first |
| Concurrency `drop`, `max: 1` | The second overlapping run gets status `skipped`, has `createdAt` but no `startedAt`; the first ran 24 s and completed | Probe `zz-probe-concurrency` with a 20 s `wait` step |

### Execution document fields for observability

Verified against the live mappings and documents:

| Index | Mapped fields used by the plan | Not mapped (`dynamic: false`) |
|---|---|---|
| `.workflows-executions` | `workflowId`, `status`, `isTestRun`, `managed`, `managedBy`, `triggeredBy` (`manual`, `scheduled`), `concurrencyGroupKey`, `createdAt`, `startedAt`, `finishedAt`, `duration`, `spaceId` | `isEphemeral`, `workflowDefinition` (object, `enabled: false`), `context`, `yaml` |
| `.workflows-step-executions` | `workflowRunId`, `workflowId`, `stepId`, `stepType`, `status`, `isTestRun`, `startedAt`, `finishedAt`, `spaceId` | `output`, `input`, `error`, `executionTimeMs`. `duration` is mapped but **not populated** (value count 0 across 15 probe step docs) |

Step status values seen: `completed`, `failed`. A step that fails under `on-failure: continue`
is `failed` while its run is `completed`.

## Environment and prerequisites

| Item | Value |
|---|---|
| Elasticsearch | `http://localhost:9200`, `elastic` / `changeme` |
| Kibana | `http://localhost:5601/tdy` (base path `/tdy`), default space |
| Node | `source ~/.nvm/nvm.sh && nvm use 24.22.3` |
| Plugin flag | `xpack.softwareInventory.enabled: true` in `config/kibana.dev.yml` (present) |
| Managed workflows | The six workflows installed in `default`, all disabled. Check: `GET /api/workflows?size=100&managed=managed` |
| Osquery saved queries | Installed by `node x-pack/solutions/security/plugins/software_inventory/scripts/install_osquery_saved_queries.js` (present; needed only for phase 3) |
| Demo seed | Loaded by `node x-pack/solutions/security/plugins/software_inventory/scripts/seed_demo_data.js` |
| Monitoring dashboard | `node x-pack/solutions/security/plugins/software_inventory/scripts/install_monitoring_dashboard.js --kibana-url=http://localhost:5601/tdy` (dashboard id `software-inventory-discovery-monitoring`) |
| NVD/KEV URL override | Required for `enrich-cves` tests; see [Minimal code change for the NVD stub](#minimal-code-change-for-the-nvd-stub). Kibana restarts once after the change |

Shell helpers used in the runbook:

```bash
export KBN=http://localhost:5601/tdy ES=http://localhost:9200 AUTH=elastic:changeme
kbn() { curl -sS -u "$AUTH" -H 'kbn-xsrf: t' -H 'elastic-api-version: 2023-10-31' \
  -H 'content-type: application/json' "$@"; }
kbi() { curl -sS -u "$AUTH" -H 'elastic-api-version: 1' -H 'x-elastic-internal-origin: kibana' "$@"; }
es()  { curl -sS -u "$AUTH" -H 'content-type: application/json' "$@"; }
WF=system-security-software-inventory
```

Pass the URL last, after any `-X`/`-d` flags (`kbn -X POST "$KBN/api/..." -d @body.json`).

## Safety

### What each workflow touches

| Workflow | Scope of writes | Demo data impact |
|---|---|---|
| `discover-osquery`, `discover-logs`, `discover-integrations` | Instances and events of the hosts in the candidates; catalog entries created only when missing | None, if every synthetic host key and catalog id is new (the preflight checks this) |
| `enrich-cves` | The `limit` catalog entries with the oldest `cve_checked_at`, missing first, regardless of host | Touches demo entries: the 2 never-checked demo entries tie with synthetic ones; any leftover `limit` reaches the oldest-checked demo entries |
| `score-exposure` `score` | `exposure` of **every** non-removed instance | Rewrites demo exposure. The 9 demo instances with seeded `inbound_public_ip` evidence lose it (no logs back it); `edge_device_role` and `manual` evidence stay |
| `score-exposure` `mark_stale` | Every `active`/`patched` instance with `last_seen` older than 30 days | None today (0 eligible); the preflight records the count |
| `score-exposure` `snapshot_rollup` | Overwrites rollup `_id` = today (UTC) | Replaces the seeded rollup for today |

Host-prefix isolation therefore protects demo data only for the three discovery workflows. For
`enrich-cves` and `score-exposure`, the harness backs up and restores the four plugin indices.

### Isolation conventions

- Every synthetic host key starts with `synth-` or `policy:synth-`, with one deliberate exception:
  the IP-keyed appliance `192.0.2.77` (TEST-NET-1).
- Every synthetic product name or version is absent from the demo catalog (the expected-results
  tables list the exact catalog ids; the preflight fails if any already exists).
- Synthetic logs live only in `logs-softwareinventory.synthetic-default`.
- Workflow test runs carry `isTestRun: true`.
- Throwaway saved workflows use the id prefix `si-test-`; never `system-` (reserved for managed ids).

### Writes that need your approval

The plan performs these writes; none of them ran during planning:

1. Back up and restore the four `.kibana-software-inventory-*` indices (harness, NDJSON in the
   scratchpad).
2. Create index template `logs-softwareinventory.synthetic` and data stream
   `logs-softwareinventory.synthetic-default`; delete both at the end.
3. Execute the six workflows (test variants and, for some cases, the production YAML) and,
   for scheduling tests, enable copies of them.
4. Edit three synthetic instance documents directly (`last_seen` for stale, `exposure.evidence`
   for manual evidence).
5. Phase 1b only: create Fleet agent policies and package policies.
6. Phase 3 only: install `osquery_manager` and enroll an Elastic Agent.

### Order of operations

1. Preflight checks and backup (always first).
2. Discovery tests (host-scoped, no demo impact).
3. Enrichment and exposure tests (demo impact, restored afterward).
4. Scheduling tests (copies only; managed workflows stay disabled).
5. Cleanup, restore, regression checks (always last, also after a failed run).

### Reset and cleanup commands

```bash
# Synthetic inventory documents (instances, events) by host key.
for idx in instances events; do
  es -X POST "$ES/.kibana-software-inventory-$idx/_delete_by_query?refresh=true&conflicts=proceed" -d '{
    "query": {"bool": {"should": [
      {"prefix": {"host.key": "synth-"}},
      {"prefix": {"host.key": "policy:synth-"}},
      {"term": {"host.key": "192.0.2.77"}}]}}}'
done
# Synthetic catalog entries: every id not in the pre-test backup (harness: cleanup.ts).
# Synthetic logs.
es -X DELETE "$ES/_data_stream/logs-softwareinventory.synthetic-default"
es -X DELETE "$ES/_index_template/logs-softwareinventory.synthetic"
# Throwaway workflows (hard delete also removes their executions).
kbn -X DELETE "$KBN/api/workflows/workflow/si-test-discover-osquery-sched?force=true"
# Exact demo restore (harness), or regenerate the demo relative to now:
node x-pack/solutions/security/plugins/software_inventory/scripts/seed_demo_data.js --clean
```

`seed_demo_data.js --clean` recreates all four indices with fresh relative timestamps; use the
harness restore when you need byte-identical demo documents.

## Observability with the monitoring dashboard

The monitoring dashboard (`scripts/monitoring_dashboard/`, installed by
`scripts/install_monitoring_dashboard.js`) is the observability tool for every case. Its runs
and steps filter on `workflowId LIKE "system-security-software-inventory-*"`. Panel names below
match the dashboard as of 2026-11-18 and may shift while it is being built.

| Section | Panel | Source |
|---|---|---|
| Workflow health | Runs, Failed runs, Success rate, Currently running, Average duration, Runs over time by status, Per-workflow summary | `.workflows-executions` |
| Step level | Step runs (failing first), Average duration by step | `.workflows-step-executions` |
| Recent failures | Last 25 failed or timed-out runs | `.workflows-executions` |
| Discovery output | Events per day by type, Instances by status, Instances by discovery source, Freshness by source, Freshness by status, Catalog entries, CVE checked, Never checked, CVE check failed | Plugin indices |
| Inventory trend | Vulnerable, exposed and known exploited instances per day | `.kibana-software-inventory-rollups` |

To make test runs visible on the dashboard, run each variant with
`{"workflowId": "<managed id>", "workflowYaml": "<variant>"}`. Runs with only `workflowYaml` are
attributed to `internal-test-workflow` and stay invisible. If the managed-id form is refused
(open question 1), the fallback is a saved copy with id `si-test-<name>` and an extra
`OR workflowId LIKE "si-test-*"` filter in the dashboard.

Gaps found while verifying, to pass to the dashboard owner:

| Gap | Effect | Suggested fix |
|---|---|---|
| Step documents have no `duration` (the engine writes unmapped `executionTimeMs`) | Average duration by step is empty; the step table's duration column is null | Compute `DATE_DIFF("ms", startedAt, finishedAt)` in ES\|QL |
| Skipped runs (concurrency `drop`) have no `startedAt` | They are filtered out by `startedAt >= ?_tstart`, so dropped runs never show | Filter on `createdAt`, and add a `skipped` count |
| No `isTestRun` split | Test runs and real runs mix | Add an `isTestRun` breakdown or control |
| Step `output` is unmapped | Per-run `created`/`patched`/`removed` counts cannot be charted | Use the events index (already used) or the plugin logs |
| A step failing under `on-failure: continue` leaves the run `completed` | Failed runs and Success rate do not move for query or ingest failures in `discover-osquery` | Rely on Step runs (failing first) for those cases |

## Test data design

### Identity reference

Fixtures and expected tables use these values. All were computed with the real
`normalizeCandidate`, `buildCpe`, and `parseNvdResponse` on 2026-11-18.

| Host key | Source | Reported identity |
|---|---|---|
| `synth-lin-01` | Osquery agent `synth-agent-lin01`, name `synth-lin-01`; logs `host.name` `synth-lin-01`, `host.id` `synth-hostid-lin01` | Linux, shared with logs |
| `synth-lin-02` | Osquery agent `synth-agent-lin02`, name `synth-lin-02` | Linux |
| `synth-agent-lin03` | Osquery agent `synth-agent-lin03`, no `agent.name` | Linux, key falls back to the agent id |
| `synth-win-01` | Osquery agent `synth-agent-win01`, name `SYNTH-WIN-01` | Windows, key lower-cased |
| `synth-mac-01` | Osquery agent `synth-agent-mac01`, name `synth-mac-01` | macOS |
| `synth-bulk-01` | Osquery agent `synth-agent-bulk`, name `synth-bulk-01` | Limit tests only |
| `synth-fw-01`, `synth-fw-02` | Logs `observer.hostname`, collected by `synth-collector-01` | Appliances |
| `synth-sn-0003` | Logs `observer.serial_number` `SYNTH-SN-0003` | Appliance without hostname |
| `192.0.2.77` | Logs `observer.ip` only | Appliance without hostname or serial |
| `synth-edge-09` | Logs `observer.hostname` | Unknown appliance vendor |
| `synth-web-01`, `synth-web-02` | Logs `host.name` | Services |
| `synth-hostid-0005` | Logs `host.id` only | Service without host name |
| `policy:synth-pol-edge`, `policy:synth-pol-web` | Fleet package policies | Policy pseudo-hosts |

### Osquery fixtures

Fixtures are TypeScript objects typed as the `osquery.runQuery` output, one per query step and
scenario. The variant builder (see [Harness to build](#harness-to-build)) injects them into the
production YAML. Every row uses `"@timestamp"` and `"ecs": {}` like real rows, and every
`columns` value is a string.

Run `R1` (baseline, all four queries `status: success`, `truncated: false`):

| Step | Agent (`agent.name`) | `columns.name` | `columns.version` | `install_path` | Normalized catalog id | Outcome |
|---|---|---|---|---|---|---|
| `query_linux` | lin01 (`synth-lin-01`) | `openssl` | `3.0.7-1ubuntu1` | `""` | `openssl:openssl:3.0.7` | created |
| | lin01 | `openssl` (duplicate row) | `3.0.7-1ubuntu1` | `""` | same | deduped |
| | lin01 | `sudo` | `1.9.9-1ubuntu2.4` | `""` | `sudo_project:sudo:1.9.9` | created |
| | lin01 | `bash` | `5.1-6ubuntu1.1` | `""` | `gnu:bash:5.1` | created |
| | lin01 | `nginx` | `1.18.0-6ubuntu14.4` | `""` | `f5:nginx:1.18.0` | created |
| | lin01 | `synth-tool` | `2.0.0` | `""` | `synth-tool:synth-tool:2.0.0` | created |
| | lin02 (`synth-lin-02`) | `""` | `1.0` | `""` | | dropped by YAML |
| | lin02 | `"   "` | `1.0` | `""` | | dropped by YAML (`blank`) |
| | `""` (`synth-lin-x`) | `bash` | `5.1` | `""` | | dropped by YAML (blank agent id) |
| | lin03 (no name) | `curl` | `7.88.1-10+deb12u5` | `""` | `haxx:curl:7.88.1` | created, key `synth-agent-lin03` |
| `query_windows` | win01 (`SYNTH-WIN-01`) | `Google Chrome` | `131.0.6778.86` | `C:\Program Files\Google\Chrome\Application` | `google:chrome:131.0.6778.86` | created |
| | win01 | `7-Zip 23.01 (x64)` | `23.01` | `C:\Program Files\7-Zip` | `7-zip:7-zip:23.01` | created |
| | win01 | `(x64)` | `1.0` | `C:\x` | | skipped by ingest |
| `query_macos` | mac01 (`synth-mac-01`) | `Slack` | `4.41.105` | `/Applications/Slack.app` | `slack:slack:4.41.105` | created |
| | mac01 | `Code` | `1.95.3` | `/Applications/Visual Studio Code.app` | `microsoft:visual_studio_code:1.95.3` | created |
| `query_dependencies` | lin01 | `log4j-core` | `2.14.1` | `/opt/app/lib/log4j-core-2.14.1.jar` | `apache:log4j:2.14.1` | created |
| | lin02 | `log4j-core` | `2.12.1` | `/srv/legacy/lib/log4j-core-2.12.1.jar` | `apache:log4j:2.12.1` | created |
| | mac01 | `requests` | `2.31.0` | `/usr/local/lib/python3.12/site-packages` | `requests:requests:2.31.0` | created |

Expected `R1` step outputs: `ingest_linux` `{created: 6, unchanged: 0, patched: 0, removed: 0, skipped: 0}`,
`ingest_windows` `{created: 2, skipped: 1}`, `ingest_macos` `{created: 2}`,
`ingest_dependencies` `{created: 3}` (all omitted fields are 0). New events: 13 `first_seen`.

Failure-injection fixtures (replace one step's fixture; others as in the case):

| Fixture id | Shape | Expected `snapshot` |
|---|---|---|
| `F-trunc` | `status: success`, `truncated: true`, `row_count: 9000`, rows as given | `false` |
| `F-failed` | `status: failed`, `error_code: DISPATCH_UNCONFIRMED`, `rows: []`, `agents.pending = total` | `false` |
| `F-partial` | `status: partial`, `agents.failed: 1`, rows of responding agents | `false` |
| `F-timedout` | `status: timed_out`, rows received before the deadline | `false` |
| `F-unreadable` | `status: success`, `error_code: RESULTS_UNREADABLE`, `truncated: false` | `false` |
| `F-empty` | `status: success`, `truncated: false`, `rows: []` | `true`, but no host reported, so nothing is removed |
| `F-throw` | Step type swapped to `elasticsearch.request` `GET /zz-si-test-missing/_doc/1` with `on-failure: continue` | `false`, `output: null` |
| `F-bulk-5000` | Liquid generator: 5000 rows `synth-pkg-<i>` / `1.0.<i>` for `synth-agent-bulk`, `truncated: true` | `false` |
| `F-bulk-5001` | Same generator with 5001 rows, `truncated: false` | `true` (ingest still fails validation) |

### Synthetic event data for logs

#### Data stream and mappings

Use data stream `logs-softwareinventory.synthetic-default`. It matches `FROM logs-*` and the
`logs-*-*` template family, cannot collide with integration data streams, and is deleted in
one call. Create a dedicated template with a higher priority so that every field the queries
read is mapped even when no document carries it (ES\|QL fails with `Unknown column` otherwise):

```json
PUT _index_template/logs-softwareinventory.synthetic
{
  "index_patterns": ["logs-softwareinventory.synthetic-*"],
  "priority": 200,
  "data_stream": {},
  "composed_of": ["logs@mappings", "logs@settings", "ecs@mappings"],
  "template": {
    "mappings": {
      "properties": {
        "host":     {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
        "observer": {"properties": {
          "hostname": {"type": "keyword"}, "serial_number": {"type": "keyword"},
          "ip": {"type": "ip"}, "vendor": {"type": "keyword"},
          "product": {"type": "keyword"}, "version": {"type": "keyword"}}},
        "service":  {"properties": {"name": {"type": "keyword"}, "version": {"type": "keyword"}}},
        "source":   {"properties": {"ip": {"type": "ip"}}},
        "network":  {"properties": {"direction": {"type": "keyword"}}},
        "event":    {"properties": {"dataset": {"type": "keyword"}}}
      }
    }
  }
}
```

Verify before writing anything with
`POST _index_template/_simulate_index/logs-softwareinventory.synthetic-default` (read-only): the
result must name `logs-softwareinventory.synthetic` and keep `index.mode: logsdb`.

Fields read by the workflows (copied from the YAML and `score_exposure.ts`):

| Consumer | Fields |
|---|---|
| `query_appliances` | `@timestamp`, `observer.product`, `observer.version`, `observer.hostname`, `observer.serial_number`, `observer.ip`, `observer.vendor` |
| `query_services` | `@timestamp`, `service.name`, `service.version`, `host.id`, `host.name` |
| `score` (search API, not ES\|QL) | `@timestamp` (`now-7d`), `source.ip`, `host.name`, `host.id`, `network.direction` (`inbound`, `ingress`) |

#### Generator specification

`generate_logs.ts` writes documents with `@timestamp = T0 - offset`, where `T0` is the
generation time passed on the command line, and `event.dataset: softwareinventory.synthetic`.
Output is deterministic for a given `T0`. Run each workflow within 60 minutes of generating, so
the 24 h and 7 d windows keep a 1 h margin. Phase A is written before the first
`discover-logs` run; phase B before the second.

| Doc id | Phase | Offset | Fields | Purpose |
|---|---|---|---|---|
| `A1` (x10) | A | 2 h…30 m | `host.name: synth-collector-01`, `observer.hostname: synth-fw-01`, `observer.vendor: Fortinet`, `observer.product: FortiGate`, `observer.version: 7.2.4` | Collector vs appliance; 10 duplicates collapse to 1 row (`observed_at` = T0-30m) |
| `A2` | A | 1 h | `host.name: synth-collector-01`, `observer.hostname: synth-fw-02`, `observer.vendor: Palo Alto Networks`, `observer.product: PAN-OS`, `observer.version: 10.2.3` | Second appliance behind the same collector |
| `A3` | A | 3 h | `observer.serial_number: SYNTH-SN-0003`, `observer.vendor: Cisco`, `observer.product: ASA`, `observer.version: 9.16.4` | Serial fallback, no `host_name` |
| `A4` | A | 4 h | `observer.ip: 192.0.2.77`, `observer.vendor: F5`, `observer.product: BIG-IP`, `observer.version: 16.1.4` | IP fallback |
| `A5` | A | 5 h | `observer.hostname: synth-edge-09`, `observer.vendor: SynthNet`, `observer.product: EdgeBox`, `observer.version: 3.1` | Unmapped observer vendor |
| `A6` | A | 1 h | `observer.hostname: synth-fw-04`, `observer.product: FortiGate`, no version | Excluded (`observer.version IS NOT NULL`) |
| `A7` | A | 26 h | `observer.hostname: synth-fw-03`, Fortinet FortiGate `7.2.4` | Excluded (outside 24 h) |
| `A8` | A | 23 h | `observer.hostname: synth-fw-05`, Fortinet FortiGate `7.0.11` | Included (inside 24 h) |
| `S1` | A | 2 h | `host.name: synth-lin-01`, `host.id: synth-hostid-lin01`, `service.name: nginx`, `service.version: 1.18.0` | Same instance as the Osquery `nginx` row |
| `S2` | A | 3 h | `host.name: synth-web-01`, no `host.id`, `service.name: synth-checkout`, `service.version: 2.4.0` | `host_id` falls back to the host name |
| `S2b` | A | 1 h | `host.name: SYNTH-Web-01`, `service.name: synth-checkout`, `service.version: 2.4.0` | Second ES\|QL row, same instance key: dedupe |
| `S3a` | A | 20 h | `host.name: synth-web-02`, `service.name: nginx`, `service.version: 1.25.2` | Version flip, before |
| `S3b` | B | 1 h | `host.name: synth-web-02`, `service.name: nginx`, `service.version: 1.27.4` | Version flip, after |
| `S4` | A | 2 h | `host.id: synth-hostid-0005`, no `host.name`, `service.name: redis`, `service.version: 7.0.11` | Key on host id |
| `S5` | A | 2 h | `host.name: synth-web-03`, `service.name: synth-api`, no version | Excluded |
| `X1` (x6) | A | 1 d | `host.name: synth-web-01`, `network.direction: inbound`, `source.ip` in {`8.8.8.8`, `1.1.1.1`, `9.9.9.9`} (2 each) | 3 distinct public sources |
| `X2` | A | 1 d | `host.name: synth-web-01`, `inbound`, `source.ip` `10.1.2.3`, `192.168.1.10` | Private, ignored |
| `X3` | A | 1 d | `host.name: synth-lin-01`, `network.direction: outbound`, `source.ip: 8.8.4.4` | Outbound, ignored |
| `X4` (x6) | A | 2 d | `host.name: synth-fw-02`, `inbound`, 6 distinct public `source.ip` | Edge plus inbound |
| `X5` | A | 1 d | `host.name: synth-web-02`, no direction, `source.ip: 1.0.0.1` | No direction, ignored |
| `X6` | A | 1 d | `host.id: synth-hostid-0005`, `network.direction: ingress`, `source.ip: 208.67.222.222` | Matched by host id, `ingress` |
| `X7` | A | 8 d | `host.name: synth-web-01`, `inbound`, `source.ip: 5.5.5.5` | Outside 7 d |
| `X8` | A | 1 d | `host.name: policy:synth-pol-edge`, `inbound`, `source.ip: 8.8.8.8` | Policy pseudo-hosts ignore logs |

Expected `discover-logs` candidates for the phase A run (`ingest` step):

| Category | `host_id` | `host_name` | Catalog id | Outcome |
|---|---|---|---|---|
| `appliance` | `synth-fw-01` | `synth-fw-01` | `fortinet:fortios:7.2.4` | created |
| `appliance` | `synth-fw-02` | `synth-fw-02` | `palo_alto_networks:pan-os:10.2.3` | created |
| `appliance` | `SYNTH-SN-0003` | (none) | `cisco:adaptive_security_appliance_software:9.16.4` | created, key `synth-sn-0003` |
| `appliance` | `192.0.2.77` | (none) | `f5:big-ip:16.1.4` | created, key `192.0.2.77` |
| `appliance` | `synth-edge-09` | `synth-edge-09` | `synthnet:edgebox:3.1` | created |
| `appliance` | `synth-fw-05` | `synth-fw-05` | `fortinet:fortios:7.0.11` | created |
| `application` | `synth-hostid-lin01` | `synth-lin-01` | `f5:nginx:1.18.0` | unchanged if `R1` ran first (sources become `[osquery, logs]`), else created |
| `application` | `synth-web-01` | `synth-web-01` and `SYNTH-Web-01` (2 rows) | `synth-checkout:synth-checkout:2.4.0` | created once |
| `application` | `synth-web-02` | `synth-web-02` | `f5:nginx:1.25.2` | created |
| `application` | `synth-hostid-0005` | (none) | `redis:redis:7.0.11` | created, key `synth-hostid-0005` |

Expected `ingest` output after `R1`: `{created: 9, unchanged: 1, patched: 0, removed: 0, skipped: 0}`.
No candidate exists for `synth-collector-01`, `synth-fw-03`, `synth-fw-04`, or `synth-web-03`.

### Synthetic Defend process events

`discover-endpoint` reads `logs-endpoint.events.process-*`. The harness writes to the data stream
`logs-endpoint.events.process-sisynthetic` (namespace `sisynthetic`) with `create` and fixed document ids,
so writing a phase twice for the same T0 is a no-op.

When the Endpoint package template (`logs-endpoint.events.process`) is installed, the data stream uses
its real mappings. Otherwise the harness installs the template `logs-softwareinventory.endpoint-synthetic`
(priority 300) that maps only the fields the workflow reads. The `cleanup` command always deletes the
data stream and deletes only the template the harness installed, never the Endpoint package template.

Every host name starts with `synth-win-`, and every timestamp is `T0 - offset`. Run each workflow within
55 minutes of T0.

| Doc id | Host | Offset | Fields | Result |
|---|---|---|---|---|
| E1-01..03 | `synth-win-01` (id and name) | 3 h, 2 h, 1 h | Mozilla Corporation, Firefox, 124.0.1 | One row, `observed_at` T0-1h |
| E2 | `synth-win-02` | 2 h | No company; code signature `Synth-Signer Inc`; Synth-Signed 1.0 | Vendor from the signature |
| E3 | `synth-win-03` (name only) | 3 h | Synth-Viewer Corp, Synth-Viewer 2.1 | `host_id` falls back to the host name |
| E4-SVC, E4-NOTEPAD | `synth-win-04` | 2 h | Microsoft Windows Operating System under `C:\Windows\` and `c:\WINDOWS\` | Excluded |
| E4-NOEXE | `synth-win-04` | 90 min | No `process.executable`; Synth-NoExe 1.5 | Kept |
| E5 | `synth-win-05` | 2 h | Product without a file version | Excluded |
| E6 | `synth-win-06` | 26 h | Synth-Old 2.0 | Outside the window |
| E7-1, E7-2 | `synth-win-07` | 5 h, 2 h | Synth-Dual 3.0 and 3.1 | Two rows, one instance (3.1) |
| E8 | `synth-win-08` | 90 min | Synth-Both 5.0 | Merged with Osquery in DE-6 |
| E9 (phase B) | `synth-win-01` | 30 min | Firefox 125.0.1 | The patch |

Phase A yields seven ES|QL rows and six instances. Phase B adds one row for the same six instances.

### Fleet fixtures

`discover-integrations` reads `steps.list_package_policies.output.items`. The variant replaces
that step with a `data.set` whose `with` is the Fleet response body:

| Package policy | `package.name` / `version` | `policy_ids` | Candidates | Expected |
|---|---|---|---|---|
| `pp-1` | `panw` / `5.3.0` | `[synth-pol-edge]` | 1 | created `palo_alto_networks:pan-os:unknown` on `policy:synth-pol-edge`, category `appliance` |
| `pp-2` | `nginx` / `1.20.0` | `[synth-pol-web, synth-pol-edge]` | 2 | created `f5:nginx:unknown` on both policy hosts |
| `pp-3` | `system` / `1.60.0` | `[synth-pol-web]` | 1 | skipped (unmapped) |
| `pp-4` | `osquery_manager` / `1.14.0` | `[synth-pol-web]` | 1 | skipped (unmapped) |
| `pp-5` | `""` / `1.0.0` | `[synth-pol-web]` | 0 | dropped by YAML |
| `pp-6` | `fortinet_fortigate` / `""` | `[]` | 0 | no agent policy, no candidate |

Expected `ingest`: `{created: 3, skipped: 2}`. Every instance has `host.id` = `host.key` =
`policy:<id>` and `host.name` = `<id>`.

### NVD and KEV stub

The stub answers `GET /rest/json/cves/2.0?cpeName=<cpe>&noRejected` and
`GET /kev.json`. It returns CVEs only for CPEs that NVD would match: a CVE returned for a version
outside all of its ranges is reported as unfixed by the parser (verified with `log4j` `2.17.1`),
so a careless fixture produces false findings.

| CPE (`cpeName`) | Behavior | Expected catalog update |
|---|---|---|
| `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*` | 200, CVE-2021-44228 (10.0), -45046 (9.0), -45105 (5.9), -44832 (6.6), three branch ranges each | `cve_count: 4`, `max_cvss: 10`, `fixed_in: 2.17.1`, `latest_known_fix: 2.17.1`, `fully_remediated: true`, `unfixed_cve_ids: []`, `known_exploited: true`, per-CVE `fixed_in` CVE-2021-44228 2.15.0, CVE-2021-45046 2.16.0, CVE-2021-45105 2.17.0, CVE-2021-44832 2.17.1 |
| `cpe:2.3:a:apache:log4j:2.12.1:...` | 200, same four CVEs | `fixed_in: 2.12.4` (branch fix), `latest_known_fix: 2.17.1`, `fully_remediated: true` |
| `cpe:2.3:a:synth-checkout:synth-checkout:2.4.0:...` | 200, CVE-2099-0001 (7.5), `versionStartIncluding: 2.0.0` only | `cve_count: 1`, `fixed_in: null`, `fully_remediated: false`, `unfixed_cve_ids: [CVE-2099-0001]` |
| `cpe:2.3:o:fortinet:fortios:7.2.4:...` | 200, CVE-2023-27997 (9.8), ranges [7.2.0, 7.2.5) and [7.0.0, 7.0.12) | `fixed_in: 7.2.5`; proves part `o` for appliance OS products |
| `cpe:2.3:o:paloaltonetworks:pan-os:10.2.3:...` | 200, CVE-2024-3400 (10.0), [10.2.0, 10.2.9-h1) | `fixed_in: 10.2.9-h1`; proves the `palo_alto_networks` to `paloaltonetworks` alias |
| `cpe:2.3:a:f5:nginx:1.25.2:...` | 200, CVE-2023-44487 (7.5), [1.9.5, 1.25.3) | `fixed_in: 1.25.3` |
| `cpe:2.3:a:slack:slack:4.41.105:...` | 200, `{"vulnerabilities": []}` | `cve_count: 0`, `fully_remediated: true`, checked |
| `cpe:2.3:a:google:chrome:131.0.6778.86:...` | 429, 429, then 200 empty | Updated; stub log shows 3 requests about 2 s and 4 s apart |
| `cpe:2.3:a:7-zip:7-zip:23.01:...` | Always 403 | `cve_check_failed: true`, `cve_checked_at` set, CVE fields unchanged; 4 requests |
| `cpe:2.3:a:microsoft:visual_studio_code:1.95.3:...` | Never answers | Failure marker after 4 timed-out attempts |
| Any other CPE | 200 empty | Checked, 0 CVEs (keeps demo entries harmless) |
| `/kev.json` | `{"vulnerabilities":[{"cveID":"CVE-2021-44228"},{"cveID":"CVE-2021-45046"},{"cveID":"CVE-2023-27997"},{"cveID":"CVE-2024-3400"}]}` | `known_exploited` true for log4j, FortiOS, PAN-OS |

Stub modes (`STUB_MODE`): `normal` (table above), `kev-500` (KEV returns 500), `offline`
(every NVD request destroys the socket, so `fetch` throws a non-abort error).

Catalog entries with version `unknown` (all Fleet entries) never reach the stub: they get
`cve_checked_at` and `cve_check_failed: false` only.

#### Minimal code change for the NVD stub

`enrich_catalog_entries.ts` hard-codes `NVD_URL`, `KEV_URL`, 6 s spacing, a 30 s timeout, and a
2 s backoff base; only `NVD_API_KEY` comes from the environment. `fetchFn` is injectable but not
from a workflow. Add optional plugin config and pass it through the step registration:

```ts
// server/config.ts
export const configSchema = schema.object({
  enabled: schema.boolean({ defaultValue: false }),
  enrichment: schema.object({
    nvdBaseUrl: schema.uri({ defaultValue: 'https://services.nvd.nist.gov/rest/json/cves/2.0' }),
    kevUrl: schema.uri({
      defaultValue: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    }),
    requestSpacing: schema.maybe(schema.duration()), // default: 6s, or 700ms with an API key
    requestTimeout: schema.duration({ defaultValue: '30s' }),
    backoffBase: schema.duration({ defaultValue: '2s' }),
  }),
});

// server/services/enrichment/enrich_catalog_entries.ts
export interface NvdEndpoints { nvdBaseUrl: string; kevUrl: string; spacingMs?: number; timeoutMs: number; backoffBaseMs: number }
export const enrichCatalogEntries = async ({ esClient, logger, limit, fetchFn = fetch, endpoints = DEFAULT_ENDPOINTS }) => { ... };
```

Then `registerSoftwareInventorySteps` receives `config.enrichment` and passes it to the
`enrichCves` handler. Test settings in `config/kibana.dev.yml`:

```yaml
xpack.softwareInventory.enrichment:
  nvdBaseUrl: http://localhost:5699/rest/json/cves/2.0
  kevUrl: http://localhost:5699/kev.json
  requestSpacing: 100ms
  requestTimeout: 2s
  backoffBase: 200ms
```

Extend `enrich_catalog_entries.test.ts` to cover the endpoint override. Revert the YAML
settings after testing; the defaults keep production behavior unchanged.

#### Stub server sketch

```ts
// scripts/discovery_test/nvd_stub/server.ts
const attempts = new Map<string, number>();
createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://localhost');
  log({ at: Date.now(), path: url.pathname, cpe: url.searchParams.get('cpeName') });
  if (url.pathname === '/kev.json') {
    return mode === 'kev-500' ? send(res, 500, {}) : send(res, 200, KEV);
  }
  if (mode === 'offline') return req.socket.destroy();
  const cpe = url.searchParams.get('cpeName') ?? '';
  const n = (attempts.get(cpe) ?? 0) + 1;
  attempts.set(cpe, n);
  const fixture = NVD_FIXTURES[cpe] ?? { kind: 'ok', body: { vulnerabilities: [] } };
  switch (fixture.kind) {
    case 'ok': return send(res, 200, fixture.body);
    case 'status': return send(res, fixture.status, {});
    case 'flaky': return n <= fixture.failures ? send(res, 429, {}) : send(res, 200, fixture.body);
    case 'hang': return; // never answers; the client aborts
  }
}).listen(5699);
// GET /__log returns the request log; POST /__reset clears attempts and the log.
```

## Test matrix

Columns: **Trigger** is `variant` (test run of a generated variant under the managed id), `prod`
(test run of the stored production YAML), or `sched` (scheduled copy). **Panels**: WH = Workflow
health, SL = Step level, RF = Recent failures, DO = Discovery output, IT = Inventory trend.
Every case passes only when all listed expectations hold; any extra event, instance, or catalog
change on a non-synthetic key fails the case.

### T0: harness self-checks

| ID | Objective | Steps and expectations |
|---|---|---|
| T0-1 | Variant fidelity | Builder output differs from production only in the four `query_*` steps (deep-equal check of all other steps, `settings`, `name` suffix) |
| T0-2 | Fixture contract | Each fixture parses with the osquery `runQueryOutputSchema` (or a vendored copy) |
| T0-3 | Managed-id test run accepted | Test-run a no-op variant of `discover-osquery` (all four fixtures `F-empty`) with `workflowId`; expect `completed`, `workflowId` = managed id, `isTestRun: true`. If refused, switch to the `si-test-` fallback |
| T0-4 | Preflight | All six workflows disabled; synthetic keys and catalog ids absent; stale-eligible demo count recorded; backup written |

### discover-osquery

| ID | Objective | Setup | Trigger | Expected run and steps | Expected inventory | Panels |
|---|---|---|---|---|---|---|
| DO-1 | Baseline ingest | `R1` fixtures | variant | Run `completed`; all 12 steps `completed`; outputs as in [Osquery fixtures](#osquery-fixtures) | 13 instances `active`, `sources: [osquery]`; 13 `first_seen` events; 13 new catalog entries with categories `os_package` (6), `application` (4), `dependency` (3) | WH Runs +1; DO Events `first_seen` +13, Instances by source `osquery` +13, Catalog entries +13, Never checked +13 |
| DO-2 | Blank and invalid rows | Within `R1` | | `ingest_windows.skipped = 1`; `ingest_linux.skipped = 0` (YAML drops blank rows before ingest) | No instance for `synth-lin-02` from Linux, none with name `(x64)` | |
| DO-3 | Duplicate rows | Within `R1` | | `ingest_linux.created = 6` from 7 non-dropped rows | One `openssl` instance on `synth-lin-01` | |
| DO-4 | Agent-id resolution fallback | `.fleet-agents` missing | | Kibana log: `could not resolve Osquery agent hosts; using agent names` | `synth-lin-01` instances: `host.id: synth-agent-lin01`, `host.name: synth-lin-01`; `synth-agent-lin03`: `host.key` = agent id, no `host.name`; `synth-win-01`: `host.name: SYNTH-WIN-01`, `host.key: synth-win-01` | |
| DO-5 | Windows and macOS categories | Within `R1` | | | Catalog `google:chrome:131.0.6778.86`, `7-zip:7-zip:23.01`, `slack:slack:4.41.105`, `microsoft:visual_studio_code:1.95.3` have `category: application`; instances carry `install_path` | |
| DO-6 | Patch, history, event | After DO-1. Linux fixture `R2`: lin01 `openssl` `3.0.14-0ubuntu3.4`, `synth-tool` absent, others unchanged; lin02, lin03 absent; other queries `F-empty` | variant | `ingest_linux` `{unchanged: 3, patched: 1, removed: 1}` | `openssl` instance: `status: patched`, `software_id: openssl:openssl:3.0.14`, `previous_software_id: openssl:openssl:3.0.7`, `version_history` length 2; `synth-tool`: `removed`; `curl` on `synth-agent-lin03` untouched; events: 1 `version_changed` (`from_version 3.0.7`, `to_version 3.0.14`, no posture fields because neither entry was checked), 1 `removed` | DO Events `version_changed` +1, `removed` +1; Instances by status `patched` +1, `removed` +1 |
| DO-7 | Idempotent re-run | Repeat DO-6 fixtures | variant | `ingest_linux` `{unchanged: 4}` | No new events; `openssl` status returns to `active` with `version_changed_at` kept | DO Events unchanged |
| DO-8 | Truncated means no removal | Linux `F-trunc` with lin01 rows minus `nginx` | variant | `snapshot` false (check the step `input`) | `nginx` on `synth-lin-01` stays `active`; `removed: 0` | |
| DO-9 | Failed query means no removal | Linux `F-failed` | variant | `build_linux` `[]`; ingest all zeros | No status changes | |
| DO-10 | Thrown query step | Linux `F-throw` | variant | `query_linux` `failed`, run `completed`, `ingest_linux` all zeros | No changes | SL `query_linux` `failed` +1; WH Failed runs unchanged |
| DO-11 | Partial, timed out, unreadable | `F-partial`, `F-timedout`, `F-unreadable` on Linux, one run each, rows missing `bash` | variant | `snapshot` false each time | Rows upserted; `bash` never removed | |
| DO-12 | Category-scoped removal | Dependencies fixture: lin01 reports `lodash` `4.17.20` only (no `log4j-core`); Linux `F-empty` | variant | `ingest_dependencies` `{created: 1, removed: 1}` | `apache:log4j:2.14.1` on `synth-lin-01` `removed`; lin01 OS packages untouched | |
| DO-13 | Absent host untouched | Linux fixture with lin02 only | variant | | No change on `synth-lin-01` or `synth-agent-lin03` | |
| DO-14 | Revive | After DO-12, dependencies fixture with lin01 `lodash` `4.17.20` and `log4j-core` `2.14.1` | variant | `{unchanged: 2}` (`lodash`, `log4j`) | `log4j` instance `active`; one `revived` event | DO Events `revived` +1 |
| DO-15 | First writer sets catalog category | Fresh keys: run `discover-logs` with `S1`-style service `synth-svc` `1.0` on `synth-lin-01` first, then Linux fixture with `synth-svc` `1.0`, then Linux fixture without it | logs, then variant x2 | Third run `removed: 0` | Catalog category stays `application`, so the Linux snapshot never removes the shared instance. Record as a known order dependency (risk R5) | |
| DO-16 | 5000 rows | Linux `F-bulk-5000` | variant | `ingest_linux.created = 5000`, step under 60 s | 5000 instances on `synth-bulk-01`; no removal | WH Average duration rises; DO Instances +5000 |
| DO-17 | Over the limit | Linux `F-bulk-5001` | variant | `ingest_linux` `failed` with a validation error naming `candidates`; run `completed` | No writes for `synth-bulk-01` beyond DO-16 | SL `ingest_linux` `failed` |
| DO-18 | Production YAML on this stack | Stored YAML | prod | Expected: each `query_*` fails before dispatch (no agents, `osquery_manager` not installed; record the error); every `ingest_*` all zeros; run `completed` | No changes | SL 4 failed query steps |

### discover-integrations

| ID | Objective | Setup | Trigger | Expected | Panels |
|---|---|---|---|---|---|
| DI-1 | Real Fleet, empty | None | prod | `list_package_policies.output.items = []`, `ingest` all zeros, run `completed` | WH Runs +1 |
| DI-2 | Mapped vs unmapped | [Fleet fixtures](#fleet-fixtures) | variant | `ingest` `{created: 3, skipped: 2}`; catalog versions `unknown` | DO Instances by source `fleet_integration` +3 |
| DI-3 | Policy pseudo-hosts | After DI-2 | | `host.key` `policy:synth-pol-edge` (2 instances) and `policy:synth-pol-web` (1); `host.name` without prefix | |
| DI-4 | Re-run, no snapshot | DI-2 fixture minus `nginx` on `synth-pol-edge` | variant | `{unchanged: 2, skipped: 2, removed: 0}` | `f5:nginx:unknown` on `policy:synth-pol-edge` stays `active` |
| DI-5 | Ingest failure fails the run | Fixture with 5001 `policy_ids` on one `panw` policy | variant | `ingest` `failed` (max 5000); run `failed` (no `on-failure` on this step) | WH Failed runs +1; RF new row |
| DI-6 | Space prefix (latent bug) | Read-only review | | `path` lacks `/s/{{ workflow.spaceId }}`; harmless in `default`, wrong in other spaces (risk R3) | |

### discover-logs

| ID | Objective | Setup | Trigger | Expected | Panels |
|---|---|---|---|---|---|
| DL-0 | No logs | Before creating the data stream | prod | Both query steps `failed` (`Unknown column`), `ingest` all zeros, run `completed` | SL 2 failed steps |
| DL-1 | Baseline | Phase A data, after DO-1 | prod | Candidates and `ingest` output as in the [logs expected table](#generator-specification) | DO Instances by source `logs` +10 |
| DL-2 | Collector vs appliance | Within DL-1 | | `synth-fw-01`, `synth-fw-02` are separate instances; nothing on `synth-collector-01` | |
| DL-3 | Fallback keys | Within DL-1 | | Keys `synth-sn-0003` and `192.0.2.77`, both without `host.name` | |
| DL-4 | Dedupe | Within DL-1 | | One `synth-checkout` instance on `synth-web-01`; `A1` duplicates yield one row with `observed_at` = T0-30m (`first_seen` = `last_seen` = that time) | |
| DL-5 | Window edges | Within DL-1 | | `synth-fw-05` present (23 h); `synth-fw-03` absent (26 h); `synth-fw-04`, `synth-web-03` absent (no version) | |
| DL-6 | Cross-source merge | Within DL-1 | | `nginx` on `synth-lin-01`: one instance, `sources: [osquery, logs]`, outcome `unchanged` | |
| DL-7 | Version flip | Write phase B (`S3b`), re-run | prod | `ingest` `{unchanged: 9, patched: 1}` | `nginx` on `synth-web-02`: `status: patched`, history `1.25.2` (T0-20h) then `1.27.4` (T0-1h); `version_changed` event at T0-1h | DO Events `version_changed` +1 |
| DL-8 | Idempotent | Re-run without new data | prod | `{unchanged: 10}`; no new events | |
| DL-9 | Missing field column | Data stream without the dedicated template (`observer.serial_number` never present) | prod | `query_appliances` `failed` (`Unknown column`), services still ingested | SL 1 failed step. Shows the template is required for appliance discovery in real clusters too (risk R4) |
| DL-10 | Multi-valued `observer.ip` | Extra doc: `observer.ip: [192.0.2.78, 10.9.9.9]`, F5 BIG-IP | prod | Record which value becomes `host_id`; `MV_FIRST` reads doc values, which are sorted, so `10.9.9.9` is expected rather than the first value in `_source` | |

### discover-endpoint

The DE cases run the stored production YAML (`prod`) against the synthetic Defend events described in
[Synthetic Defend process events](#synthetic-defend-process-events). They run after the DL family and
DO-15..DO-18, because the endpoint data stream also matches `logs-*` and DL-0 needs a cluster without
logs. The harness registers them as `DE-0` to `DE-6`.

| ID | Objective | Setup | Trigger | Expected | Panels |
|---|---|---|---|---|---|
| DE-0 | No endpoint data stream | No `logs-endpoint.events.process-*` data stream exists | prod | `query_processes` `failed` (`Unknown column`), run `completed` (the step continues on failure), `ingest` all zeros with 0 candidates, no writes. The case is `blocked` when such a data stream exists | SL 1 failed step |
| DE-1 | Baseline | Phase A | prod | Seven ES\|QL rows; `ingest` `{created: 6}`; source `endpoint`, category `application`, catalog `mozilla:firefox:124.0.1` and the five synthetic ids; `first_seen` events at each row's `observed_at` | DO Instances by source `endpoint` +6 |
| DE-2 | Exclusions | Within DE-1 | | `synth-win-04` has only the document without an executable (`C:\Windows\` and `c:\WINDOWS\` binaries add nothing); `synth-win-05` (no file version) and `synth-win-06` (26 h old) have no instance | |
| DE-3 | Version flip | Write phase B (`E9`), re-run | prod | `ingest` `{unchanged: 5, patched: 1}`; Firefox on `synth-win-01` is `patched` with history `124.0.1` (T0-1h) then `125.0.1` (T0-30m), a `version_changed` event, and `previous_software_id` `mozilla:firefox:124.0.1` | DO Events `version_changed` +1 |
| DE-4 | Snapshot false | Delete the `synth-win-03` documents, re-run, then restore them | prod | `ingest` `{unchanged: 5}` with 7 candidates; the `synth-win-03` instance stays `active` with unchanged sightings; Firefox returns from `patched` to `active` and keeps its history | |
| DE-5 | Latest sighting wins | Within DE-1 | | `synth-win-07` reports `Synth-Dual` 3.0 (T0-5h) and 3.1 (T0-2h): one instance at 3.1, history `[3.1]`, no catalog entry for 3.0 | |
| DE-6 | Cross-source identity | After DE-4, ingest an Osquery row for `synth-win-08`, then re-run the stored workflow | prod | One `Synth-Both` instance with `sources: [endpoint, osquery]`, `first_seen` at the endpoint sighting, `last_seen` at or after the Osquery run, one `first_seen` event (source `endpoint`); the re-run reports `{unchanged: 6}` | |

### enrich-cves

Run each case as a variant with `limit` set to the number of never-checked entries the case
needs (the managed YAML uses 25), stub in `normal` mode unless stated.

| ID | Objective | Expected | Panels |
|---|---|---|---|
| EC-1 | Multi-CVE safe version | `apache:log4j:2.14.1` as in the stub table; `cve_details` sorted by CVSS; `first_published: 2021-12-10T10:15:09.143Z` | DO CVE checked +N, Never checked -N |
| EC-2 | Multi-branch | `apache:log4j:2.12.1` `fixed_in: 2.12.4`, `latest_known_fix: 2.17.1` | |
| EC-3 | Unfixed | `synth-checkout:synth-checkout:2.4.0` `unfixed_cve_ids: [CVE-2099-0001]`, `fully_remediated: false` | |
| EC-4 | Appliance CPE part and vendor alias | Stub log shows `cpe:2.3:o:fortinet:fortios:7.2.4` and `cpe:2.3:o:paloaltonetworks:pan-os:10.2.3`; both entries `known_exploited: true` | |
| EC-5 | Unknown version skipped | Fleet entries (`...:unknown`) get `cve_checked_at`, no stub request | |
| EC-6 | Rate limit with backoff | Chrome entry updated; 3 requests about `backoffBase` and 2 x `backoffBase` apart; step `enrich.output.failed` excludes it | |
| EC-7 | Persistent 403 | 7-Zip entry `cve_check_failed: true`; output `failed` +1; 4 requests | DO CVE check failed +1 |
| EC-8 | Timeout | VS Code entry failure marker after 4 attempts (about 4 x `requestTimeout` + backoff) | SL `enrich` duration |
| EC-9 | Network unavailable | `STUB_MODE=offline`, one never-checked entry with a real version | `output.failed = 1`; that entry and every later entry keep no `cve_checked_at`; no failure marker | DO Never checked unchanged |
| EC-10 | KEV unavailable | `STUB_MODE=kev-500`, re-check log4j (clear its `cve_checked_at` on the synthetic entry first) | `known_exploited` keeps its previous value; Kibana warns `CISA KEV catalog responded with status 500` | |
| EC-11 | Ordering | Two runs with `limit: 3` | Never-checked entries first, then oldest `cve_checked_at`; failure markers move behind healthy entries | |
| EC-12 | Production limit | Production YAML (`limit: 25`) once after all synthetic entries are checked | Touches the 25 oldest entries, including demo entries; stub answers "any other CPE" with empty results. Proves demo restore works | |

### score-exposure

Run after DO-1, DI-2, DL-1, and EC-1..4. Before the run, the harness sets manual evidence on the
`synth-web-02` `nginx` instance: `{signal: manual, detail: "synthetic manual", weight: 30}`.

| ID | Instance | Expected `exposure` |
|---|---|---|
| SE-1 | `synth-web-01` / `synth-checkout` | `inbound_public_ip` weight 44 (3 sources: 40 + 2 x 2), `medium`; samples exclude private IPs and `5.5.5.5` (8 days old) |
| SE-2 | `synth-lin-01` (all instances) | `none` (outbound only) |
| SE-3 | `synth-fw-02` / PAN-OS | `edge_device_role` 50 + `inbound_public_ip` 50 (6 sources) = 100, `high` |
| SE-4 | `synth-fw-01`, `synth-fw-05`, `synth-sn-0003`, `192.0.2.77`, `synth-edge-09` | `edge_device_role` 50, `medium` (inbound traffic of collected appliances arrives under the collector's `host.name`, risk R6) |
| SE-5 | `synth-hostid-0005` / redis | Matched by `host.id`, `ingress`: 40, `medium` |
| SE-6 | `synth-web-02` / nginx | Manual 30 kept, no other signal: 30, `low` |
| SE-7 | `policy:synth-pol-edge` / PAN-OS | Edge 50, `medium`; `X8` ignored. `policy:*` / nginx: `none` |
| SE-8 | Step output | `score.output.scored` = count of non-removed instances at run time (oracle query) |
| SE-9 | Demo impact | The 9 demo instances with `inbound_public_ip` lose that evidence; record the before and after levels, then restore |
| SE-10 | Mark stale | Harness sets `last_seen` = T0-31d on `synth-mac-01` / Slack. `mark_stale.output.marked` = 1 + demo-eligible count (0 at planning time); one `stale` event; a later `R1` macOS fixture yields a `revived` event |
| SE-11 | Rollup | `snapshot_rollup.output.date` = today (UTC); doc `_id` = today; every count equals its oracle query (for example `total_instances` = count of `status` in `active`, `patched`) |
| SE-12 | Rollup idempotent | Second run: still one doc for today, identical counts | 

Panels for SE: DO Instances by status (`stale` +1), Events `stale` and `revived`, IT today's
point moves, WH Runs +1 per run.

### Cross-workflow end-to-end

| ID | Objective | Sequence | Assertions |
|---|---|---|---|
| E2E-1 | Full pipeline | Backup; logs phase A; DO-1 (`R1`); DI-2; DL-1; EC (normal stub, `limit` 40); logs phase B; DL-7; SE run | All step outputs as in the per-workflow tables; DO panels match oracle counts |
| E2E-2 | Vulnerable in a 3-day window | After E2E-1, `GET /internal/software_inventory/hosts/synth-web-02/timeline` | `from` = T0-3d, `to` = now: `vulnerable_in_range: true`, `first_vulnerable_at` = T0-20h, `cve_ids` = `[CVE-2023-44487]`, `vulnerable_duration_ms` = 19 h ± 1 min. `from` = T0-30m: `vulnerable_in_range: false`. `from` = T0-3d, `to` = T0-21h: item absent, `false` |
| E2E-3 | Posture on the patch event | Part of E2E-1 (EC runs before phase B) | `version_changed` event on `synth-web-02` carries `cve_count_before: 1`, `max_cvss_before: 7.5`, `known_exploited_before: false`, and no `*_after` fields: `f5:nginx:1.27.4` is created in the same ingest call, so it has no posture yet. Repeat with EC after phase B: no posture fields at all |
| E2E-4 | log4j host timeline | `GET .../hosts/synth-lin-01/timeline?from=T0-3d&to=now` | `vulnerable_in_range: true`, `cve_ids` has the four log4j CVEs, `first_vulnerable_at` = the `R1` run time |
| E2E-5 | Instances route | `GET /internal/software_inventory/instances?host_id=synth-agent-lin01&...` | Matches the oracle |

### Scheduling, concurrency, and failure injection

Do not enable the managed workflows: enabling schedules a Task Manager task with no `runAt`, so
the first run starts within seconds, and the production `enrich-cves` would call the real NVD.

| ID | Objective | Setup | Expected | Panels |
|---|---|---|---|---|
| SC-1 | Scheduled trigger fires | Saved copy `si-test-discover-osquery-sched` (variant, `F-empty` fixtures, `every: 1m`, own concurrency key), enabled in `default` | First run within about 1 min of enabling, then every minute; `triggeredBy: scheduled`; disable after 3 runs | WH Runs over time |
| SC-2 | Global space skipped | Read-only: confirm the managed workflows' `spaceId` is `default`, not global | Scheduler fires only for space-scoped workflows (already verified by you) | |
| SC-3 | Concurrency `drop` | Copy with a 90 s `wait` step and production concurrency settings, `every: 1m` | Overlapping run `skipped`, no `startedAt` | Not visible today (dashboard gap) |
| SC-4 | Test run shares the slot | While SC-3 holds the slot, test-run a variant with the same `concurrency.key` | `skipped`; a variant with a different key runs | |
| SC-5 | On-failure continue | Covered by DO-10, DL-0 | Run `completed` with failed steps | SL |
| SC-6 | Step timeout | Variant with `timeout: 5s` on a `wait: 30s` step replacing `query_linux` | Step `timed_out` or `failed`; record which; downstream `ingest_linux` all zeros | RF if the run fails |
| SC-7 | Restart mid-run | Start DO-16 (5000 rows), restart Kibana during `ingest_linux` | Record the final status (resumed, failed, or stuck `running`). No duplicate instances (ids are deterministic); possible duplicate `first_seen` events on a replayed bulk | WH Currently running |
| SC-8 | Managed `every` override | `PUT /api/workflows/managed/workflow/{id}` with `every: 1m` on a disabled workflow, then restart Kibana | Stored YAML reverts to `every: 6h` after restart (`versionStrategy: auto`); `enabled` unchanged. Needs your approval | |
| SC-9 | Enable or disable managed via API | `PUT /api/workflows/workflow/{id}` `{"enabled": true}` then `false` on `discover-integrations` only (harmless: Fleet is empty) | Both succeed for `elastic`; one scheduled run appears; disable removes the task | WH Runs +1 |

### Regression checks on demo data

Run after cleanup and restore.

| ID | Check |
|---|---|
| RG-1 | Doc counts and `_id` sets of the four plugin indices equal the backup |
| RG-2 | `_source` of every demo instance and catalog entry equals the backup (hash compare) |
| RG-3 | No document with a synthetic host key, synthetic catalog id, or `192.0.2.77` remains |
| RG-4 | Today's rollup equals the backup copy |
| RG-5 | The six managed workflows are disabled with an unchanged `definitionHash` |
| RG-6 | `logs-softwareinventory.synthetic-*` and its template are gone; no `si-test-*` workflow remains |

## Execution procedure

### Runbook

1. Preflight and backup:

   ```bash
   kbn "$KBN/api/workflows?size=100&managed=managed" | jq -c '[.results[]|select(.id|startswith("'$WF'"))|{id,enabled}]'
   node x-pack/solutions/security/plugins/software_inventory/scripts/run_discovery_tests.js preflight
   node x-pack/solutions/security/plugins/software_inventory/scripts/run_discovery_tests.js backup --out "$SCRATCH/si-backup"
   ```

2. Install the dashboard and open it at `http://localhost:5601/tdy/app/dashboards#/view/software-inventory-discovery-monitoring`, time range `now-24h`.
3. Run T0-1 to T0-3.
4. Create the template and phase A logs:

   ```bash
   es -X PUT "$ES/_index_template/logs-softwareinventory.synthetic" -d @template.json
   node .../run_discovery_tests.js logs --phase A --t0 "$(date -u +%FT%TZ)"
   ```

5. Run a variant and wait for it (the harness does this for every case):

   ```bash
   jq -n --rawfile y variant.yaml --arg id "$WF-discover-osquery" \
     '{workflowId: $id, workflowYaml: $y, inputs: {}}' > body.json
   X=$(kbn -X POST "$KBN/api/workflows/test" -d @body.json | jq -r .workflowExecutionId)
   until S=$(kbn "$KBN/api/workflows/executions/$X" | jq -r .status); \
     [[ "$S" =~ ^(completed|failed|cancelled|timed_out|skipped)$ ]]; do sleep 2; done
   kbn "$KBN/api/workflows/executions/$X" | jq -c '.stepExecutions[]|{stepId,status,id}'
   kbn "$KBN/api/workflows/executions/$X/step/<stepExecutionId>" | jq .output
   ```

6. Run the discovery cases in order: DO-1..DO-14, DI-1..DI-5, DL-0 (before step 4 if you run it), DL-1..DL-10, DO-15..DO-18, DE-0..DE-6. DE-0 needs a cluster without any `logs-endpoint.events.process-*` data stream.
7. Start the stub (`node .../run_discovery_tests.js nvd-stub --port 5699`), confirm the config change is active, and run EC-1..EC-12.
8. Run SE-1..SE-12, then E2E-1..E2E-5 from a clean synthetic state (`cleanup --synthetic-only`).
9. Run SC-1..SC-9 (SC-8 only with approval).
10. Clean up and restore, then run RG-1..RG-6:

    ```bash
    node .../run_discovery_tests.js cleanup
    node .../run_discovery_tests.js restore --from "$SCRATCH/si-backup"
    node .../run_discovery_tests.js regression --from "$SCRATCH/si-backup"
    ```

### Assertion approach

Each case asserts three layers, in this order:

1. Engine: run status and every step status from `GET /api/workflows/executions/{id}`.
2. Step contract: `output` (and for snapshot cases, `input.snapshot`) from the step route.
3. Inventory: oracle queries on the plugin indices, by deterministic id where possible
   (`buildInstanceId({hostKey, vendor, product, installPath})` and the catalog id), plus an
   events query scoped to `@timestamp >= run.startedAt - 25h` and the case's host keys.

Example oracle check for DO-6:

```bash
es "$ES/.kibana-software-inventory-events/_search" -d '{
  "size": 10,
  "query": {"bool": {"filter": [
    {"term": {"host.key": "synth-lin-01"}},
    {"range": {"@timestamp": {"gte": "'$RUN_START'"}}}]}},
  "_source": ["type", "software_id", "from_version", "to_version"]}' \
| jq -c '[.hits.hits[]._source] | sort_by(.type)'
# expected: [{"type":"removed","software_id":"synth-tool:synth-tool:2.0.0","from_version":"2.0.0"},
#            {"type":"version_changed","software_id":"openssl:openssl:3.0.14","from_version":"3.0.7","to_version":"3.0.14"}]
```

### Results template

| Case | Date | Execution id | Run status | Step statuses as expected | Step outputs as expected | Inventory as expected | Panels moved as expected | Result | Notes |
|---|---|---|---|---|---|---|---|---|---|
| DO-1 | | | | | | | | Pass / Fail / Blocked | |

The harness writes this table to `<scratchpad>/discovery_test_results.md` with one row per case
and a diff of expected and actual values for every failure.

## Harness to build

Location: `x-pack/solutions/security/plugins/software_inventory/scripts/discovery_test/`, entry
`scripts/run_discovery_tests.js` (`require('@kbn/setup-node-env')`, like the other scripts).
Nothing below exists yet.

| File | Responsibility |
|---|---|
| `cli.ts` | Commands `preflight`, `backup`, `restore`, `logs`, `nvd-stub`, `run <case ids>`, `cleanup`, `regression`, `report`; flags `--kibana-url`, `--es-url`, `--space`, `--t0` |
| `clients.ts` | Kibana and ES helpers: test-run, poll, step output, internal routes with the origin header |
| `variants/build_variant.ts` | Generic transformer: replace named steps of a production YAML with fixtures, keep everything else, enforce the fidelity invariant |
| `variants/osquery.ts`, `variants/integrations.ts`, `variants/enrich.ts` | Per-workflow step maps (`query_*`, `list_package_policies`, `enrich.with.limit`) |
| `fixtures/osquery.ts` | `R1`, `R2`, and the `F-*` fixtures as typed objects; liquid generator for bulk rows |
| `fixtures/fleet.ts` | Package policy fixtures |
| `logs/template.ts`, `logs/generate_logs.ts` | Template body; deterministic phase A and B documents relative to `--t0` |
| `nvd_stub/server.ts`, `nvd_stub/fixtures.ts` | Stub server, modes, request log |
| `expected/*.ts` | Expected outcomes per case, using `buildInstanceId` and `buildCatalogId` from the plugin |
| `assertions.ts` | Three-layer assertions and diffs |
| `backup.ts` | NDJSON backup and exact restore of the four plugin indices (delete ids not in the backup, re-index the rest with their ids) |
| `cleanup.ts` | Synthetic deletes by host key and by catalog-id diff; data stream and template; `si-test-*` workflows with `force=true` |
| `report.ts` | Results table |
| `*.test.ts` | Jest for the transformer invariant, fixture contract, generator determinism, expected-id computation |

### Variant transformer sketch

```ts
import { parseDocument, isMap, isSeq, type YAMLMap } from 'yaml';
import { isDeepStrictEqual } from 'util';

type Replacement =
  | { kind: 'fixture'; output: Record<string, unknown> }
  | { kind: 'throw' };

export const buildVariant = (
  productionYaml: string,
  replacements: Readonly<Record<string, Replacement>>,
  { label, every }: { label: string; every?: string }
): string => {
  const doc = parseDocument(productionYaml);
  const steps = doc.get('steps');
  if (!isSeq(steps)) throw new Error('steps missing');
  for (const item of steps.items) {
    if (!isMap(item)) continue;
    const step = item as YAMLMap;
    const replacement = replacements[String(step.get('name'))];
    if (!replacement) continue;
    if (replacement.kind === 'throw') {
      step.set('type', 'elasticsearch.request');
      step.set('with', doc.createNode({ method: 'GET', path: '/zz-si-test-missing/_doc/1' }));
    } else {
      step.set('type', 'data.set');
      step.set('with', doc.createNode(replacement.output));
    }
    // Keep `on-failure: continue` so failure semantics match production.
  }
  doc.set('name', `${doc.get('name')} [test: ${label}]`);
  if (every) doc.setIn(['triggers', 0, 'with', 'every'], every);
  const variant = doc.toString();
  assertFidelity(productionYaml, variant, Object.keys(replacements), { allowTrigger: !!every });
  return variant;
};

const assertFidelity = (prod: string, variant: string, replaced: string[], opts: { allowTrigger: boolean }) => {
  const a = parseDocument(prod).toJS();
  const b = parseDocument(variant).toJS();
  const keep = (steps: Array<{ name: string }>) => steps.filter((s) => !replaced.includes(s.name));
  if (!isDeepStrictEqual(keep(a.steps), keep(b.steps))) throw new Error('non-replaced steps changed');
  if (!isDeepStrictEqual(a.settings, b.settings)) throw new Error('settings changed');
  if (!opts.allowTrigger && !isDeepStrictEqual(a.triggers, b.triggers)) throw new Error('triggers changed');
};
```

### Expected-outcome assertion sketch

```ts
interface ExpectedInstance {
  hostKey: string; vendor: string; product: string; installPath?: string;
  status: InstanceDoc['status']; softwareId: string; sources: DiscoverySource[];
  versions?: string[]; hostName?: string | null; hostId?: string;
}

export const assertInstances = async (es: Client, expected: readonly ExpectedInstance[]) => {
  const ids = expected.map((e) => buildInstanceId(e));
  const { docs } = await es.mget<InstanceDoc>({ index: INSTANCES_INDEX, ids });
  return expected.flatMap((exp, i) => {
    const doc = docs[i];
    if (!('found' in doc) || !doc.found || !doc._source) return [`missing ${exp.hostKey}/${exp.product}`];
    const src = doc._source;
    const diffs: string[] = [];
    if (src.status !== exp.status) diffs.push(`status ${src.status} != ${exp.status}`);
    if (src.software_id !== exp.softwareId) diffs.push(`software_id ${src.software_id}`);
    if (!isDeepStrictEqual([...src.sources].sort(), [...exp.sources].sort())) diffs.push(`sources ${src.sources}`);
    if (exp.versions && !isDeepStrictEqual(src.version_history.map((h) => h.version), exp.versions)) diffs.push('history');
    if (exp.hostName !== undefined && (src.host.name ?? null) !== exp.hostName) diffs.push(`host.name ${src.host.name}`);
    return diffs.map((d) => `${exp.hostKey}/${exp.product}: ${d}`);
  });
};

// A case also fails on any unexpected write: count docs with "@timestamp" >= run start whose
// host.key is not in the case's expected host keys.
```

## Risks and open questions

### Risks

| ID | Risk | Mitigation |
|---|---|---|
| R1 | `enrich-cves` and `score-exposure` are not host-scoped and change demo documents | Backup and exact restore; RG checks |
| R2 | The managed-id test run (`workflowId` + `workflowYaml`) is untested on managed workflows | T0-3; fallback `si-test-*` copies |
| R3 | `discover-integrations` calls `/api/fleet/package_policies` without `/s/{{ workflow.spaceId }}`, so in a non-default space it reads the default space (the managed-workflows guide requires the prefix) | DI-6; fix in the YAML before multi-space use |
| R4 | `discover-logs` fails a query step on clusters where any referenced field is unmapped in every `logs-*` index (for example `observer.serial_number`) | DL-9; consider `COALESCE` on fields known to exist, or document the requirement |
| R5 | The catalog category comes from whichever source creates the entry first; Osquery removals depend on it | DO-15 records the behavior |
| R6 | Appliance inbound traffic usually arrives with the collector's `host.name`, so collected appliances never get `inbound_public_ip` | SE-4 records it |
| R7 | Demo seed ids differ from production normalization (`paloaltonetworks:pan-os`, `apache:log4j-core` in the seed; production produces `palo_alto_networks:pan-os` and `apache:log4j`) | Avoid relying on seed ids in tests; consider aligning the seed |
| R8 | NVD fixtures that return CVEs for unaffected versions turn into "unfixed" findings | Stub returns CVEs only for matching CPEs |
| R9 | Test runs land in `.workflows-*` and the dashboard; the engine has no API to delete ephemeral executions | Accept; filter by `isTestRun` |

### Open questions

1. May the harness test-run variant YAML under the managed workflow ids (`workflowId` +
   `workflowYaml`)? It makes runs visible on the dashboard and is the only form that does not
   need a second dashboard filter.
2. Do you approve the [writes listed under Safety](#writes-that-need-your-approval), in
   particular backup and restore of the plugin indices and the logs template?
3. Do you want the NVD config override (plugin config, default-preserving) merged, or kept as a
   local patch for testing only?
4. Should the demo restore be exact (harness backup) or is `seed_demo_data.js --clean` enough?
5. Phase 1b: may the harness create Fleet agent policies and package policies (needs the package
   registry for `panw` and `nginx`)?
6. Phase 3: is an enrolled Elastic Agent with `osquery_manager` available (Docker or a VM)?
7. Should the dashboard owner adopt the gaps listed in
   [Observability](#observability-with-the-monitoring-dashboard) before the test run?

## Phased rollout

| Phase | Content | Exit criteria |
|---|---|---|
| 1 | Harness, Osquery fixtures, synthetic logs, Fleet fixtures, NVD stub with the config change; T0, DO, DI-1..5, DL, EC, SE, E2E, SC-1..7, RG | Every case passes or has a filed risk; demo restored |
| 1b | Real Fleet package policies (`panw`, `nginx`, `system`) on test agent policies; DI-2 to DI-4 with the production YAML | Same outcomes as the fixtures |
| 2 | Live NVD smoke: test-run `enrich-cves` with `limit: 2` on two synthetic entries (`apache:log4j:2.14.1`, `slack:slack:4.41.105`), default URLs, 6 s spacing (or `NVD_API_KEY`). Expect 4 CVEs and `known_exploited: true` for log4j; if Kibana has no outbound network, expect `failed: 1` and both entries still unchecked (network-unavailable path) | Real responses parse to the same fields as the stub |
| 3 | Real Osquery: install `osquery_manager`, enroll one Linux agent, run the production `discover-osquery`. Adds: real dispatch and wait, real `agent.name`, `.fleet-agents` resolution (`host.id` and `host.name` from `local_metadata`), real row counts against `max_rows: 5000`, `RESULTS_UNREADABLE` and `partial` in practice, and the cost of the 10 m `wait_timeout` | Linux host instances keyed by the Fleet host name; a second run is idempotent |
