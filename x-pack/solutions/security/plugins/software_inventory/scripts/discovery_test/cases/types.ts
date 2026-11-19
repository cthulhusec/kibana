/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Contract for discovery test cases. Each family module (`t0.ts`, `do.ts`, ...) exports
 * `cases: TestCase[]`; `cases/index.ts` combines them in execution order. A case receives a
 * `CaseContext` and returns a `CaseResult` built from the three assertion layers. The runner adds
 * the case id, timing, and the execution ids of every run the case started.
 */

import type { LayerResult } from '../assertions';
import type { CompletedRun, EsClient, JsonObject, KibanaClient, WaitOptions } from '../clients';
import type { EndpointPhase, SyntheticEndpointDoc } from '../logs/generate_endpoint';
import type { LogPhase, SyntheticLogDoc } from '../logs/generate_logs';
import type { WorkflowKey } from '../variants/build_variant';
import type { NvdStub } from '../nvd_stub/server';

export type CaseFamily = 'T0' | 'DO' | 'DI' | 'DL' | 'DE' | 'EC' | 'SE' | 'E2E' | 'SC' | 'RG';
export const CASE_FAMILIES: readonly CaseFamily[] = [
  'T0',
  'DO',
  'DI',
  'DL',
  'DE',
  'EC',
  'SE',
  'E2E',
  'SC',
  'RG',
];

/** Resources the runner provides before the case starts. */
export type CaseNeed =
  /** The NVD/KEV stub, started in-process on `--nvd-port`; available as `ctx.nvdStub`. */
  'nvd-stub';

export interface TestCase {
  /** Test matrix id, for example `DO-6`. */
  readonly id: string;
  readonly family: CaseFamily;
  readonly title: string;
  /**
   * Case ids that must have passed earlier (in this invocation or a previous one recorded in the
   * results file). The runner marks the case `blocked` otherwise; it never runs them implicitly.
   */
  readonly requires?: readonly string[];
  readonly needs?: readonly CaseNeed[];
  readonly run: (ctx: CaseContext) => Promise<CaseResult>;
}

export interface HarnessConfig {
  /** Includes the base path, for example `http://localhost:5601/tdy`. */
  readonly kibanaUrl: string;
  readonly esUrl: string;
  readonly username: string;
  readonly password: string;
  readonly space: string;
  /** Results, state, and the Markdown report are written here. */
  readonly resultsDir: string;
  readonly nvdPort: number;
}

export interface HarnessLogger {
  readonly info: (message: string) => void;
  readonly warn: (message: string) => void;
  readonly debug: (message: string) => void;
}

export interface RunWorkflowArgs {
  readonly workflow: WorkflowKey;
  /**
   * Variant YAML from a `variants/*` builder. Omit it to test-run the STORED production YAML
   * (trigger `prod` in the test matrix).
   */
  readonly yaml?: string;
  /**
   * Attribution id; defaults to the managed id of `workflow`, so runs show on the monitoring
   * dashboard. Use an `si-test-` id for the fallback form.
   */
  readonly workflowId?: string;
  readonly inputs?: JsonObject;
  readonly wait?: WaitOptions;
}

export interface CaseContext {
  readonly config: HarnessConfig;
  readonly kibana: KibanaClient;
  readonly es: EsClient;
  /** Generation time of the synthetic logs (`--t0`, else the value `logs` recorded, else now). */
  readonly t0: Date;
  readonly log: HarnessLogger;
  /** Set when the case declares `needs: ['nvd-stub']`. */
  readonly nvdStub?: NvdStub;
  /** Results of earlier cases (this invocation first, then the results file). */
  readonly priorResults: ReadonlyMap<string, CaseRecord>;
  /** Test-runs a workflow (variant or stored YAML), waits for it, and records its execution id. */
  readonly runWorkflow: (args: RunWorkflowArgs) => Promise<CompletedRun>;
  /** Writes a phase of the synthetic logs (template and data stream are created when missing). */
  readonly writeLogs: (phase: LogPhase) => Promise<{ written: number; existing: number }>;
  /** Writes ad-hoc synthetic log documents (for example DL-10 or DO-15). */
  readonly writeLogDocs: (
    docs: readonly SyntheticLogDoc[]
  ) => Promise<{ written: number; existing: number }>;
  /** Writes a phase of the synthetic Defend process events (data stream created when missing). */
  readonly writeEndpointLogs: (
    phase: EndpointPhase
  ) => Promise<{ written: number; existing: number }>;
  /** Writes ad-hoc synthetic Defend process events (for example the DE-4 restore). */
  readonly writeEndpointDocs: (
    docs: readonly SyntheticEndpointDoc[]
  ) => Promise<{ written: number; existing: number }>;
}

export type CaseStatus = 'pass' | 'fail' | 'blocked' | 'error';

export interface CaseResult {
  readonly status: CaseStatus;
  /** One entry per assertion layer (engine, step, inventory), in that order. */
  readonly layers: readonly LayerResult[];
  readonly notes?: readonly string[];
}

/** What the runner stores for each executed case. */
export interface CaseRecord extends CaseResult {
  readonly id: string;
  readonly family: CaseFamily;
  readonly title: string;
  readonly startedAt: string;
  readonly durationMs: number;
  readonly executionIds: readonly string[];
}

/** Builds a result: `pass` when every layer passed, `fail` otherwise. */
export const caseResult = (
  layers: readonly LayerResult[],
  notes?: readonly string[]
): CaseResult => ({
  status: layers.every((layer) => layer.pass) ? 'pass' : 'fail',
  layers,
  ...(notes && notes.length > 0 ? { notes } : {}),
});

/** A case that could not run (missing prerequisite, resource, or stack state). */
export const blockedResult = (reason: string): CaseResult => ({
  status: 'blocked',
  layers: [],
  notes: [reason],
});
