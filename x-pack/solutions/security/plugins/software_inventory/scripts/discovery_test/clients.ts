/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Kibana and Elasticsearch helpers for the discovery test harness. Plain `fetch` with basic auth,
 * bounded request timeouts, bounded polling, and errors that carry the method, path, status, and
 * the start of the response body.
 */

import { API_VERSION as INTERNAL_API_VERSION } from '../../common/constants';

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export interface JsonObject {
  [key: string]: JsonValue;
}

export type FetchFn = typeof fetch;

/** Public workflow API version. */
export const PUBLIC_API_VERSION = '2023-10-31';
export const TERMINAL_EXECUTION_STATUSES = [
  'completed',
  'failed',
  'cancelled',
  'timed_out',
  'skipped',
] as const;
export type TerminalExecutionStatus = (typeof TERMINAL_EXECUTION_STATUSES)[number];

const DEFAULT_REQUEST_TIMEOUT_MS = 60_000;
const DEFAULT_POLL_TIMEOUT_MS = 5 * 60_000;
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const ERROR_BODY_LIMIT = 800;

export class HttpError extends Error {
  constructor(
    public readonly method: string,
    public readonly url: string,
    public readonly status: number,
    public readonly body: string
  ) {
    super(`${method} ${url} failed with ${status}: ${body.slice(0, ERROR_BODY_LIMIT)}`);
    this.name = 'HttpError';
  }
}

export interface Credentials {
  readonly username: string;
  readonly password: string;
}

export const basicAuthHeader = ({ username, password }: Credentials): string =>
  `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;

type QueryValue = string | number | boolean | undefined;

export const buildQueryString = (query?: Readonly<Record<string, QueryValue>>): string => {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined) params.append(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : '';
};

export const getSpacePrefix = (space: string): string =>
  space === '' || space === 'default' ? '' : `/s/${encodeURIComponent(space)}`;

interface RequestOptions {
  readonly body?: object | string;
  readonly query?: Readonly<Record<string, QueryValue>>;
  readonly headers?: Readonly<Record<string, string>>;
  /** Statuses returned as `{ status, body }` instead of thrown (for example 404). */
  readonly allowStatuses?: readonly number[];
  readonly timeoutMs?: number;
}

export interface RawResponse<T> {
  readonly status: number;
  readonly body: T;
}

const createRequester =
  (baseUrl: string, baseHeaders: Readonly<Record<string, string>>, fetchFn: FetchFn) =>
  async <T>(
    method: string,
    path: string,
    options: RequestOptions = {}
  ): Promise<RawResponse<T>> => {
    const url = `${baseUrl}${path}${buildQueryString(options.query)}`;
    const body =
      options.body === undefined
        ? undefined
        : typeof options.body === 'string'
        ? options.body
        : JSON.stringify(options.body);
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS
    );
    let response: Response;
    let text: string;
    try {
      response = await fetchFn(url, {
        method,
        headers: {
          ...baseHeaders,
          ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...options.headers,
        },
        body,
        signal: controller.signal,
      });
      text = await response.text();
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok && !(options.allowStatuses ?? []).includes(response.status)) {
      throw new HttpError(method, url, response.status, text);
    }
    const parsed = text === '' ? null : safeJsonParse(text);
    return { status: response.status, body: parsed as T };
  };

const safeJsonParse = (text: string): JsonValue => {
  try {
    return JSON.parse(text) as JsonValue;
  } catch {
    return text;
  }
};

// -------------------------------------------------------------------------------------------------
// Kibana
// -------------------------------------------------------------------------------------------------

export interface StepExecutionSummary {
  readonly id: string;
  readonly stepId: string;
  readonly stepType?: string;
  readonly status: string;
  readonly error?: JsonValue;
  readonly startedAt?: string;
  readonly finishedAt?: string;
}

export interface WorkflowExecution {
  readonly id: string;
  readonly workflowId?: string;
  readonly status: string;
  readonly isTestRun?: boolean;
  readonly createdAt?: string;
  readonly startedAt?: string;
  readonly finishedAt?: string;
  readonly error?: JsonValue;
  readonly stepExecutions: readonly StepExecutionSummary[];
}

export interface StepExecutionDetail extends StepExecutionSummary {
  readonly input?: JsonValue;
  readonly output?: JsonValue;
}

export interface WorkflowSummary {
  readonly id: string;
  readonly name: string;
  readonly enabled: boolean;
  readonly managed?: boolean;
  readonly definitionHash?: string;
  readonly yaml?: string;
}

export interface WorkflowList {
  readonly results: readonly WorkflowSummary[];
  readonly total: number;
}

export interface TestRunRequest {
  /** Saved (or managed) workflow id the execution is attributed to. */
  readonly workflowId?: string;
  /** Variant YAML; omitted to test-run the stored YAML. */
  readonly workflowYaml?: string;
  readonly inputs?: JsonObject;
}

export interface WaitOptions {
  readonly timeoutMs?: number;
  readonly intervalMs?: number;
}

export interface KibanaClientOptions extends Credentials {
  /** Include the base path, for example `http://localhost:5601/tdy`. */
  readonly kibanaUrl: string;
  readonly space: string;
  readonly fetchFn?: FetchFn;
  /** Injected for tests. */
  readonly sleep?: (ms: number) => Promise<void>;
}

export const isTerminalStatus = (status: string): status is TerminalExecutionStatus =>
  (TERMINAL_EXECUTION_STATUSES as readonly string[]).includes(status);

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

export const createKibanaClient = (options: KibanaClientOptions) => {
  const fetchFn = options.fetchFn ?? fetch;
  const sleep = options.sleep ?? defaultSleep;
  const base = `${options.kibanaUrl.replace(/\/+$/, '')}${getSpacePrefix(options.space)}`;
  const auth = basicAuthHeader(options);
  const publicRequest = createRequester(
    base,
    {
      authorization: auth,
      'kbn-xsrf': 'software-inventory-discovery-test',
      'elastic-api-version': PUBLIC_API_VERSION,
    },
    fetchFn
  );
  const internalRequest = createRequester(
    base,
    {
      authorization: auth,
      'kbn-xsrf': 'software-inventory-discovery-test',
      'elastic-api-version': INTERNAL_API_VERSION,
      'x-elastic-internal-origin': 'kibana',
    },
    fetchFn
  );

  const getExecution = async (executionId: string): Promise<WorkflowExecution> =>
    (
      await publicRequest<WorkflowExecution>(
        'GET',
        `/api/workflows/executions/${encodeURIComponent(executionId)}`
      )
    ).body;

  const getStepExecution = async (
    executionId: string,
    stepExecutionId: string
  ): Promise<StepExecutionDetail> =>
    (
      await publicRequest<StepExecutionDetail>(
        'GET',
        `/api/workflows/executions/${encodeURIComponent(executionId)}/step/${encodeURIComponent(
          stepExecutionId
        )}`
      )
    ).body;

  /** Polls until the execution reaches a terminal status; throws after `timeoutMs`. */
  const waitForExecution = async (
    executionId: string,
    { timeoutMs = DEFAULT_POLL_TIMEOUT_MS, intervalMs = DEFAULT_POLL_INTERVAL_MS }: WaitOptions = {}
  ): Promise<WorkflowExecution> => {
    const deadline = Date.now() + timeoutMs;
    let last: WorkflowExecution | undefined;
    while (Date.now() <= deadline) {
      last = await getExecution(executionId);
      if (isTerminalStatus(last.status)) return last;
      await sleep(intervalMs);
    }
    throw new Error(
      `Execution ${executionId} did not finish within ${timeoutMs} ms (last status: ${
        last?.status ?? 'unknown'
      })`
    );
  };

  return {
    baseUrl: base,
    request: publicRequest,
    internalRequest,

    /** `POST /api/workflows/test`; returns the execution id. */
    testRun: async ({ workflowId, workflowYaml, inputs = {} }: TestRunRequest): Promise<string> => {
      if (!workflowId && !workflowYaml) {
        throw new Error('testRun needs a workflowId, a workflowYaml, or both');
      }
      const { body } = await publicRequest<{ workflowExecutionId?: string }>(
        'POST',
        '/api/workflows/test',
        {
          body: {
            ...(workflowId ? { workflowId } : {}),
            ...(workflowYaml ? { workflowYaml } : {}),
            inputs,
          },
        }
      );
      if (!body?.workflowExecutionId) {
        throw new Error(
          `POST /api/workflows/test returned no workflowExecutionId: ${JSON.stringify(body)}`
        );
      }
      return body.workflowExecutionId;
    },
    getExecution,
    getStepExecution,
    waitForExecution,

    listWorkflows: async ({
      managed = false,
      page = 1,
      size = 100,
      query,
    }: {
      managed?: boolean;
      page?: number;
      size?: number;
      query?: string;
    } = {}): Promise<WorkflowList> =>
      (
        await publicRequest<WorkflowList>('GET', '/api/workflows', {
          query: {
            size,
            page,
            ...(managed ? { managed: 'managed' } : {}),
            ...(query ? { query } : {}),
          },
        })
      ).body,
    getWorkflow: async (id: string): Promise<WorkflowSummary | undefined> => {
      const { status, body } = await publicRequest<WorkflowSummary>(
        'GET',
        `/api/workflows/workflow/${encodeURIComponent(id)}`,
        { allowStatuses: [404] }
      );
      return status === 404 ? undefined : body;
    },
    /** Hard delete (`force=true`) also removes the workflow's executions. */
    deleteWorkflow: async (
      id: string,
      { force = true }: { force?: boolean } = {}
    ): Promise<boolean> => {
      const { status } = await publicRequest<JsonValue>(
        'DELETE',
        `/api/workflows/workflow/${encodeURIComponent(id)}`,
        { query: { force }, allowStatuses: [404] }
      );
      return status !== 404;
    },

    // Internal software inventory routes (need the internal origin header).
    getInstances: async (query: Readonly<Record<string, QueryValue>>): Promise<JsonObject> =>
      (
        await internalRequest<JsonObject>('GET', '/internal/software_inventory/instances', {
          query,
        })
      ).body,
    getCatalogDetail: async (catalogId: string): Promise<RawResponse<JsonObject>> =>
      internalRequest<JsonObject>(
        'GET',
        `/internal/software_inventory/catalog/${encodeURIComponent(catalogId)}`,
        { allowStatuses: [404] }
      ),
    getHostTimeline: async (
      hostKey: string,
      range: { from: string; to: string }
    ): Promise<RawResponse<JsonObject>> =>
      internalRequest<JsonObject>(
        'GET',
        `/internal/software_inventory/hosts/${encodeURIComponent(hostKey)}/timeline`,
        { query: range, allowStatuses: [404] }
      ),
    getTrends: async (range: { from: string; to: string }): Promise<JsonObject> =>
      (
        await internalRequest<JsonObject>('GET', '/internal/software_inventory/trends', {
          query: range,
        })
      ).body,
  };
};

export type KibanaClient = ReturnType<typeof createKibanaClient>;

// -------------------------------------------------------------------------------------------------
// Elasticsearch
// -------------------------------------------------------------------------------------------------

export interface EsClientOptions extends Credentials {
  readonly esUrl: string;
  readonly fetchFn?: FetchFn;
}

export interface SearchHit<T> {
  readonly _id: string;
  readonly _index: string;
  readonly _source?: T;
  readonly sort?: Array<string | number>;
}

export interface SearchResponse<T> {
  readonly hits: { readonly total?: { value: number }; readonly hits: ReadonlyArray<SearchHit<T>> };
  readonly aggregations?: JsonObject;
}

export interface MgetResponse<T> {
  readonly docs: ReadonlyArray<{ _id: string; found?: boolean; _source?: T }>;
}

export interface BulkResponse {
  readonly errors: boolean;
  readonly items: ReadonlyArray<
    Record<string, { status: number; error?: JsonValue; _id?: string }>
  >;
}

export interface BulkSummary {
  readonly total: number;
  readonly failed: number;
  /** Items rejected as already existing (`create` with a fixed id). */
  readonly conflicts: number;
  readonly firstError?: string;
}

export const summarizeBulk = (response: BulkResponse): BulkSummary => {
  let failed = 0;
  let conflicts = 0;
  let firstError: string | undefined;
  for (const item of response.items) {
    const result = Object.values(item)[0];
    if (!result?.error) continue;
    if (result.status === 409) {
      conflicts++;
      continue;
    }
    failed++;
    firstError ??= JSON.stringify(result.error);
  }
  return { total: response.items.length, failed, conflicts, ...(firstError ? { firstError } : {}) };
};

export const createEsClient = (options: EsClientOptions) => {
  const request = createRequester(
    options.esUrl.replace(/\/+$/, ''),
    { authorization: basicAuthHeader(options) },
    options.fetchFn ?? fetch
  );

  return {
    request,
    search: async <T>(index: string, body: object): Promise<SearchResponse<T>> =>
      (
        await request<SearchResponse<T>>('POST', `/${index}/_search`, {
          body,
          query: { ignore_unavailable: true, allow_no_indices: true },
        })
      ).body,
    count: async (index: string, query?: object): Promise<number> => {
      const { body } = await request<{ count: number }>('POST', `/${index}/_count`, {
        body: query ? { query } : {},
        query: { ignore_unavailable: true, allow_no_indices: true },
      });
      return body.count;
    },
    mget: async <T>(index: string, ids: readonly string[]): Promise<MgetResponse<T>> =>
      (await request<MgetResponse<T>>('POST', `/${index}/_mget`, { body: { ids } })).body,
    /** Sends NDJSON bulk operations; `refresh` defaults to `wait_for`. */
    bulk: async (
      operations: readonly object[],
      { refresh = 'wait_for' }: { refresh?: 'true' | 'false' | 'wait_for' } = {}
    ): Promise<BulkSummary> => {
      if (operations.length === 0) return { total: 0, failed: 0, conflicts: 0 };
      const body = `${operations.map((op) => JSON.stringify(op)).join('\n')}\n`;
      const { body: response } = await request<BulkResponse>('POST', '/_bulk', {
        body,
        query: { refresh },
        headers: { 'content-type': 'application/x-ndjson' },
      });
      return summarizeBulk(response);
    },
    deleteByQuery: async (index: string, query: object): Promise<number> => {
      const { body } = await request<{ deleted: number }>('POST', `/${index}/_delete_by_query`, {
        body: { query },
        query: {
          refresh: true,
          conflicts: 'proceed',
          ignore_unavailable: true,
          allow_no_indices: true,
        },
        timeoutMs: 5 * 60_000,
      });
      return body.deleted;
    },
    exists: async (path: string): Promise<boolean> => {
      const { status } = await request<JsonValue>('GET', path, { allowStatuses: [404] });
      return status !== 404;
    },
  };
};

export type EsClient = ReturnType<typeof createEsClient>;

// -------------------------------------------------------------------------------------------------
// Run and wait
// -------------------------------------------------------------------------------------------------

/** A finished execution plus lazy access to each step's `input` and `output`. */
export interface CompletedRun {
  readonly executionId: string;
  readonly execution: WorkflowExecution;
  /** Step executions by step name (the last one when a step ran more than once). */
  readonly stepsByName: ReadonlyMap<string, StepExecutionSummary>;
  /** Fetches (and caches) the step detail with `input` and `output`; throws if the step never ran. */
  readonly step: (stepName: string) => Promise<StepExecutionDetail>;
}

export const toCompletedRun = (
  kibana: Pick<KibanaClient, 'getStepExecution'>,
  execution: WorkflowExecution
): CompletedRun => {
  const stepsByName = new Map(execution.stepExecutions.map((step) => [step.stepId, step]));
  const cache = new Map<string, Promise<StepExecutionDetail>>();
  return {
    executionId: execution.id,
    execution,
    stepsByName,
    step: (stepName) => {
      const summary = stepsByName.get(stepName);
      if (!summary) {
        return Promise.reject(
          new Error(
            `Step "${stepName}" did not run in execution ${execution.id} (ran: ${[
              ...stepsByName.keys(),
            ].join(', ')})`
          )
        );
      }
      const cached = cache.get(stepName) ?? kibana.getStepExecution(execution.id, summary.id);
      cache.set(stepName, cached);
      return cached;
    },
  };
};

/** Test-runs a workflow, waits for a terminal status, and returns the run. */
export const runAndWait = async (
  kibana: Pick<KibanaClient, 'testRun' | 'waitForExecution' | 'getStepExecution'>,
  request: TestRunRequest,
  wait: WaitOptions = {}
): Promise<CompletedRun> => {
  const executionId = await kibana.testRun(request);
  const execution = await kibana.waitForExecution(executionId, wait);
  return toCompletedRun(kibana, execution);
};
