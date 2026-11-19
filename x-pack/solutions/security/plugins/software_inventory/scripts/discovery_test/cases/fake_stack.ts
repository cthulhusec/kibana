/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Test double for the DL and SE case tests: an in-memory Elasticsearch behind the real
 * `createEsClient`, and a Kibana client behind a registry of fake workflow executions. It
 * evaluates only the query clauses the cases use (bool, term, terms, prefix, range, exists).
 */

import type { JsonValue, StepExecutionDetail, WorkflowExecution } from '../clients';
import { createEsClient, createKibanaClient, toCompletedRun } from '../clients';
import type { CompletedRun, FetchFn, KibanaClient, EsClient } from '../clients';
import { buildEndpointDocs } from '../logs/generate_endpoint';
import type { EndpointPhase, SyntheticEndpointDoc } from '../logs/generate_endpoint';
import type { LogPhase, SyntheticLogDoc } from '../logs/generate_logs';
import { buildPhaseDocs } from '../logs/generate_logs';
import type { CaseContext, CaseRecord, HarnessConfig, RunWorkflowArgs } from './types';

export type DocValue = string | number | boolean | null | undefined | DocValue[] | Doc;
export interface Doc {
  [key: string]: DocValue;
}

const isDoc = (value: DocValue): value is Doc =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const valuesAt = (doc: DocValue, path: string): DocValue[] => {
  let current: DocValue[] = [doc];
  for (const part of path.split('.')) {
    current = current.flatMap((item) => {
      if (Array.isArray(item)) return item.flatMap((inner) => (isDoc(inner) ? [inner[part]] : []));
      return isDoc(item) ? [item[part]] : [];
    });
  }
  return current.flatMap((item) => (Array.isArray(item) ? item : [item])).filter((v) => v != null);
};

const asArray = (value: DocValue): DocValue[] => (Array.isArray(value) ? value : [value]);

const toComparable = (value: DocValue): number | string => {
  if (typeof value === 'number') return value;
  const text = String(value);
  const parsed = Date.parse(text);
  return Number.isNaN(parsed) ? text : parsed;
};

const clauses = (value: DocValue): DocValue[] => (value === undefined ? [] : asArray(value));

export const matches = (doc: Doc, query: DocValue): boolean => {
  if (!isDoc(query) || Object.keys(query).length === 0) return true;
  const [[kind, spec]] = Object.entries(query);
  if (kind === 'match_all') return true;
  if (kind === 'bool' && isDoc(spec)) {
    const should = clauses(spec.should);
    const minimum = typeof spec.minimum_should_match === 'number' ? spec.minimum_should_match : 0;
    return (
      [...clauses(spec.filter), ...clauses(spec.must)].every((q) => matches(doc, q)) &&
      clauses(spec.must_not).every((q) => !matches(doc, q)) &&
      (should.length === 0 || minimum === 0
        ? true
        : should.filter((q) => matches(doc, q)).length >= minimum)
    );
  }
  if (!isDoc(spec)) throw new Error(`Unsupported query ${JSON.stringify(query)}`);
  const [[field, argument]] = Object.entries(spec);
  const actual = valuesAt(doc, field);
  if (kind === 'term') {
    const wanted = isDoc(argument) ? argument.value : argument;
    return actual.some((value) => String(value) === String(wanted));
  }
  if (kind === 'terms') {
    const wanted = asArray(argument).map(String);
    return actual.some((value) => wanted.includes(String(value)));
  }
  if (kind === 'prefix') return actual.some((value) => String(value).startsWith(String(argument)));
  if (kind === 'exists') return valuesAt(doc, String(argument)).length > 0;
  if (kind === 'range' && isDoc(argument)) {
    return actual.some((value) => {
      const left = toComparable(value);
      const check = (bound: DocValue, op: (a: number | string, b: number | string) => boolean) =>
        bound === undefined || op(left, toComparable(bound));
      return (
        check(argument.gte, (a, b) => a >= b) &&
        check(argument.gt, (a, b) => a > b) &&
        check(argument.lte, (a, b) => a <= b) &&
        check(argument.lt, (a, b) => a < b)
      );
    });
  }
  throw new Error(`Unsupported query ${JSON.stringify(query)}`);
};

const mergeDeep = (target: Doc, patch: Doc): Doc => {
  const result: Doc = { ...target };
  for (const [key, value] of Object.entries(patch)) {
    const current = result[key];
    result[key] = isDoc(value) && isDoc(current) ? mergeDeep(current, value) : value;
  }
  return result;
};

interface Stored {
  source: Doc;
  version: number;
}

export interface FakeStepResult {
  readonly status?: string;
  readonly input?: JsonValue;
  readonly output?: JsonValue;
  readonly error?: JsonValue;
}

export interface FakeRun {
  readonly workflowId: string;
  readonly status?: string;
  readonly steps: Readonly<Record<string, FakeStepResult>>;
}

const json = (body: object | null, status = 200): Response =>
  new Response(JSON.stringify(body), { status });

export interface FakeStack {
  readonly es: EsClient;
  readonly kibana: KibanaClient;
  readonly put: (name: string, id: string, source: Doc) => void;
  readonly get: (name: string, id: string) => Doc | undefined;
  readonly version: (name: string, id: string) => number | undefined;
  readonly all: (name: string) => Doc[];
  readonly dataStreams: Set<string>;
  readonly templates: Set<string>;
  readonly calls: string[];
  readonly logPhasesWritten: LogPhase[];
  readonly endpointPhasesWritten: EndpointPhase[];
  readonly registerRun: (run: FakeRun) => CompletedRun;
  readonly buildContext: (options: {
    t0: Date;
    runWorkflow: (args: RunWorkflowArgs) => CompletedRun | Promise<CompletedRun>;
    priorResults?: ReadonlyMap<string, CaseRecord>;
  }) => { ctx: CaseContext; started: RunWorkflowArgs[]; executionIds: string[] };
}

export const buildFakeStack = (): FakeStack => {
  const indices = new Map<string, Map<string, Stored>>();
  const dataStreams = new Set<string>();
  const templates = new Set<string>();
  const calls: string[] = [];
  const executions = new Map<string, WorkflowExecution>();
  const stepDetails = new Map<string, StepExecutionDetail>();
  let counter = 0;

  const index = (name: string): Map<string, Stored> => {
    const found = indices.get(name) ?? new Map<string, Stored>();
    indices.set(name, found);
    return found;
  };

  const put = (name: string, id: string, source: Doc): void => {
    const store = index(name);
    store.set(id, { source, version: (store.get(id)?.version ?? 0) + 1 });
  };

  const bulk = (body: string): Response => {
    const lines = body.split('\n').filter((line) => line !== '');
    const items: object[] = [];
    for (let i = 0; i < lines.length; i += 2) {
      const [[op, meta]] = Object.entries(JSON.parse(lines[i]) as Record<string, Doc>);
      const target = String(meta._index);
      const id = String(meta._id);
      if (op === 'create' && index(target).has(id)) {
        items.push({
          create: { status: 409, error: { type: 'version_conflict_engine_exception' } },
        });
        continue;
      }
      put(target, id, JSON.parse(lines[i + 1]) as Doc);
      items.push({ [op]: { status: 201 } });
    }
    return json({ errors: items.some((item) => JSON.stringify(item).includes('409')), items });
  };

  const fetchEs: FetchFn = async (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? 'GET';
    const path = decodeURIComponent(url.pathname);
    calls.push(`${method} ${path}`);
    const body = init?.body === undefined ? '' : String(init.body);
    const parts = path.split('/').filter((part) => part !== '');
    if (path === '/_bulk') return bulk(body);
    if (parts[0] === '_data_stream') {
      const name = parts[1];
      if (method === 'GET' && name.includes('*')) {
        const prefix = name.replace('*', '');
        return json({
          data_streams: [...dataStreams]
            .filter((n) => n.startsWith(prefix))
            .map((n) => ({ name: n })),
        });
      }
      if (method === 'GET')
        return dataStreams.has(name) ? json({ data_streams: [{ name }] }) : json({}, 404);
      if (method === 'PUT') {
        dataStreams.add(name);
        return json({ acknowledged: true });
      }
      if (method === 'DELETE') {
        if (!dataStreams.delete(name)) return json({}, 404);
        indices.delete(name);
        return json({ acknowledged: true });
      }
    }
    if (parts[0] === '_index_template' && parts[1] !== '_simulate_index') {
      const name = parts[1];
      if (method === 'PUT') {
        templates.add(name);
        return json({ acknowledged: true });
      }
      if (method === 'DELETE')
        return templates.delete(name) ? json({ acknowledged: true }) : json({}, 404);
      return templates.has(name) ? json({}) : json({}, 404);
    }
    const [name, action, id] = parts;
    const store = index(name);
    // Every write is visible to the next read in this fake, so a refresh has nothing to do.
    if (action === '_refresh' && method === 'POST') return json({ _shards: { failed: 0 } });
    if (action === '_search') {
      const request = JSON.parse(body || '{}') as Doc;
      let hits = [...store.entries()]
        .filter(([, stored]) => matches(stored.source, request.query))
        .map(([_id, stored]) => ({ _id, _index: name, _source: stored.source }));
      const sort = clauses(request.sort);
      if (sort.length > 0 && isDoc(sort[0])) {
        const [field] = Object.keys(sort[0]);
        hits = hits.sort((a, b) => {
          const left = toComparable(valuesAt(a._source, field)[0]);
          const right = toComparable(valuesAt(b._source, field)[0]);
          return left < right ? -1 : left > right ? 1 : 0;
        });
      }
      const size = typeof request.size === 'number' ? request.size : 10;
      return json({ hits: { total: { value: hits.length }, hits: hits.slice(0, size) } });
    }
    if (action === '_delete_by_query' && method === 'POST') {
      const request = JSON.parse(body || '{}') as Doc;
      const doomed = [...store.entries()].filter(([, stored]) =>
        matches(stored.source, request.query)
      );
      doomed.forEach(([docId]) => store.delete(docId));
      return json({ deleted: doomed.length });
    }
    if (action === '_count') {
      const request = JSON.parse(body || '{}') as Doc;
      return json({
        count: [...store.values()].filter((stored) => matches(stored.source, request.query)).length,
      });
    }
    if (action === '_mget') {
      const { ids } = JSON.parse(body) as { ids: string[] };
      return json({
        docs: ids.map((docId) => {
          const stored = store.get(docId);
          return stored
            ? { _id: docId, found: true, _source: stored.source }
            : { _id: docId, found: false };
        }),
      });
    }
    if (action === '_doc' && method === 'GET') {
      const stored = store.get(id);
      return stored
        ? json({ found: true, _version: stored.version, _source: stored.source })
        : json({ found: false }, 404);
    }
    if (action === '_update') {
      const stored = store.get(id);
      if (!stored) return json({ error: 'not found' }, 404);
      put(name, id, mergeDeep(stored.source, (JSON.parse(body) as { doc: Doc }).doc));
      return json({ result: 'updated' });
    }
    return json({ error: `unhandled ${method} ${path}` }, 500);
  };

  const fetchKibana: FetchFn = async (input) => {
    const parts = new URL(String(input)).pathname.split('/').filter((part) => part !== '');
    const executionId = parts[3];
    if (parts[2] === 'executions' && parts[4] === 'step') {
      const detail = stepDetails.get(`${executionId}/${parts[5]}`);
      return detail ? json(detail) : json({}, 404);
    }
    const execution = executions.get(executionId);
    return execution ? json(execution) : json({}, 404);
  };

  const credentials = { username: 'elastic', password: 'changeme' };
  const es: EsClient = createEsClient({ ...credentials, esUrl: 'http://es', fetchFn: fetchEs });
  const kibana: KibanaClient = createKibanaClient({
    ...credentials,
    kibanaUrl: 'http://kbn',
    space: 'default',
    fetchFn: fetchKibana,
  });

  /** Registers a finished execution and returns it as a `CompletedRun`. */
  const registerRun = (run: FakeRun): CompletedRun => {
    const id = `exec-${++counter}`;
    const stepExecutions = Object.entries(run.steps).map(([stepId, result], position) => {
      const stepExecutionId = `${id}-s${position}`;
      const summary = {
        id: stepExecutionId,
        stepId,
        status: result.status ?? 'completed',
        ...(result.error !== undefined ? { error: result.error } : {}),
      };
      stepDetails.set(`${id}/${stepExecutionId}`, {
        ...summary,
        ...(result.input !== undefined ? { input: result.input } : {}),
        ...(result.output !== undefined ? { output: result.output } : {}),
      });
      return summary;
    });
    const execution: WorkflowExecution = {
      id,
      workflowId: run.workflowId,
      status: run.status ?? 'completed',
      isTestRun: true,
      stepExecutions,
    };
    executions.set(id, execution);
    return toCompletedRun(kibana, execution);
  };

  const logPhasesWritten: LogPhase[] = [];
  const endpointPhasesWritten: EndpointPhase[] = [];

  const buildContext = (options: {
    t0: Date;
    runWorkflow: (args: RunWorkflowArgs) => CompletedRun | Promise<CompletedRun>;
    priorResults?: ReadonlyMap<string, CaseRecord>;
  }): { ctx: CaseContext; started: RunWorkflowArgs[]; executionIds: string[] } => {
    const started: RunWorkflowArgs[] = [];
    const executionIds: string[] = [];
    const writeDocs = (docs: readonly SyntheticLogDoc[]) => {
      let written = 0;
      let existing = 0;
      dataStreams.add('logs-softwareinventory.synthetic-default');
      for (const doc of docs) {
        const store = index('logs-softwareinventory.synthetic-default');
        if (store.has(doc._id)) existing++;
        else written++;
        put(
          'logs-softwareinventory.synthetic-default',
          doc._id,
          JSON.parse(JSON.stringify(doc._source))
        );
      }
      return Promise.resolve({ written, existing });
    };
    const endpointStream = 'logs-endpoint.events.process-sisynthetic';
    const writeEndpoint = (docs: readonly SyntheticEndpointDoc[]) => {
      let written = 0;
      let existing = 0;
      dataStreams.add(endpointStream);
      for (const doc of docs) {
        if (index(endpointStream).has(doc._id)) existing++;
        else written++;
        put(endpointStream, doc._id, JSON.parse(JSON.stringify(doc._source)));
      }
      return Promise.resolve({ written, existing });
    };
    const config: HarnessConfig = {
      kibanaUrl: 'http://kbn',
      esUrl: 'http://es',
      ...credentials,
      space: 'default',
      resultsDir: '/tmp/unused',
      nvdPort: 0,
    };
    const ctx: CaseContext = {
      config,
      kibana,
      es,
      t0: options.t0,
      log: { info: () => {}, warn: () => {}, debug: () => {} },
      priorResults: options.priorResults ?? new Map(),
      runWorkflow: async (args) => {
        started.push(args);
        const run = await options.runWorkflow(args);
        executionIds.push(run.executionId);
        return run;
      },
      writeLogs: (phase) => {
        logPhasesWritten.push(phase);
        return writeDocs(buildPhaseDocs(phase, options.t0));
      },
      writeLogDocs: writeDocs,
      writeEndpointLogs: (phase) => {
        endpointPhasesWritten.push(phase);
        return writeEndpoint(buildEndpointDocs(phase, options.t0));
      },
      writeEndpointDocs: writeEndpoint,
    };
    return { ctx, started, executionIds };
  };

  return {
    es,
    kibana,
    put,
    get: (name: string, id: string): Doc | undefined => index(name).get(id)?.source,
    version: (name: string, id: string): number | undefined => index(name).get(id)?.version,
    all: (name: string): Doc[] => [...index(name).values()].map(({ source }) => source),
    dataStreams,
    templates,
    calls,
    logPhasesWritten,
    endpointPhasesWritten,
    registerRun,
    buildContext,
  };
};
