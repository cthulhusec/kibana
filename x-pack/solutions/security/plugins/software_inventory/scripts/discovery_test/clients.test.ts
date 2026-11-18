/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * @jest-environment node
 */

import type { FetchFn } from './clients';
import {
  HttpError,
  buildQueryString,
  createEsClient,
  createKibanaClient,
  getSpacePrefix,
  runAndWait,
  summarizeBulk,
} from './clients';

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

const fakeFetch = (responses: Array<{ status?: number; body: object | string }>) => {
  const calls: Call[] = [];
  const fetchFn: FetchFn = async (input, init) => {
    calls.push({
      url: String(input),
      method: init?.method ?? 'GET',
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body === undefined ? undefined : String(init.body),
    });
    const next = responses.shift() ?? { status: 500, body: 'no more responses' };
    const text = typeof next.body === 'string' ? next.body : JSON.stringify(next.body);
    return new Response(text, { status: next.status ?? 200 });
  };
  return { calls, fetchFn };
};

const credentials = { username: 'elastic', password: 'changeme' };

describe('kibana client', () => {
  it('sends public headers, the space prefix, and the test-run body', async () => {
    const { calls, fetchFn } = fakeFetch([{ body: { workflowExecutionId: 'exec-1' } }]);
    const kibana = createKibanaClient({
      ...credentials,
      kibanaUrl: 'http://k/tdy/',
      space: 'sec',
      fetchFn,
    });
    await expect(
      kibana.testRun({ workflowId: 'wf', workflowYaml: 'yaml', inputs: {} })
    ).resolves.toBe('exec-1');
    expect(calls[0].url).toBe('http://k/tdy/s/sec/api/workflows/test');
    expect(calls[0].headers).toEqual(
      expect.objectContaining({
        'kbn-xsrf': expect.any(String),
        'elastic-api-version': '2023-10-31',
        authorization: `Basic ${Buffer.from('elastic:changeme').toString('base64')}`,
      })
    );
    expect(JSON.parse(calls[0].body ?? '')).toEqual({
      workflowId: 'wf',
      workflowYaml: 'yaml',
      inputs: {},
    });
  });

  it('sends the internal origin header and version 1 to plugin routes', async () => {
    const { calls, fetchFn } = fakeFetch([{ status: 404, body: { message: 'No software found' } }]);
    const kibana = createKibanaClient({
      ...credentials,
      kibanaUrl: 'http://k',
      space: 'default',
      fetchFn,
    });
    const response = await kibana.getHostTimeline('synth-web-02', { from: 'a', to: 'b' });
    expect(response.status).toBe(404);
    expect(calls[0].url).toBe(
      'http://k/internal/software_inventory/hosts/synth-web-02/timeline?from=a&to=b'
    );
    expect(calls[0].headers).toEqual(
      expect.objectContaining({ 'elastic-api-version': '1', 'x-elastic-internal-origin': 'kibana' })
    );
  });

  it('polls until a terminal status and then reads step details lazily', async () => {
    const step = { id: 's1', stepId: 'ingest_linux', status: 'completed' };
    const { calls, fetchFn } = fakeFetch([
      { body: { workflowExecutionId: 'exec-1' } },
      { body: { id: 'exec-1', status: 'running', stepExecutions: [] } },
      { body: { id: 'exec-1', status: 'completed', stepExecutions: [step] } },
      { body: { ...step, output: { created: 1 }, input: { snapshot: true } } },
    ]);
    const kibana = createKibanaClient({
      ...credentials,
      kibanaUrl: 'http://k',
      space: 'default',
      fetchFn,
      sleep: async () => {},
    });
    const run = await runAndWait(kibana, { workflowId: 'wf' }, { intervalMs: 1 });
    expect(run.execution.status).toBe('completed');
    await expect(run.step('ingest_linux')).resolves.toEqual(
      expect.objectContaining({ output: { created: 1 } })
    );
    await run.step('ingest_linux');
    expect(calls).toHaveLength(4);
    await expect(run.step('build_linux')).rejects.toThrow(/did not run/);
  });

  it('times out polling with the last status', async () => {
    const running = { body: { id: 'exec-1', status: 'running', stepExecutions: [] } };
    const { fetchFn } = fakeFetch(Array.from({ length: 20 }, () => running));
    const kibana = createKibanaClient({
      ...credentials,
      kibanaUrl: 'http://k',
      space: 'default',
      fetchFn,
      sleep: () => new Promise((resolve) => setTimeout(resolve, 5)),
    });
    await expect(
      kibana.waitForExecution('exec-1', { timeoutMs: 20, intervalMs: 5 })
    ).rejects.toThrow(/did not finish within 20 ms \(last status: running\)/);
  });

  it('throws an HttpError with the status and body', async () => {
    const { fetchFn } = fakeFetch([{ status: 400, body: { message: 'Workflow is disabled' } }]);
    const kibana = createKibanaClient({
      ...credentials,
      kibanaUrl: 'http://k',
      space: 'default',
      fetchFn,
    });
    const error = await kibana.testRun({ workflowId: 'wf' }).catch((e: HttpError) => e);
    expect(error).toBeInstanceOf(HttpError);
    expect((error as HttpError).status).toBe(400);
    expect((error as HttpError).message).toMatch(
      /POST http:\/\/k\/api\/workflows\/test failed with 400/
    );
  });
});

describe('es client', () => {
  it('sends NDJSON bulk bodies and counts conflicts separately', async () => {
    const { calls, fetchFn } = fakeFetch([
      {
        body: {
          errors: true,
          items: [
            { create: { status: 201 } },
            { create: { status: 409, error: { type: 'version_conflict_engine_exception' } } },
          ],
        },
      },
    ]);
    const es = createEsClient({ ...credentials, esUrl: 'http://es/', fetchFn });
    const summary = await es.bulk([{ create: { _index: 'x', _id: '1' } }, { a: 1 }]);
    expect(summary).toEqual({ total: 2, failed: 0, conflicts: 1 });
    expect(calls[0].url).toBe('http://es/_bulk?refresh=wait_for');
    expect(calls[0].body).toBe('{"create":{"_index":"x","_id":"1"}}\n{"a":1}\n');
    expect(calls[0].headers['content-type']).toBe('application/x-ndjson');
  });

  it('summarizes real failures', () => {
    expect(
      summarizeBulk({
        errors: true,
        items: [{ index: { status: 400, error: { type: 'mapper' } } }],
      })
    ).toEqual({ total: 1, failed: 1, conflicts: 0, firstError: '{"type":"mapper"}' });
  });
});

describe('helpers', () => {
  it('builds query strings and space prefixes', () => {
    expect(buildQueryString({ a: 1, b: undefined, c: true })).toBe('?a=1&c=true');
    expect(buildQueryString({})).toBe('');
    expect(getSpacePrefix('default')).toBe('');
    expect(getSpacePrefix('')).toBe('');
    expect(getSpacePrefix('my space')).toBe('/s/my%20space');
  });
});
