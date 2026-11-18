/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { InventoryEvent } from '../../common/history';
import type { InstanceDoc } from '../../common/types';
import { checkEngine, diffEvents, diffInstance, diffValues, ingestOutput } from './assertions';
import type { WorkflowExecution } from './clients';

describe('diffValues', () => {
  it('compares objects as subsets and reports paths', () => {
    expect(diffValues({ a: 1 }, { a: 1, b: 2 })).toEqual([]);
    expect(diffValues({ a: { b: 1 } }, { a: { b: 2 } })).toEqual(['$.a.b: expected 1, got 2']);
    expect(diffValues({ a: undefined }, { a: 1 })).toEqual(['$.a: expected undefined, got 1']);
  });

  it('compares arrays exactly', () => {
    expect(diffValues([1, 2], [1, 2])).toEqual([]);
    expect(diffValues([1], [1, 2])[0]).toMatch(/expected 1 item/);
    expect(diffValues(null, null)).toEqual([]);
    expect(diffValues({ a: 1 }, null)).toEqual(['$: expected an object, got null']);
  });

  it('fills omitted ingest counters with 0', () => {
    expect(ingestOutput({ created: 2, skipped: 1 })).toEqual({
      created: 2,
      unchanged: 0,
      patched: 0,
      removed: 0,
      skipped: 1,
    });
  });
});

describe('checkEngine', () => {
  const execution: WorkflowExecution = {
    id: 'exec-1',
    workflowId: 'system-security-software-inventory-discover-osquery',
    status: 'completed',
    isTestRun: true,
    stepExecutions: [
      { id: 's1', stepId: 'query_linux', status: 'failed', error: { message: 'boom' } },
      { id: 's2', stepId: 'ingest_linux', status: 'completed' },
    ],
  };

  it('passes when run and step statuses match', () => {
    const result = checkEngine(execution, { steps: { query_linux: 'failed' }, isTestRun: true });
    expect(result.pass).toBe(true);
    expect(result.checks).toBe(4);
  });

  it('reports unexpected step statuses with the step error', () => {
    const result = checkEngine(execution, {});
    expect(result.pass).toBe(false);
    expect(result.diffs).toEqual([
      'step query_linux: expected completed, got failed ({"message":"boom"})',
    ]);
  });

  it('reports steps that should not have run and a wrong run status', () => {
    const result = checkEngine(execution, {
      status: 'failed',
      defaultStepStatus: null,
      notRun: ['ingest_linux'],
    });
    expect(result.diffs).toEqual([
      'run status: expected failed, got completed',
      'step ingest_linux: expected not to run, but it ran',
    ]);
  });
});

describe('diffInstance', () => {
  const doc: InstanceDoc = {
    id: 'x',
    host: { key: 'synth-lin-01', id: 'synth-agent-lin01', name: 'synth-lin-01' },
    software_id: 'openssl:openssl:3.0.14',
    previous_software_id: 'openssl:openssl:3.0.7',
    version_history: [
      { version: '3.0.7', first_seen: 'a', last_seen: 'b' },
      { version: '3.0.14', first_seen: 'c', last_seen: 'd' },
    ],
    sources: ['osquery'],
    status: 'patched',
    first_seen: 'a',
    last_seen: 'd',
    exposure: { level: 'none', score: 0, evidence: [] },
    '@timestamp': 'd',
  };

  it('passes a matching instance', () => {
    expect(
      diffInstance(
        {
          hostKey: 'synth-lin-01',
          catalogId: 'openssl:openssl:3.0.14',
          status: 'patched',
          versions: ['3.0.7', '3.0.14'],
          sources: ['osquery'],
          hostName: 'synth-lin-01',
          previousSoftwareId: 'openssl:openssl:3.0.7',
        },
        doc
      )
    ).toEqual([]);
  });

  it('reports each mismatch with the instance label', () => {
    expect(
      diffInstance(
        {
          hostKey: 'synth-lin-01',
          catalogId: 'openssl:openssl:3.0.14',
          status: 'active',
          hostName: null,
        },
        doc
      )
    ).toEqual([
      'synth-lin-01/openssl:openssl:3.0.14: status patched != active',
      'synth-lin-01/openssl:openssl:3.0.14: host.name "synth-lin-01" != null',
    ]);
    expect(diffInstance({ hostKey: 'h', catalogId: 'a:b:1' }, undefined)).toEqual([
      'h/a:b:1: missing',
    ]);
    expect(diffInstance({ hostKey: 'h', catalogId: 'a:b:1', absent: true }, undefined)).toEqual([]);
  });
});

describe('diffEvents', () => {
  const event = (type: InventoryEvent['type'], softwareId: string): InventoryEvent => ({
    '@timestamp': '2026-11-18T10:00:00Z',
    instance_id: 'i',
    host: { key: 'synth-lin-01' },
    type,
    source: 'osquery',
    software_id: softwareId,
  });

  it('compares events as multisets', () => {
    const actual = [
      event('version_changed', 'openssl:openssl:3.0.14'),
      event('removed', 'synth-tool:synth-tool:2.0.0'),
    ];
    expect(
      diffEvents(
        [
          { type: 'removed', software_id: 'synth-tool:synth-tool:2.0.0' },
          { type: 'version_changed', software_id: 'openssl:openssl:3.0.14' },
        ],
        actual
      )
    ).toEqual([]);
    expect(diffEvents([{ type: 'removed' }], actual)[0]).toMatch(/expected 1 .* got 2/);
  });
});
