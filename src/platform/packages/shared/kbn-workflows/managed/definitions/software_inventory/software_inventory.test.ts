/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { parse } from 'yaml';
import {
  SOFTWARE_INVENTORY_DISCOVER_INTEGRATIONS_WORKFLOW,
  SOFTWARE_INVENTORY_DISCOVER_LOGS_WORKFLOW,
  SOFTWARE_INVENTORY_DISCOVER_OSQUERY_WORKFLOW,
  SOFTWARE_INVENTORY_ENRICH_CVES_WORKFLOW,
  SOFTWARE_INVENTORY_SCORE_EXPOSURE_WORKFLOW,
  SOFTWARE_INVENTORY_WORKFLOW_IDS,
} from '.';
import { managedWorkflowDefinitions } from '..';
import { createWorkflowLiquidEngine } from '../../../common/utils';

interface Step {
  name: string;
  type: string;
  with?: Record<string, unknown>;
}
interface Workflow {
  enabled?: boolean;
  settings?: { concurrency?: { strategy?: string; max?: number } };
  triggers: Array<{ type: string }>;
  steps: Step[];
}

const definitions = [
  SOFTWARE_INVENTORY_DISCOVER_OSQUERY_WORKFLOW,
  SOFTWARE_INVENTORY_DISCOVER_INTEGRATIONS_WORKFLOW,
  SOFTWARE_INVENTORY_DISCOVER_LOGS_WORKFLOW,
  SOFTWARE_INVENTORY_ENRICH_CVES_WORKFLOW,
  SOFTWARE_INVENTORY_SCORE_EXPOSURE_WORKFLOW,
];

const render = async (
  workflow: Workflow,
  context: Record<string, unknown>,
  stepName = 'build_candidates'
): Promise<unknown[]> => {
  const build = workflow.steps.find((s) => s.name === stepName);
  const template = build?.with?.candidates_json as string;
  const out = await createWorkflowLiquidEngine().parseAndRender(template, context);
  return JSON.parse(out);
};

/** Evaluates a `${{ }}` step input the way the execution engine does. */
const evaluate = (expression: string, context: Record<string, unknown>): unknown => {
  const inner = expression.slice(expression.indexOf('{{') + 2, expression.lastIndexOf('}}'));
  return createWorkflowLiquidEngine().evalValueSync(inner.trim(), context);
};

const OSQUERY_QUERIES = ['linux', 'windows', 'macos', 'dependencies'] as const;

describe('software inventory managed workflows', () => {
  it('registers every definition with the expected ids', () => {
    expect(definitions.map((d) => d.id)).toEqual([...SOFTWARE_INVENTORY_WORKFLOW_IDS]);
    for (const definition of definitions) {
      expect(managedWorkflowDefinitions).toContain(definition);
      expect(definition.pluginId).toBe('softwareInventory');
    }
  });

  it.each(definitions.map((d) => [d.id, d] as const))(
    '%s is a disabled scheduled workflow with drop/max 1 concurrency',
    (_id, definition) => {
      const workflow = parse(definition.yaml) as Workflow;
      expect(workflow.enabled).toBe(false);
      expect(workflow.triggers.map((t) => t.type)).toEqual(['scheduled']);
      expect(workflow.settings?.concurrency).toMatchObject({ strategy: 'drop', max: 1 });
    }
  );

  it('calls the custom steps with the agreed input fields', () => {
    const byType = (yaml: string, type: string) =>
      (parse(yaml) as Workflow).steps.find((s) => s.type === type)?.with;
    expect(
      byType(SOFTWARE_INVENTORY_ENRICH_CVES_WORKFLOW.yaml, 'softwareInventory.enrichCves')
    ).toEqual({
      limit: 25,
    });
    expect(
      byType(SOFTWARE_INVENTORY_SCORE_EXPOSURE_WORKFLOW.yaml, 'softwareInventory.scoreExposure')
    ).toEqual({ lookback_days: 7 });
    expect(
      byType(SOFTWARE_INVENTORY_SCORE_EXPOSURE_WORKFLOW.yaml, 'softwareInventory.markStale')
    ).toEqual({ stale_after_days: 30 });
    const scoreSteps = (parse(SOFTWARE_INVENTORY_SCORE_EXPOSURE_WORKFLOW.yaml) as Workflow).steps;
    expect(scoreSteps.map((s) => s.type)).toEqual([
      'softwareInventory.scoreExposure',
      'softwareInventory.markStale',
      'softwareInventory.snapshotRollup',
    ]);
    expect(
      byType(
        SOFTWARE_INVENTORY_DISCOVER_INTEGRATIONS_WORKFLOW.yaml,
        'softwareInventory.ingestCandidates'
      )
    ).toMatchObject({ source: 'fleet_integration', snapshot: false });
    expect(
      byType(SOFTWARE_INVENTORY_DISCOVER_LOGS_WORKFLOW.yaml, 'softwareInventory.ingestCandidates')
    ).toMatchObject({ source: 'logs', snapshot: false });
  });

  it('ingests each osquery query in its own call with a completeness-gated snapshot', () => {
    const { steps } = parse(SOFTWARE_INVENTORY_DISCOVER_OSQUERY_WORKFLOW.yaml) as Workflow;
    for (const query of OSQUERY_QUERIES) {
      expect(steps.find((s) => s.name === `query_${query}`)?.with).toMatchObject({
        max_rows: 5000,
      });
      const ingest = steps.find((s) => s.name === `ingest_${query}`);
      expect(ingest?.type).toBe('softwareInventory.ingestCandidates');
      expect(ingest?.with).toMatchObject({ source: 'osquery' });
      expect(ingest?.with?.candidates).toContain(`steps.build_${query}.output`);
      expect(ingest?.with?.snapshot).toContain(`steps.query_${query}.output`);
    }
  });

  it('sets snapshot only for a complete query result', () => {
    const { steps } = parse(SOFTWARE_INVENTORY_DISCOVER_OSQUERY_WORKFLOW.yaml) as Workflow;
    const snapshot = steps.find((s) => s.name === 'ingest_linux')?.with?.snapshot as string;
    const withOutput = (output?: Record<string, unknown>) =>
      evaluate(snapshot, { steps: { query_linux: output ? { output } : {} } });

    expect(withOutput({ status: 'success', truncated: false })).toBe(true);
    expect(withOutput({ status: 'success', truncated: true })).toBe(false);
    expect(withOutput({ status: 'partial', truncated: false })).toBe(false);
    expect(withOutput({ status: 'failed', truncated: false })).toBe(false);
    expect(
      withOutput({ status: 'success', truncated: false, error_code: 'RESULTS_UNREADABLE' })
    ).toBe(false);
    // The query step failed and has no output.
    expect(withOutput()).toBe(false);
  });

  it('maps osquery rows to raw candidates and omits empty optional fields', async () => {
    const workflow = parse(SOFTWARE_INVENTORY_DISCOVER_OSQUERY_WORKFLOW.yaml) as Workflow;
    const context = {
      steps: {
        query_linux: {
          output: {
            rows: [
              {
                agent: { id: 'a1', name: 'h1' },
                columns: { name: 'openssl', version: '3.0.2', install_path: '' },
              },
            ],
          },
        },
        query_windows: {
          output: {
            rows: [
              {
                agent: { id: 'a2' },
                columns: { name: 'My "App"', version: '1.0', install_path: 'C:\\Apps' },
              },
            ],
          },
        },
        query_macos: { output: { rows: [] } },
        // query_dependencies failed: no output
      },
    };
    expect(await render(workflow, context, 'build_linux')).toEqual([
      { host_id: 'a1', host_name: 'h1', name: 'openssl', version: '3.0.2', category: 'os_package' },
    ]);
    expect(await render(workflow, context, 'build_windows')).toEqual([
      {
        host_id: 'a2',
        name: 'My "App"',
        version: '1.0',
        install_path: 'C:\\Apps',
        category: 'application',
      },
    ]);
    expect(await render(workflow, context, 'build_macos')).toEqual([]);
    for (const query of OSQUERY_QUERIES) {
      expect(await render(workflow, { steps: {} }, `build_${query}`)).toEqual([]);
    }
  });

  it('drops osquery rows with a blank name or agent id and omits blank optional fields', async () => {
    const workflow = parse(SOFTWARE_INVENTORY_DISCOVER_OSQUERY_WORKFLOW.yaml) as Workflow;
    const candidates = await render(
      workflow,
      {
        steps: {
          query_macos: {
            output: {
              rows: [
                {
                  agent: { id: 'a1', name: 'mac-1' },
                  columns: { name: '', version: '1', install_path: '/A.app' },
                },
                { agent: { id: 'a1', name: 'mac-1' }, columns: { name: '   ', version: '1' } },
                { agent: { id: '', name: 'mac-1' }, columns: { name: 'Orphan', version: '1' } },
                {
                  agent: { id: 'a1', name: '' },
                  columns: { name: 'Safari', version: '', install_path: '' },
                },
              ],
            },
          },
        },
      },
      'build_macos'
    );
    expect(candidates).toEqual([{ host_id: 'a1', name: 'Safari', category: 'application' }]);
  });

  it('maps fleet package policies to one candidate per agent policy', async () => {
    const workflow = parse(SOFTWARE_INVENTORY_DISCOVER_INTEGRATIONS_WORKFLOW.yaml) as Workflow;
    const candidates = await render(workflow, {
      steps: {
        list_package_policies: {
          output: {
            items: [
              { policy_ids: ['p1', 'p2'], package: { name: 'nginx', version: '1.2.3' } },
              { policy_ids: ['p1'] },
            ],
          },
        },
      },
    });
    expect(candidates).toEqual([
      {
        host_id: 'policy:p1',
        host_name: 'p1',
        name: 'nginx',
        version: '1.2.3',
        category: 'application',
      },
      {
        host_id: 'policy:p2',
        host_name: 'p2',
        name: 'nginx',
        version: '1.2.3',
        category: 'application',
      },
    ]);
  });

  it('maps ES|QL log rows to raw candidates', async () => {
    const workflow = parse(SOFTWARE_INVENTORY_DISCOVER_LOGS_WORKFLOW.yaml) as Workflow;
    const candidates = await render(workflow, {
      steps: {
        query_appliances: {
          output: {
            values: [
              ['fw-1', 'fw-1', 'Fortinet', 'FortiGate', '7.0.1', '2026-11-17T10:00:00.000Z'],
              ['SN123', null, 'Fortinet', 'FortiGate', '7.0.2', '2026-11-17T11:00:00.000Z'],
              ['fw-3', 'fw-3', null, '', '7.0.1', null],
            ],
          },
        },
        query_services: {
          output: { values: [['h2', 'web', null, 'nginx', '1.25.0', '2026-11-17T12:00:00.000Z']] },
        },
      },
    });
    expect(candidates).toEqual([
      {
        host_id: 'fw-1',
        host_name: 'fw-1',
        vendor: 'Fortinet',
        name: 'FortiGate',
        version: '7.0.1',
        observed_at: '2026-11-17T10:00:00.000Z',
        category: 'appliance',
      },
      {
        host_id: 'SN123',
        vendor: 'Fortinet',
        name: 'FortiGate',
        version: '7.0.2',
        observed_at: '2026-11-17T11:00:00.000Z',
        category: 'appliance',
      },
      {
        host_id: 'h2',
        host_name: 'web',
        name: 'nginx',
        version: '1.25.0',
        observed_at: '2026-11-17T12:00:00.000Z',
        category: 'application',
      },
    ]);
  });

  it('keys log appliances on the observer, not the collecting host', () => {
    const { steps } = parse(SOFTWARE_INVENTORY_DISCOVER_LOGS_WORKFLOW.yaml) as Workflow;
    const query = steps.find((s) => s.name === 'query_appliances')?.with?.query as string;
    expect(query).toContain('COALESCE(observer.hostname, observer.serial_number');
    expect(query).not.toMatch(/\bhost\.(id|name)\b/);
    expect(query).toContain('observed_at');
  });
});
