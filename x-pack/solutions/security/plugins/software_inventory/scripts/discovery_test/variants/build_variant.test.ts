/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { parse, stringify } from 'yaml';
import { createWorkflowLiquidEngine } from '@kbn/workflows/common/utils';
import {
  F_BULK_5000,
  F_BULK_5001,
  F_EMPTY,
  F_FAILED,
  OSQUERY_QUERY_STEPS,
  R1,
} from '../fixtures/osquery';
import { FLEET_MAPPED_AND_UNMAPPED } from '../fixtures/fleet';
import type { Replacements, VariantOptions, WorkflowKey } from './build_variant';
import {
  PRODUCTION_WORKFLOWS,
  THROW_STEP_PATH,
  THROW_STEP_TYPE,
  assertFidelity,
  buildVariant,
  getProductionYaml,
  helperStepName,
} from './build_variant';
import { buildOsqueryVariant, osqueryReplacements } from './osquery';
import { buildIntegrationsVariant } from './integrations';
import { buildEnrichVariant } from './enrich';

interface Step {
  name: string;
  type: string;
  with?: Record<string, string | number | boolean | object>;
  'on-failure'?: { continue?: boolean };
}
interface Workflow {
  name: string;
  settings: { concurrency: { key: string } };
  triggers: Array<{ type: string; with?: { every?: string } }>;
  steps: Step[];
}

const parseWorkflow = (yaml: string): Workflow => parse(yaml) as Workflow;
const stepOf = (workflow: Workflow, name: string): Step => {
  const step = workflow.steps.find((s) => s.name === name);
  if (!step) throw new Error(`no step ${name}`);
  return step;
};

const osqueryProduction = getProductionYaml('discoverOsquery');
const R1_OPTIONS: VariantOptions = { label: 'R1' };

describe('buildVariant on the production discover-osquery YAML', () => {
  const variant = buildOsqueryVariant({ label: 'R1', steps: R1 });
  const workflow = parseWorkflow(variant);
  const production = parseWorkflow(osqueryProduction);

  it('keeps all 12 production steps in order', () => {
    expect(workflow.steps.map((s) => s.name)).toEqual(production.steps.map((s) => s.name));
    expect(workflow.steps).toHaveLength(12);
  });

  it('replaces each query step with a data.set emitting the fixture and keeps on-failure', () => {
    for (const name of OSQUERY_QUERY_STEPS) {
      const step = stepOf(workflow, name);
      expect(step.type).toBe('data.set');
      expect(step.with).toEqual(R1[name].output);
      expect(step['on-failure']).toEqual({ continue: true });
    }
  });

  it('keeps every other step byte-identical (production text appears verbatim)', () => {
    const buildLinuxStart = osqueryProduction.indexOf('  # Row -> RawCandidate mapping only');
    expect(buildLinuxStart).toBeGreaterThan(0);
    expect(variant).toContain(osqueryProduction.slice(buildLinuxStart));
    for (const name of production.steps.map((s) => s.name)) {
      if (name.startsWith('query_')) continue;
      expect(stepOf(workflow, name)).toEqual(stepOf(production, name));
    }
  });

  it('keeps settings and triggers and suffixes the name', () => {
    expect(workflow.settings).toEqual(production.settings);
    expect(workflow.triggers).toEqual(production.triggers);
    expect(workflow.name).toBe(`${production.name} [test: R1]`);
  });

  it('defaults query steps the spec leaves out to F-empty', () => {
    const replacements = osqueryReplacements({ query_linux: F_FAILED });
    expect(replacements.query_linux).toEqual({ kind: 'fixture', output: F_FAILED.output });
    expect(replacements.query_macos).toEqual({ kind: 'fixture', output: F_EMPTY.output });
  });

  it('replaces a step with a failing elasticsearch.request for `throw`', () => {
    const thrown = parseWorkflow(
      buildOsqueryVariant({ label: 'throw', steps: { query_linux: { kind: 'throw' } } })
    );
    const step = stepOf(thrown, 'query_linux');
    expect(step.type).toBe(THROW_STEP_TYPE);
    expect(step.with).toEqual({ method: 'GET', path: THROW_STEP_PATH });
    expect(step['on-failure']).toEqual({ continue: true });
  });

  it('inserts a helper step for generated bulk rows, before the replaced step', () => {
    const bulk = parseWorkflow(
      buildOsqueryVariant({ label: 'bulk', steps: { query_linux: F_BULK_5000 } })
    );
    const names = bulk.steps.map((s) => s.name);
    expect(names.slice(0, 2)).toEqual([helperStepName('query_linux'), 'query_linux']);
    expect(stepOf(bulk, 'query_linux').with?.rows).toBe(
      `\${{ steps.${helperStepName('query_linux')}.output.rows_json | json_parse }}`
    );
  });

  it('throws when a replaced step does not exist', () => {
    expect(() =>
      buildVariant(osqueryProduction, { query_solaris: { kind: 'throw' } }, R1_OPTIONS)
    ).toThrow(/not found in the production YAML: query_solaris/);
  });

  it('allows trigger and concurrency overrides only when asked', () => {
    const scheduled = parseWorkflow(
      buildOsqueryVariant({ label: 'sched', steps: {}, every: '1m', concurrencyKey: 'si-test-key' })
    );
    expect(scheduled.triggers[0].with?.every).toBe('1m');
    expect(scheduled.settings.concurrency).toEqual({
      ...production.settings.concurrency,
      key: 'si-test-key',
    });
    const manual = parseWorkflow(
      buildOsqueryVariant({ label: 'manual', steps: {}, manualTrigger: true })
    );
    expect(manual.triggers).toEqual([{ type: 'manual' }]);
  });
});

describe('assertFidelity negative tests', () => {
  const replacements: Replacements = osqueryReplacements(R1);
  const variant = buildOsqueryVariant({ label: 'R1', steps: R1 });

  it('accepts the untampered variant', () => {
    expect(() =>
      assertFidelity(osqueryProduction, variant, replacements, R1_OPTIONS)
    ).not.toThrow();
  });

  it('rejects a changed snapshot expression in a non-replaced step', () => {
    const tampered = variant.replace(
      'steps.query_linux.output.truncated == false',
      'steps.query_linux.output.truncated == true'
    );
    expect(tampered).not.toBe(variant);
    expect(() => assertFidelity(osqueryProduction, tampered, replacements, R1_OPTIONS)).toThrow(
      /"ingest_linux" is not byte-identical/
    );
  });

  it('rejects a whitespace-only change in a non-replaced step', () => {
    const tampered = variant.replace('      source: osquery\n', '      source:  osquery\n');
    expect(() => assertFidelity(osqueryProduction, tampered, replacements, R1_OPTIONS)).toThrow(
      /not byte-identical/
    );
  });

  it('rejects a removed on-failure on a replaced step', () => {
    const tampered = variant.replace(
      /(- name: query_linux[\s\S]*?)\n\s+on-failure:\n\s+continue: true/,
      '$1'
    );
    expect(tampered).not.toBe(variant);
    expect(() => assertFidelity(osqueryProduction, tampered, replacements, R1_OPTIONS)).toThrow(
      /"query_linux" changed `on-failure`/
    );
  });

  it('rejects reordered steps', () => {
    const production = parseWorkflow(osqueryProduction);
    const swapped = { ...parseWorkflow(variant) };
    swapped.steps = [...swapped.steps];
    [swapped.steps[4], swapped.steps[5]] = [swapped.steps[5], swapped.steps[4]];
    expect(production.steps[4].name).toBe('build_linux');
    expect(() =>
      assertFidelity(osqueryProduction, stringify(swapped), replacements, R1_OPTIONS)
    ).toThrow(/step order changed/);
  });

  it('rejects a settings change and an unrequested trigger change', () => {
    const settings = variant.replace('strategy: drop', 'strategy: queue');
    expect(() => assertFidelity(osqueryProduction, settings, replacements, R1_OPTIONS)).toThrow(
      /top-level keys/
    );
    const trigger = variant.replace('every: "6h"', 'every: "1m"');
    expect(() => assertFidelity(osqueryProduction, trigger, replacements, R1_OPTIONS)).toThrow(
      /top-level keys/
    );
  });

  it('rejects an unexpected helper step and a wrong name', () => {
    const helper = variant.replace(
      '  - name: build_linux',
      '  - name: si_test_extra\n    type: data.set\n    with: {}\n\n  - name: build_linux'
    );
    expect(() => assertFidelity(osqueryProduction, helper, replacements, R1_OPTIONS)).toThrow(
      /helper steps/
    );
    expect(() =>
      assertFidelity(osqueryProduction, variant, replacements, { label: 'other' })
    ).toThrow(/name/);
  });
});

describe('fixtures rendered through the production YAML liquid', () => {
  const engine = createWorkflowLiquidEngine();
  const production = parseWorkflow(osqueryProduction);
  const BUILD_STEP = {
    query_linux: 'build_linux',
    query_windows: 'build_windows',
    query_macos: 'build_macos',
    query_dependencies: 'build_dependencies',
  } as const;
  const INGEST_STEP = {
    query_linux: 'ingest_linux',
    query_windows: 'ingest_windows',
    query_macos: 'ingest_macos',
    query_dependencies: 'ingest_dependencies',
  } as const;

  const evaluate = (expression: string, context: object): boolean | object => {
    const inner = expression.slice(expression.indexOf('{{') + 2, expression.lastIndexOf('}}'));
    return engine.evalValueSync(inner.trim(), context);
  };

  it.each(OSQUERY_QUERY_STEPS)(
    'R1 %s yields the documented candidates and snapshot',
    async (query) => {
      const fixture = R1[query];
      const context = { steps: { [query]: { output: fixture.output } } };
      const template = String(stepOf(production, BUILD_STEP[query]).with?.candidates_json);
      const candidates = JSON.parse(await engine.parseAndRender(template, context));
      expect(candidates.length).toBe(fixture.expected.buildCandidates);
      const snapshot = String(stepOf(production, INGEST_STEP[query]).with?.snapshot);
      expect(evaluate(snapshot, context)).toBe(fixture.expected.snapshot);
    }
  );

  it('renders the bulk generator into 5000 and 5001 rows with the contract shape', async () => {
    for (const fixture of [F_BULK_5000, F_BULK_5001]) {
      const variant = parseWorkflow(
        buildOsqueryVariant({ label: 'bulk', steps: { query_linux: fixture } })
      );
      const helper = stepOf(variant, helperStepName('query_linux'));
      const rowsJson = await engine.parseAndRender(String(helper.with?.rows_json), {});
      const context = {
        steps: { [helperStepName('query_linux')]: { output: { rows_json: rowsJson } } },
      };
      const rows = evaluate(String(stepOf(variant, 'query_linux').with?.rows), context);
      expect(Array.isArray(rows) && rows.length).toBe(fixture.rows.count);
      expect(Array.isArray(rows) && rows[fixture.rows.count - 1]).toEqual({
        agent: { id: 'synth-agent-bulk', name: 'synth-bulk-01' },
        '@timestamp': expect.any(String),
        columns: {
          name: `synth-pkg-${fixture.rows.count}`,
          version: `1.0.${fixture.rows.count}`,
          install_path: '',
        },
        ecs: {},
      });
    }
  });
});

describe('integrations and enrich variants', () => {
  it('replaces only list_package_policies with the Fleet response', () => {
    const variant = parseWorkflow(
      buildIntegrationsVariant({ label: 'DI-2', response: FLEET_MAPPED_AND_UNMAPPED.response })
    );
    const step = stepOf(variant, 'list_package_policies');
    expect(step.type).toBe('data.set');
    expect(step.with).toEqual(FLEET_MAPPED_AND_UNMAPPED.response);
  });

  it('changes only enrich.with.limit', () => {
    const variant = parseWorkflow(buildEnrichVariant({ label: 'EC', limit: 3 }));
    expect(stepOf(variant, 'enrich')).toEqual({
      name: 'enrich',
      type: 'softwareInventory.enrichCves',
      with: { limit: 3 },
    });
    expect(() => buildEnrichVariant({ label: 'EC', limit: 0 })).toThrow(/positive integer/);
  });

  it.each(Object.keys(PRODUCTION_WORKFLOWS) as WorkflowKey[])(
    'a variant of %s without replacements differs only in its name',
    (key) => {
      const production = getProductionYaml(key);
      const variant = buildVariant(production, {}, { label: 'noop' });
      const { name: prodName, ...prodRest } = parseWorkflow(production);
      const { name, ...rest } = parseWorkflow(variant);
      expect(rest).toEqual(prodRest);
      expect(name).toBe(`${prodName} [test: noop]`);
    }
  );
});
