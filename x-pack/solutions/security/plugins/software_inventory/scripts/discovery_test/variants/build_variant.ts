/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Generic variant transformer (see "Variant transformer sketch" in docs/discovery_test_plan.md).
 *
 * A variant is the PRODUCTION workflow YAML with a few named steps replaced. The transformer edits
 * the YAML text in place: it splices new text over the replaced steps (and over the overridden
 * scalars such as `name`), so every other byte of the production file stays as it is. Then
 * `assertFidelity` re-parses both files and throws unless every non-replaced step is byte-identical
 * and structurally equal, the step order is unchanged, and everything outside `steps` is equal
 * apart from the overrides that were asked for.
 */

import { isDeepStrictEqual } from 'util';
import { Document, isMap, isScalar, isSeq, parseDocument } from 'yaml';
import {
  SOFTWARE_INVENTORY_DISCOVER_INTEGRATIONS_WORKFLOW_ID,
  SOFTWARE_INVENTORY_DISCOVER_LOGS_WORKFLOW_ID,
  SOFTWARE_INVENTORY_DISCOVER_OSQUERY_WORKFLOW_ID,
  SOFTWARE_INVENTORY_ENRICH_CVES_WORKFLOW_ID,
  SOFTWARE_INVENTORY_SCORE_EXPOSURE_WORKFLOW_ID,
  getManagedWorkflowDefinition,
} from '@kbn/workflows/managed';
import { HELPER_STEP_PREFIX } from '../ids';

/** Ids of the five managed workflows, by harness key. */
export const PRODUCTION_WORKFLOWS = {
  discoverOsquery: SOFTWARE_INVENTORY_DISCOVER_OSQUERY_WORKFLOW_ID,
  discoverIntegrations: SOFTWARE_INVENTORY_DISCOVER_INTEGRATIONS_WORKFLOW_ID,
  discoverLogs: SOFTWARE_INVENTORY_DISCOVER_LOGS_WORKFLOW_ID,
  enrichCves: SOFTWARE_INVENTORY_ENRICH_CVES_WORKFLOW_ID,
  scoreExposure: SOFTWARE_INVENTORY_SCORE_EXPOSURE_WORKFLOW_ID,
} as const;
export type WorkflowKey = keyof typeof PRODUCTION_WORKFLOWS;

export const getWorkflowId = (key: WorkflowKey): string => PRODUCTION_WORKFLOWS[key];

/** The registered production YAML, read from the managed definition on every call. */
export const getProductionYaml = (key: WorkflowKey): string => {
  const definition = getManagedWorkflowDefinition(PRODUCTION_WORKFLOWS[key]);
  if (!definition || typeof definition.yaml !== 'string') {
    throw new Error(`No static YAML registered for managed workflow ${PRODUCTION_WORKFLOWS[key]}`);
  }
  return definition.yaml;
};

/** Step type and path a `throw` replacement uses: a GET on an index that never exists. */
export const THROW_STEP_TYPE = 'elasticsearch.request';
export const THROW_STEP_PATH = '/zz-si-test-missing/_doc/1';

export type StepReplacement =
  /** `data.set` that emits `output` (the step's `with`); keeps `if`, `timeout`, `on-failure`. */
  | { readonly kind: 'fixture'; readonly output: object }
  /** `data.set` emitting `output` plus `rows` parsed from a helper step rendering `rowsTemplate`. */
  | { readonly kind: 'generated'; readonly output: object; readonly rowsTemplate: string }
  /** A failing `elasticsearch.request`; keeps `on-failure` so failure semantics match production. */
  | { readonly kind: 'throw' }
  /** Same step type; merges `with` into the production `with` (for example `limit`). */
  | { readonly kind: 'with'; readonly with: object }
  /** Any step body (the name is kept). Shape checks on `if`/`on-failure` are skipped. */
  | { readonly kind: 'step'; readonly step: object };

export type Replacements = Readonly<Record<string, StepReplacement>>;

export interface VariantOptions {
  /** Appended to the workflow `name` as ` [test: <label>]`. */
  readonly label: string;
  /** Replaces `every` of the first (scheduled) trigger. */
  readonly every?: string;
  /** Replaces the triggers with a single manual trigger. */
  readonly manualTrigger?: boolean;
  /** Replaces `settings.concurrency.key`. */
  readonly concurrencyKey?: string;
}

/** Name of the helper step a `generated` replacement inserts before the replaced step. */
export const helperStepName = (stepName: string): string => `${HELPER_STEP_PREFIX}gen_${stepName}`;

export const variantName = (productionName: string, label: string): string =>
  `${productionName} [test: ${label}]`;

interface StepSlice {
  readonly name: string;
  /** First line (the `- ` line) and the line after the last line of the step. */
  readonly startLine: number;
  readonly endLine: number;
  readonly indent: string;
}

interface Edit {
  readonly start: number;
  readonly end: number;
  readonly text: string;
}

interface ParsedWorkflow {
  readonly doc: ReturnType<typeof parseDocument>;
  readonly lines: readonly string[];
  readonly lineOffsets: readonly number[];
  readonly slices: readonly StepSlice[];
}

const isBlankOrComment = (line: string): boolean => /^\s*(#.*)?$/.test(line);
const indentOf = (line: string): number => line.length - line.trimStart().length;

const lineIndexAt = (lineOffsets: readonly number[], offset: number): number => {
  let index = 0;
  while (index + 1 < lineOffsets.length && lineOffsets[index + 1] <= offset) {
    index++;
  }
  return index;
};

const parseWorkflow = (text: string, label: string): ParsedWorkflow => {
  const doc = parseDocument(text);
  if (doc.errors.length > 0) {
    throw new Error(`${label}: invalid YAML: ${doc.errors.map((e) => e.message).join('; ')}`);
  }
  const lines = text.split('\n');
  const lineOffsets: number[] = [];
  let offset = 0;
  for (const line of lines) {
    lineOffsets.push(offset);
    offset += line.length + 1;
  }
  const steps = doc.get('steps', true);
  if (!isSeq(steps)) {
    throw new Error(`${label}: \`steps\` is missing or not a sequence`);
  }
  const slices = steps.items.map((item, index): StepSlice => {
    if (!isMap(item) || !item.range) {
      throw new Error(`${label}: step #${index} is not a mapping`);
    }
    const name = item.get('name');
    if (typeof name !== 'string' || name === '') {
      throw new Error(`${label}: step #${index} has no name`);
    }
    const startLine = lineIndexAt(lineOffsets, item.range[0]);
    const dash = /^(\s*)- /.exec(lines[startLine]);
    if (!dash || lineOffsets[startLine] + dash[0].length !== item.range[0]) {
      throw new Error(`${label}: step "${name}" must start with "- " on its own line`);
    }
    const indent = dash[1];
    let endLine = startLine + 1;
    while (
      endLine < lines.length &&
      (isBlankOrComment(lines[endLine]) || indentOf(lines[endLine]) > indent.length)
    ) {
      endLine++;
    }
    // Comments and blank lines between steps stay in place: they belong to no step.
    while (
      endLine > startLine + 1 &&
      (lines[endLine - 1].trim() === '' ||
        (isBlankOrComment(lines[endLine - 1]) && indentOf(lines[endLine - 1]) <= indent.length))
    ) {
      endLine--;
    }
    return { name, startLine, endLine, indent };
  });
  return { doc, lines, lineOffsets, slices };
};

const sliceText = (parsed: ParsedWorkflow, slice: StepSlice): string =>
  parsed.lines.slice(slice.startLine, slice.endLine).join('\n');

const stepsAsJs = (parsed: ParsedWorkflow): Array<Record<string, object | string>> => {
  const js = parsed.doc.toJS() as { steps: Array<Record<string, object | string>> };
  return js.steps;
};

/** Serializes step objects as a block sequence indented like the production steps. */
const serializeSteps = (steps: readonly object[], indent: string): string =>
  new Document(steps, { aliasDuplicateObjects: false })
    .toString({ lineWidth: 0 })
    .replace(/\n$/, '')
    .split('\n')
    .map((line) => (line === '' ? line : `${indent}${line}`))
    .join('\n');

/** Keeps the production key order; replaces `type`/`with` in place. */
const withTypeAndWith = (
  original: Record<string, object | string>,
  type: string,
  withValue: object
): Record<string, object | string> => {
  const result: Record<string, object | string> = {};
  for (const [key, value] of Object.entries(original)) {
    if (key === 'type') result.type = type;
    else if (key === 'with') result.with = withValue;
    else result[key] = value;
  }
  if (!('type' in result)) result.type = type;
  if (!('with' in result)) result.with = withValue;
  return result;
};

const replacementSteps = (
  name: string,
  original: Record<string, object | string>,
  replacement: StepReplacement
): object[] => {
  switch (replacement.kind) {
    case 'fixture':
      return [withTypeAndWith(original, 'data.set', replacement.output)];
    case 'generated': {
      const helper = helperStepName(name);
      return [
        { name: helper, type: 'data.set', with: { rows_json: replacement.rowsTemplate } },
        withTypeAndWith(original, 'data.set', {
          ...replacement.output,
          rows: `\${{ steps.${helper}.output.rows_json | json_parse }}`,
        }),
      ];
    }
    case 'throw':
      return [withTypeAndWith(original, THROW_STEP_TYPE, { method: 'GET', path: THROW_STEP_PATH })];
    case 'with': {
      const current = original.with;
      const merged =
        typeof current === 'object' ? { ...current, ...replacement.with } : replacement.with;
      return [withTypeAndWith(original, String(original.type), merged)];
    }
    case 'step':
      return [{ ...replacement.step, name }];
  }
};

const scalarEdit = (
  parsed: ParsedWorkflow,
  path: readonly (string | number)[],
  value: string
): Edit => {
  const node = parsed.doc.getIn(path, true);
  if (!isScalar(node) || !node.range) {
    throw new Error(`Cannot override ${path.join('.')}: not a scalar in the production YAML`);
  }
  return { start: node.range[0], end: node.range[1], text: JSON.stringify(value) };
};

const applyEdits = (text: string, edits: readonly Edit[]): string => {
  const sorted = [...edits].sort((a, b) => b.start - a.start);
  let result = text;
  let previousStart = Number.POSITIVE_INFINITY;
  for (const edit of sorted) {
    if (edit.end > previousStart) {
      throw new Error('Overlapping variant edits');
    }
    result = result.slice(0, edit.start) + edit.text + result.slice(edit.end);
    previousStart = edit.start;
  }
  return result;
};

/** Builds a variant of `productionYaml` and enforces the fidelity invariant before returning it. */
export const buildVariant = (
  productionYaml: string,
  replacements: Replacements,
  options: VariantOptions
): string => {
  const parsed = parseWorkflow(productionYaml, 'production');
  const names = parsed.slices.map(({ name }) => name);
  const missing = Object.keys(replacements).filter((name) => !names.includes(name));
  if (missing.length > 0) {
    throw new Error(`Replaced step(s) not found in the production YAML: ${missing.join(', ')}`);
  }
  if (options.every !== undefined && options.manualTrigger) {
    throw new Error('Use either `every` or `manualTrigger`, not both');
  }

  const jsSteps = stepsAsJs(parsed);
  const edits: Edit[] = [];
  parsed.slices.forEach((slice, index) => {
    const replacement = replacements[slice.name];
    if (!replacement) return;
    const lastLine = slice.endLine - 1;
    edits.push({
      start: parsed.lineOffsets[slice.startLine],
      end: parsed.lineOffsets[lastLine] + parsed.lines[lastLine].length,
      text: serializeSteps(replacementSteps(slice.name, jsSteps[index], replacement), slice.indent),
    });
  });

  const productionName = parsed.doc.get('name');
  if (typeof productionName !== 'string') {
    throw new Error('production: `name` is missing');
  }
  edits.push(scalarEdit(parsed, ['name'], variantName(productionName, options.label)));
  if (options.every !== undefined) {
    if (parsed.doc.getIn(['triggers', 0, 'type']) !== 'scheduled') {
      throw new Error('Cannot override `every`: the first trigger is not scheduled');
    }
    edits.push(scalarEdit(parsed, ['triggers', 0, 'with', 'every'], options.every));
  }
  if (options.concurrencyKey !== undefined) {
    edits.push(scalarEdit(parsed, ['settings', 'concurrency', 'key'], options.concurrencyKey));
  }
  if (options.manualTrigger) {
    const triggers = parsed.doc.get('triggers', true);
    if (!isSeq(triggers) || !triggers.range) {
      throw new Error('Cannot replace triggers: `triggers` is not a sequence');
    }
    edits.push({ start: triggers.range[0], end: triggers.range[1], text: '[{ type: manual }]\n' });
  }

  const variant = applyEdits(productionYaml, edits);
  assertFidelity(productionYaml, variant, replacements, options);
  return variant;
};

const FAILURE_SEMANTICS_KEYS = ['if', 'on-failure', 'timeout'] as const;

const withoutKeys = (
  value: Record<string, object | string>,
  keys: readonly string[]
): Record<string, object | string> =>
  Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));

/**
 * Throws unless `variantYaml` differs from `productionYaml` only by the given replacements and
 * options: non-replaced steps byte-identical and in the same order, replaced steps keep `if`,
 * `timeout`, and `on-failure`, and everything outside `steps` is equal apart from the overrides.
 */
export const assertFidelity = (
  productionYaml: string,
  variantYaml: string,
  replacements: Replacements,
  options: VariantOptions
): void => {
  const prod = parseWorkflow(productionYaml, 'production');
  const variant = parseWorkflow(variantYaml, 'variant');
  const problems: string[] = [];

  const replaced = new Set(Object.keys(replacements));
  const expectedHelpers = Object.entries(replacements)
    .filter(([, replacement]) => replacement.kind === 'generated')
    .map(([name]) => helperStepName(name));
  const variantNames = variant.slices.map(({ name }) => name);
  const helpers = variantNames.filter((name) => name.startsWith(HELPER_STEP_PREFIX));
  if (!isDeepStrictEqual(helpers, expectedHelpers)) {
    problems.push(`helper steps ${JSON.stringify(helpers)} != ${JSON.stringify(expectedHelpers)}`);
  }
  const prodNames = prod.slices.map(({ name }) => name);
  const variantStepNames = variantNames.filter((name) => !name.startsWith(HELPER_STEP_PREFIX));
  if (!isDeepStrictEqual(prodNames, variantStepNames)) {
    problems.push(
      `step order changed: ${JSON.stringify(prodNames)} != ${JSON.stringify(variantStepNames)}`
    );
  }

  const prodSteps = stepsAsJs(prod);
  const variantSteps = stepsAsJs(variant);
  prod.slices.forEach((prodSlice, prodIndex) => {
    const variantIndex = variantNames.indexOf(prodSlice.name);
    if (variantIndex === -1) {
      problems.push(`step "${prodSlice.name}" is missing`);
      return;
    }
    const prodStep = prodSteps[prodIndex];
    const variantStep = variantSteps[variantIndex];
    const replacement = replacements[prodSlice.name];
    if (!replacement) {
      if (sliceText(prod, prodSlice) !== sliceText(variant, variant.slices[variantIndex])) {
        problems.push(`step "${prodSlice.name}" is not byte-identical to production`);
      }
      if (!isDeepStrictEqual(prodStep, variantStep)) {
        problems.push(`step "${prodSlice.name}" differs structurally from production`);
      }
      return;
    }
    if (replacement.kind === 'step') return;
    for (const key of FAILURE_SEMANTICS_KEYS) {
      if (!isDeepStrictEqual(prodStep[key], variantStep[key])) {
        problems.push(`replaced step "${prodSlice.name}" changed \`${key}\``);
      }
    }
    if (replacement.kind === 'with' && prodStep.type !== variantStep.type) {
      problems.push(`step "${prodSlice.name}" changed its type`);
    }
  });
  for (const name of replaced) {
    if (!prodNames.includes(name)) problems.push(`replaced step "${name}" is not in production`);
  }

  const prodJs = prod.doc.toJS() as Record<string, object | string>;
  const variantJs = variant.doc.toJS() as Record<string, object | string>;
  const expectedName = variantName(String(prodJs.name), options.label);
  if (variantJs.name !== expectedName) {
    problems.push(`name ${JSON.stringify(variantJs.name)} != ${JSON.stringify(expectedName)}`);
  }
  const ignored = ['steps', 'name'];
  if (options.every !== undefined || options.manualTrigger) ignored.push('triggers');
  if (options.concurrencyKey !== undefined) ignored.push('settings');
  if (!isDeepStrictEqual(withoutKeys(prodJs, ignored), withoutKeys(variantJs, ignored))) {
    problems.push(`top-level keys other than ${ignored.join(', ')} changed`);
  }
  if (options.concurrencyKey !== undefined) {
    const prodSettings = prod.doc.toJS().settings;
    const expectedSettings = {
      ...prodSettings,
      concurrency: { ...prodSettings?.concurrency, key: options.concurrencyKey },
    };
    if (!isDeepStrictEqual(variant.doc.toJS().settings, expectedSettings)) {
      problems.push('settings differ beyond `concurrency.key`');
    }
  }
  if (options.every !== undefined) {
    const expectedTriggers = prod.doc.toJS().triggers;
    expectedTriggers[0].with.every = options.every;
    if (!isDeepStrictEqual(variant.doc.toJS().triggers, expectedTriggers)) {
      problems.push('triggers differ beyond `every`');
    }
  }

  if (problems.length > 0) {
    throw new Error(`Variant fidelity check failed:\n- ${problems.join('\n- ')}`);
  }
};
