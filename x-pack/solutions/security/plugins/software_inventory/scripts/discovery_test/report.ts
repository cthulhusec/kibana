/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Results persistence and reporting. Case records accumulate in `<resultsDir>/results.json` (the
 * latest record per case id wins), and every save also writes `discovery_test_results.md` with the
 * plan's results table plus a diff section for each failure.
 */

import { mkdir, readFile, writeFile } from 'fs/promises';
import { join } from 'path';
import type { LayerName, LayerResult } from './assertions';
import type { CaseRecord } from './cases/types';

export const RESULTS_FILE = 'results.json';
export const STATE_FILE = 'state.json';
export const MARKDOWN_FILE = 'discovery_test_results.md';

export interface ResultsFile {
  readonly updatedAt: string;
  readonly records: Readonly<Record<string, CaseRecord>>;
}

/** Harness state shared between invocations (for example the T0 that `logs` used). */
export interface HarnessState {
  readonly t0?: string;
  readonly logPhasesWritten?: readonly string[];
}

const readJson = async <T>(path: string, fallback: T): Promise<T> => {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return fallback;
    throw new Error(`Cannot read ${path}: ${(error as Error).message}`);
  }
};

export const loadResults = (dir: string): Promise<ResultsFile> =>
  readJson<ResultsFile>(join(dir, RESULTS_FILE), { updatedAt: '', records: {} });

export const loadState = (dir: string): Promise<HarnessState> =>
  readJson<HarnessState>(join(dir, STATE_FILE), {});

export const saveState = async (dir: string, state: HarnessState): Promise<void> => {
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, STATE_FILE), `${JSON.stringify(state, null, 2)}\n`);
};

/** Pure: merges new records into the file, newest record per id wins. */
export const mergeResults = (
  current: ResultsFile,
  records: readonly CaseRecord[],
  now: string
): ResultsFile => ({
  updatedAt: now,
  records: {
    ...current.records,
    ...Object.fromEntries(records.map((record) => [record.id, record])),
  },
});

/** Saves the merged results and the Markdown report; returns both paths. */
export const saveResults = async (
  dir: string,
  records: readonly CaseRecord[],
  order: readonly string[]
): Promise<{ json: string; markdown: string }> => {
  await mkdir(dir, { recursive: true });
  const merged = mergeResults(await loadResults(dir), records, new Date().toISOString());
  const json = join(dir, RESULTS_FILE);
  const markdown = join(dir, MARKDOWN_FILE);
  await writeFile(json, `${JSON.stringify(merged, null, 2)}\n`);
  await writeFile(markdown, renderMarkdown(orderRecords(merged, order)));
  return { json, markdown };
};

/** Pure: records in registry order first, then any unknown ids alphabetically. */
export const orderRecords = (results: ResultsFile, order: readonly string[]): CaseRecord[] => {
  const known = order.flatMap((id) => (results.records[id] ? [results.records[id]] : []));
  const unknown = Object.keys(results.records)
    .filter((id) => !order.includes(id))
    .sort()
    .map((id) => results.records[id]);
  return [...known, ...unknown];
};

const layerCell = (layers: readonly LayerResult[], name: LayerName): string => {
  const matching = layers.filter((layer) => layer.layer === name);
  if (matching.length === 0) return '-';
  return matching.every((layer) => layer.pass) ? 'yes' : 'NO';
};

const RESULT_LABEL: Record<CaseRecord['status'], string> = {
  pass: 'Pass',
  fail: 'Fail',
  blocked: 'Blocked',
  error: 'Error',
};

const escapeCell = (value: string): string => value.replace(/\|/g, '\\|').replace(/\n/g, ' ');

/** The plan's results template; panels are checked by hand on the dashboard. */
export const renderMarkdown = (records: readonly CaseRecord[]): string => {
  const header =
    '| Case | Date | Execution id | Engine (run + steps) | Step outputs | Inventory | Harness | Panels | Result | Notes |\n' +
    '|---|---|---|---|---|---|---|---|---|---|\n';
  const rows = records
    .map((record) =>
      [
        record.id,
        record.startedAt.slice(0, 19).replace('T', ' '),
        record.executionIds.join(', ') || '-',
        layerCell(record.layers, 'engine'),
        layerCell(record.layers, 'step'),
        layerCell(record.layers, 'inventory'),
        layerCell(record.layers, 'harness'),
        'manual',
        RESULT_LABEL[record.status],
        escapeCell((record.notes ?? []).join('; ')),
      ].join(' | ')
    )
    .map((line) => `| ${line} |`)
    .join('\n');
  const failures = records
    .filter((record) => record.status !== 'pass')
    .map((record) => {
      const diffs = record.layers.flatMap((layer) =>
        layer.diffs.map((diff) => `- [${layer.layer}] ${diff}`)
      );
      const notes = (record.notes ?? []).map((note) => `- note: ${note}`);
      return `### ${record.id}: ${record.title}\n\n${
        [...diffs, ...notes].join('\n') || '- no diffs recorded'
      }\n`;
    })
    .join('\n');
  return (
    `# Software inventory discovery test results\n\n${header}${rows}\n` +
    (failures ? `\n## Expected vs actual for non-passing cases\n\n${failures}` : '')
  );
};

/** Plain-text table for the terminal. */
export const renderText = (records: readonly CaseRecord[]): string => {
  if (records.length === 0) return 'No results recorded.';
  const lines = records.map((record) => {
    const status = RESULT_LABEL[record.status].padEnd(7);
    const layers = record.layers
      .map((layer) => `${layer.layer}:${layer.pass ? 'ok' : `${layer.diffs.length} diff(s)`}`)
      .join(' ');
    return `${status} ${record.id.padEnd(7)} ${String(record.durationMs).padStart(
      7
    )} ms  ${layers}  ${record.title}`;
  });
  const details = records
    .filter((record) => record.status !== 'pass')
    .flatMap((record) => [
      `\n${record.id} (${record.status}):`,
      ...record.layers.flatMap((layer) => layer.diffs.map((diff) => `  [${layer.layer}] ${diff}`)),
      ...(record.notes ?? []).map((note) => `  note: ${note}`),
    ]);
  const counts = (['pass', 'fail', 'blocked', 'error'] as const)
    .map((status) => `${status} ${records.filter((record) => record.status === status).length}`)
    .join(', ');
  return [...lines, ...details, '', `Total ${records.length}: ${counts}`].join('\n');
};
