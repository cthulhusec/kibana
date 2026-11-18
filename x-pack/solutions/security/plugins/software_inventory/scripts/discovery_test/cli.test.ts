/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EsClient, KibanaClient } from './clients';
import { ALL_CASES, selectCases, validateRegistry } from './cases';
import type { CaseRecord, HarnessConfig, HarnessLogger, TestCase } from './cases/types';
import { blockedResult } from './cases/types';
import type { RunnerDeps } from './cli';
import { DEFAULTS, parseCliArgs, readStringFlag, resolveConfig, runCases } from './cli';
import { mergeResults, orderRecords, renderMarkdown, renderText } from './report';

describe('parseCliArgs', () => {
  it('reads the command, positionals, and both flag forms', () => {
    const args = parseCliArgs([
      'run',
      'DO-1',
      'DO-2',
      '--space=s1',
      '--t0',
      '2026-11-18T10:00:00Z',
      '--dry-run',
    ]);
    expect(args.command).toBe('run');
    expect(args.positionals).toEqual(['DO-1', 'DO-2']);
    expect(args.flags.get('space')).toBe('s1');
    expect(args.flags.get('t0')).toBe('2026-11-18T10:00:00Z');
    expect(args.flags.get('dry-run')).toBe(true);
  });

  it('keeps "=" inside values and gives empty string flags an empty value', () => {
    const args = parseCliArgs(['logs', '--kibana-url=http://h/a=b', '--phase=', '--password']);
    expect(args.flags.get('kibana-url')).toBe('http://h/a=b');
    expect(args.flags.get('phase')).toBe('');
    expect(args.flags.get('password')).toBe('');
  });

  it('does not swallow a following flag as a value', () => {
    const args = parseCliArgs(['cleanup', '--space', '--synthetic-only']);
    expect(args.flags.get('space')).toBe('');
    expect(args.flags.get('synthetic-only')).toBe(true);
  });
});

describe('readStringFlag and resolveConfig', () => {
  it('treats empty strings as not provided', () => {
    expect(readStringFlag('', 'fallback')).toBe('fallback');
    expect(readStringFlag(true, 'fallback')).toBe('fallback');
    expect(readStringFlag(undefined, 'fallback')).toBe('fallback');
    expect(readStringFlag('value', 'fallback')).toBe('value');
  });

  it('applies defaults for empty flags and environment fallbacks', () => {
    const config = resolveConfig(
      parseCliArgs(['preflight', '--space=', '--kibana-url=', '--password=']),
      {
        KIBANA_URL: 'http://localhost:5601/tdy/',
        ES_PASSWORD: 'from-env',
      }
    );
    expect(config.space).toBe(DEFAULTS.space);
    expect(config.kibanaUrl).toBe('http://localhost:5601/tdy');
    expect(config.esUrl).toBe(DEFAULTS.esUrl);
    expect(config.password).toBe('from-env');
    expect(config.nvdPort).toBe(DEFAULTS.nvdPort);
  });

  it('prefers flags over the environment and validates ports', () => {
    const config = resolveConfig(parseCliArgs(['run', '--password=flag', '--nvd-port=6000']), {
      KIBANA_PASSWORD: 'env',
    });
    expect(config.password).toBe('flag');
    expect(config.nvdPort).toBe(6000);
    expect(() => resolveConfig(parseCliArgs(['run', '--nvd-port=abc']), {})).toThrow(
      /Invalid port/
    );
  });
});

describe('case registry', () => {
  it('is valid and starts with the T0 self-checks', () => {
    expect(() => validateRegistry(ALL_CASES)).not.toThrow();
    expect(ALL_CASES.slice(0, 3).map(({ id }) => id)).toEqual(['T0-1', 'T0-2', 'T0-3']);
  });

  it('puts DO-15..DO-18 after the log cases and keeps RG out of "all"', () => {
    const order = ALL_CASES.map(({ id }) => id);
    expect(order.indexOf('DL-10')).toBeLessThan(order.indexOf('DO-15'));
    expect(order.indexOf('DO-14')).toBeLessThan(order.indexOf('DL-0'));
    expect(order.indexOf('DO-18')).toBeLessThan(order.indexOf('EC-1'));
  });

  it('selects by family, id, and "all", in registry order', () => {
    expect(selectCases('t0-3,T0-1').map(({ id }) => id)).toEqual(['T0-1', 'T0-3']);
    expect(selectCases('T0').map(({ id }) => id)).toEqual(['T0-1', 'T0-2', 'T0-3']);
    expect(selectCases('all')).toHaveLength(
      ALL_CASES.filter(({ family }) => family !== 'RG').length
    );
    expect(selectCases('all').some(({ family }) => family === 'RG')).toBe(false);
    expect(selectCases('RG').length).toBeGreaterThan(0);
    const discoverOsquery = selectCases('DO');
    expect(discoverOsquery.length).toBeGreaterThan(0);
    expect(discoverOsquery.every(({ id, family }) => family === 'DO' && id.startsWith('DO-'))).toBe(true);
    expect(() => selectCases('XX-1')).toThrow(/Unknown case/);
    expect(() => selectCases('')).toThrow(/Select cases/);
  });

  it('rejects duplicates, family mismatches, and unknown prerequisites', () => {
    const run = async () => blockedResult('n/a');
    expect(() =>
      validateRegistry([
        { id: 'DO-1', family: 'DO', title: 'a', run },
        { id: 'DO-1', family: 'DI', title: 'b', requires: ['DO-99'], run },
      ])
    ).toThrow(/duplicate case id DO-1[\s\S]*family DI[\s\S]*unknown case DO-99/);
  });
});

describe('runCases', () => {
  const config: HarnessConfig = {
    kibanaUrl: 'http://kibana.invalid',
    esUrl: 'http://es.invalid',
    username: 'u',
    password: 'p',
    space: 'default',
    resultsDir: '/nonexistent',
    nvdPort: 5699,
  };
  const silent: HarnessLogger = { info: () => {}, warn: () => {}, debug: () => {} };
  const deps = (overrides: Partial<RunnerDeps> = {}): RunnerDeps => ({
    config,
    kibana: {} as KibanaClient,
    es: {} as EsClient,
    t0: new Date('2026-11-18T10:00:00Z'),
    log: silent,
    prior: new Map(),
    startNvdStub: () => Promise.reject(new Error('no stub in unit tests')),
    ...overrides,
  });

  it('runs the offline T0 self-checks (fidelity and fixture contract) and passes them', async () => {
    const records = await runCases(selectCases('T0-1,T0-2'), deps());
    expect(records.map(({ id, status }) => [id, status])).toEqual([
      ['T0-1', 'pass'],
      ['T0-2', 'pass'],
    ]);
    expect(records[0].layers[0]).toEqual(expect.objectContaining({ layer: 'harness', pass: true }));
  });

  it('blocks a case whose prerequisite did not pass, and records thrown errors', async () => {
    const failing: TestCase = {
      id: 'DO-1',
      family: 'DO',
      title: 'throws',
      run: () => Promise.reject(new Error('boom')),
    };
    const dependent: TestCase = {
      id: 'DO-2',
      family: 'DO',
      title: 'needs DO-1',
      requires: ['DO-1'],
      run: failing.run,
    };
    const recorded: CaseRecord[] = [];
    const records = await runCases(
      [failing, dependent],
      deps({
        onRecord: async (r) => {
          recorded.push(r);
        },
      })
    );
    expect(records.map(({ status }) => status)).toEqual(['error', 'blocked']);
    expect(records[0].notes?.[0]).toMatch(/boom/);
    expect(records[1].notes).toEqual(['requires passing DO-1']);
    expect(recorded).toHaveLength(2);
  });

  it('marks a case that needs the NVD stub as error when the stub cannot start', async () => {
    const needsStub: TestCase = {
      id: 'EC-1',
      family: 'EC',
      title: 'stub',
      needs: ['nvd-stub'],
      run: async () => blockedResult('unreachable'),
    };
    const [record] = await runCases([needsStub], deps());
    expect(record.status).toBe('error');
    expect(record.notes?.[0]).toMatch(/no stub/);
  });
});

describe('report', () => {
  const record = (id: string, status: CaseRecord['status']): CaseRecord => ({
    id,
    family: 'T0',
    title: `title ${id}`,
    status,
    layers: [
      {
        layer: 'engine',
        pass: status === 'pass',
        checks: 1,
        diffs: status === 'pass' ? [] : ['run status: expected completed, got failed'],
      },
    ],
    startedAt: '2026-11-18T10:00:00.000Z',
    durationMs: 12,
    executionIds: ['exec-1'],
  });

  it('merges records, newest per id wins, and orders by registry', () => {
    const merged = mergeResults(
      mergeResults({ updatedAt: '', records: {} }, [record('T0-2', 'fail')], 'a'),
      [record('T0-2', 'pass'), record('T0-1', 'pass')],
      'b'
    );
    expect(
      orderRecords(merged, ['T0-1', 'T0-2']).map(({ id, status }) => `${id}:${status}`)
    ).toEqual(['T0-1:pass', 'T0-2:pass']);
  });

  it('renders the results table and failure diffs', () => {
    const markdown = renderMarkdown([record('T0-1', 'pass'), record('T0-3', 'fail')]);
    expect(markdown).toContain(
      '| T0-3 | 2026-11-18 10:00:00 | exec-1 | NO | - | - | - | manual | Fail |  |'
    );
    expect(markdown).toContain('- [engine] run status: expected completed, got failed');
    expect(renderText([record('T0-1', 'pass')])).toContain(
      'Total 1: pass 1, fail 0, blocked 0, error 0'
    );
  });
});
