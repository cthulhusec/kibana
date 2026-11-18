/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { WORKFLOW_IDS } from '../../common/constants';
import type { DashboardPanel, DashboardSection } from './dashboard';
import {
  ALLOWED_INDICES,
  DASHBOARD_ID,
  QUERIES,
  WORKFLOW_ID_LIST,
  buildDefinition,
} from './dashboard';
import { getDashboardUrl, getSpacePrefix, parseArgs } from './install';

const isSection = (item: DashboardPanel | DashboardSection): item is DashboardSection =>
  'panels' in item;

const flatten = (): DashboardPanel[] =>
  buildDefinition().panels.flatMap((item) => (isSection(item) ? item.panels : [item]));

describe('monitoring dashboard definition', () => {
  it('gives every panel a grid within the 48 column layout', () => {
    for (const { grid } of flatten()) {
      expect(grid.w).toBeGreaterThan(0);
      expect(grid.h).toBeGreaterThan(0);
      expect(grid.x + grid.w).toBeLessThanOrEqual(48);
    }
  });

  it('uses a valid as-code id', () => {
    expect(DASHBOARD_ID).toMatch(/^[a-z0-9_-]+$/);
  });

  it('only reads the allowed indices', () => {
    for (const query of Object.values(QUERIES)) {
      const sources = [...query.matchAll(/FROM\s+(\S+)/g)].map(([, index]) => index);
      expect(sources.length).toBeGreaterThan(0);
      for (const source of sources) {
        expect(ALLOWED_INDICES).toContain(source);
      }
    }
  });

  it('uses every named query in at least one panel', () => {
    const serialized = JSON.stringify(buildDefinition());
    for (const query of Object.values(QUERIES)) {
      expect(serialized).toContain(JSON.stringify(query).slice(1, -1));
    }
  });

  it('does not hard-code a base path', () => {
    expect(JSON.stringify(buildDefinition())).not.toMatch(/localhost|\/tdy|\/app\/|\/s\//);
  });

  it('has unique section titles', () => {
    const { panels } = buildDefinition();
    const sectionTitles = panels.filter(isSection).map(({ title }) => title);
    expect(new Set(sectionTitles).size).toBe(sectionTitles.length);
  });

  it('lists the workflow ids from WORKFLOW_IDS', () => {
    expect([...WORKFLOW_ID_LIST].sort()).toEqual(Object.values(WORKFLOW_IDS).sort());
    const header = JSON.stringify(buildDefinition().panels[0]);
    for (const id of Object.values(WORKFLOW_IDS)) {
      expect(header).toContain(id.replace('system-security-software-inventory-', ''));
    }
  });
});

describe('monitoring dashboard installer options', () => {
  it('uses defaults for empty string flags', () => {
    const options = parseArgs(['--kibana-url=', '--username=', '--space='], {});
    expect(options).toEqual({
      kibanaUrl: 'http://localhost:5601',
      username: 'elastic',
      password: 'changeme',
      space: 'default',
      remove: false,
    });
  });

  it('reads the password from the environment and detects --delete', () => {
    const options = parseArgs(['--delete', '--kibana-url=http://k:5601/base/'], {
      KIBANA_PASSWORD: 'secret',
    });
    expect(options.password).toBe('secret');
    expect(options.remove).toBe(true);
    expect(options.kibanaUrl).toBe('http://k:5601/base');
  });

  it('builds the dashboard url with the space prefix', () => {
    expect(getSpacePrefix('default')).toBe('');
    expect(getDashboardUrl(parseArgs(['--space=sec'], {}))).toBe(
      `http://localhost:5601/s/sec/app/dashboards#/view/${DASHBOARD_ID}`
    );
  });
});
