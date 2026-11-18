/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import { InstancesTable } from './instances_table';
import { DEFAULT_TABLE_STATE } from '../lib/filters';
import type { InstanceRow } from '../../common/types';

const makeRow = (overrides: Partial<InstanceRow> = {}): InstanceRow => ({
  id: 'i1',
  host: { key: 'web-1', id: 'h1', name: 'web-1' },
  software_id: 'apache:httpd:2.4.58',
  version_history: [],
  sources: ['osquery'],
  status: 'active',
  first_seen: '2026-01-01T00:00:00.000Z',
  last_seen: '2026-01-02T00:00:00.000Z',
  exposure: { level: 'high', score: 80, evidence: [] },
  '@timestamp': '2026-01-02T00:00:00.000Z',
  software: {
    id: 'apache:httpd:2.4.58',
    vendor: 'apache',
    product: 'httpd',
    version: '2.4.58',
    display_name: 'Apache HTTP Server',
    category: 'application',
    cve_count: 3,
    max_cvss: 9.8,
    known_exploited: true,
    fixed_in: '2.4.60',
    cve_ids: ['CVE-2024-1'],
    '@timestamp': '2026-01-02T00:00:00.000Z',
  },
  ...overrides,
});

const renderTable = (items: InstanceRow[]) =>
  render(
    <InstancesTable
      items={items}
      total={items.length}
      tableState={DEFAULT_TABLE_STATE}
      loading={false}
      onTableChange={jest.fn()}
      onSelect={jest.fn()}
    />
  );

describe('InstancesTable', () => {
  it('renders row details', () => {
    renderTable([makeRow()]);
    expect(screen.getByText('Apache HTTP Server 2.4.58')).toBeInTheDocument();
    expect(screen.getByText('web-1')).toBeInTheDocument();
    expect(screen.getByText('High (80)')).toBeInTheDocument();
    expect(screen.getByText('3 (max CVSS 9.8)')).toBeInTheDocument();
    expect(screen.getByTestId('softwareInventoryKnownExploited')).toBeInTheDocument();
    expect(screen.getByText('2.4.60')).toBeInTheDocument();
    expect(screen.queryByTestId('softwareInventoryPatchedFrom')).not.toBeInTheDocument();
  });

  it('shows the patched indicator when previous_software_id is set', () => {
    renderTable([
      makeRow({
        status: 'patched',
        previous_software_id: 'apache:httpd:2.4.57',
        version_history: [{ version: '2.4.57', first_seen: 'a', last_seen: 'b' }],
      }),
    ]);
    expect(screen.getByTestId('softwareInventoryPatchedFrom')).toHaveTextContent(
      'Patched from 2.4.57 → 2.4.58'
    );
  });
});
