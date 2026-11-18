/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { FilterBar } from './filter_bar';
import { CATEGORY_LABELS, SOURCE_LABELS } from './labels';
import { DEFAULT_TABLE_STATE, EMPTY_FILTERS, toFindInstancesParams } from '../lib/filters';
import type { FilterState } from '../lib/filters';

let latest: FilterState = EMPTY_FILTERS;

const Harness: React.FC = () => {
  const [filters, setFilters] = useState<FilterState>(EMPTY_FILTERS);
  latest = filters;
  return <FilterBar filters={filters} onChange={setFilters} />;
};

describe('FilterBar', () => {
  beforeEach(() => {
    latest = EMPTY_FILTERS;
  });

  it('sends both selected categories in the query params', () => {
    render(<Harness />);
    fireEvent.click(screen.getByTestId('softwareInventoryCategoryFilter'));
    fireEvent.click(screen.getByTestId('softwareInventoryCategoryFilter-option-os_package'));
    fireEvent.click(screen.getByTestId('softwareInventoryCategoryFilter-option-appliance'));

    expect(toFindInstancesParams(latest, DEFAULT_TABLE_STATE).category).toEqual([
      'appliance',
      'os_package',
    ]);
    expect(screen.getByText('OS package')).toBeInTheDocument();
  });

  it('clears all filters', () => {
    render(<Harness />);
    expect(screen.queryByTestId('softwareInventoryClearFilters')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId('softwareInventoryKnownExploitedFilter'));
    expect(latest.knownExploited).toBe(true);
    fireEvent.click(screen.getByTestId('softwareInventoryClearFilters'));
    expect(latest).toEqual(EMPTY_FILTERS);
  });

  it('uses human-readable labels', () => {
    expect(CATEGORY_LABELS.os_package).toBe('OS package');
    expect(CATEGORY_LABELS.appliance).toBe('Appliance');
    expect(SOURCE_LABELS.fleet_integration).toBe('Fleet integration');
  });
});
