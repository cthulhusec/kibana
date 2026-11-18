/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { EuiProvider } from '@elastic/eui';
import { PeriodControls } from './period_controls';
import { FilterBar } from './filter_bar';
import { DEFAULT_TIME_RANGE, resolveTimeRange } from '../lib/time_range';
import { DEFAULT_TABLE_STATE, EMPTY_FILTERS, toFindInstancesParams } from '../lib/filters';
import type { FilterState } from '../lib/filters';
import type { TimeRangeInput } from '../lib/time_range';

let latestParams: ReturnType<typeof toFindInstancesParams>;

const Harness: React.FC<{ initialRange?: TimeRangeInput }> = ({
  initialRange = DEFAULT_TIME_RANGE,
}) => {
  const [range, setRange] = useState(initialRange);
  const [isCurrent, setIsCurrent] = useState(false);
  const [filters, setFilters] = useState<FilterState>(EMPTY_FILTERS);
  const resolution = resolveTimeRange(range);
  const period = !isCurrent && resolution.status === 'ok' ? resolution.period : undefined;
  latestParams = toFindInstancesParams(filters, DEFAULT_TABLE_STATE, period);
  return (
    <EuiProvider>
      <PeriodControls
        range={range}
        resolution={resolution}
        isCurrentInventory={isCurrent}
        onRangeChange={setRange}
        onRefresh={jest.fn()}
        onCurrentInventoryChange={setIsCurrent}
      />
      <FilterBar filters={filters} onChange={setFilters} isPeriodScoped={period !== undefined} />
    </EuiProvider>
  );
};

describe('PeriodControls', () => {
  it('maps the default period to as_of params and explains the semantics', () => {
    render(<Harness />);
    expect(latestParams.as_of_from).toBeDefined();
    expect(latestParams.as_of_to).toBeDefined();
    expect(screen.getByTestId('softwareInventoryPeriodCaption')).toHaveTextContent(
      'installed at any point during the selected period'
    );
  });

  it('omits the as_of params and the period filter in current inventory mode', () => {
    render(<Harness />);
    expect(screen.getByTestId('softwareInventoryVulnerableInRangeFilter')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('softwareInventoryCurrentToggle'));

    expect(latestParams).not.toHaveProperty('as_of_from');
    expect(latestParams).not.toHaveProperty('as_of_to');
    expect(
      screen.queryByTestId('softwareInventoryVulnerableInRangeFilter')
    ).not.toBeInTheDocument();
  });

  it('maps the vulnerable during period filter to vulnerable_in_range', () => {
    render(<Harness />);
    fireEvent.click(screen.getByTestId('softwareInventoryVulnerableInRangeFilter'));
    expect(latestParams.vulnerable_in_range).toBe(true);
  });

  it('warns when the range is clamped', () => {
    render(<Harness initialRange={{ start: 'now-3y', end: 'now' }} />);
    expect(screen.getByTestId('softwareInventoryRangeClamped')).toHaveTextContent('366 days');
  });

  it('warns when the range is invalid and sends no as_of params', () => {
    render(<Harness initialRange={{ start: 'now', end: 'now-1d' }} />);
    expect(screen.getByTestId('softwareInventoryRangeInvalid')).toBeInTheDocument();
    expect(latestParams).not.toHaveProperty('as_of_from');
  });
});
