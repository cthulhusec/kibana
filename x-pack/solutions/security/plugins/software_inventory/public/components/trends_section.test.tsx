/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { render, screen } from '@testing-library/react';
import { EuiProvider } from '@elastic/eui';
import { TrendsSection } from './trends_section';
import { makeRollup, makeTrends } from '../lib/history_fixtures';

jest.mock('@kbn/charts-theme', () => ({ useElasticChartsTheme: () => ({}) }));
// jsdom has no canvas; the chart components stand in as markers.
jest.mock('./trend_charts', () => ({
  ExposureTrendChart: () => <div data-test-subj="exposureChartMock" />,
  ChangesTrendChart: () => <div data-test-subj="changesChartMock" />,
}));

const renderSection = (props: React.ComponentProps<typeof TrendsSection>) =>
  render(
    <EuiProvider>
      <TrendsSection {...props} />
    </EuiProvider>
  );

describe('TrendsSection', () => {
  it('shows the patch summary tiles and both charts', () => {
    renderSection({ data: makeTrends(), isLoading: false, error: null });

    expect(screen.getByTestId('softwareInventoryTrendStat-patches')).toHaveTextContent('7');
    expect(screen.getByTestId('softwareInventoryTrendStat-remediatingPatches')).toHaveTextContent(
      '5'
    );
    expect(screen.getByTestId('softwareInventoryTrendStat-medianTimeToPatch')).toHaveTextContent(
      '2d'
    );
    expect(screen.getByTestId('exposureChartMock')).toBeInTheDocument();
    expect(screen.getByTestId('changesChartMock')).toBeInTheDocument();
  });

  it('shows a dash when the median time to patch is unknown', () => {
    renderSection({
      data: makeTrends({
        patch_summary: { patches: 0, remediating_patches: 0 },
        buckets: [makeRollup()],
      }),
      isLoading: false,
      error: null,
    });
    expect(screen.getByTestId('softwareInventoryTrendStat-medianTimeToPatch')).toHaveTextContent(
      '-'
    );
  });

  it('explains where rollups come from when there are no buckets', () => {
    renderSection({ data: makeTrends({ buckets: [] }), isLoading: false, error: null });
    expect(screen.getByTestId('softwareInventoryTrendsEmpty')).toHaveTextContent('score exposure');
    expect(screen.queryByTestId('exposureChartMock')).not.toBeInTheDocument();
  });

  it('shows loading and error states', () => {
    const { unmount } = renderSection({ data: undefined, isLoading: true, error: null });
    expect(screen.getByTestId('softwareInventoryTrendsLoading')).toBeInTheDocument();
    unmount();
    renderSection({ data: undefined, isLoading: false, error: new Error('boom') });
    expect(screen.getByTestId('softwareInventoryTrendsError')).toHaveTextContent('boom');
  });
});
