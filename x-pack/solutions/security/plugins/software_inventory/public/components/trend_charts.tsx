/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import {
  AreaSeries,
  Axis,
  BarSeries,
  Chart,
  CurveType,
  Position,
  ScaleType,
  Settings,
  Tooltip,
  TooltipType,
} from '@elastic/charts';
import { useEuiTheme } from '@elastic/eui';
import { useElasticChartsTheme } from '@kbn/charts-theme';
import { i18n } from '@kbn/i18n';
import type { TrendRow } from '../lib/trends';

const CHART_HEIGHT = 220;
const TIME_ZONE = 'UTC';

interface Props {
  rows: TrendRow[];
}

const useSeriesColors = (): string[] => {
  const { euiTheme } = useEuiTheme();
  const { euiColorVis0, euiColorVis4, euiColorVis6 } = euiTheme.colors.vis;
  return [euiColorVis0, euiColorVis4, euiColorVis6];
};

const useTimeFormatter = (): ((value: number) => string) => {
  const locale = i18n.getLocale();
  return (value) =>
    new Date(value).toLocaleDateString(locale, {
      month: 'short',
      day: 'numeric',
      timeZone: TIME_ZONE,
    });
};

const SERIES_NAMES = {
  vulnerable: i18n.translate('xpack.softwareInventory.trends.vulnerableSeriesName', {
    defaultMessage: 'Vulnerable',
  }),
  exposed: i18n.translate('xpack.softwareInventory.trends.exposedSeriesName', {
    defaultMessage: 'Exposed',
  }),
  knownExploited: i18n.translate('xpack.softwareInventory.trends.knownExploitedSeriesName', {
    defaultMessage: 'Known exploited',
  }),
  added: i18n.translate('xpack.softwareInventory.trends.newSeriesName', { defaultMessage: 'New' }),
  patched: i18n.translate('xpack.softwareInventory.trends.patchedSeriesName', {
    defaultMessage: 'Patched',
  }),
  removed: i18n.translate('xpack.softwareInventory.trends.removedSeriesName', {
    defaultMessage: 'Removed',
  }),
};

export const ExposureTrendChart: React.FC<Props> = ({ rows }) => {
  const baseTheme = useElasticChartsTheme();
  const colors = useSeriesColors();
  const formatTime = useTimeFormatter();
  const locale = i18n.getLocale();

  return (
    <Chart size={{ height: CHART_HEIGHT }} data-test-subj="softwareInventoryExposureChart">
      <Settings
        baseTheme={baseTheme}
        theme={[{ colors: { vizColors: colors } }]}
        locale={locale}
        showLegend
        legendPosition={Position.Bottom}
        ariaLabel={i18n.translate('xpack.softwareInventory.trends.exposureChartAriaLabel', {
          defaultMessage: 'Vulnerable, exposed and known exploited instances per day',
        })}
      />
      <Tooltip type={TooltipType.VerticalCursor} />
      <Axis
        id="exposure-x"
        position={Position.Bottom}
        tickFormat={formatTime}
        gridLine={{ visible: false }}
      />
      <Axis id="exposure-y" position={Position.Left} integersOnly />
      <AreaSeries
        id="exposure"
        xScaleType={ScaleType.Time}
        yScaleType={ScaleType.Linear}
        xAccessor="x"
        yAccessors={['vulnerable', 'exposed', 'knownExploited']}
        data={rows}
        timeZone={TIME_ZONE}
        curve={CurveType.CURVE_MONOTONE_X}
        areaSeriesStyle={{ area: { opacity: 0.1 }, line: { strokeWidth: 2 } }}
        yNice
        name={({ yAccessor }) => SERIES_NAMES[yAccessor as keyof typeof SERIES_NAMES]}
      />
    </Chart>
  );
};

export const ChangesTrendChart: React.FC<Props> = ({ rows }) => {
  const baseTheme = useElasticChartsTheme();
  const colors = useSeriesColors();
  const formatTime = useTimeFormatter();
  const locale = i18n.getLocale();

  return (
    <Chart size={{ height: CHART_HEIGHT }} data-test-subj="softwareInventoryChangesChart">
      <Settings
        baseTheme={baseTheme}
        theme={[{ colors: { vizColors: colors } }]}
        locale={locale}
        showLegend
        legendPosition={Position.Bottom}
        ariaLabel={i18n.translate('xpack.softwareInventory.trends.changesChartAriaLabel', {
          defaultMessage: 'New, patched and removed instances per day',
        })}
      />
      <Tooltip type={TooltipType.VerticalCursor} />
      <Axis
        id="changes-x"
        position={Position.Bottom}
        tickFormat={formatTime}
        gridLine={{ visible: false }}
      />
      <Axis id="changes-y" position={Position.Left} integersOnly />
      <BarSeries
        id="changes"
        xScaleType={ScaleType.Time}
        yScaleType={ScaleType.Linear}
        xAccessor="x"
        yAccessors={['added', 'patched', 'removed']}
        stackAccessors={['x']}
        data={rows}
        timeZone={TIME_ZONE}
        name={({ yAccessor }) => SERIES_NAMES[yAccessor as keyof typeof SERIES_NAMES]}
      />
    </Chart>
  );
};
