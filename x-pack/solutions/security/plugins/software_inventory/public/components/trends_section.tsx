/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from 'react';
import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiPanel,
  EuiSkeletonText,
  EuiSpacer,
  EuiStat,
  EuiTitle,
} from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import { KbnDangerCallout, KbnInfoCallout } from '@kbn/ui-callout';
import type { TrendsResponse } from '../../common/history';
import { formatDuration } from '../lib/duration';
import { toTrendRows } from '../lib/trends';
import { ChangesTrendChart, ExposureTrendChart } from './trend_charts';

interface Props {
  data: TrendsResponse | undefined;
  isLoading: boolean;
  error: Error | null;
}

const NO_VALUE = '-';

const ChartPanel: React.FC<{ title: string; testSubj: string; children: React.ReactNode }> = ({
  title,
  testSubj,
  children,
}) => (
  <EuiPanel hasBorder paddingSize="m" data-test-subj={testSubj}>
    <EuiTitle size="xxs">
      <h3>{title}</h3>
    </EuiTitle>
    <EuiSpacer size="s" />
    {children}
  </EuiPanel>
);

export const TrendsSection: React.FC<Props> = ({ data, isLoading, error }) => {
  const rows = useMemo(() => toTrendRows(data?.buckets ?? []), [data]);

  if (error) {
    return (
      <KbnDangerCallout
        announceOnMount
        data-test-subj="softwareInventoryTrendsError"
        title={i18n.translate('xpack.softwareInventory.trends.errorTitle', {
          defaultMessage: 'Unable to load trends',
        })}
      >
        {error.message}
      </KbnDangerCallout>
    );
  }
  if (isLoading || !data) {
    return <EuiSkeletonText lines={6} data-test-subj="softwareInventoryTrendsLoading" />;
  }

  const { patch_summary: patchSummary } = data;
  const tiles = [
    {
      id: 'patches',
      title: i18n.translate('xpack.softwareInventory.trends.patchesLabel', {
        defaultMessage: 'Patches',
      }),
      value: String(patchSummary.patches),
    },
    {
      id: 'remediatingPatches',
      title: i18n.translate('xpack.softwareInventory.trends.remediatingPatchesLabel', {
        defaultMessage: 'Remediating patches',
      }),
      value: String(patchSummary.remediating_patches),
    },
    {
      id: 'medianTimeToPatch',
      title: i18n.translate('xpack.softwareInventory.trends.medianTimeToPatchLabel', {
        defaultMessage: 'Median time to patch',
      }),
      value:
        patchSummary.median_time_to_patch_ms === undefined
          ? NO_VALUE
          : formatDuration(patchSummary.median_time_to_patch_ms),
    },
  ];

  return (
    <div data-test-subj="softwareInventoryTrends">
      <EuiFlexGroup gutterSize="m" wrap>
        {tiles.map(({ id, title, value }) => (
          <EuiFlexItem key={id}>
            <EuiPanel hasBorder paddingSize="m">
              <EuiStat
                title={value}
                description={title}
                titleSize="m"
                data-test-subj={`softwareInventoryTrendStat-${id}`}
              />
            </EuiPanel>
          </EuiFlexItem>
        ))}
      </EuiFlexGroup>
      <EuiSpacer />
      {rows.length === 0 ? (
        <KbnInfoCallout
          size="s"
          data-test-subj="softwareInventoryTrendsEmpty"
          title={i18n.translate('xpack.softwareInventory.trends.emptyTitle', {
            defaultMessage: 'No daily rollups in this period',
          })}
        >
          {i18n.translate('xpack.softwareInventory.trends.emptyDescription', {
            defaultMessage:
              'Daily rollups are written by the "score exposure" workflow and by the seed script. Run one of them, or choose a period that includes a day it ran.',
          })}
        </KbnInfoCallout>
      ) : (
        <EuiFlexGroup gutterSize="m" wrap>
          <EuiFlexItem css={{ minWidth: 320 }}>
            <ChartPanel
              testSubj="softwareInventoryExposurePanel"
              title={i18n.translate('xpack.softwareInventory.trends.exposureChartTitle', {
                defaultMessage: 'Vulnerable and exposed instances per day',
              })}
            >
              <ExposureTrendChart rows={rows} />
            </ChartPanel>
          </EuiFlexItem>
          <EuiFlexItem css={{ minWidth: 320 }}>
            <ChartPanel
              testSubj="softwareInventoryChangesPanel"
              title={i18n.translate('xpack.softwareInventory.trends.changesChartTitle', {
                defaultMessage: 'New, patched and removed instances per day',
              })}
            >
              <ChangesTrendChart rows={rows} />
            </ChartPanel>
          </EuiFlexItem>
        </EuiFlexGroup>
      )}
    </div>
  );
};
