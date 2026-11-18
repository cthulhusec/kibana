/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { EuiFlexGroup, EuiFlexItem, EuiPanel, EuiStat } from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import type { SummaryResponse } from '../../common/types';

interface Props {
  summary: SummaryResponse | undefined;
  loading: boolean;
}

export const SummaryStats: React.FC<Props> = ({ summary, loading }) => {
  const stats = [
    {
      id: 'totalSoftware',
      title: i18n.translate('xpack.softwareInventory.summary.totalSoftwareLabel', {
        defaultMessage: 'Total software',
      }),
      value: summary?.total_software,
    },
    {
      id: 'instances',
      title: i18n.translate('xpack.softwareInventory.summary.instancesLabel', {
        defaultMessage: 'Instances',
      }),
      value: summary?.total_instances,
    },
    {
      id: 'exposed',
      title: i18n.translate('xpack.softwareInventory.summary.exposedLabel', {
        defaultMessage: 'Exposed',
      }),
      value: summary?.exposed_instances,
    },
    {
      id: 'vulnerable',
      title: i18n.translate('xpack.softwareInventory.summary.vulnerableLabel', {
        defaultMessage: 'Vulnerable',
      }),
      value: summary?.vulnerable_instances,
    },
    {
      id: 'knownExploited',
      title: i18n.translate('xpack.softwareInventory.summary.knownExploitedLabel', {
        defaultMessage: 'Known exploited',
      }),
      value: summary?.known_exploited_instances,
    },
    {
      id: 'recentlyPatched',
      title: i18n.translate('xpack.softwareInventory.summary.recentlyPatchedLabel', {
        defaultMessage: 'Recently patched',
      }),
      value: summary?.recently_patched_instances,
    },
  ];

  return (
    <EuiFlexGroup gutterSize="m" wrap data-test-subj="softwareInventorySummary">
      {stats.map(({ id, title, value }) => (
        <EuiFlexItem key={id}>
          <EuiPanel hasBorder>
            <EuiStat
              title={value === undefined ? '-' : value.toLocaleString()}
              description={title}
              isLoading={loading}
              titleSize="m"
              data-test-subj={`softwareInventoryStat-${id}`}
            />
          </EuiPanel>
        </EuiFlexItem>
      ))}
    </EuiFlexGroup>
  );
};
