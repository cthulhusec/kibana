/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { EuiBadge } from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import type { ExposureLevel, InstanceStatus } from '../../common/types';
import { EXPOSURE_LABELS, STATUS_LABELS } from './labels';

const STATUS_COLOR: Record<InstanceStatus, string> = {
  active: 'success',
  patched: 'primary',
  removed: 'default',
  stale: 'warning',
};

const EXPOSURE_COLOR: Record<ExposureLevel, string> = {
  none: 'default',
  low: 'hollow',
  medium: 'warning',
  high: 'danger',
};

export const StatusBadge: React.FC<{ status: InstanceStatus }> = ({ status }) => (
  <EuiBadge color={STATUS_COLOR[status]} data-test-subj={`softwareInventoryStatus-${status}`}>
    {STATUS_LABELS[status]}
  </EuiBadge>
);

export const ExposureBadge: React.FC<{ level: ExposureLevel; score: number }> = ({
  level,
  score,
}) => (
  <EuiBadge color={EXPOSURE_COLOR[level]} data-test-subj={`softwareInventoryExposure-${level}`}>
    {i18n.translate('xpack.softwareInventory.exposure.badgeLabel', {
      defaultMessage: '{level} ({score})',
      values: { level: EXPOSURE_LABELS[level], score },
    })}
  </EuiBadge>
);
