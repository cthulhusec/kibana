/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiSpacer,
  EuiSuperDatePicker,
  EuiSwitch,
  EuiText,
  type OnTimeChangeProps,
} from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import { KbnWarningCallout } from '@kbn/ui-callout';
import { MAX_HISTORY_RANGE_DAYS } from '../../common/constants';
import type { RangeResolution, TimeRangeInput } from '../lib/time_range';
import { PERIOD_LABELS } from './labels';

interface Props {
  range: TimeRangeInput;
  resolution: RangeResolution;
  isCurrentInventory: boolean;
  onRangeChange: (next: TimeRangeInput) => void;
  onRefresh: () => void;
  onCurrentInventoryChange: (next: boolean) => void;
}

const COMMONLY_USED_RANGES = [
  {
    start: 'now-24h',
    end: 'now',
    label: i18n.translate('xpack.softwareInventory.period.last24HoursRangeLabel', {
      defaultMessage: 'Last 24 hours',
    }),
  },
  {
    start: 'now-7d',
    end: 'now',
    label: i18n.translate('xpack.softwareInventory.period.last7DaysRangeLabel', {
      defaultMessage: 'Last 7 days',
    }),
  },
  {
    start: 'now-30d',
    end: 'now',
    label: i18n.translate('xpack.softwareInventory.period.last30DaysRangeLabel', {
      defaultMessage: 'Last 30 days',
    }),
  },
  {
    start: 'now-90d',
    end: 'now',
    label: i18n.translate('xpack.softwareInventory.period.last90DaysRangeLabel', {
      defaultMessage: 'Last 90 days',
    }),
  },
  {
    start: 'now-1y',
    end: 'now',
    label: i18n.translate('xpack.softwareInventory.period.lastYearRangeLabel', {
      defaultMessage: 'Last year',
    }),
  },
];

export const PeriodControls: React.FC<Props> = ({
  range,
  resolution,
  isCurrentInventory,
  onRangeChange,
  onRefresh,
  onCurrentInventoryChange,
}) => {
  const handleTimeChange = ({ start, end }: OnTimeChangeProps): void =>
    onRangeChange({ start, end });

  return (
    <div data-test-subj="softwareInventoryPeriodControls">
      <EuiFlexGroup gutterSize="m" alignItems="center" wrap responsive={false}>
        <EuiFlexItem grow={false}>
          <EuiSuperDatePicker
            start={range.start}
            end={range.end}
            onTimeChange={handleTimeChange}
            onRefresh={onRefresh}
            commonlyUsedRanges={COMMONLY_USED_RANGES}
            data-test-subj="softwareInventoryDatePicker"
          />
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiSwitch
            label={PERIOD_LABELS.currentInventory}
            checked={isCurrentInventory}
            onChange={(e) => onCurrentInventoryChange(e.target.checked)}
            data-test-subj="softwareInventoryCurrentToggle"
          />
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size="s" />
      <EuiText size="s" color="subdued" data-test-subj="softwareInventoryPeriodCaption">
        {isCurrentInventory ? PERIOD_LABELS.currentCaption : PERIOD_LABELS.caption}
      </EuiText>
      {resolution.status === 'invalid' ? (
        <>
          <EuiSpacer size="s" />
          <KbnWarningCallout
            size="s"
            data-test-subj="softwareInventoryRangeInvalid"
            title={i18n.translate('xpack.softwareInventory.period.invalidRangeTitle', {
              defaultMessage: 'Choose a valid time range. The start must be before the end.',
            })}
          />
        </>
      ) : null}
      {resolution.status === 'ok' && resolution.clamped ? (
        <>
          <EuiSpacer size="s" />
          <KbnWarningCallout
            size="s"
            data-test-subj="softwareInventoryRangeClamped"
            title={i18n.translate('xpack.softwareInventory.period.clampedRangeTitle', {
              defaultMessage:
                'The selected range is longer than {days} days. Showing the most recent {days} days.',
              values: { days: MAX_HISTORY_RANGE_DAYS },
            })}
          />
        </>
      ) : null}
    </div>
  );
};
