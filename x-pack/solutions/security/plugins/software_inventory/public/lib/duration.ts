/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { i18n } from '@kbn/i18n';

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

/**
 * Formats a millisecond duration using its two largest non-zero units, for example `2d 4h`,
 * `3h 20m` or `45m`. Durations under a minute read `<1m`.
 */
export const formatDuration = (ms: number): string => {
  const total = Math.max(0, Math.floor(ms));
  if (total === 0)
    return i18n.translate('xpack.softwareInventory.duration.zeroLabel', {
      defaultMessage: '0m',
    });
  if (total < MINUTE_MS)
    return i18n.translate('xpack.softwareInventory.duration.underMinuteLabel', {
      defaultMessage: '<1m',
    });

  const days = Math.floor(total / DAY_MS);
  const hours = Math.floor((total % DAY_MS) / HOUR_MS);
  const minutes = Math.floor((total % HOUR_MS) / MINUTE_MS);

  if (days > 0) {
    return hours > 0
      ? i18n.translate('xpack.softwareInventory.duration.daysHoursLabel', {
          defaultMessage: '{days}d {hours}h',
          values: { days, hours },
        })
      : i18n.translate('xpack.softwareInventory.duration.daysLabel', {
          defaultMessage: '{days}d',
          values: { days },
        });
  }
  if (hours > 0) {
    return minutes > 0
      ? i18n.translate('xpack.softwareInventory.duration.hoursMinutesLabel', {
          defaultMessage: '{hours}h {minutes}m',
          values: { hours, minutes },
        })
      : i18n.translate('xpack.softwareInventory.duration.hoursLabel', {
          defaultMessage: '{hours}h',
          values: { hours },
        });
  }
  return i18n.translate('xpack.softwareInventory.duration.minutesLabel', {
    defaultMessage: '{minutes}m',
    values: { minutes },
  });
};
