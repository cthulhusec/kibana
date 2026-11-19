/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { i18n } from '@kbn/i18n';
import type {
  DiscoverySource,
  ExposureLevel,
  InstanceStatus,
  SoftwareCategory,
} from '../../common/types';

export const CATEGORY_LABELS: Record<SoftwareCategory, string> = {
  application: i18n.translate('xpack.softwareInventory.category.applicationLabel', {
    defaultMessage: 'Application',
  }),
  dependency: i18n.translate('xpack.softwareInventory.category.dependencyLabel', {
    defaultMessage: 'Dependency',
  }),
  appliance: i18n.translate('xpack.softwareInventory.category.applianceLabel', {
    defaultMessage: 'Appliance',
  }),
  os_package: i18n.translate('xpack.softwareInventory.category.osPackageLabel', {
    defaultMessage: 'OS package',
  }),
  other: i18n.translate('xpack.softwareInventory.category.otherLabel', {
    defaultMessage: 'Other',
  }),
};

export const SOURCE_LABELS: Record<DiscoverySource, string> = {
  osquery: i18n.translate('xpack.softwareInventory.source.osqueryLabel', {
    defaultMessage: 'Osquery',
  }),
  fleet_integration: i18n.translate('xpack.softwareInventory.source.fleetIntegrationLabel', {
    defaultMessage: 'Fleet integration',
  }),
  logs: i18n.translate('xpack.softwareInventory.source.logsLabel', { defaultMessage: 'Logs' }),
  endpoint: i18n.translate('xpack.softwareInventory.source.endpointLabel', {
    defaultMessage: 'Endpoint',
  }),
  manual: i18n.translate('xpack.softwareInventory.source.manualLabel', {
    defaultMessage: 'Manual',
  }),
};

export const STATUS_LABELS: Record<InstanceStatus, string> = {
  active: i18n.translate('xpack.softwareInventory.status.activeLabel', {
    defaultMessage: 'Active',
  }),
  patched: i18n.translate('xpack.softwareInventory.status.patchedLabel', {
    defaultMessage: 'Patched',
  }),
  removed: i18n.translate('xpack.softwareInventory.status.removedLabel', {
    defaultMessage: 'Removed',
  }),
  stale: i18n.translate('xpack.softwareInventory.status.staleLabel', {
    defaultMessage: 'Stale',
  }),
};

export const EXPOSURE_LABELS: Record<ExposureLevel, string> = {
  none: i18n.translate('xpack.softwareInventory.exposure.noneLabel', { defaultMessage: 'None' }),
  low: i18n.translate('xpack.softwareInventory.exposure.lowLabel', { defaultMessage: 'Low' }),
  medium: i18n.translate('xpack.softwareInventory.exposure.mediumLabel', {
    defaultMessage: 'Medium',
  }),
  high: i18n.translate('xpack.softwareInventory.exposure.highLabel', { defaultMessage: 'High' }),
};

export const PERIOD_LABELS = {
  currentInventory: i18n.translate('xpack.softwareInventory.period.currentInventoryToggleSwitch', {
    defaultMessage: 'Current inventory',
  }),
  caption: i18n.translate('xpack.softwareInventory.period.captionDescription', {
    defaultMessage:
      'Showing software that was installed at any point during the selected period. The version shown is the one that ran during it.',
  }),
  currentCaption: i18n.translate('xpack.softwareInventory.period.currentCaptionDescription', {
    defaultMessage:
      'Showing the current inventory. The trends above still use the selected period.',
  }),
  vulnerableDuringPeriod: i18n.translate('xpack.softwareInventory.period.vulnerableFilterLabel', {
    defaultMessage: 'Vulnerable during period',
  }),
  vulnerableInPeriodColumn: i18n.translate(
    'xpack.softwareInventory.period.vulnerableInPeriodColumn',
    { defaultMessage: 'Vulnerable in period' }
  ),
  vulnerableBadge: i18n.translate('xpack.softwareInventory.period.vulnerableBadge', {
    defaultMessage: 'Vulnerable',
  }),
  notVulnerableBadge: i18n.translate('xpack.softwareInventory.period.notVulnerableBadge', {
    defaultMessage: 'Not vulnerable',
  }),
};
