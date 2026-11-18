/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import type { ManagedWorkflowDefinition } from '../../types';
import { readManagedWorkflowYaml } from '../read_managed_workflow_yaml';

// Keep these ids equal to `WORKFLOW_IDS` in the software_inventory plugin's common/constants.ts.
export const SOFTWARE_INVENTORY_DISCOVER_OSQUERY_WORKFLOW_ID =
  'system-security-software-inventory-discover-osquery';
export const SOFTWARE_INVENTORY_DISCOVER_INTEGRATIONS_WORKFLOW_ID =
  'system-security-software-inventory-discover-integrations';
export const SOFTWARE_INVENTORY_DISCOVER_LOGS_WORKFLOW_ID =
  'system-security-software-inventory-discover-logs';
export const SOFTWARE_INVENTORY_ENRICH_CVES_WORKFLOW_ID =
  'system-security-software-inventory-enrich-cves';
export const SOFTWARE_INVENTORY_SCORE_EXPOSURE_WORKFLOW_ID =
  'system-security-software-inventory-score-exposure';

const MANAGEMENT = {
  enablement: 'restorable',
  lifecycle: 'static',
  versionStrategy: 'auto',
} as const;

const PLUGIN_ID = 'softwareInventory';

const VISIBILITY = {
  solutions: ['security'],
} as const;

export const SOFTWARE_INVENTORY_DISCOVER_OSQUERY_WORKFLOW = {
  billable: true,
  id: SOFTWARE_INVENTORY_DISCOVER_OSQUERY_WORKFLOW_ID,
  management: MANAGEMENT,
  pluginId: PLUGIN_ID,
  version: 1,
  visibility: VISIBILITY,
  get yaml() {
    return readManagedWorkflowYaml(__dirname, 'discover_osquery.yaml');
  },
} as const satisfies ManagedWorkflowDefinition;

export const SOFTWARE_INVENTORY_DISCOVER_INTEGRATIONS_WORKFLOW = {
  billable: true,
  id: SOFTWARE_INVENTORY_DISCOVER_INTEGRATIONS_WORKFLOW_ID,
  management: MANAGEMENT,
  pluginId: PLUGIN_ID,
  version: 1,
  visibility: VISIBILITY,
  get yaml() {
    return readManagedWorkflowYaml(__dirname, 'discover_integrations.yaml');
  },
} as const satisfies ManagedWorkflowDefinition;

export const SOFTWARE_INVENTORY_DISCOVER_LOGS_WORKFLOW = {
  billable: true,
  id: SOFTWARE_INVENTORY_DISCOVER_LOGS_WORKFLOW_ID,
  management: MANAGEMENT,
  pluginId: PLUGIN_ID,
  version: 1,
  visibility: VISIBILITY,
  get yaml() {
    return readManagedWorkflowYaml(__dirname, 'discover_logs.yaml');
  },
} as const satisfies ManagedWorkflowDefinition;

export const SOFTWARE_INVENTORY_ENRICH_CVES_WORKFLOW = {
  billable: true,
  id: SOFTWARE_INVENTORY_ENRICH_CVES_WORKFLOW_ID,
  management: MANAGEMENT,
  pluginId: PLUGIN_ID,
  version: 1,
  visibility: VISIBILITY,
  get yaml() {
    return readManagedWorkflowYaml(__dirname, 'enrich_cves.yaml');
  },
} as const satisfies ManagedWorkflowDefinition;

export const SOFTWARE_INVENTORY_SCORE_EXPOSURE_WORKFLOW = {
  billable: true,
  id: SOFTWARE_INVENTORY_SCORE_EXPOSURE_WORKFLOW_ID,
  management: MANAGEMENT,
  pluginId: PLUGIN_ID,
  version: 1,
  visibility: VISIBILITY,
  get yaml() {
    return readManagedWorkflowYaml(__dirname, 'score_exposure.yaml');
  },
} as const satisfies ManagedWorkflowDefinition;

export const SOFTWARE_INVENTORY_WORKFLOW_IDS = [
  SOFTWARE_INVENTORY_DISCOVER_OSQUERY_WORKFLOW_ID,
  SOFTWARE_INVENTORY_DISCOVER_INTEGRATIONS_WORKFLOW_ID,
  SOFTWARE_INVENTORY_DISCOVER_LOGS_WORKFLOW_ID,
  SOFTWARE_INVENTORY_ENRICH_CVES_WORKFLOW_ID,
  SOFTWARE_INVENTORY_SCORE_EXPOSURE_WORKFLOW_ID,
] as const;
