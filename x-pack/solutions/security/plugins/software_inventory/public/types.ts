/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { WorkflowsExtensionsPublicPluginSetup } from '@kbn/workflows-extensions/public';
import type { SharePluginStart } from '@kbn/share-plugin/public';

export interface SoftwareInventoryClientConfig {
  enabled: boolean;
}

export interface SoftwareInventorySetupDependencies {
  workflowsExtensions: WorkflowsExtensionsPublicPluginSetup;
}

export interface SoftwareInventoryStartDependencies {
  share?: SharePluginStart;
}

export type SoftwareInventoryPublicSetup = Record<string, never>;
export type SoftwareInventoryPublicStart = Record<string, never>;
