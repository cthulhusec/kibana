/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AgentBuilderPluginSetup } from '@kbn/agent-builder-server';
import type { FeaturesPluginSetup } from '@kbn/features-plugin/server';
import type { SecurityPluginStart } from '@kbn/security-plugin-types-server';
import type {
  TaskManagerSetupContract,
  TaskManagerStartContract,
} from '@kbn/task-manager-plugin/server';
import type {
  WorkflowsExtensionsServerPluginSetup,
  WorkflowsExtensionsServerPluginStart,
} from '@kbn/workflows-extensions/server';
import type { WorkflowsServerPluginSetup } from '@kbn/workflows-management-plugin/server';

export interface SoftwareInventoryServerSetupDependencies {
  features: FeaturesPluginSetup;
  workflowsExtensions: WorkflowsExtensionsServerPluginSetup;
  workflowsManagement: WorkflowsServerPluginSetup;
  taskManager: TaskManagerSetupContract;
  agentBuilder?: AgentBuilderPluginSetup;
}

export interface SoftwareInventoryServerStartDependencies {
  workflowsExtensions: WorkflowsExtensionsServerPluginStart;
  taskManager: TaskManagerStartContract;
  security?: SecurityPluginStart;
}

export interface SoftwareInventoryServerSetup {
  isEnabled: boolean;
}

export type SoftwareInventoryServerStart = Record<string, never>;
