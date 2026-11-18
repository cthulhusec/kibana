/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  CoreSetup,
  CoreStart,
  ElasticsearchClient,
  Logger,
  Plugin,
  PluginInitializerContext,
} from '@kbn/core/server';
import { MANAGED_WORKFLOW_OWNER_ID } from '../common/constants';
import type { SoftwareInventoryConfig } from './config';
import type {
  SoftwareInventoryServerSetup,
  SoftwareInventoryServerSetupDependencies,
  SoftwareInventoryServerStart,
  SoftwareInventoryServerStartDependencies,
} from './types';
import { registerSoftwareInventoryFeature } from './features';
import { registerRoutes } from './routes/register_routes';
import { registerSoftwareInventorySkill } from './agent_builder/register_skill';
import { registerSoftwareInventorySteps } from './steps/register_steps';
import { ensureIndices } from './services/indices';
import { installManagedWorkflows } from './services/managed_workflows/install_managed_workflows';

const errorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

export class SoftwareInventoryServerPlugin
  implements
    Plugin<
      SoftwareInventoryServerSetup,
      SoftwareInventoryServerStart,
      SoftwareInventoryServerSetupDependencies,
      SoftwareInventoryServerStartDependencies
    >
{
  private readonly logger: Logger;
  private readonly config: SoftwareInventoryConfig;
  private security?: SoftwareInventoryServerStartDependencies['security'];

  constructor(context: PluginInitializerContext<SoftwareInventoryConfig>) {
    this.logger = context.logger.get();
    this.config = context.config.get();
  }

  public setup(
    core: CoreSetup<SoftwareInventoryServerStartDependencies, SoftwareInventoryServerStart>,
    { features, workflowsExtensions, agentBuilder }: SoftwareInventoryServerSetupDependencies
  ): SoftwareInventoryServerSetup {
    if (!this.config.enabled) {
      this.logger.debug('Software inventory plugin is disabled');
      return { isEnabled: false };
    }

    // The inventory indices are plugin-owned and hidden, so every reader and writer uses the
    // internal user. Routes and tools enforce the feature privilege before calling it.
    const getEsClient = async (): Promise<ElasticsearchClient> => {
      const [coreStart] = await core.getStartServices();
      return coreStart.elasticsearch.client.asInternalUser;
    };

    // Registered before start so orphan cleanup never sees these workflows as ownerless.
    workflowsExtensions.registerManagedWorkflowOwner(MANAGED_WORKFLOW_OWNER_ID);
    registerSoftwareInventorySteps({
      workflowsExtensions,
      getEsClient,
      logger: this.logger.get('steps'),
    });
    registerSoftwareInventoryFeature(features);
    registerRoutes({ router: core.http.createRouter(), logger: this.logger, getEsClient });
    if (agentBuilder) {
      registerSoftwareInventorySkill({
        agentBuilder,
        getEsClient,
        logger: this.logger.get('agent_builder'),
        getSecurity: () => this.security,
      });
    }

    return { isEnabled: true };
  }

  public start(
    core: CoreStart,
    { workflowsExtensions, security }: SoftwareInventoryServerStartDependencies
  ): SoftwareInventoryServerStart {
    this.security = security;
    if (!this.config.enabled) {
      return {};
    }

    // Plugin start cannot return a promise. Workflows run only after the indices exist, because
    // managed workflows install after this resolves.
    const esClient = core.elasticsearch.client.asInternalUser;
    void ensureIndices({ esClient, logger: this.logger })
      .then(() => installManagedWorkflows({ workflowsExtensions, logger: this.logger }))
      .catch((error) => {
        this.logger.error(`Software inventory initialization failed: ${errorMessage(error)}`);
      });

    return {};
  }

  public stop(): void {}
}
