/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import type { AgentBuilderPluginSetup } from '@kbn/agent-builder-server';
import type { SecurityPluginStart } from '@kbn/security-plugin-types-server';
import { createHasReadAccess } from './access';
import { createSoftwareInventorySkill } from './software_inventory_skill';

/**
 * Registers the software inventory skill and its read-only tools.
 * `getSecurity` supplies the security start contract for privilege checks; without it the tools
 * and skill stay unavailable (fail closed).
 */
export const registerSoftwareInventorySkill = ({
  agentBuilder,
  getEsClient,
  logger,
  getSecurity,
}: {
  agentBuilder: AgentBuilderPluginSetup;
  getEsClient: () => Promise<ElasticsearchClient>;
  logger: Logger;
  getSecurity?: () => SecurityPluginStart | undefined;
}): void => {
  agentBuilder.skills.register(
    createSoftwareInventorySkill({
      getEsClient,
      logger,
      hasReadAccess: createHasReadAccess(getSecurity),
    })
  );
};
