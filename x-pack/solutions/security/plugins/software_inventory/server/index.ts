/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PluginInitializer, PluginInitializerContext } from '@kbn/core/server';
import type { SoftwareInventoryConfig } from './config';
import type {
  SoftwareInventoryServerSetup,
  SoftwareInventoryServerSetupDependencies,
  SoftwareInventoryServerStart,
  SoftwareInventoryServerStartDependencies,
} from './types';

export type { SoftwareInventoryServerSetup, SoftwareInventoryServerStart } from './types';

export const plugin: PluginInitializer<
  SoftwareInventoryServerSetup,
  SoftwareInventoryServerStart,
  SoftwareInventoryServerSetupDependencies,
  SoftwareInventoryServerStartDependencies
> = async (initializerContext: PluginInitializerContext<SoftwareInventoryConfig>) => {
  const { SoftwareInventoryServerPlugin } = await import('./plugin');
  return new SoftwareInventoryServerPlugin(initializerContext);
};

export { config } from './config';
