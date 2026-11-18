/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PluginInitializer, PluginInitializerContext } from '@kbn/core/public';
import { SoftwareInventoryPublicPlugin } from './plugin';
import type {
  SoftwareInventoryClientConfig,
  SoftwareInventoryPublicSetup,
  SoftwareInventoryPublicStart,
  SoftwareInventorySetupDependencies,
  SoftwareInventoryStartDependencies,
} from './types';

export const plugin: PluginInitializer<
  SoftwareInventoryPublicSetup,
  SoftwareInventoryPublicStart,
  SoftwareInventorySetupDependencies,
  SoftwareInventoryStartDependencies
> = (context: PluginInitializerContext<SoftwareInventoryClientConfig>) =>
  new SoftwareInventoryPublicPlugin(context);
