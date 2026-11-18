/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  DEFAULT_APP_CATEGORIES,
  type CoreSetup,
  type CoreStart,
  type Plugin,
  type PluginInitializerContext,
} from '@kbn/core/public';
import { i18n } from '@kbn/i18n';
import { APP_PATH, PLUGIN_ID } from '../common/constants';
import { registerSoftwareInventoryPublicSteps } from './steps';
import type {
  SoftwareInventoryClientConfig,
  SoftwareInventoryPublicSetup,
  SoftwareInventoryPublicStart,
  SoftwareInventorySetupDependencies,
  SoftwareInventoryStartDependencies,
} from './types';

// A literal, not `PLUGIN_NAME`: the i18n extractor only reads string literals.
const APP_TITLE = i18n.translate('xpack.softwareInventory.appTitle', {
  defaultMessage: 'Software inventory',
});

export class SoftwareInventoryPublicPlugin
  implements
    Plugin<
      SoftwareInventoryPublicSetup,
      SoftwareInventoryPublicStart,
      SoftwareInventorySetupDependencies,
      SoftwareInventoryStartDependencies
    >
{
  private readonly config: SoftwareInventoryClientConfig;

  constructor(context: PluginInitializerContext<SoftwareInventoryClientConfig>) {
    this.config = context.config.get();
  }

  public setup(
    core: CoreSetup<SoftwareInventoryStartDependencies, SoftwareInventoryPublicStart>,
    deps: SoftwareInventorySetupDependencies
  ): SoftwareInventoryPublicSetup {
    if (!this.config.enabled) {
      return {};
    }

    registerSoftwareInventoryPublicSteps(deps.workflowsExtensions);

    core.application.register({
      id: PLUGIN_ID,
      title: APP_TITLE,
      appRoute: APP_PATH,
      category: DEFAULT_APP_CATEGORIES.security,
      euiIconType: 'package',
      visibleIn: ['projectSideNav', 'globalSearch'],
      order: 102,
      mount: async (params) => {
        const [coreStart, startDeps] = await core.getStartServices();
        const { renderApp } = await import('./application');
        return renderApp({ coreStart, startDeps, params });
      },
    });

    return {};
  }

  public start(_core: CoreStart): SoftwareInventoryPublicStart {
    return {};
  }

  public stop(): void {}
}
