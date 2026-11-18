/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { DEFAULT_APP_CATEGORIES } from '@kbn/core/server';
import type { FeaturesPluginSetup } from '@kbn/features-plugin/server';
import { PLUGIN_ID, PLUGIN_NAME } from '../common/constants';
import { SOFTWARE_INVENTORY_API_ALL, SOFTWARE_INVENTORY_API_READ } from './privileges';

export const registerSoftwareInventoryFeature = (features: FeaturesPluginSetup): void => {
  features.registerKibanaFeature({
    id: PLUGIN_ID,
    name: PLUGIN_NAME,
    order: 1102,
    category: DEFAULT_APP_CATEGORIES.security,
    app: [PLUGIN_ID],
    privileges: {
      all: {
        app: [PLUGIN_ID],
        api: [SOFTWARE_INVENTORY_API_ALL, SOFTWARE_INVENTORY_API_READ],
        savedObject: { all: [], read: [] },
        ui: ['show', 'write'],
      },
      read: {
        app: [PLUGIN_ID],
        api: [SOFTWARE_INVENTORY_API_READ],
        savedObject: { all: [], read: [] },
        ui: ['show'],
      },
    },
  });
};
