/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FeaturesPluginSetup } from '@kbn/features-plugin/server';
import { registerSoftwareInventoryFeature } from './features';
import { SOFTWARE_INVENTORY_API_ALL, SOFTWARE_INVENTORY_API_READ } from './privileges';

describe('registerSoftwareInventoryFeature', () => {
  it('registers read and all privileges with the expected api privileges', () => {
    const registerKibanaFeature = jest.fn();
    registerSoftwareInventoryFeature({ registerKibanaFeature } as unknown as FeaturesPluginSetup);

    expect(registerKibanaFeature).toHaveBeenCalledTimes(1);
    const [feature] = registerKibanaFeature.mock.calls[0];
    expect(feature.privileges.read.api).toEqual([SOFTWARE_INVENTORY_API_READ]);
    expect(feature.privileges.all.api).toEqual([
      SOFTWARE_INVENTORY_API_ALL,
      SOFTWARE_INVENTORY_API_READ,
    ]);
  });
});
