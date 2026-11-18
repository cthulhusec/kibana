/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PluginConfigDescriptor } from '@kbn/core/server';
import { schema, type TypeOf } from '@kbn/config-schema';

export const configSchema = schema.object({
  /** Kill switch for every side effect: indices, steps, managed workflows, routes, and feature. */
  enabled: schema.boolean({ defaultValue: false }),
});

export type SoftwareInventoryConfig = TypeOf<typeof configSchema>;

export const config: PluginConfigDescriptor<SoftwareInventoryConfig> = {
  exposeToBrowser: {
    enabled: true,
  },
  schema: configSchema,
};
