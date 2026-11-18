/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaRequest } from '@kbn/core/server';
import type { SecurityPluginStart } from '@kbn/security-plugin-types-server';
import { SOFTWARE_INVENTORY_API_READ } from '../privileges';

export type HasReadAccess = (request: KibanaRequest) => Promise<boolean>;

/**
 * Checks the caller for the software inventory read privilege. Fails closed when the security
 * plugin is unavailable, because the tools query system indices as the internal user.
 */
export const createHasReadAccess =
  (getSecurity?: () => SecurityPluginStart | undefined): HasReadAccess =>
  async (request) => {
    const security = getSecurity?.();
    if (!security) return false;
    try {
      const { hasAllRequested } = await security.authz.checkPrivilegesDynamicallyWithRequest(
        request
      )({
        kibana: [security.authz.actions.api.get(SOFTWARE_INVENTORY_API_READ)],
      });
      return hasAllRequested;
    } catch {
      return false;
    }
  };
