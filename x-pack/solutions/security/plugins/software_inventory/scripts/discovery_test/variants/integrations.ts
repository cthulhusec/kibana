/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FleetPackagePoliciesResponse } from '../fixtures/fleet';
import type { VariantOptions } from './build_variant';
import { buildVariant, getProductionYaml } from './build_variant';

export const FLEET_LIST_STEP = 'list_package_policies';

export interface IntegrationsVariantSpec extends VariantOptions {
  /** The Fleet response body `list_package_policies` returns in the variant. */
  readonly response: FleetPackagePoliciesResponse;
}

/** `discover-integrations` with the Fleet list step replaced by a `data.set` fixture. */
export const buildIntegrationsVariant = ({
  response,
  ...options
}: IntegrationsVariantSpec): string =>
  buildVariant(
    getProductionYaml('discoverIntegrations'),
    { [FLEET_LIST_STEP]: { kind: 'fixture', output: response } },
    options
  );
