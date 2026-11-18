/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { PluginConfigDescriptor } from '@kbn/core/server';
import { schema, type TypeOf } from '@kbn/config-schema';
import type { Duration } from 'moment';

const MAX_URL_LENGTH = 2048;

const validateHttpUrl = (value: string): string | undefined => {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return 'must be a valid http or https URL';
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return 'must be a valid http or https URL';
  }
};

const urlSchema = schema.maybe(
  schema.string({ maxLength: MAX_URL_LENGTH, validate: validateHttpUrl })
);

const durationInRange =
  (minMs: number, maxMs: number) =>
  (value: Duration): string | undefined => {
    const ms = value.asMilliseconds();
    if (ms < minMs || ms > maxMs) {
      return `must be between ${minMs}ms and ${maxMs}ms`;
    }
  };

/*
 * Optional CVE enrichment endpoint overrides, for tests that point the `enrich_cves` step at a
 * local stub. Both keys are server-only and unset by default, which keeps the live endpoints.
 *
 *   xpack.softwareInventory.enrichment.nvdBaseUrl  Full URL of the NVD CVE endpoint. Default:
 *                                                  https://services.nvd.nist.gov/rest/json/cves/2.0
 *   xpack.softwareInventory.enrichment.kevUrl      Full URL of the CISA KEV JSON feed. Default:
 *                                                  the CISA known exploited vulnerabilities feed
 *   xpack.softwareInventory.enrichment.requestSpacing  Delay between NVD requests, 0ms to 60s.
 *                                                  Default: 6s without the NVD_API_KEY environment
 *                                                  variable, 700ms with it. When set, it wins.
 *   xpack.softwareInventory.enrichment.requestTimeout  Per-request timeout, 100ms to 120s.
 *                                                  Default: 30s
 *   xpack.softwareInventory.enrichment.backoffBase  Base retry delay, 10ms to 60s; retry n waits
 *                                                  backoffBase * 2^n. Default: 2s
 */
export const configSchema = schema.object({
  /** Kill switch for every side effect: indices, steps, managed workflows, routes, and feature. */
  enabled: schema.boolean({ defaultValue: false }),
  enrichment: schema.object({
    nvdBaseUrl: urlSchema,
    kevUrl: urlSchema,
    requestSpacing: schema.maybe(schema.duration({ validate: durationInRange(0, 60_000) })),
    requestTimeout: schema.maybe(schema.duration({ validate: durationInRange(100, 120_000) })),
    backoffBase: schema.maybe(schema.duration({ validate: durationInRange(10, 60_000) })),
  }),
});

export type SoftwareInventoryConfig = TypeOf<typeof configSchema>;

export const config: PluginConfigDescriptor<SoftwareInventoryConfig> = {
  exposeToBrowser: {
    enabled: true,
  },
  schema: configSchema,
};
