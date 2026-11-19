/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema, type Type } from '@kbn/config-schema';
import type { ElasticsearchClient, IRouter, Logger, RouteSecurity } from '@kbn/core/server';
import {
  API_VERSION,
  CATALOG_DETAIL_URL,
  HOST_TIMELINE_URL,
  INSTANCES_URL,
  MAX_PAGE_SIZE,
  SUMMARY_URL,
  TRENDS_URL,
} from '../../common/constants';
import { SOFTWARE_INVENTORY_API_READ } from '../privileges';
import { findInstances, getCatalogDetail, getSummary } from './data_access';
import type {
  DiscoverySource,
  ExposureLevel,
  InstanceStatus,
  SoftwareCategory,
} from '../../common/types';
import { toArray, validatePageWindow, type AsOfRange } from './query_builders';
import {
  getHostTimeline,
  getTrends,
  validateHistoryRange,
} from '../services/history/history_data_access';

const MAX_DATE_LENGTH = 64;
const isoDate = () => schema.string({ minLength: 1, maxLength: MAX_DATE_LENGTH });

const MAX_FILTER_VALUES = 20;

const listOf = <T extends string>(item: Type<T>) =>
  schema.maybe(schema.oneOf([schema.arrayOf<T>(item, { maxSize: MAX_FILTER_VALUES }), item]));

const querySchema = schema.object({
  page: schema.number({ min: 1, max: 10000, defaultValue: 1 }),
  per_page: schema.number({ min: 1, max: MAX_PAGE_SIZE, defaultValue: 25 }),
  sort_field: schema.oneOf(
    [
      schema.literal('last_seen'),
      schema.literal('first_seen'),
      schema.literal('version_changed_at'),
      schema.literal('exposure.score'),
      schema.literal('host.name'),
    ],
    { defaultValue: 'last_seen' }
  ),
  sort_order: schema.oneOf([schema.literal('asc'), schema.literal('desc')], {
    defaultValue: 'desc',
  }),
  search: schema.maybe(schema.string({ minLength: 1, maxLength: 256 })),
  category: listOf<SoftwareCategory>(
    schema.oneOf([
      schema.literal('application'),
      schema.literal('dependency'),
      schema.literal('appliance'),
      schema.literal('os_package'),
      schema.literal('other'),
    ])
  ),
  source: listOf<DiscoverySource>(
    schema.oneOf([
      schema.literal('osquery'),
      schema.literal('fleet_integration'),
      schema.literal('logs'),
      schema.literal('endpoint'),
      schema.literal('manual'),
    ])
  ),
  status: listOf<InstanceStatus>(
    schema.oneOf([
      schema.literal('active'),
      schema.literal('patched'),
      schema.literal('removed'),
      schema.literal('stale'),
    ])
  ),
  exposure_level: listOf<ExposureLevel>(
    schema.oneOf([
      schema.literal('none'),
      schema.literal('low'),
      schema.literal('medium'),
      schema.literal('high'),
    ])
  ),
  min_cve_count: schema.maybe(schema.number({ min: 0, max: 100000 })),
  known_exploited: schema.maybe(schema.boolean()),
  patched_within_days: schema.maybe(schema.number({ min: 1, max: 3650 })),
  host_id: schema.maybe(schema.string({ minLength: 1, maxLength: 512 })),
  as_of_from: schema.maybe(isoDate()),
  as_of_to: schema.maybe(isoDate()),
  vulnerable_in_range: schema.maybe(schema.boolean()),
});

const rangeQuerySchema = schema.object({ from: isoDate(), to: isoDate() });

const hostTimelineParamsSchema = schema.object({
  host_key: schema.string({ minLength: 1, maxLength: 512 }),
});

/** Validates the optional `as_of_from`/`as_of_to` pair of the instances route. */
export const parseAsOf = ({
  as_of_from: from,
  as_of_to: to,
  vulnerable_in_range: vulnerableInRange,
}: {
  as_of_from?: string;
  as_of_to?: string;
  vulnerable_in_range?: boolean;
}): { asOf?: AsOfRange; error?: string } => {
  if (from === undefined && to === undefined) {
    return vulnerableInRange === true
      ? { error: '`vulnerable_in_range` requires `as_of_from` and `as_of_to`' }
      : {};
  }
  if (from === undefined || to === undefined) {
    return { error: '`as_of_from` and `as_of_to` must be passed together' };
  }
  const validation = validateHistoryRange(from, to);
  return validation.error !== undefined ? { error: validation.error } : { asOf: validation.range };
};

const detailParamsSchema = schema.object({
  id: schema.string({ minLength: 1, maxLength: 512 }),
});

const security: RouteSecurity = {
  authz: { requiredPrivileges: [SOFTWARE_INVENTORY_API_READ] },
};

export const registerRoutes = ({
  router,
  logger,
  getEsClient,
}: {
  router: IRouter;
  logger: Logger;
  getEsClient: () => Promise<ElasticsearchClient>;
}): void => {
  router.versioned
    .get({ path: INSTANCES_URL, access: 'internal', security })
    .addVersion(
      { version: API_VERSION, validate: { request: { query: querySchema } } },
      async (_context, request, response) => {
        const {
          as_of_from: asOfFrom,
          as_of_to: asOfTo,
          vulnerable_in_range: vulnerableInRange,
          ...query
        } = request.query;
        const windowError = validatePageWindow(query.page, query.per_page);
        if (windowError) return response.badRequest({ body: { message: windowError } });
        const { asOf, error: asOfError } = parseAsOf({
          as_of_from: asOfFrom,
          as_of_to: asOfTo,
          vulnerable_in_range: vulnerableInRange,
        });
        if (asOfError) return response.badRequest({ body: { message: asOfError } });
        try {
          const esClient = await getEsClient();
          const body = await findInstances(esClient, {
            ...query,
            as_of: asOf,
            vulnerable_in_range: vulnerableInRange,
            category: toArray(query.category),
            source: toArray(query.source),
            status: toArray(query.status),
            exposure_level: toArray(query.exposure_level),
          });
          return response.ok({ body });
        } catch (error) {
          logger.error(`Failed to list software instances: ${error}`);
          return response.customError({
            statusCode: 500,
            body: { message: 'Failed to list software instances' },
          });
        }
      }
    );

  router.versioned
    .get({ path: SUMMARY_URL, access: 'internal', security })
    .addVersion({ version: API_VERSION, validate: false }, async (_context, _request, response) => {
      try {
        const body = await getSummary(await getEsClient());
        return response.ok({ body });
      } catch (error) {
        logger.error(`Failed to build software inventory summary: ${error}`);
        return response.customError({
          statusCode: 500,
          body: { message: 'Failed to build software inventory summary' },
        });
      }
    });

  router.versioned
    .get({ path: CATALOG_DETAIL_URL, access: 'internal', security })
    .addVersion(
      { version: API_VERSION, validate: { request: { params: detailParamsSchema } } },
      async (_context, request, response) => {
        try {
          const body = await getCatalogDetail(await getEsClient(), request.params.id);
          if (!body) {
            return response.notFound({ body: { message: 'Software entry not found' } });
          }
          return response.ok({ body });
        } catch (error) {
          logger.error(`Failed to get software catalog entry: ${error}`);
          return response.customError({
            statusCode: 500,
            body: { message: 'Failed to get software catalog entry' },
          });
        }
      }
    );

  router.versioned
    .get({ path: TRENDS_URL, access: 'internal', security })
    .addVersion(
      { version: API_VERSION, validate: { request: { query: rangeQuerySchema } } },
      async (_context, request, response) => {
        const validation = validateHistoryRange(request.query.from, request.query.to);
        if (validation.error !== undefined) {
          return response.badRequest({ body: { message: validation.error } });
        }
        try {
          const body = await getTrends(await getEsClient(), validation.range);
          return response.ok({ body });
        } catch (error) {
          logger.error(`Failed to get software inventory trends: ${error}`);
          return response.customError({
            statusCode: 500,
            body: { message: 'Failed to get software inventory trends' },
          });
        }
      }
    );

  router.versioned.get({ path: HOST_TIMELINE_URL, access: 'internal', security }).addVersion(
    {
      version: API_VERSION,
      validate: { request: { params: hostTimelineParamsSchema, query: rangeQuerySchema } },
    },
    async (_context, request, response) => {
      const validation = validateHistoryRange(request.query.from, request.query.to);
      if (validation.error !== undefined) {
        return response.badRequest({ body: { message: validation.error } });
      }
      try {
        const body = await getHostTimeline(
          await getEsClient(),
          request.params.host_key,
          validation.range
        );
        if (!body) {
          return response.notFound({ body: { message: 'No software found for this host' } });
        }
        return response.ok({ body });
      } catch (error) {
        logger.error(`Failed to get software inventory host timeline: ${error}`);
        return response.customError({
          statusCode: 500,
          body: { message: 'Failed to get software inventory host timeline' },
        });
      }
    }
  );
};
