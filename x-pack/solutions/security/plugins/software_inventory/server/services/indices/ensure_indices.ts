/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import { errors } from '@elastic/elasticsearch';
import type { MappingProperty, MappingTypeMapping } from '@elastic/elasticsearch/lib/api/types';
import {
  CATALOG_INDEX,
  EVENTS_INDEX,
  INSTANCES_INDEX,
  ROLLUPS_INDEX,
} from '../../../common/constants';
import {
  CATALOG_MAPPINGS,
  EVENTS_MAPPINGS,
  INSTANCES_MAPPINGS,
  ROLLUPS_MAPPINGS,
} from '../../../common/mappings';

const INDICES: ReadonlyArray<{ index: string; mappings: MappingTypeMapping }> = [
  { index: CATALOG_INDEX, mappings: CATALOG_MAPPINGS },
  { index: INSTANCES_INDEX, mappings: INSTANCES_MAPPINGS },
  { index: EVENTS_INDEX, mappings: EVENTS_MAPPINGS },
  { index: ROLLUPS_INDEX, mappings: ROLLUPS_MAPPINGS },
];

/** Fields that are `nested` in the current mappings and were `object` in earlier versions. */
const NESTED_FIELDS: Readonly<Record<string, readonly string[]>> = {
  [INSTANCES_INDEX]: ['version_history'],
};

const isAlreadyExistsError = (error: unknown): boolean =>
  error instanceof errors.ResponseError &&
  error.body?.error?.type === 'resource_already_exists_exception';

const createIndex = async (
  esClient: ElasticsearchClient,
  logger: Logger,
  index: string,
  mappings: MappingTypeMapping
): Promise<void> => {
  try {
    await esClient.indices.create({
      index,
      mappings,
      // Shard and replica settings are left out: serverless rejects them.
      settings: { hidden: true },
    });
    logger.info(`Created software inventory index ${index}`);
  } catch (error) {
    // Another Kibana node created it first.
    if (isAlreadyExistsError(error)) {
      return;
    }
    throw error;
  }
};

/** Names of `nestedFields` that the live index maps as something other than `nested`. */
export const findNonNestedFields = (
  liveProperties: Record<string, MappingProperty> | undefined,
  nestedFields: readonly string[]
): string[] =>
  nestedFields.filter((field) => {
    const live = liveProperties?.[field];
    return live !== undefined && live.type !== 'nested';
  });

/**
 * Downgrades `nested` fields to `object` (keeping their sub-properties), so `putMapping` can still
 * add new sub-fields to a legacy index without the type change Elasticsearch rejects.
 */
export const asLegacyObjectProperties = (
  properties: Record<string, MappingProperty>,
  legacyFields: readonly string[]
): Record<string, MappingProperty> =>
  Object.fromEntries(
    Object.entries(properties).map(([name, property]) => {
      if (!legacyFields.includes(name) || !('properties' in property)) return [name, property];
      return [name, { properties: property.properties }];
    })
  );

const liveProperties = async (
  esClient: ElasticsearchClient,
  index: string
): Promise<Record<string, MappingProperty> | undefined> => {
  const response = await esClient.indices.getMapping({ index });
  const [first] = Object.values(response);
  return first?.mappings?.properties;
};

/**
 * Handles an index whose mapping has an `object` field that is now `nested`. Elasticsearch cannot
 * change that in place: an empty index is recreated; an index with documents is kept, gets the new
 * sub-fields as `object`, and an error asks the operator to recreate it. Returns true when handled.
 */
const migrateNestedFields = async (
  esClient: ElasticsearchClient,
  logger: Logger,
  index: string,
  mappings: MappingTypeMapping
): Promise<boolean> => {
  const nestedFields = NESTED_FIELDS[index] ?? [];
  if (nestedFields.length === 0) return false;
  const legacy = findNonNestedFields(await liveProperties(esClient, index), nestedFields);
  if (legacy.length === 0) return false;

  const { count } = await esClient.count({ index });
  if (count === 0) {
    await esClient.indices.delete({ index });
    logger.info(`Recreating empty software inventory index ${index} to map ${legacy} as nested`);
    await createIndex(esClient, logger, index, mappings);
    return true;
  }

  logger.error(
    `Software inventory index ${index} maps ${legacy.join(', ')} as object, but history ` +
      `features need nested. Elasticsearch cannot change this in place, so the index was left ` +
      `unchanged with its ${count} document(s); ingest keeps working but history queries fail. ` +
      `Delete the index (or run the seed script with --clean) and restart Kibana to recreate it.`
  );
  await esClient.indices.putMapping({
    index,
    properties: asLegacyObjectProperties(mappings.properties ?? {}, legacy),
  });
  return true;
};

const ensureIndex = async (
  esClient: ElasticsearchClient,
  logger: Logger,
  index: string,
  mappings: MappingTypeMapping
): Promise<void> => {
  const exists = await esClient.indices.exists({ index });
  if (!exists) {
    await createIndex(esClient, logger, index, mappings);
    return;
  }
  if (await migrateNestedFields(esClient, logger, index, mappings)) {
    return;
  }
  // Adds fields introduced since the index was created. Mapping changes are additive only.
  const { properties } = mappings;
  await esClient.indices.putMapping({ index, properties });
};

/**
 * Creates the catalog, instances, events, and rollups indices when missing, and updates their
 * mappings. Safe to call on every start. A legacy `object` mapping that is now `nested` is handled
 * without throwing (see `migrateNestedFields`); other failures propagate to the caller.
 */
export const ensureIndices = async ({
  esClient,
  logger,
}: {
  esClient: ElasticsearchClient;
  logger: Logger;
}): Promise<void> => {
  for (const { index, mappings } of INDICES) {
    await ensureIndex(esClient, logger, index, mappings);
  }
};
