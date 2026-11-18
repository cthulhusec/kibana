/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { elasticsearchServiceMock } from '@kbn/core-elasticsearch-server-mocks';
import { loggingSystemMock } from '@kbn/core-logging-server-mocks';
import {
  CATALOG_INDEX,
  EVENTS_INDEX,
  INSTANCES_INDEX,
  ROLLUPS_INDEX,
} from '../../../common/constants';
import { asLegacyObjectProperties, ensureIndices, findNonNestedFields } from './ensure_indices';

const setup = ({
  existing,
  versionHistoryType,
  count = 0,
}: {
  existing: string[];
  versionHistoryType?: string;
  count?: number;
}) => {
  const esClient = elasticsearchServiceMock.createElasticsearchClient();
  const logger = loggingSystemMock.createLogger();
  esClient.indices.exists.mockImplementation((async ({ index }: { index: string }) =>
    existing.includes(index)) as never);
  esClient.indices.getMapping.mockResolvedValue({
    [INSTANCES_INDEX]: {
      mappings: {
        properties: versionHistoryType
          ? { version_history: { type: versionHistoryType, properties: {} } }
          : {},
      },
    },
  } as never);
  esClient.count.mockResolvedValue({ count } as never);
  return { esClient, logger };
};

const createdIndices = (esClient: ReturnType<typeof setup>['esClient']) =>
  esClient.indices.create.mock.calls.map(([request]) => request.index);

describe('ensureIndices', () => {
  it('creates all four indices as hidden when missing', async () => {
    const { esClient, logger } = setup({ existing: [] });
    await ensureIndices({ esClient, logger });
    expect(createdIndices(esClient)).toEqual([
      CATALOG_INDEX,
      INSTANCES_INDEX,
      EVENTS_INDEX,
      ROLLUPS_INDEX,
    ]);
    expect(esClient.indices.create.mock.calls[2][0]).toMatchObject({
      settings: { hidden: true },
    });
  });

  it('updates mappings of existing indices whose nested fields are already nested', async () => {
    const all = [CATALOG_INDEX, INSTANCES_INDEX, EVENTS_INDEX, ROLLUPS_INDEX];
    const { esClient, logger } = setup({ existing: all, versionHistoryType: 'nested' });
    await ensureIndices({ esClient, logger });
    expect(esClient.indices.putMapping).toHaveBeenCalledTimes(4);
    expect(esClient.indices.delete).not.toHaveBeenCalled();
  });

  it('recreates an empty instances index whose version_history is not nested', async () => {
    const { esClient, logger } = setup({
      existing: [CATALOG_INDEX, INSTANCES_INDEX],
      versionHistoryType: 'object',
      count: 0,
    });
    await ensureIndices({ esClient, logger });
    expect(esClient.indices.delete).toHaveBeenCalledWith({ index: INSTANCES_INDEX });
    expect(createdIndices(esClient)).toContain(INSTANCES_INDEX);
    expect(logger.error).not.toHaveBeenCalled();
  });

  it('keeps a non-empty legacy instances index, logs an error, and adds new sub-fields', async () => {
    const { esClient, logger } = setup({
      existing: [CATALOG_INDEX, INSTANCES_INDEX, EVENTS_INDEX, ROLLUPS_INDEX],
      // An object field has no explicit type in the mapping response.
      versionHistoryType: undefined,
      count: 12,
    });
    esClient.indices.getMapping.mockResolvedValue({
      [INSTANCES_INDEX]: { mappings: { properties: { version_history: { properties: {} } } } },
    } as never);
    await expect(ensureIndices({ esClient, logger })).resolves.toBeUndefined();
    expect(esClient.indices.delete).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('--clean'));
    const instancesPut = esClient.indices.putMapping.mock.calls.find(
      ([request]) => request.index === INSTANCES_INDEX
    );
    expect(instancesPut?.[0].properties?.version_history).toEqual({
      properties: expect.objectContaining({ software_id: { type: 'keyword' } }),
    });
  });
});

describe('mapping helpers', () => {
  it('finds fields that are mapped but not nested', () => {
    expect(
      findNonNestedFields({ a: { type: 'nested' }, b: { properties: {} } }, ['a', 'b', 'c'])
    ).toEqual(['b']);
  });

  it('downgrades only the legacy nested fields to object', () => {
    expect(
      asLegacyObjectProperties(
        { a: { type: 'nested', properties: { x: { type: 'keyword' } } }, b: { type: 'keyword' } },
        ['a']
      )
    ).toEqual({ a: { properties: { x: { type: 'keyword' } } }, b: { type: 'keyword' } });
  });
});
