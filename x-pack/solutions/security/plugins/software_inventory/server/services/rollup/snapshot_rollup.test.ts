/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { elasticsearchServiceMock } from '@kbn/core-elasticsearch-server-mocks';
import { loggingSystemMock } from '@kbn/core-logging-server-mocks';
import { ROLLUPS_INDEX } from '../../../common/constants';
import {
  buildRollupAggregations,
  partitionRollupCatalog,
  shapeRollup,
  snapshotRollup,
  utcDay,
} from './snapshot_rollup';

describe('utcDay', () => {
  it('uses the UTC calendar day', () => {
    expect(utcDay(new Date('2026-11-18T23:30:00-05:00'))).toEqual({
      id: '2026-11-19',
      start: '2026-11-19T00:00:00.000Z',
      end: '2026-11-20T00:00:00.000Z',
    });
  });
});

describe('partitionRollupCatalog', () => {
  it('groups by vulnerability, severity, KEV and category', () => {
    const partition = partitionRollupCatalog([
      { id: 'a', category: 'application', cve_count: 2, max_cvss: 9.8, known_exploited: true },
      { id: 'b', category: 'os_package', cve_count: 1, max_cvss: 7, known_exploited: false },
      { id: 'c', category: 'dependency', cve_count: 0, known_exploited: false },
    ]);
    expect(partition).toMatchObject({
      vulnerable: ['a', 'b'],
      critical: ['a'],
      high: ['b'],
      knownExploited: ['a'],
    });
    expect(partition.byCategory.dependency).toEqual(['c']);
  });

  it('builds a filter that matches nothing for an empty id list', () => {
    const aggs = buildRollupAggregations(partitionRollupCatalog([]));
    expect(aggs.vulnerable).toEqual({ filter: { bool: { must_not: { match_all: {} } } } });
  });
});

describe('shapeRollup', () => {
  it('maps aggregations and event counts', () => {
    const rollup = shapeRollup({
      dayStart: '2026-11-18T00:00:00.000Z',
      instances: {
        hits: { total: { value: 10, relation: 'eq' }, hits: [] },
        aggregations: {
          software: { value: 4 },
          vulnerable: { doc_count: 3 },
          exposed_and_vulnerable: { doc_count: 1 },
          category_application: { doc_count: 6 },
        } as never,
      },
      eventCounts: { first_seen: 2, version_changed: 1 },
    });
    expect(rollup).toMatchObject({
      '@timestamp': '2026-11-18T00:00:00.000Z',
      total_instances: 10,
      total_software: 4,
      vulnerable_instances: 3,
      exposed_and_vulnerable_instances: 1,
      new_instances: 2,
      patched_instances: 1,
      removed_instances: 0,
      categories: { application: 6, dependency: 0, appliance: 0, os_package: 0, other: 0 },
    });
  });
});

describe('snapshotRollup', () => {
  it('writes the rollup with the UTC day as id, so re-runs overwrite', async () => {
    const esClient = elasticsearchServiceMock.createElasticsearchClient();
    esClient.search
      .mockResolvedValueOnce({ hits: { total: { value: 0 }, hits: [] } } as never)
      .mockResolvedValueOnce({ hits: { total: { value: 0 }, hits: [] }, aggregations: {} } as never)
      .mockResolvedValueOnce({
        hits: { hits: [] },
        aggregations: { by_type: { buckets: [{ key: 'removed', doc_count: 5 }] } },
      } as never);
    const result = await snapshotRollup({
      esClient,
      logger: loggingSystemMock.createLogger(),
      now: new Date('2026-11-18T12:00:00.000Z'),
    });
    expect(result.date).toBe('2026-11-18');
    expect(esClient.index).toHaveBeenCalledWith(
      expect.objectContaining({
        index: ROLLUPS_INDEX,
        id: '2026-11-18',
        document: expect.objectContaining({ removed_instances: 5 }),
      })
    );
  });
});
