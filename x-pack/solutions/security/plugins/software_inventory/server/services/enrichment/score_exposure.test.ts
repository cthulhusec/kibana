/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient } from '@kbn/core/server';
import type { SearchRequest } from '@elastic/elasticsearch/lib/api/types';
import { loggingSystemMock } from '@kbn/core-logging-server-mocks';
import { elasticsearchServiceMock } from '@kbn/core-elasticsearch-server-mocks';
import { CATALOG_INDEX, INSTANCES_INDEX } from '../../../common/constants';
import type { InstanceDoc } from '../../../common/types';
import { scoreExposure } from './score_exposure';

const instance = (id: string, host: InstanceDoc['host']): InstanceDoc => ({
  id,
  host,
  software_id: 'f5:nginx:1.0',
  version_history: [],
  sources: ['osquery'],
  status: 'active',
  first_seen: '2026-11-01T00:00:00.000Z',
  last_seen: '2026-11-01T00:00:00.000Z',
  exposure: { level: 'none', score: 0, evidence: [] },
  '@timestamp': '2026-11-01T00:00:00.000Z',
});

const bucket = (key: string, distinct: number) => ({
  key,
  distinct: { value: distinct },
  top: { buckets: [{ key: '203.0.113.7' }] },
});

describe('scoreExposure', () => {
  const logger = loggingSystemMock.createLogger();
  let esClient: ReturnType<typeof elasticsearchServiceMock.createElasticsearchClient>;
  let logRequests: SearchRequest[];

  const setup = (instances: InstanceDoc[], byName: ReturnType<typeof bucket>[]) => {
    logRequests = [];
    esClient = elasticsearchServiceMock.createElasticsearchClient();
    esClient.bulk.mockResolvedValue({ errors: false, items: [], took: 1 });
    esClient.search.mockImplementation((async (request: SearchRequest) => {
      if (request.index === INSTANCES_INDEX) {
        return {
          hits: {
            hits: request.search_after
              ? []
              : instances.map((doc) => ({ _id: doc.id, _source: doc, sort: [doc.id] })),
          },
        };
      }
      if (request.index === CATALOG_INDEX) {
        return {
          hits: {
            hits: [
              {
                _source: {
                  id: 'f5:nginx:1.0',
                  vendor: 'f5',
                  product: 'nginx',
                  category: 'application',
                },
              },
            ],
          },
        };
      }
      logRequests.push(request);
      return { hits: { hits: [] }, aggregations: { by_name: { buckets: byName }, by_id: {} } };
    }) as never);
  };

  const exposureOf = (id: string) => {
    const operations = esClient.bulk.mock.calls[0][0]?.operations as Array<
      Record<string, { _id?: string; exposure?: InstanceDoc['exposure'] }>
    >;
    const index = operations.findIndex((op) => op.update?._id === id);
    return operations[index + 1].doc?.exposure;
  };

  const run = () =>
    scoreExposure({
      esClient: esClient as unknown as ElasticsearchClient,
      logger,
      lookbackDays: 7,
    });

  it('matches log host names to instances by canonical key, ignoring case', async () => {
    setup([instance('a', { key: 'web-1', id: 'agent-uuid', name: 'web-1' })], [bucket('WEB-1', 3)]);
    expect(await run()).toEqual({ scored: 1 });
    expect(exposureOf('a')?.evidence.map(({ signal }) => signal)).toEqual(['inbound_public_ip']);
  });

  it('counts only events marked inbound or ingress', async () => {
    setup([instance('a', { key: 'web-1', id: 'h1', name: 'web-1' })], []);
    await run();
    const filters = (logRequests[0].query?.bool?.filter ?? []) as object[];
    expect(filters).toContainEqual({ terms: { 'network.direction': ['inbound', 'ingress'] } });
    expect(JSON.stringify(filters)).not.toContain('event.category');
  });

  it('never matches Fleet policy pseudo-hosts against logs', async () => {
    setup(
      [
        instance('policy', { key: 'policy:p1', id: 'policy:p1', name: 'p1' }),
        instance('real', { key: 'web-1', id: 'h1', name: 'web-1' }),
      ],
      [bucket('p1', 5), bucket('policy:p1', 5)]
    );
    await run();
    expect(exposureOf('policy')?.evidence).toEqual([]);
    const shouldClauses = JSON.stringify(logRequests[0].query);
    expect(shouldClauses).not.toContain('policy:p1');
  });

  it('queries each host once, by its reported name and its key', async () => {
    setup(
      [
        instance('a', { key: 'web-1', id: 'h1', name: 'Web-1' }),
        instance('b', { key: 'web-1', id: 'h1', name: 'Web-1' }),
      ],
      []
    );
    await run();
    expect(logRequests).toHaveLength(1);
    const query = JSON.stringify(logRequests[0].query);
    expect(query).toContain('"host.name":["web-1","Web-1"]');
  });
});
