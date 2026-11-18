/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  buildHuntQueries,
  escapeEsqlLike,
  escapeEsqlString,
  MAX_HUNT_HOSTS,
  MAX_LOOKBACK_DAYS,
} from './hunt_queries';

describe('hunt_queries', () => {
  it('escapes quotes, backslashes and control characters', () => {
    expect(escapeEsqlString('a"b\\c\nd')).toBe('a\\"b\\\\c d');
  });

  it('escapes LIKE wildcards', () => {
    expect(escapeEsqlLike('a*b?')).toBe('a\\\\*b\\\\?');
  });

  it('returns no queries without hosts', () => {
    expect(buildHuntQueries({ hostNames: [] })).toEqual([]);
    expect(buildHuntQueries({ hostNames: [''] })).toEqual([]);
  });

  it('scopes every query to the affected hosts and lookback', () => {
    const queries = buildHuntQueries({
      hostNames: ['web-1', 'web-1', 'db"2'],
      product: 'NGINX',
      lookbackDays: 14,
    });
    expect(queries.map(({ name }) => name)).toEqual(['host_activity', 'process', 'network']);
    for (const { esql } of queries) {
      expect(esql).toContain('FROM logs-*');
      expect(esql).toContain('NOW() - 14 days');
      expect(esql).toContain('host.name IN ("web-1", "db\\"2")');
    }
    expect(queries[1].esql).toContain('LIKE "*nginx*"');
  });

  it('caps hosts and lookback', () => {
    const hostNames = Array.from({ length: MAX_HUNT_HOSTS + 20 }, (_, i) => `h${i}`);
    const [query] = buildHuntQueries({ hostNames, lookbackDays: 10000 });
    expect(query.esql.match(/"h\d+"/g)).toHaveLength(MAX_HUNT_HOSTS);
    expect(query.esql).toContain(`${MAX_LOOKBACK_DAYS} days`);
  });
});
