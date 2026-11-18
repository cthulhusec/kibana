/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { buildHuntQuery, MAX_HUNT_HOSTS } from './hunt_query';

describe('buildHuntQuery', () => {
  it('scopes the query to unique host names', () => {
    const query = buildHuntQuery(['web-1', 'web-2', 'web-1']);
    expect(query).toContain('FROM logs-*');
    expect(query).toContain('| WHERE host.name IN ("web-1", "web-2")');
  });

  it('escapes quotes and backslashes', () => {
    expect(buildHuntQuery(['a"b\\c'])).toContain('IN ("a\\"b\\\\c")');
  });

  it('returns undefined without host names', () => {
    expect(buildHuntQuery([])).toBeUndefined();
    expect(buildHuntQuery([undefined, ''])).toBeUndefined();
  });

  it('caps the host list', () => {
    const hosts = Array.from({ length: MAX_HUNT_HOSTS + 10 }, (_, i) => `h${i}`);
    const query = buildHuntQuery(hosts) ?? '';
    expect(query).toContain(`"h${MAX_HUNT_HOSTS - 1}"`);
    expect(query).not.toContain(`"h${MAX_HUNT_HOSTS}"`);
  });
});
