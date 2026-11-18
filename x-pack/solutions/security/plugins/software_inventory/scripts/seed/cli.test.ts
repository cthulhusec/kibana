/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { readStringFlag } from './cli';

describe('readStringFlag', () => {
  it('returns the fallback for an empty string, which is what unset string flags default to', () => {
    expect(readStringFlag('', 'http://localhost:9200')).toBe('http://localhost:9200');
  });

  it('returns the fallback for non-string values', () => {
    expect(readStringFlag(undefined, 'elastic')).toBe('elastic');
    expect(readStringFlag(true, 'elastic')).toBe('elastic');
  });

  it('returns the provided value when it is a non-empty string', () => {
    expect(readStringFlag('http://es:9200', 'http://localhost:9200')).toBe('http://es:9200');
  });
});
