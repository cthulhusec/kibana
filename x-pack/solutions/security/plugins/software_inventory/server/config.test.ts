/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { config, configSchema } from './config';

describe('software inventory config', () => {
  it('leaves the enrichment overrides unset by default', () => {
    expect(configSchema.validate({})).toEqual({ enabled: false, enrichment: {} });
  });

  it('accepts http and https overrides', () => {
    expect(
      configSchema.validate({
        enrichment: {
          nvdBaseUrl: 'http://localhost:5699/rest/json/cves/2.0',
          kevUrl: 'https://example.com/kev.json',
        },
      }).enrichment
    ).toEqual({
      nvdBaseUrl: 'http://localhost:5699/rest/json/cves/2.0',
      kevUrl: 'https://example.com/kev.json',
    });
  });

  it.each(['ftp://example.com/kev.json', 'file:///etc/passwd', 'not a url', '/relative/path', ''])(
    'rejects %p',
    (value) => {
      expect(() => configSchema.validate({ enrichment: { nvdBaseUrl: value } })).toThrow(
        /http or https URL/
      );
      expect(() => configSchema.validate({ enrichment: { kevUrl: value } })).toThrow(
        /http or https URL/
      );
    }
  );

  it('rejects an overlong URL', () => {
    expect(() =>
      configSchema.validate({ enrichment: { kevUrl: `http://a.test/${'x'.repeat(3000)}` } })
    ).toThrow();
  });

  it('accepts timing overrides as durations and numbers of milliseconds', () => {
    const { enrichment } = configSchema.validate({
      enrichment: { requestSpacing: '0ms', requestTimeout: '250ms', backoffBase: 50 },
    });
    expect(enrichment.requestSpacing?.asMilliseconds()).toBe(0);
    expect(enrichment.requestTimeout?.asMilliseconds()).toBe(250);
    expect(enrichment.backoffBase?.asMilliseconds()).toBe(50);
    expect(
      configSchema
        .validate({ enrichment: { requestSpacing: '60s', requestTimeout: '120s' } })
        .enrichment.requestTimeout?.asMilliseconds()
    ).toBe(120000);
  });

  it.each([
    ['requestSpacing', '61s'],
    ['requestSpacing', '-1s'],
    ['requestTimeout', '99ms'],
    ['requestTimeout', '121s'],
    ['backoffBase', '9ms'],
    ['backoffBase', '2m'],
    ['backoffBase', 'soon'],
    ['requestTimeout', ''],
  ])('rejects %s of %p', (key, value) => {
    expect(() => configSchema.validate({ enrichment: { [key]: value } })).toThrow();
  });

  it('does not expose the enrichment keys to the browser', () => {
    expect(config.exposeToBrowser).toEqual({ enabled: true });
  });
});
