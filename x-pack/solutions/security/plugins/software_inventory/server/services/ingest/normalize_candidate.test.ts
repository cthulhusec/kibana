/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  UNKNOWN_VERSION,
  cleanVersion,
  normalizeCandidate,
  normalizeSoftware,
} from './normalize_candidate';

const NOW = '2026-11-18T00:00:00.000Z';

describe('cleanVersion', () => {
  it.each([
    ['v1.2.3', '1.2.3'],
    ['V2.0', '2.0'],
    ['  3.0.1  ', '3.0.1'],
    ['1:1.2.11.dfsg-2ubuntu9.2', '1.2.11.dfsg'],
    ['3.0.2-0ubuntu1.10', '3.0.2'],
    ['1.1.1k-1+deb11u1', '1.1.1k'],
    ['1.20.1-1.el9', '1.20.1'],
    ['2.4.57-5.fc38', '2.4.57'],
    ['very-1', 'very-1'],
    ['1.2.3-rc1', '1.2.3-rc1'],
    ['', UNKNOWN_VERSION],
    [undefined, UNKNOWN_VERSION],
    [null, UNKNOWN_VERSION],
  ])('cleans %p to %p', (input, expected) => {
    expect(cleanVersion(input)).toBe(expected);
  });
});

describe('normalizeSoftware', () => {
  it('infers the vendor of well-known software from the name', () => {
    expect(normalizeSoftware({ name: 'Google Chrome', version: '120.0.6099.109' })).toEqual({
      vendor: 'google',
      product: 'chrome',
      version: '120.0.6099.109',
      display_name: 'Google Chrome',
      category: 'application',
    });
  });

  it.each([
    ['OpenSSL', 'openssl', 'openssl', 'dependency'],
    ['libssl3', 'openssl', 'openssl', 'dependency'],
    ['nginx', 'f5', 'nginx', 'application'],
    ['Mozilla Firefox (x64 en-US)', 'mozilla', 'firefox', 'application'],
    ['Python 3.11.4 (64-bit)', 'python', 'python', 'application'],
    ['7-Zip 23.01 (x64)', '7-zip', '7-zip', 'application'],
    ['Apache HTTP Server', 'apache', 'http_server', 'application'],
    ['log4j-core', 'apache', 'log4j', 'dependency'],
    ['libc6', 'gnu', 'glibc', 'os_package'],
  ])('maps %p to %p/%p', (name, vendor, product, category) => {
    expect(normalizeSoftware({ name, version: '1.0' })).toMatchObject({
      vendor,
      product,
      category,
    });
  });

  it('prefers the reported category over the table category', () => {
    expect(normalizeSoftware({ name: 'OpenSSL', category: 'os_package' })?.category).toBe(
      'os_package'
    );
  });

  it('cleans the reported vendor and strips it from the product name', () => {
    expect(
      normalizeSoftware({ name: 'Acme Widget Pro', vendor: 'Acme, Inc.', version: 'v4.1' })
    ).toEqual({
      vendor: 'acme',
      product: 'widget_pro',
      version: '4.1',
      display_name: 'Acme Widget Pro',
      category: 'application',
    });
  });

  it('strips repeated corporate suffixes', () => {
    expect(
      normalizeSoftware({ name: 'Thing', vendor: 'Foo Software Corporation Ltd' })?.vendor
    ).toBe('foo_software');
  });

  it('falls back to the product as vendor when none is known', () => {
    expect(normalizeSoftware({ name: 'zlib1g' })).toMatchObject({
      vendor: 'zlib1g',
      product: 'zlib1g',
      version: UNKNOWN_VERSION,
    });
  });

  it('returns undefined for a name with no usable characters', () => {
    expect(normalizeSoftware({ name: '  ()  ' })).toBeUndefined();
  });
});

describe('normalizeCandidate', () => {
  it('keeps host and install path and defaults observed_at to now', () => {
    expect(
      normalizeCandidate(
        {
          host_id: ' h1 ',
          host_name: 'web-1',
          name: 'nginx',
          version: '1.24.0',
          install_path: '/usr/sbin/nginx',
        },
        NOW
      )
    ).toEqual({
      host_key: 'web-1',
      host_id: 'h1',
      host_name: 'web-1',
      install_path: '/usr/sbin/nginx',
      vendor: 'f5',
      product: 'nginx',
      version: '1.24.0',
      display_name: 'nginx',
      category: 'application',
      observed_at: NOW,
    });
  });

  it('normalizes a valid observed_at and ignores an invalid one', () => {
    expect(
      normalizeCandidate({ host_id: 'h1', name: 'x', observed_at: '2026-11-17T10:00:00Z' }, NOW)
        ?.observed_at
    ).toBe('2026-11-17T10:00:00.000Z');
    expect(
      normalizeCandidate({ host_id: 'h1', name: 'x', observed_at: 'yesterday' }, NOW)?.observed_at
    ).toBe(NOW);
  });

  it('drops rows without a host id', () => {
    expect(normalizeCandidate({ host_id: '  ', name: 'nginx' }, NOW)).toBeUndefined();
  });

  it('keys hosts on the lower-cased name, else the id', () => {
    expect(
      normalizeCandidate({ host_id: 'agent-1', host_name: 'WEB-1', name: 'nginx' }, NOW, 'osquery')
        ?.host_key
    ).toBe('web-1');
    expect(
      normalizeCandidate({ host_id: 'Agent-1', name: 'nginx' }, NOW, 'osquery')?.host_key
    ).toBe('agent-1');
  });

  describe('fleet integrations', () => {
    it('maps a known package to the software it monitors with an unknown version', () => {
      expect(
        normalizeCandidate(
          { host_id: 'policy:p1', host_name: 'p1', name: 'panw', version: '5.3.0' },
          NOW,
          'fleet_integration'
        )
      ).toMatchObject({
        host_key: 'policy:p1',
        vendor: 'palo_alto_networks',
        product: 'pan-os',
        version: UNKNOWN_VERSION,
        category: 'appliance',
      });
    });

    it.each(['system', 'endpoint', 'fleet_server'])('drops unmapped package %p', (name) => {
      expect(
        normalizeCandidate(
          { host_id: 'policy:p1', name, version: '1.0.0' },
          NOW,
          'fleet_integration'
        )
      ).toBeUndefined();
    });
  });

  describe('log appliances', () => {
    it('resolves observer vendor and product and keeps the firmware version', () => {
      expect(
        normalizeCandidate(
          {
            host_id: 'fw-1',
            name: 'PAN-OS',
            vendor: 'Palo Alto Networks',
            version: '10.2.8',
            category: 'appliance',
          },
          NOW,
          'logs'
        )
      ).toMatchObject({
        vendor: 'palo_alto_networks',
        product: 'pan-os',
        version: '10.2.8',
        category: 'appliance',
      });
    });

    it('falls back to generic normalization for unknown observers', () => {
      expect(
        normalizeCandidate(
          {
            host_id: 'fw-1',
            name: 'Gizmo',
            vendor: 'Acme Inc.',
            version: '1',
            category: 'appliance',
          },
          NOW,
          'logs'
        )
      ).toMatchObject({ vendor: 'acme', product: 'gizmo', category: 'appliance' });
    });
  });
});
