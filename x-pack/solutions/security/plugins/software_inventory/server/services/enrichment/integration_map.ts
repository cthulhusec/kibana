/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { normalizeToken } from '../../../common/normalize';
import type { SoftwareCategory } from '../../../common/types';

export interface ResolvedIntegration {
  vendor: string;
  product: string;
  category: SoftwareCategory;
  isEdge: boolean;
}

const entry = (
  vendor: string,
  product: string,
  category: SoftwareCategory,
  isEdge: boolean
): ResolvedIntegration => ({ vendor, product, category, isEdge });

/** Fleet package name -> normalized software identity. Only high-confidence entries. */
const INTEGRATIONS: Readonly<Record<string, ResolvedIntegration>> = {
  panw: entry('palo_alto_networks', 'pan-os', 'appliance', true),
  fortinet_fortigate: entry('fortinet', 'fortios', 'appliance', true),
  cisco_asa: entry('cisco', 'adaptive_security_appliance_software', 'appliance', true),
  cisco_ftd: entry('cisco', 'firepower_threat_defense', 'appliance', true),
  cisco_ios: entry('cisco', 'ios', 'appliance', true),
  checkpoint: entry('checkpoint', 'gaia_os', 'appliance', true),
  juniper_srx: entry('juniper', 'junos', 'appliance', true),
  f5_bigip: entry('f5', 'big-ip', 'appliance', true),
  sonicwall_firewall: entry('sonicwall', 'sonicos', 'appliance', true),
  pfsense: entry('netgate', 'pfsense', 'appliance', true),
  opnsense: entry('opnsense', 'opnsense', 'appliance', true),
  zeek: entry('zeek', 'zeek', 'application', false),
  nginx: entry('f5', 'nginx', 'application', false),
  apache: entry('apache', 'http_server', 'application', false),
  iis: entry('microsoft', 'internet_information_services', 'application', false),
  haproxy: entry('haproxy', 'haproxy', 'application', false),
  tomcat: entry('apache', 'tomcat', 'application', false),
  mysql: entry('oracle', 'mysql', 'application', false),
  postgresql: entry('postgresql', 'postgresql', 'application', false),
  mongodb: entry('mongodb', 'mongodb', 'application', false),
  redis: entry('redis', 'redis', 'application', false),
  kafka: entry('apache', 'kafka', 'application', false),
};

/** Substring patterns for observer.vendor / observer.product strings (normalized tokens). */
const OBSERVER_PATTERNS: ReadonlyArray<{
  vendor: RegExp;
  product?: RegExp;
  result: ResolvedIntegration;
}> = [
  { vendor: /palo_?alto|^panw$/, result: INTEGRATIONS.panw },
  { vendor: /fortinet/, result: INTEGRATIONS.fortinet_fortigate },
  { vendor: /^cisco/, product: /asa|adaptive_security/, result: INTEGRATIONS.cisco_asa },
  { vendor: /^cisco/, product: /ftd|firepower/, result: INTEGRATIONS.cisco_ftd },
  { vendor: /^cisco/, product: /^ios/, result: INTEGRATIONS.cisco_ios },
  { vendor: /check_?point/, result: INTEGRATIONS.checkpoint },
  { vendor: /juniper/, result: INTEGRATIONS.juniper_srx },
  { vendor: /^f5/, result: INTEGRATIONS.f5_bigip },
  { vendor: /sonic_?wall/, result: INTEGRATIONS.sonicwall_firewall },
  { vendor: /netgate|pfsense/, result: INTEGRATIONS.pfsense },
  { vendor: /opnsense/, result: INTEGRATIONS.opnsense },
  { vendor: /zeek/, result: INTEGRATIONS.zeek },
];

export const resolveIntegration = (packageName: string): ResolvedIntegration | undefined => {
  if (typeof packageName !== 'string') return undefined;
  const key = packageName.trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(INTEGRATIONS, key) ? INTEGRATIONS[key] : undefined;
};

/** Resolves observer.vendor / observer.product strings to a normalized identity. */
export const resolveObserver = (
  vendor?: string,
  product?: string
): ResolvedIntegration | undefined => {
  if (!vendor) return undefined;
  const normVendor = normalizeToken(vendor);
  const normProduct = product ? normalizeToken(product) : '';
  const match = OBSERVER_PATTERNS.find(
    (pattern) =>
      pattern.vendor.test(normVendor) &&
      (pattern.product === undefined || pattern.product.test(normProduct))
  );
  return match?.result;
};

/** Compares normalized tokens on both sides, so `pan-os` and `PAN-OS` match the same entry. */
const findByVendorProduct = (vendor: string, product: string): ResolvedIntegration | undefined => {
  const v = normalizeToken(vendor);
  const p = normalizeToken(product);
  return Object.values(INTEGRATIONS).find(
    (item) => normalizeToken(item.vendor) === v && normalizeToken(item.product) === p
  );
};

/** True when vendor and product are both in the static known table. */
export const isKnownVendorProduct = (vendor: string, product: string): boolean =>
  findByVendorProduct(vendor, product) !== undefined;

/** True when vendor and product resolve to an edge (internet-facing) device. */
export const isEdgeProduct = (vendor: string, product: string): boolean =>
  findByVendorProduct(vendor, product)?.isEdge === true;
