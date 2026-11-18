/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SoftwareCategory } from '../../../common/types';

/** Products that NVD lists as operating systems (part 'o'). */
const OS_PRODUCTS: ReadonlySet<string> = new Set([
  'pan-os',
  'fortios',
  'ios',
  'junos',
  'sonicos',
  'gaia_os',
  'nx-os',
]);

/** Our normalized vendor -> NVD vendor naming differences. */
const NVD_VENDOR_ALIASES: Readonly<Record<string, string>> = {
  palo_alto_networks: 'paloaltonetworks',
};

export const toNvdVendor = (vendor: string): string => NVD_VENDOR_ALIASES[vendor] ?? vendor;

/**
 * CPE 2.3 formatted-string binding: `.`, `-` and `_` stay unquoted (NVD writes `7-zip`, `pan-os`),
 * and every other non-alphanumeric character is quoted with a backslash (`notepad\+\+`).
 */
const escapeCpeComponent = (value: string): string =>
  value
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9._-]/g, (char) => `\\${char}`);

export const buildCpe = ({
  vendor,
  product,
  version,
  category,
}: {
  vendor: string;
  product: string;
  version: string;
  category?: SoftwareCategory;
}): string => {
  const part = category === 'appliance' && OS_PRODUCTS.has(product) ? 'o' : 'a';
  const nvdVendor = toNvdVendor(vendor);
  const ver = version.trim() === '' ? '*' : escapeCpeComponent(version);
  return `cpe:2.3:${part}:${escapeCpeComponent(nvdVendor)}:${escapeCpeComponent(
    product
  )}:${ver}:*:*:*:*:*:*:*`;
};
