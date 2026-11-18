/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** Non-public ranges (RFC1918, loopback, link-local, CGNAT, ULA, multicast, reserved). */
export const NON_PUBLIC_IPV4_CIDRS: readonly string[] = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
];

export const NON_PUBLIC_IPV6_CIDRS: readonly string[] = [
  '::/128',
  '::1/128',
  'fc00::/7',
  'fe80::/10',
  'ff00::/8',
  '2001:db8::/32',
];

export const NON_PUBLIC_CIDRS: readonly string[] = [
  ...NON_PUBLIC_IPV4_CIDRS,
  ...NON_PUBLIC_IPV6_CIDRS,
];

const parseIpv4 = (ip: string): bigint | undefined => {
  const parts = ip.split('.');
  if (parts.length !== 4) return undefined;
  let result = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined;
    const n = Number(part);
    if (n > 255) return undefined;
    result = (result << 8n) | BigInt(n);
  }
  return result;
};

const parseIpv6 = (input: string): bigint | undefined => {
  let ip = input;
  const zone = ip.indexOf('%');
  if (zone >= 0) ip = ip.slice(0, zone);
  // Embedded IPv4 tail (e.g. ::ffff:1.2.3.4)
  const lastColon = ip.lastIndexOf(':');
  if (lastColon >= 0 && ip.slice(lastColon + 1).includes('.')) {
    const v4 = parseIpv4(ip.slice(lastColon + 1));
    if (v4 === undefined) return undefined;
    const hi = ((v4 >> 16n) & 0xffffn).toString(16);
    const lo = (v4 & 0xffffn).toString(16);
    ip = `${ip.slice(0, lastColon + 1)}${hi}:${lo}`;
  }
  const halves = ip.split('::');
  if (halves.length > 2) return undefined;
  const toGroups = (s: string): string[] => (s === '' ? [] : s.split(':'));
  const head = toGroups(halves[0]);
  const tail = halves.length === 2 ? toGroups(halves[1]) : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return undefined;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  let result = 0n;
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return undefined;
    result = (result << 16n) | BigInt(parseInt(group, 16));
  }
  return result;
};

const inCidr = (value: bigint, bits: number, cidr: string): boolean => {
  const [base, prefixText] = cidr.split('/');
  const baseValue = bits === 32 ? parseIpv4(base) : parseIpv6(base);
  if (baseValue === undefined) return false;
  const shift = BigInt(bits - Number(prefixText));
  return value >> shift === baseValue >> shift;
};

/** Returns true only for a valid, globally routable IPv4 or IPv6 address. */
export const isPublicIp = (ip: string): boolean => {
  const trimmed = ip.trim();
  if (trimmed === '') return false;
  if (trimmed.includes(':')) {
    const v6 = parseIpv6(trimmed);
    if (v6 === undefined) return false;
    // IPv4-mapped (::ffff:0:0/96): classify the embedded IPv4 address.
    if (v6 >> 32n === 0xffffn) return isPublicIp(parseIpv4Back(v6 & 0xffffffffn));
    return !NON_PUBLIC_IPV6_CIDRS.some((cidr) => inCidr(v6, 128, cidr));
  }
  const v4 = parseIpv4(trimmed);
  if (v4 === undefined) return false;
  return !NON_PUBLIC_IPV4_CIDRS.some((cidr) => inCidr(v4, 32, cidr));
};

const parseIpv4Back = (value: bigint): string =>
  [24n, 16n, 8n, 0n].map((shift) => Number((value >> shift) & 255n)).join('.');
