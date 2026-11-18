/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const MAX_HUNT_HOSTS = 100;
export const DEFAULT_LOOKBACK_DAYS = 7;
export const MAX_LOOKBACK_DAYS = 90;

export interface HuntQuery {
  name: 'host_activity' | 'process' | 'network';
  purpose: string;
  esql: string;
}

export interface BuildHuntQueriesInput {
  hostNames: string[];
  /** Lower-case normalized product name, used to narrow the process query. */
  product?: string;
  lookbackDays?: number;
}

/** Escapes a value for use inside an ES|QL double-quoted string literal. */
export const escapeEsqlString = (value: string): string =>
  value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/[\r\n\t]/g, ' ');

/** Escapes a value for an ES|QL LIKE pattern inside a string literal (wildcards match literally). */
export const escapeEsqlLike = (value: string): string =>
  escapeEsqlString(value).replace(/([*?])/g, '\\\\$1');

const clampLookback = (days: number | undefined): number =>
  Math.min(Math.max(Math.trunc(days ?? DEFAULT_LOOKBACK_DAYS), 1), MAX_LOOKBACK_DAYS);

/** Builds scoped ES|QL hunt queries around the hosts that run an inventory item. Returns [] without hosts. */
export const buildHuntQueries = ({
  hostNames,
  product,
  lookbackDays,
}: BuildHuntQueriesInput): HuntQuery[] => {
  const hosts = [...new Set(hostNames.filter((name) => name.length > 0))].slice(0, MAX_HUNT_HOSTS);
  if (hosts.length === 0) return [];

  const hostList = hosts.map((name) => `"${escapeEsqlString(name)}"`).join(', ');
  const days = clampLookback(lookbackDays);
  const base = `FROM logs-*\n| WHERE @timestamp >= NOW() - ${days} days AND host.name IN (${hostList})`;

  const productClause = product
    ? `\n| WHERE process.name IS NOT NULL AND (TO_LOWER(process.name) LIKE "*${escapeEsqlLike(
        product.toLowerCase()
      )}*" OR TO_LOWER(process.executable) LIKE "*${escapeEsqlLike(product.toLowerCase())}*")`
    : '';

  return [
    {
      name: 'host_activity',
      purpose: 'Event volume per affected host by category and action.',
      esql: `${base}\n| STATS events = COUNT(*) BY host.name, event.category, event.action\n| SORT events DESC\n| LIMIT 100`,
    },
    {
      name: 'process',
      purpose: product
        ? `Process executions on affected hosts that match "${escapeEsqlString(product)}".`
        : 'Process executions on affected hosts.',
      esql: `${base}\n| WHERE event.category == "process"${productClause}\n| STATS executions = COUNT(*), last_seen = MAX(@timestamp) BY host.name, process.name, process.parent.name, user.name\n| SORT executions DESC\n| LIMIT 100`,
    },
    {
      name: 'network',
      purpose: 'Network connections from affected hosts, grouped by destination.',
      esql: `${base}\n| WHERE event.category == "network"\n| STATS connections = COUNT(*), last_seen = MAX(@timestamp) BY host.name, process.name, destination.ip, destination.port\n| SORT connections DESC\n| LIMIT 100`,
    },
  ];
};
