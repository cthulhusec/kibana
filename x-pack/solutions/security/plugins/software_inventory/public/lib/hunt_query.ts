/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const HUNT_INDEX_PATTERN = 'logs-*';
export const MAX_HUNT_HOSTS = 200;

const escapeEsqlString = (value: string): string =>
  value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/[\r\n]+/g, ' ');

/**
 * Builds an ES|QL query over `logs-*` scoped to the given affected hosts.
 * Returns undefined when there are no host names to scope to.
 */
export const buildHuntQuery = (
  hostNames: ReadonlyArray<string | undefined>
): string | undefined => {
  const unique = Array.from(
    new Set(hostNames.filter((name): name is string => typeof name === 'string' && name !== ''))
  ).slice(0, MAX_HUNT_HOSTS);
  if (unique.length === 0) {
    return undefined;
  }
  const list = unique.map((name) => `"${escapeEsqlString(name)}"`).join(', ');
  return [
    `FROM ${HUNT_INDEX_PATTERN}`,
    `| WHERE host.name IN (${list})`,
    '| STATS events = COUNT(*), last_event = MAX(@timestamp) BY host.name, event.category',
    '| SORT last_event DESC',
    '| LIMIT 100',
  ].join('\n');
};
