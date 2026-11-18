/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { DASHBOARD_ID, buildDefinition } from './dashboard';

const API_VERSION = '2023-10-31';
const DEFAULT_KIBANA_URL = 'http://localhost:5601';
const DEFAULT_USERNAME = 'elastic';
const DEFAULT_PASSWORD = 'changeme';
const DEFAULT_SPACE = 'default';

export interface InstallOptions {
  kibanaUrl: string;
  username: string;
  password: string;
  space: string;
  remove: boolean;
}

/** An empty string means "not provided", as for string flags that default to ''. */
export const readStringFlag = (value: string | undefined, fallback: string): string =>
  typeof value === 'string' && value !== '' ? value : fallback;

export const parseArgs = (
  argv: readonly string[],
  env: Record<string, string | undefined> = {}
): InstallOptions => {
  const flags = new Map<string, string>();
  for (const arg of argv) {
    if (!arg.startsWith('--')) continue;
    const [key, ...rest] = arg.slice(2).split('=');
    flags.set(key, rest.join('='));
  }
  return {
    kibanaUrl: readStringFlag(flags.get('kibana-url'), DEFAULT_KIBANA_URL).replace(/\/+$/, ''),
    username: readStringFlag(flags.get('username'), DEFAULT_USERNAME),
    password: readStringFlag(flags.get('password'), env.KIBANA_PASSWORD ?? DEFAULT_PASSWORD),
    space: readStringFlag(flags.get('space'), DEFAULT_SPACE),
    remove: flags.has('delete'),
  };
};

export const getSpacePrefix = (space: string): string =>
  space === DEFAULT_SPACE ? '' : `/s/${encodeURIComponent(space)}`;

export const getDashboardUrl = ({ kibanaUrl, space }: InstallOptions): string =>
  `${kibanaUrl}${getSpacePrefix(space)}/app/dashboards#/view/${DASHBOARD_ID}`;

export const run = async (options: InstallOptions): Promise<void> => {
  const { kibanaUrl, username, password, space, remove } = options;
  const url = `${kibanaUrl}${getSpacePrefix(space)}/api/dashboards/${DASHBOARD_ID}`;
  const response = await fetch(url, {
    method: remove ? 'DELETE' : 'PUT',
    headers: {
      'content-type': 'application/json',
      'kbn-xsrf': 'software-inventory-setup',
      'elastic-api-version': API_VERSION,
      authorization: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`,
    },
    body: remove ? undefined : JSON.stringify(buildDefinition()),
  });

  if (remove) {
    if (response.status === 404) {
      process.stdout.write(
        `${`Dashboard "${DASHBOARD_ID}" does not exist in space "${space}".`}\n`
      );
      return;
    }
    if (!response.ok) {
      throw new Error(
        `DELETE failed with ${response.status}: ${(await response.text()).slice(0, 500)}`
      );
    }
    process.stdout.write(`Deleted dashboard "${DASHBOARD_ID}" from space "${space}".\n`);
    return;
  }

  if (!response.ok) {
    throw new Error(
      `PUT failed with ${response.status}: ${(await response.text()).slice(0, 1500)}`
    );
  }
  process.stdout.write(`Installed dashboard "${DASHBOARD_ID}" in space "${space}".\n`);
  process.stdout.write(`${getDashboardUrl(options)}\n`);
};

export const main = (argv: readonly string[]): void => {
  run(parseArgs(argv, process.env)).catch((error: Error) => {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  });
};
