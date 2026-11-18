/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Creates the four Osquery saved queries that the software inventory discovery workflow runs.
 * The script is idempotent: it skips any saved query that already exists in the target space.
 *
 * Usage:
 *   node x-pack/solutions/security/plugins/software_inventory/scripts/install_osquery_saved_queries.js \
 *     [--kibana-url=http://localhost:5601] [--username=elastic] [--password=changeme] [--space=default]
 *
 * The password can also come from the KIBANA_PASSWORD environment variable.
 * The workflow resolves saved queries in its own space, so use the space that runs the workflow.
 */

const OSQUERY_API_VERSION = '2023-10-31';

// The Osquery create route requires `interval` (seconds, as a string). It only seeds the default
// interval if someone adds the query to a pack; the discovery workflow runs these queries ad hoc.
const DEFAULT_INTERVAL = '3600';

const SAVED_QUERIES = [
  {
    id: 'software_inventory_linux_packages',
    description: 'Software inventory: Debian and RPM packages',
    platform: 'linux',
    query:
      "SELECT name, version, '' AS install_path FROM deb_packages UNION ALL SELECT name, version, '' AS install_path FROM rpm_packages;",
  },
  {
    id: 'software_inventory_windows_programs',
    description: 'Software inventory: Windows installed programs',
    platform: 'windows',
    query: 'SELECT name, version, install_location AS install_path FROM programs;',
  },
  {
    id: 'software_inventory_macos_apps',
    description: 'Software inventory: macOS applications',
    platform: 'darwin',
    query:
      'SELECT bundle_name AS name, bundle_short_version AS version, path AS install_path FROM apps;',
  },
  {
    id: 'software_inventory_dependencies',
    description: 'Software inventory: Python and npm packages (all platforms)',
    platform: 'linux,darwin,windows',
    query:
      'SELECT name, version, path AS install_path FROM python_packages UNION ALL SELECT name, version, path AS install_path FROM npm_packages;',
  },
];

const parseArgs = (argv) =>
  Object.fromEntries(
    argv
      .filter((arg) => arg.startsWith('--') && arg.includes('='))
      .map((arg) => {
        const [key, ...rest] = arg.slice(2).split('=');
        return [key, rest.join('=')];
      })
  );

const main = async () => {
  const args = parseArgs(process.argv.slice(2));
  const kibanaUrl = (args['kibana-url'] ?? 'http://localhost:5601').replace(/\/+$/, '');
  const username = args.username ?? 'elastic';
  const password = args.password ?? process.env.KIBANA_PASSWORD ?? 'changeme';
  const space = args.space ?? 'default';
  const spacePrefix = space === 'default' ? '' : `/s/${encodeURIComponent(space)}`;

  const headers = {
    'content-type': 'application/json',
    'kbn-xsrf': 'software-inventory-setup',
    'elastic-api-version': OSQUERY_API_VERSION,
    authorization: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`,
  };

  const request = async (method, path, body) => {
    const response = await fetch(`${kibanaUrl}${spacePrefix}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`${method} ${path} failed with ${response.status}: ${text.slice(0, 300)}`);
    }
    return response.json();
  };

  for (const savedQuery of SAVED_QUERIES) {
    const existing = await request(
      'GET',
      `/api/osquery/saved_queries?id=${encodeURIComponent(savedQuery.id)}&page=1&pageSize=5`
    );
    const exactMatch = (existing.data ?? []).some((item) => item.id === savedQuery.id);
    if (exactMatch) {
      console.log(`Skipped "${savedQuery.id}": already exists in space "${space}".`);
      continue;
    }
    await request('POST', '/api/osquery/saved_queries', {
      ...savedQuery,
      interval: DEFAULT_INTERVAL,
    });
    console.log(`Created "${savedQuery.id}" in space "${space}".`);
  }
};

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
