/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Creates the four Osquery saved queries that the software inventory discovery workflow runs.

/*
 * Installs (or removes) the "discovery workflow monitoring" dashboard, a test aid for the software
 * inventory discovery workflows. The script is idempotent: it upserts the dashboard by its
 * deterministic id with PUT /api/dashboards/{id}.
 *
 * Usage:
 *   node x-pack/solutions/security/plugins/software_inventory/scripts/install_monitoring_dashboard.js \
 *     [--kibana-url=http://localhost:5601] [--username=elastic] [--password=changeme] \
 *     [--space=default] [--delete]
 *
 * The password can also come from the KIBANA_PASSWORD environment variable. If Kibana runs under a
 * base path, include it in --kibana-url (for example http://localhost:5601/tdy).
 */

require('@kbn/setup-node-env');
require('./monitoring_dashboard/install').main(process.argv.slice(2));
