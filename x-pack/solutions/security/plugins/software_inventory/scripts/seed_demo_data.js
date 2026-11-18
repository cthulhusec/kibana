#!/usr/bin/env node
/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Seeds SYNTHETIC demo data for the software inventory plugin. Every document is fake.
 *
 * Usage:
 *   node x-pack/solutions/security/plugins/software_inventory/scripts/seed_demo_data.js \
 *     [--es-url=http://localhost:9200] [--username=elastic] [--password=changeme] [--clean]
 *
 * The password can also come from the ES_PASSWORD environment variable.
 */

require('@kbn/setup-node-env');
require('./seed/cli').cli();
