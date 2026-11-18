#!/usr/bin/env node
/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Discovery test harness for the software inventory managed workflows. See
 * docs/discovery_test_plan.md ("Execution procedure").
 *
 * Usage:
 *   node x-pack/solutions/security/plugins/software_inventory/scripts/run_discovery_tests.js \
 *     <list|preflight|logs|nvd-stub|run|cleanup|restore|regression|report> \
 *     [--kibana-url=http://localhost:5601/tdy] [--es-url=http://localhost:9200] \
 *     [--username=elastic] [--password=changeme] [--space=default] [--t0=<ISO>]
 *
 * The password can also come from the KIBANA_PASSWORD or ES_PASSWORD environment variable.
 * Run without a command for the full help.
 */

require('@kbn/setup-node-env');
require('./discovery_test/cli').cli();
