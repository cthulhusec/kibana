/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { Client } from '@elastic/elasticsearch';
import { run } from '@kbn/dev-cli-runner';
import {
  CATALOG_INDEX,
  EVENTS_INDEX,
  INSTANCES_INDEX,
  ROLLUPS_INDEX,
} from '../../common/constants';
import {
  CATALOG_MAPPINGS,
  EVENTS_MAPPINGS,
  INSTANCES_MAPPINGS,
  ROLLUPS_MAPPINGS,
} from '../../common/mappings';
import { generateSeedData } from './generate_seed_data';

const DEFAULT_ES_URL = 'http://localhost:9200';
const DEFAULT_USERNAME = 'elastic';
// Documented local dev default only; override with --password or ES_PASSWORD.
const DEFAULT_PASSWORD = 'changeme';

/** String flags declared in `flags.string` default to '', so an empty value means "not provided". */
export const readStringFlag = (value: unknown, fallback: string): string =>
  typeof value === 'string' && value !== '' ? value : fallback;

export const cli = (): void => {
  run(
    async ({ flags, log }) => {
      const esUrl = readStringFlag(flags['es-url'], DEFAULT_ES_URL);
      const username = readStringFlag(flags.username, DEFAULT_USERNAME);
      const password = readStringFlag(flags.password, process.env.ES_PASSWORD ?? DEFAULT_PASSWORD);
      const clean = flags.clean === true;

      const client = new Client({ node: esUrl, auth: { username, password } });
      const targets = [
        { index: CATALOG_INDEX, mappings: CATALOG_MAPPINGS },
        { index: INSTANCES_INDEX, mappings: INSTANCES_MAPPINGS },
        { index: EVENTS_INDEX, mappings: EVENTS_MAPPINGS },
        { index: ROLLUPS_INDEX, mappings: ROLLUPS_MAPPINGS },
      ];

      // `version_history` must be nested to correlate software_id with its interval; a mapping
      // type cannot change in place, so an old index has to be recreated.
      if (!clean && (await client.indices.exists({ index: INSTANCES_INDEX }))) {
        const current = await client.indices.getMapping({ index: INSTANCES_INDEX });
        const historyType = Object.values(current)[0]?.mappings?.properties?.version_history;
        if (historyType && historyType.type !== 'nested') {
          await client.close();
          throw new Error(
            `${INSTANCES_INDEX} has a non-nested version_history mapping. Re-run with --clean to recreate the indices.`
          );
        }
      }

      for (const { index, mappings } of targets) {
        const exists = await client.indices.exists({ index });
        if (exists && clean) {
          await client.indices.delete({ index });
          log.info(`Deleted ${index}`);
        }
        if (!exists || clean) {
          // Hidden, like the indices the plugin creates at start.
          await client.indices.create({ index, mappings, settings: { hidden: true } });
          log.info(`Created ${index}`);
        } else {
          // Adds fields introduced since the index was created, as the plugin does at start.
          await client.indices.putMapping({ index, properties: mappings.properties });
        }
      }

      const { catalog, instances, events, rollups } = generateSeedData(new Date());

      // Seeded timestamps are relative to now, so events cannot have stable ids. Remove the events
      // of the seeded instances first so a re-run without --clean does not append duplicates. The
      // delete is scoped to those instance ids and leaves events from real discovery alone.
      await client.deleteByQuery({
        index: EVENTS_INDEX,
        query: { terms: { instance_id: instances.map((doc) => doc.id) } },
        refresh: true,
        conflicts: 'proceed',
        ignore_unavailable: true,
      });

      const operations = [
        ...catalog.flatMap((doc) => [{ index: { _index: CATALOG_INDEX, _id: doc.id } }, doc]),
        ...instances.flatMap((doc) => [{ index: { _index: INSTANCES_INDEX, _id: doc.id } }, doc]),
        // Generated ids; the scoped delete above keeps re-runs from duplicating them.
        ...events.flatMap((doc) => [{ index: { _index: EVENTS_INDEX } }, doc]),
        // One rollup per UTC day, keyed by YYYY-MM-DD, so re-runs overwrite.
        ...rollups.flatMap((doc) => [
          { index: { _index: ROLLUPS_INDEX, _id: doc['@timestamp'].slice(0, 10) } },
          doc,
        ]),
      ];
      const response = await client.bulk({ operations, refresh: 'wait_for' });
      if (response.errors) {
        const failed = response.items.filter((item) => item.index?.error).length;
        throw new Error(`Bulk indexing reported ${failed} failed item(s)`);
      }

      log.success(
        `Indexed ${catalog.length} catalog entries, ${instances.length} instances, ` +
          `${events.length} events and ${rollups.length} daily rollups. ` +
          'All documents are SYNTHETIC demo data.'
      );
      await client.close();
    },
    {
      description: 'Seed synthetic demo data for the software inventory plugin.',
      flags: {
        string: ['es-url', 'username', 'password'],
        boolean: ['clean'],
        help: `
          --es-url    Elasticsearch URL (default: ${DEFAULT_ES_URL})
          --username  Elasticsearch username (default: ${DEFAULT_USERNAME})
          --password  Elasticsearch password (default: $ES_PASSWORD, else the local dev default)
          --clean     Delete and recreate all four indices before seeding
        `,
      },
    }
  );
};
