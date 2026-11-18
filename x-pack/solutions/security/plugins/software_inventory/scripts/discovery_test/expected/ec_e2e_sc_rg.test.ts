/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { CatalogEntry, SoftwareCategory } from '../../../common/types';
import { buildCpe, toNvdVendor } from '../../../server/services/enrichment/build_cpe';
import { buildCatalogUpdate } from '../../../server/services/enrichment/enrich_catalog_entries';
import { parseKevCveIds, parseNvdResponse } from '../../../server/services/enrichment/nvd_parse';
import { diffValues } from '../assertions';
import { KNOWN_SYNTHETIC_CATALOG_IDS, seedCatalogIds } from '../cleanup';
import { CPE_RULES, KEV_BODY } from '../nvd_stub/fixtures';
import { parseCatalogId } from '../ids';
import {
  EC11_SEED_CATALOG_IDS,
  EC9_SEED_CATALOG_IDS,
  EC_CPES,
  EC_IDS,
  EC_REQUIRED_CATALOG_IDS,
  EXPECTED_CHROME,
  EXPECTED_FORTIOS_7_2_4,
  EXPECTED_LOG4J_2_12_1,
  EXPECTED_LOG4J_2_14_1,
  EXPECTED_NGINX_1_25_2,
  EXPECTED_PANOS_10_2_3,
  EXPECTED_SLACK,
  EXPECTED_SYNTH_CHECKOUT,
} from './ec';
import {
  DAY_MS,
  E2E3_REPEAT_CATALOG_IDS,
  E2E_CHECKED_CATALOG_IDS,
  E2E_EVENT_COUNTS,
  E2E_SYNTHETIC_INSTANCES,
  E2E_UNCHECKED_CATALOG_ID,
  HOUR_MS,
  e2e2Expectations,
} from './e2e';
import {
  EXPECTED_SEED_COUNTS,
  EXTRA_SYNTHETIC_CATALOG_IDS,
  diffRollupDays,
  expectedDemo,
} from './rg';
import { SC1, SC_COPY_IDS, scheduledTaskDocPath } from './sc';

const CATEGORY: Readonly<Record<string, SoftwareCategory>> = {
  [EC_IDS.log4j2141]: 'dependency',
  [EC_IDS.log4j2121]: 'dependency',
  [EC_IDS.synthCheckout]: 'application',
  [EC_IDS.fortios724]: 'appliance',
  [EC_IDS.panos1023]: 'appliance',
  [EC_IDS.nginx1252]: 'application',
  [EC_IDS.slack]: 'application',
  [EC_IDS.chrome]: 'application',
};

const entryFor = (id: string): CatalogEntry => {
  const { vendor, product, version } = parseCatalogId(id);
  return {
    id,
    vendor,
    product,
    version,
    display_name: id,
    category: CATEGORY[id] ?? 'application',
    cve_count: 0,
    known_exploited: false,
    cve_ids: [],
    '@timestamp': '2026-11-18T00:00:00.000Z',
  };
};

/** The catalog update the plugin computes from the stub's answer for this entry. */
const updateFromStub = (id: string) => {
  const entry = entryFor(id);
  const rule = CPE_RULES[buildCpe(entry)];
  const body =
    rule?.kind === 'body'
      ? rule.body
      : rule?.kind === 'sequence'
      ? rule.then
      : { vulnerabilities: [] };
  const parsed = parseNvdResponse(body, {
    nvdVendor: toNvdVendor(entry.vendor),
    product: entry.product,
    version: entry.version,
    category: entry.category,
  });
  return buildCatalogUpdate({ entry, parsed, kev: parseKevCveIds(KEV_BODY), now: 'now' });
};

describe('expected/ec', () => {
  it('builds the plan CPE for every stub-table entry with the plugin code', () => {
    const pairs: Array<[string, string]> = [
      [EC_IDS.log4j2141, EC_CPES.log4j2141],
      [EC_IDS.log4j2121, EC_CPES.log4j2121],
      [EC_IDS.synthCheckout, EC_CPES.synthCheckout],
      [EC_IDS.fortios724, EC_CPES.fortios724],
      [EC_IDS.panos1023, EC_CPES.panos1023],
      [EC_IDS.nginx1252, EC_CPES.nginx1252],
      [EC_IDS.slack, EC_CPES.slack],
      [EC_IDS.chrome, EC_CPES.chrome],
      [EC_IDS.sevenZip, EC_CPES.sevenZip],
      [EC_IDS.vscode, EC_CPES.vscode],
    ];
    for (const [id, cpe] of pairs) {
      expect(buildCpe(entryFor(id))).toBe(cpe);
      expect(Object.keys(CPE_RULES).includes(cpe) || id === EC_IDS.slack).toBe(true);
    }
  });

  it.each([
    ['log4j 2.14.1', EC_IDS.log4j2141, EXPECTED_LOG4J_2_14_1],
    ['log4j 2.12.1', EC_IDS.log4j2121, EXPECTED_LOG4J_2_12_1],
    ['synth-checkout', EC_IDS.synthCheckout, EXPECTED_SYNTH_CHECKOUT],
    ['FortiOS', EC_IDS.fortios724, EXPECTED_FORTIOS_7_2_4],
    ['PAN-OS', EC_IDS.panos1023, EXPECTED_PANOS_10_2_3],
    ['nginx 1.25.2', EC_IDS.nginx1252, EXPECTED_NGINX_1_25_2],
    ['Slack', EC_IDS.slack, EXPECTED_SLACK],
    ['Chrome after 429s', EC_IDS.chrome, EXPECTED_CHROME],
  ])('matches what the plugin computes from the stub answer: %s', (_label, id, expected) => {
    const { cve_check_failed: failed, ...rest } = expected;
    expect(diffValues(rest, updateFromStub(id))).toEqual([]);
    expect(failed).toBe(false);
  });

  it('keeps the corrected per-CVE log4j fixes, highest CVSS first', () => {
    expect(
      (
        EXPECTED_LOG4J_2_14_1.cve_details as ReadonlyArray<
          Record<string, string | number | boolean>
        >
      ).map(({ id, fixed_in: fixedIn }) => `${id} ${fixedIn}`)
    ).toEqual([
      'CVE-2021-44228 2.15.0',
      'CVE-2021-45046 2.16.0',
      'CVE-2021-44832 2.17.1',
      'CVE-2021-45105 2.17.0',
    ]);
  });

  it('derives the seed catalog ids with the ingest normalization; none collides with the demo seed', () => {
    expect(EC9_SEED_CATALOG_IDS).toEqual([
      'synth-ec-offline-a:synth-ec-offline-a:1.0.0',
      'synth-ec-offline-b:synth-ec-offline-b:2.0.0',
    ]);
    expect(EC11_SEED_CATALOG_IDS).toEqual(['synth-ec-order-a:synth-ec-order-a:1.0.0']);
    const seed = new Set(seedCatalogIds());
    for (const id of [...EC_REQUIRED_CATALOG_IDS, ...EXTRA_SYNTHETIC_CATALOG_IDS]) {
      expect(seed.has(id)).toBe(false);
    }
    expect(EC_REQUIRED_CATALOG_IDS.every((id) => KNOWN_SYNTHETIC_CATALOG_IDS.includes(id))).toBe(
      true
    );
  });
});

describe('expected/e2e', () => {
  it('counts the pipeline instances and the catalog entries EC checks', () => {
    expect(E2E_SYNTHETIC_INSTANCES).toBe(25);
    expect(E2E_EVENT_COUNTS).toEqual({ first_seen: 25, version_changed: 1 });
    expect(E2E_CHECKED_CATALOG_IDS).toHaveLength(24);
    expect(E2E_CHECKED_CATALOG_IDS).not.toContain(E2E_UNCHECKED_CATALOG_ID);
    expect(E2E_UNCHECKED_CATALOG_ID).toBe('f5:nginx:1.27.4');
    expect(E2E3_REPEAT_CATALOG_IDS).toEqual({
      before: 'f5:nginx:1.25.1',
      after: 'f5:nginx:1.27.5',
    });
  });

  it('puts the synth-web-02 window at T0-20h..T0-1h (19 h)', () => {
    const t0 = new Date('2026-11-18T10:00:00.000Z');
    const now = new Date('2026-11-18T10:20:00.000Z');
    const [threeDays, recent, before] = e2e2Expectations(t0, now);
    expect(threeDays).toEqual(
      expect.objectContaining({
        from: new Date(t0.getTime() - 3 * DAY_MS).toISOString(),
        to: now.toISOString(),
        vulnerableInRange: true,
        firstVulnerableAt: '2026-11-17T14:00:00.000Z',
        cveIds: ['CVE-2023-44487'],
        vulnerableDurationMs: 19 * HOUR_MS,
      })
    );
    expect(recent).toEqual(
      expect.objectContaining({ from: '2026-11-18T09:30:00.000Z', vulnerableInRange: false })
    );
    expect(before).toEqual(
      expect.objectContaining({
        to: '2026-11-17T13:00:00.000Z',
        vulnerableInRange: false,
        itemAbsent: true,
      })
    );
  });
});

describe('expected/rg', () => {
  it('matches the demo seed structure and ignores timestamps', () => {
    const a = expectedDemo(new Date('2026-11-18T10:00:00Z'));
    const b = expectedDemo(new Date('2026-11-20T03:00:00Z'));
    expect({
      catalog: a.catalog.length,
      instances: a.instances.length,
      events: a.eventKeys.length,
      rollups: a.rollupCount,
    }).toEqual(EXPECTED_SEED_COUNTS);
    expect(b.catalog).toEqual(a.catalog);
    expect(b.instances).toEqual(a.instances);
    expect(b.eventKeys).toEqual(a.eventKeys);
    expect(a.catalog.filter(({ checked }) => checked === false).map(({ id }) => id)).toEqual([
      'djangoproject:django:4.2.16',
      'notepad-plus-plus:notepad++:8.6.2',
    ]);
    expect(a.todayRollup.id).toBe('2026-11-18');
  });

  it('accepts consecutive rollup days ending today or yesterday only', () => {
    const now = new Date('2026-11-18T10:00:00Z');
    const days = (last: string, count: number) =>
      Array.from({ length: count }, (_, index) =>
        new Date(Date.parse(last) - index * DAY_MS).toISOString().slice(0, 10)
      );
    expect(diffRollupDays(days('2026-11-18', 60), 60, now)).toEqual([]);
    expect(diffRollupDays(days('2026-11-17', 60), 60, now)).toEqual([]);
    expect(diffRollupDays(days('2026-11-15', 60), 60, now)).toEqual([
      'rollups: latest day 2026-11-15, expected 2026-11-18',
    ]);
    expect(diffRollupDays(days('2026-11-18', 59), 60, now)[0]).toMatch(/expected 60 documents/);
  });
});

describe('expected/sc', () => {
  it('uses si-test- copies and the Task Manager id of the scheduler', () => {
    expect(Object.values(SC_COPY_IDS).every((id) => id.startsWith('si-test-'))).toBe(true);
    expect(SC1.concurrencyKey).not.toBe('software-inventory-discover-osquery');
    expect(scheduledTaskDocPath('si-test-x')).toBe(
      '/.kibana_task_manager/_doc/task%3Aworkflow%3Asi-test-x%3Ascheduled'
    );
  });
});
