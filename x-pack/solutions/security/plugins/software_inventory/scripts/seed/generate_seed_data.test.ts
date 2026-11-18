/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { InstanceDoc } from '../../common/types';
import {
  CATALOG_MAPPINGS,
  EVENTS_MAPPINGS,
  INSTANCES_MAPPINGS,
  ROLLUPS_MAPPINGS,
} from '../../common/mappings';
import { buildHostKey, buildInstanceId } from '../../server/lib/instance_identity';
import { compareVersions } from '../../server/services/enrichment/compare_versions';
import { generateSeedData } from './generate_seed_data';

const DAY_MS = 86_400_000;
const NOW = new Date('2026-11-18T12:00:00.000Z');

type Properties = Record<string, { properties?: Properties }>;

const unknownFields = (doc: object, properties: Properties, prefix = ''): string[] =>
  Object.entries(doc).flatMap(([key, value]) => {
    const mapping = properties[key];
    if (!mapping) {
      return [`${prefix}${key}`];
    }
    const nested = Array.isArray(value) ? value : [value];
    return nested.flatMap((item) =>
      mapping.properties && item !== null && typeof item === 'object'
        ? unknownFields(item, mapping.properties, `${prefix}${key}.`)
        : []
    );
  });

describe('generateSeedData', () => {
  const { catalog, instances, events, rollups } = generateSeedData(NOW);
  const catalogIds = new Set(catalog.map(({ id }) => id));

  it('is deterministic for a given now', () => {
    expect(generateSeedData(NOW)).toEqual({ catalog, instances, events, rollups });
  });

  it('generates a realistic volume', () => {
    expect(catalog.length).toBeGreaterThanOrEqual(30);
    expect(instances.length).toBeGreaterThanOrEqual(55);
    expect(new Set(instances.map(({ host }) => host.id)).size).toBe(19); // 15 base hosts plus 4 scenario hosts
  });

  it('uses unique ids', () => {
    expect(catalogIds.size).toBe(catalog.length);
    expect(new Set(instances.map(({ id }) => id)).size).toBe(instances.length);
  });

  it('derives instance ids exactly like ingest does', () => {
    instances.forEach(({ id, host, software_id: softwareId, install_path: installPath }) => {
      const entry = catalog.find((item) => item.id === softwareId);
      expect(host.key).toBe(buildHostKey({ hostName: host.name, hostId: host.id }));
      expect(id).toBe(
        buildInstanceId({
          hostKey: host.key,
          vendor: entry?.vendor ?? '',
          product: entry?.product ?? '',
          installPath,
        })
      );
    });
  });

  it('references only catalog entries that exist', () => {
    instances.forEach(({ software_id: softwareId, previous_software_id: previousId }) => {
      expect(catalogIds.has(softwareId)).toBe(true);
      if (previousId) {
        expect(catalogIds.has(previousId)).toBe(true);
      }
    });
  });

  it('covers every lifecycle state', () => {
    expect(new Set(instances.map(({ status }) => status))).toEqual(
      new Set(['active', 'patched', 'removed', 'stale'])
    );
  });

  it('covers multi-source, one-to-many and multi-version cases', () => {
    expect(instances.some(({ sources }) => sources.length > 1)).toBe(true);
    const hostsBySoftware = new Map<string, Set<string>>();
    instances.forEach(({ software_id: id, host }) =>
      hostsBySoftware.set(id, (hostsBySoftware.get(id) ?? new Set()).add(host.id))
    );
    expect(Math.max(...[...hostsBySoftware.values()].map((hosts) => hosts.size))).toBeGreaterThan(
      3
    );
    const versionsByProduct = new Map<string, Set<string>>();
    catalog.forEach(({ vendor, product, version }) =>
      versionsByProduct.set(
        `${vendor}:${product}`,
        (versionsByProduct.get(`${vendor}:${product}`) ?? new Set()).add(version)
      )
    );
    expect([...versionsByProduct.values()].some((versions) => versions.size > 1)).toBe(true);
  });

  it('orders dates and keeps version history consistent', () => {
    instances.forEach((instance) => {
      const { first_seen: first, last_seen: last, version_history: history } = instance;
      expect(Date.parse(first)).toBeLessThanOrEqual(Date.parse(last));
      expect(Date.parse(last)).toBeLessThanOrEqual(NOW.getTime());
      history.forEach((item) =>
        expect(Date.parse(item.first_seen)).toBeLessThanOrEqual(Date.parse(item.last_seen))
      );
      const [firstItem] = history;
      const lastItem = history[history.length - 1];
      expect(firstItem.first_seen).toBe(first);
      expect(lastItem.last_seen).toBe(last);
      const entry = catalog.find(({ id }) => id === instance.software_id);
      expect(lastItem.version).toBe(entry?.version);
    });
  });

  it('keeps patched instances within the last 7 days with a vulnerable previous version', () => {
    const patched = instances.filter(({ status }) => status === 'patched');
    expect(patched.length).toBeGreaterThan(0);
    patched.forEach((instance) => {
      const changedAt = Date.parse(instance.version_changed_at ?? '');
      expect(NOW.getTime() - changedAt).toBeLessThanOrEqual(7 * DAY_MS);
      expect(changedAt).toBeLessThanOrEqual(NOW.getTime());
      expect(instance.version_history).toHaveLength(2);
      const previous = catalog.find(({ id }) => id === instance.previous_software_id);
      expect(previous?.cve_count).toBeGreaterThan(0);
      expect(instance.version_history[0].last_seen).toBe(instance.version_changed_at);
    });
  });

  it('marks stale instances older than 30 days', () => {
    instances
      .filter(({ status }) => status === 'stale')
      .forEach(({ last_seen: lastSeen }) =>
        expect(NOW.getTime() - Date.parse(lastSeen)).toBeGreaterThan(30 * DAY_MS)
      );
  });

  it('models exposure and enrichment gaps', () => {
    const high = instances.filter(({ exposure }) => exposure.level === 'high');
    expect(high.length).toBeGreaterThanOrEqual(4);
    expect(catalog.filter(({ cve_checked_at: checked }) => !checked)).toHaveLength(2);
    expect(catalog.some(({ cve_count: count }) => count === 0)).toBe(true);
    expect(catalog.some(({ cpe_match_confidence: conf }) => conf !== undefined && conf < 1)).toBe(
      true
    );
    expect(catalog.some(({ known_exploited: kev }) => kev)).toBe(true);
    const edge = instances.filter(({ exposure }) =>
      exposure.evidence.some(({ signal }) => signal === 'edge_device_role')
    );
    expect(edge).toHaveLength(4);
  });

  it('sets fixed_in to the minimal safe version that covers every fixable CVE', () => {
    const log4j = catalog.find(
      ({ version, product }) => product === 'log4j-core' && version === '2.14.1'
    );
    // The lowest per-CVE fix (2.15.0) would still leave three CVEs open.
    expect(log4j).toMatchObject({ fixed_in: '2.17.1', fully_remediated: true, cve_count: 4 });

    catalog
      .filter(({ cve_checked_at: checked }) => checked)
      .forEach((entry) => {
        const details = entry.cve_details ?? [];
        expect(details.map(({ id }) => id).sort()).toEqual(entry.cve_ids);
        details.forEach((detail) => {
          if (detail.fixed_in && entry.fixed_in) {
            expect(compareVersions(entry.fixed_in, detail.fixed_in)).toBeGreaterThanOrEqual(0);
          }
        });
        const unfixed = details.filter(({ fixed_in: fixedIn }) => !fixedIn).map(({ id }) => id);
        expect(entry.unfixed_cve_ids).toEqual(unfixed.sort());
        expect(entry.fully_remediated).toBe(unfixed.length === 0);
        expect(entry.known_exploited).toBe(details.some(({ known_exploited: kev }) => kev));
      });
  });

  it('seeds unverified fixes as unfixed and flags caveats', () => {
    const byProduct = (product: string) => catalog.find((entry) => entry.product === product);
    expect(byProduct('adaptive_security_appliance_software')).toMatchObject({
      fully_remediated: false,
      unfixed_cve_ids: ['CVE-2024-20353'],
    });
    expect(byProduct('adaptive_security_appliance_software')?.fixed_in).toBeUndefined();
    expect(catalog.find(({ version }) => version === '1.25.3')?.fixed_in).toBeUndefined();
    expect(catalog.find(({ version }) => version === '9.7p1')?.remediation_caveat).toEqual([
      'distro_backports',
      'low_version_confidence',
    ]);
    catalog
      .flatMap(({ cve_details: details }) => details ?? [])
      .forEach(({ published }) => {
        if (published) expect(Number.isNaN(Date.parse(published))).toBe(false);
      });
  });

  it('fits the strict index mappings', () => {
    catalog.forEach((doc) =>
      expect(unknownFields(doc, CATALOG_MAPPINGS.properties as Properties)).toEqual([])
    );
    instances.forEach((doc) =>
      expect(unknownFields(doc, INSTANCES_MAPPINGS.properties as Properties)).toEqual([])
    );
    events.forEach((doc) =>
      expect(unknownFields(doc, EVENTS_MAPPINGS.properties as Properties)).toEqual([])
    );
    rollups.forEach((doc) =>
      expect(unknownFields(doc, ROLLUPS_MAPPINGS.properties as Properties)).toEqual([])
    );
  });

  it('stamps every version history entry with the catalog id of its version', () => {
    instances.forEach(({ version_history: history }) =>
      history.forEach((item) => {
        const entry = catalog.find(({ id }) => id === item.software_id);
        expect(entry?.version).toBe(item.version);
      })
    );
  });

  describe('events', () => {
    const cutoff = NOW.getTime() - 90 * DAY_MS;
    const forInstance = (id: string, type: string) =>
      events.filter((event) => event.instance_id === id && event.type === type);

    it('has exactly one version_changed event per history boundary within 90 days', () => {
      instances.forEach(({ id, version_history: history }) => {
        history.slice(1).forEach((item, index) => {
          const at = Date.parse(item.first_seen);
          const matching = forInstance(id, 'version_changed').filter(
            (event) => event['@timestamp'] === item.first_seen
          );
          expect(matching).toHaveLength(at >= cutoff ? 1 : 0);
          if (matching[0]) {
            expect(matching[0]).toMatchObject({
              from_version: history[index].version,
              to_version: item.version,
              previous_software_id: history[index].software_id,
              software_id: item.software_id,
            });
          }
        });
        expect(forInstance(id, 'version_changed')).toHaveLength(
          history.slice(1).filter(({ first_seen: at }) => Date.parse(at) >= cutoff).length
        );
      });
    });

    it('has first_seen, removed and stale events matching statuses and stays in the window', () => {
      instances.forEach((instance) => {
        const first = forInstance(instance.id, 'first_seen');
        expect(first.map((event) => event['@timestamp'])).toEqual(
          Date.parse(instance.first_seen) >= cutoff ? [instance.first_seen] : []
        );
        expect(forInstance(instance.id, 'removed').map((e) => e['@timestamp'])).toEqual(
          instance.status === 'removed' ? [instance.last_seen] : []
        );
        expect(forInstance(instance.id, 'stale')).toHaveLength(
          instance.status === 'stale' && Date.parse(instance.last_seen) + 30 * DAY_MS >= cutoff
            ? 1
            : 0
        );
      });
      events.forEach((event) => {
        expect(Date.parse(event['@timestamp'])).toBeGreaterThanOrEqual(cutoff);
        expect(Date.parse(event['@timestamp'])).toBeLessThanOrEqual(NOW.getTime());
      });
    });

    it('records the vulnerability posture before and after a change', () => {
      const event = events.find(({ type }) => type === 'version_changed');
      const before = catalog.find(({ id }) => id === event?.previous_software_id);
      const after = catalog.find(({ id }) => id === event?.software_id);
      expect(event?.cve_count_before).toBe(before?.cve_count);
      expect(event?.cve_count_after).toBe(after?.cve_count);
    });

    it('has patches spread over 30 days, at least 2 within 3 days', () => {
      const changes = events
        .filter(({ type }) => type === 'version_changed')
        .map(({ '@timestamp': at }) => (NOW.getTime() - Date.parse(at)) / DAY_MS);
      expect(changes.filter((age) => age <= 3).length).toBeGreaterThanOrEqual(2);
      expect(changes.filter((age) => age > 15 && age <= 30).length).toBeGreaterThanOrEqual(2);
    });
  });

  // Independent replay: written separately from the generator on purpose.
  const isVulnerableAt = (instance: InstanceDoc, at: number): boolean => {
    const { version_history: history } = instance;
    const index = history.findIndex((item, i) => {
      const start = Date.parse(item.first_seen);
      const next = history[i + 1];
      const openEnded = instance.status === 'active' || instance.status === 'patched';
      let end = Infinity;
      if (next) end = Date.parse(next.first_seen);
      else if (!openEnded) end = Date.parse(instance.last_seen);
      return start <= at && at < end;
    });
    if (index < 0) return false;
    const entry = catalog.find(({ id }) => id === history[index].software_id);
    return (entry?.cve_details ?? []).some(
      (cve) => !cve.published || Date.parse(cve.published) <= at
    );
  };
  const dayEnd = (day: string): number => Math.min(Date.parse(day) + DAY_MS - 1, NOW.getTime());

  describe('rollups', () => {
    it('has 60 ascending UTC days with no gaps, ending today', () => {
      expect(rollups).toHaveLength(60);
      rollups.forEach((rollup, index) => {
        if (index > 0) {
          expect(
            Date.parse(rollup['@timestamp']) - Date.parse(rollups[index - 1]['@timestamp'])
          ).toBe(DAY_MS);
        }
      });
      expect(rollups[59]['@timestamp']).toBe('2026-11-18T00:00:00.000Z');
      expect(rollups[0]['@timestamp']).toBe('2026-09-20T00:00:00.000Z');
    });

    it('recomputes vulnerable and total counts from the histories', () => {
      [0, 10, 30, 45, 57, 58, 59].forEach((index) => {
        const at = dayEnd(rollups[index]['@timestamp']);
        const present = instances.filter(
          ({ version_history: history, status, last_seen: last }) => {
            const open = status === 'active' || status === 'patched';
            return Date.parse(history[0].first_seen) <= at && (open || Date.parse(last) > at);
          }
        );
        expect(rollups[index].total_instances).toBe(present.length);
        expect(rollups[index].vulnerable_instances).toBe(
          instances.filter((instance) => isVulnerableAt(instance, at)).length
        );
        expect(
          Object.values(rollups[index].categories).reduce((sum, count) => sum + count, 0)
        ).toBe(present.length);
      });
    });

    it('shows the vulnerable count dropping as patches land', () => {
      const counts = rollups.map(({ vulnerable_instances: count }) => count);
      expect(new Set(counts).size).toBeGreaterThan(4);
      expect(counts[59]).toBeLessThan(counts[29]);
      expect(rollups[59].patched_instances + rollups[58].patched_instances).toBeGreaterThan(0);
    });

    it('counts event types per UTC day', () => {
      const total = (key: 'new_instances' | 'patched_instances' | 'removed_instances') =>
        rollups.reduce((sum, rollup) => sum + rollup[key], 0);
      const windowStart = Date.parse(rollups[0]['@timestamp']);
      const inWindow = events.filter(({ '@timestamp': at }) => Date.parse(at) >= windowStart);
      expect(total('new_instances')).toBe(
        inWindow.filter(({ type }) => type === 'first_seen').length
      );
      expect(total('patched_instances')).toBe(
        inWindow.filter(({ type }) => type === 'version_changed').length
      );
      expect(total('removed_instances')).toBe(
        inWindow.filter(({ type }) => type === 'removed').length
      );
    });
  });

  describe('demo scenarios', () => {
    const hostInstances = (name: string) => instances.filter(({ host }) => host.name === name);
    const vulnerableAnyTime = (name: string, from: number, to: number): boolean =>
      hostInstances(name).some((instance) =>
        // Vulnerability can only change at history boundaries and CVE publish dates; sample hourly.
        Array.from(
          { length: Math.floor((to - from) / 3_600_000) + 1 },
          (_, i) => from + i * 3_600_000
        )
          .concat(to)
          .some((at) => isVulnerableAt(instance, at))
      );
    const now = NOW.getTime();

    it('(a) web-patched-2d-ago is vulnerable until a patch 2 days ago', () => {
      expect(hostInstances('web-patched-2d-ago').length).toBeGreaterThan(0);
      expect(vulnerableAnyTime('web-patched-2d-ago', now - 3 * DAY_MS, now)).toBe(true);
      expect(vulnerableAnyTime('web-patched-2d-ago', now - 2 * DAY_MS + 1000, now)).toBe(false);
      expect(
        vulnerableAnyTime('web-patched-2d-ago', now - 30 * DAY_MS, now - 2 * DAY_MS - 1000)
      ).toBe(true);
    });

    it('(b) web-patched-20d-ago is clean in a 3-day window last week', () => {
      expect(vulnerableAnyTime('web-patched-20d-ago', now - 9 * DAY_MS, now - 6 * DAY_MS)).toBe(
        false
      );
      expect(vulnerableAnyTime('web-patched-20d-ago', now - 30 * DAY_MS, now - 21 * DAY_MS)).toBe(
        true
      );
    });

    it('(c) app-always-vulnerable is vulnerable throughout', () => {
      [0, 1, 7, 30, 59].forEach((daysAgo) =>
        expect(
          hostInstances('app-always-vulnerable').some((instance) =>
            isVulnerableAt(instance, now - daysAgo * DAY_MS)
          )
        ).toBe(true)
      );
    });

    it('(d) app-never-vulnerable is never vulnerable', () => {
      expect(hostInstances('app-never-vulnerable').length).toBeGreaterThan(0);
      expect(vulnerableAnyTime('app-never-vulnerable', now - 99 * DAY_MS, now)).toBe(false);
    });
  });
});
