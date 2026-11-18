/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { CatalogEntry, CveDetail } from '../../../common/types';
import type { InventoryEvent } from '../../../common/history';
import {
  buildHostTimeline,
  buildVersionIntervals,
  computeVulnerableWindows,
  deriveSoftwareId,
  isRemediatingPatch,
  latestSoftwareIdInRange,
  medianTimeToPatch,
  unionDuration,
  vulnerableInRange,
  type MsRange,
  type TimelineInstance,
  type VersionInterval,
} from './history_math';

const DAY = 24 * 60 * 60 * 1000;
const T0 = Date.parse('2026-11-01T00:00:00.000Z');
const day = (n: number): number => T0 + n * DAY;
const iso = (n: number): string => new Date(day(n)).toISOString();
const NOW = new Date(day(20));

const entry = (
  id: string,
  cves: Array<Partial<CveDetail> & { id: string }> = [],
  overrides: Partial<CatalogEntry> = {}
): CatalogEntry => {
  const [vendor, product, version] = id.split(':');
  return {
    id,
    vendor,
    product,
    version,
    display_name: `${product} ${version}`,
    category: 'application',
    cve_count: cves.length,
    known_exploited: cves.some((cve) => cve.known_exploited),
    cve_ids: cves.map((cve) => cve.id),
    cve_details: cves.map((cve) => ({ known_exploited: false, ...cve })),
    '@timestamp': iso(0),
    ...overrides,
  };
};

const instance = (overrides: Partial<TimelineInstance> = {}): TimelineInstance => ({
  id: 'i1',
  software_id: 'acme:app:2.0',
  status: 'active',
  first_seen: iso(0),
  last_seen: iso(19),
  exposure: { level: 'none', score: 0, evidence: [] },
  version_history: [
    { version: '1.0', software_id: 'acme:app:1.0', first_seen: iso(0), last_seen: iso(9) },
    { version: '2.0', software_id: 'acme:app:2.0', first_seen: iso(10), last_seen: iso(19) },
  ],
  ...overrides,
});

const catalogOf = (...entries: CatalogEntry[]) => new Map(entries.map((e) => [e.id, e]));
const range = (from: number, to: number): MsRange => ({ from: day(from), to: day(to) });
const interval = (start: number, end?: number): VersionInterval => ({
  software_id: 'acme:app:1.0',
  version: '1.0',
  start: day(start),
  ...(end !== undefined ? { end: day(end) } : {}),
});

describe('buildVersionIntervals', () => {
  it('ends each interval at the next first_seen and leaves the last one open while active', () => {
    expect(buildVersionIntervals(instance(), NOW)).toEqual([
      {
        software_id: 'acme:app:1.0',
        version: '1.0',
        start: day(0),
        end: day(10),
        patched_to_version: '2.0',
      },
      { software_id: 'acme:app:2.0', version: '2.0', start: day(10) },
    ]);
  });

  it('ends the last interval at last_seen when the instance is removed or stale', () => {
    for (const status of ['removed', 'stale'] as const) {
      const intervals = buildVersionIntervals(instance({ status, last_seen: iso(15) }), NOW);
      expect(intervals[1]).toMatchObject({ start: day(10), end: day(15) });
    }
  });

  it('keeps the last interval open for patched instances', () => {
    expect(buildVersionIntervals(instance({ status: 'patched' }), NOW)[1].end).toBeUndefined();
  });

  it('orders unordered history by first_seen', () => {
    const [a, b] = instance().version_history;
    expect(
      buildVersionIntervals(instance({ version_history: [b, a] }), NOW).map((i) => i.version)
    ).toEqual(['1.0', '2.0']);
  });

  it('derives software_id for legacy entries that lack it', () => {
    const legacy = instance({
      version_history: [
        { version: '1.0', first_seen: iso(0), last_seen: iso(9) },
        { version: '2.0', first_seen: iso(10), last_seen: iso(19) },
      ],
    });
    expect(buildVersionIntervals(legacy, NOW).map((i) => i.software_id)).toEqual([
      'acme:app:1.0',
      'acme:app:2.0',
    ]);
  });

  it('falls back to one interval from first_seen when there is no history', () => {
    expect(buildVersionIntervals(instance({ version_history: [] }), NOW)).toEqual([
      { software_id: 'acme:app:2.0', version: '2.0', start: day(0) },
    ]);
  });
});

describe('deriveSoftwareId', () => {
  it('rebuilds the id from the current vendor and product', () => {
    expect(deriveSoftwareId('acme:app:2.0', '1.0 Beta')).toBe('acme:app:1.0_beta');
  });
  it('returns undefined for an unexpected id shape', () => {
    expect(deriveSoftwareId('not-an-id', '1.0')).toBeUndefined();
  });
});

describe('computeVulnerableWindows', () => {
  it('starts the window at the interval start when the CVE was published before it', () => {
    const windows = computeVulnerableWindows(
      interval(0, 10),
      entry('acme:app:1.0', [{ id: 'CVE-A', published: iso(-30), cvss: 7.5 }]),
      undefined,
      NOW
    );
    expect(windows).toEqual([
      { start: day(0), end: day(10), cve_ids: ['CVE-A'], max_cvss: 7.5, known_exploited: false },
    ]);
  });

  it('starts the window at the publish date when the CVE was published mid-interval', () => {
    const [window] = computeVulnerableWindows(
      interval(0, 10),
      entry('acme:app:1.0', [{ id: 'CVE-A', published: iso(4) }]),
      undefined,
      NOW
    );
    expect(window).toMatchObject({ start: day(4), end: day(10) });
  });

  it('is not vulnerable when the CVE was published after the interval ended', () => {
    expect(
      computeVulnerableWindows(
        interval(0, 10),
        entry('acme:app:1.0', [{ id: 'CVE-A', published: iso(12) }]),
        undefined,
        NOW
      )
    ).toEqual([]);
  });

  it('is not vulnerable when the CVE was published exactly when the interval ended', () => {
    expect(
      computeVulnerableWindows(
        interval(0, 10),
        entry('acme:app:1.0', [{ id: 'CVE-A', published: iso(10) }]),
        undefined,
        NOW
      )
    ).toEqual([]);
  });

  it('keeps an open-ended interval open, and stops at now when clipped', () => {
    const vulnerable = entry('acme:app:1.0', [{ id: 'CVE-A', published: iso(2) }]);
    expect(computeVulnerableWindows(interval(0), vulnerable, undefined, NOW)[0]).toEqual({
      start: day(2),
      cve_ids: ['CVE-A'],
      known_exploited: false,
    });
    expect(computeVulnerableWindows(interval(0), vulnerable, range(5, 40), NOW)[0]).toMatchObject({
      start: day(5),
      end: NOW.getTime(),
    });
  });

  it('ignores an open CVE published in the future', () => {
    expect(
      computeVulnerableWindows(
        interval(0),
        entry('acme:app:1.0', [{ id: 'CVE-A', published: iso(25) }]),
        undefined,
        NOW
      )
    ).toEqual([]);
  });

  it('merges multiple CVEs into one window with the union of ids, max CVSS and KEV', () => {
    const [window] = computeVulnerableWindows(
      interval(0, 10),
      entry('acme:app:1.0', [
        { id: 'CVE-A', published: iso(6), cvss: 5 },
        { id: 'CVE-B', published: iso(3), cvss: 9.8, known_exploited: true },
        { id: 'CVE-C', published: iso(30), cvss: 10 },
      ]),
      undefined,
      NOW
    );
    expect(window).toEqual({
      start: day(3),
      end: day(10),
      cve_ids: ['CVE-A', 'CVE-B'],
      max_cvss: 9.8,
      known_exploited: true,
    });
  });

  it('counts a CVE with an unknown publish date from the interval start', () => {
    const [window] = computeVulnerableWindows(
      interval(0, 10),
      entry('acme:app:1.0', [{ id: 'CVE-A' }, { id: 'CVE-B', published: iso(5) }]),
      undefined,
      NOW
    );
    expect(window).toMatchObject({ start: day(0), cve_ids: ['CVE-A', 'CVE-B'] });
  });

  it('counts CVE ids without details from the start and uses entry-level values', () => {
    const [window] = computeVulnerableWindows(
      interval(0, 10),
      entry('acme:app:1.0', [], {
        cve_ids: ['CVE-X'],
        cve_count: 1,
        max_cvss: 8.1,
        known_exploited: true,
        cve_details: undefined,
      }),
      undefined,
      NOW
    );
    expect(window).toEqual({
      start: day(0),
      end: day(10),
      cve_ids: ['CVE-X'],
      max_cvss: 8.1,
      known_exploited: true,
    });
  });

  it('returns nothing without a catalog entry or CVEs', () => {
    expect(computeVulnerableWindows(interval(0, 10), undefined, undefined, NOW)).toEqual([]);
    expect(
      computeVulnerableWindows(interval(0, 10), entry('acme:app:1.0'), undefined, NOW)
    ).toEqual([]);
  });

  describe('range boundaries', () => {
    const vulnerable = entry('acme:app:1.0', [
      { id: 'CVE-A', published: iso(-1) },
      { id: 'CVE-B', published: iso(8) },
    ]);

    it('clips the window to the range and lists only CVEs published inside it', () => {
      expect(computeVulnerableWindows(interval(0, 10), vulnerable, range(2, 5), NOW)).toEqual([
        { start: day(2), end: day(5), cve_ids: ['CVE-A'], known_exploited: false },
      ]);
    });

    it('treats the range end as inclusive', () => {
      const late = entry('acme:app:1.0', [{ id: 'CVE-A', published: iso(5) }]);
      expect(computeVulnerableWindows(interval(0, 10), late, range(2, 5), NOW)).toHaveLength(1);
    });

    it('treats the window end as exclusive: a window ending at `from` does not overlap', () => {
      expect(computeVulnerableWindows(interval(0, 10), vulnerable, range(10, 12), NOW)).toEqual([]);
    });

    it('does not overlap a range that ends before the window starts', () => {
      const late = entry('acme:app:1.0', [{ id: 'CVE-A', published: iso(6) }]);
      expect(computeVulnerableWindows(interval(0, 10), late, range(1, 5), NOW)).toEqual([]);
    });
  });
});

describe('vulnerableInRange', () => {
  // 1.0 runs days 0-10 and is affected by CVE-A (published day -5); 2.0 runs from day 10 and is clean.
  const catalog = catalogOf(
    entry('acme:app:1.0', [{ id: 'CVE-A', published: iso(-5), cvss: 9.1 }]),
    entry('acme:app:2.0')
  );

  it('answers "was this host vulnerable over a 3-day period": yes, before the patch', () => {
    expect(vulnerableInRange({ instance: instance(), catalog, range: range(3, 6), now: NOW })).toBe(
      true
    );
  });

  it('answers yes when the version was patched mid-range', () => {
    expect(
      vulnerableInRange({ instance: instance(), catalog, range: range(9, 12), now: NOW })
    ).toBe(true);
  });

  it('answers "was this host vulnerable over a 3-day period": no, after the patch', () => {
    expect(
      vulnerableInRange({ instance: instance(), catalog, range: range(12, 15), now: NOW })
    ).toBe(false);
  });

  it('answers no for a period before the CVE was published', () => {
    const late = catalogOf(
      entry('acme:app:1.0', [{ id: 'CVE-A', published: iso(7) }]),
      entry('acme:app:2.0')
    );
    expect(
      vulnerableInRange({ instance: instance(), catalog: late, range: range(1, 4), now: NOW })
    ).toBe(false);
    expect(
      vulnerableInRange({ instance: instance(), catalog: late, range: range(5, 8), now: NOW })
    ).toBe(true);
  });

  it('answers no after a removed instance was last seen', () => {
    const removed = instance({
      status: 'removed',
      last_seen: iso(5),
      version_history: [
        { version: '1.0', software_id: 'acme:app:1.0', first_seen: iso(0), last_seen: iso(5) },
      ],
    });
    expect(vulnerableInRange({ instance: removed, catalog, range: range(6, 9), now: NOW })).toBe(
      false
    );
    expect(vulnerableInRange({ instance: removed, catalog, range: range(3, 6), now: NOW })).toBe(
      true
    );
  });

  it('works with legacy history entries without software_id', () => {
    const legacy = instance({
      version_history: [
        { version: '1.0', first_seen: iso(0), last_seen: iso(9) },
        { version: '2.0', first_seen: iso(10), last_seen: iso(19) },
      ],
    });
    expect(vulnerableInRange({ instance: legacy, catalog, range: range(3, 6), now: NOW })).toBe(
      true
    );
    expect(vulnerableInRange({ instance: legacy, catalog, range: range(12, 15), now: NOW })).toBe(
      false
    );
  });
});

describe('latestSoftwareIdInRange', () => {
  it('returns the latest version that ran during the range', () => {
    expect(latestSoftwareIdInRange(instance(), range(2, 4), NOW)).toBe('acme:app:1.0');
    expect(latestSoftwareIdInRange(instance(), range(8, 12), NOW)).toBe('acme:app:2.0');
    expect(
      latestSoftwareIdInRange(instance({ first_seen: iso(30) }), range(-10, -5), NOW)
    ).toBeUndefined();
  });
});

describe('unionDuration', () => {
  it('merges overlapping windows and evaluates open ends at now', () => {
    expect(
      unionDuration(
        [
          { start: 0, end: 10, cve_ids: [], known_exploited: false },
          { start: 5, end: 15, cve_ids: [], known_exploited: false },
          { start: 20, cve_ids: [], known_exploited: false },
        ],
        25
      )
    ).toBe(20);
  });
});

describe('buildHostTimeline', () => {
  const catalog = catalogOf(
    entry('acme:app:1.0', [{ id: 'CVE-A', published: iso(-5), cvss: 9.1 }]),
    entry('acme:app:2.0'),
    entry('acme:lib:3.0', [{ id: 'CVE-L', published: iso(4), known_exploited: true }])
  );
  const lib = instance({
    id: 'i2',
    software_id: 'acme:lib:3.0',
    version_history: [
      { version: '3.0', software_id: 'acme:lib:3.0', first_seen: iso(0), last_seen: iso(19) },
    ],
  });

  it('answers yes for a 3-day period with windows, CVEs, duration and first vulnerable time', () => {
    const timeline = buildHostTimeline({
      hostKey: 'web-1',
      instances: [instance(), lib],
      catalog,
      range: range(3, 6),
      now: NOW,
    });
    expect(timeline).toMatchObject({
      host_key: 'web-1',
      from: iso(3),
      to: iso(6),
      vulnerable_in_range: true,
      vulnerable_duration_ms: 3 * DAY,
      first_vulnerable_at: iso(3),
      cve_ids: ['CVE-A', 'CVE-L'],
    });
    const app = timeline.items.find(({ product }) => product === 'app');
    expect(app?.intervals).toEqual([
      {
        software_id: 'acme:app:1.0',
        display_name: 'app 1.0',
        version: '1.0',
        start: iso(0),
        end: iso(10),
        patched_to_version: '2.0',
        vulnerable_windows: [
          {
            start: iso(0),
            end: iso(10),
            cve_ids: ['CVE-A'],
            max_cvss: 9.1,
            known_exploited: false,
          },
        ],
      },
    ]);
  });

  it('answers no for a 3-day period after the patch', () => {
    const timeline = buildHostTimeline({
      hostKey: 'web-1',
      instances: [instance()],
      catalog,
      range: range(12, 15),
      now: NOW,
    });
    expect(timeline).toMatchObject({
      vulnerable_in_range: false,
      vulnerable_duration_ms: 0,
      cve_ids: [],
    });
    expect(timeline.first_vulnerable_at).toBeUndefined();
    expect(timeline.items[0]).toMatchObject({ vulnerable_in_range: false });
    expect(timeline.items[0].intervals.map(({ version }) => version)).toEqual(['2.0']);
  });

  it('leaves out instances that did not run during the range', () => {
    const later = instance({ id: 'i3', first_seen: iso(18), version_history: [] });
    const timeline = buildHostTimeline({
      hostKey: 'web-1',
      instances: [later],
      catalog,
      range: range(1, 2),
      now: NOW,
    });
    expect(timeline.items).toEqual([]);
  });
});

describe('medianTimeToPatch and isRemediatingPatch', () => {
  const catalog = catalogOf(
    entry('acme:app:1.0', [{ id: 'CVE-A', published: iso(0) }]),
    entry('acme:app:2.0'),
    entry('acme:lib:1.0', [{ id: 'CVE-L', published: iso(2) }]),
    entry('acme:lib:2.0', [{ id: 'CVE-M', published: iso(30) }])
  );
  const patch = (
    softwareId: string,
    previous: string,
    at: number,
    extra: Partial<InventoryEvent> = {}
  ): InventoryEvent => ({
    '@timestamp': iso(at),
    instance_id: 'i',
    host: { key: 'h' },
    type: 'version_changed',
    source: 'osquery',
    software_id: softwareId,
    previous_software_id: previous,
    ...extra,
  });

  it('computes the median from the earliest publish date of the old version', () => {
    const events = [
      patch('acme:app:2.0', 'acme:app:1.0', 4),
      patch('acme:lib:2.0', 'acme:lib:1.0', 8),
      // Old version with no published CVE before the patch: ignored.
      patch('acme:app:1.0', 'acme:lib:2.0', 9),
    ];
    expect(medianTimeToPatch(events, catalog)).toBe(5 * DAY);
  });

  it('is undefined when no patch qualifies', () => {
    expect(medianTimeToPatch([], catalog)).toBeUndefined();
  });

  it('uses recorded posture first, then the catalog', () => {
    expect(
      isRemediatingPatch(patch('x', 'y', 1, { cve_count_before: 3, cve_count_after: 1 }), new Map())
    ).toBe(true);
    expect(isRemediatingPatch(patch('acme:app:2.0', 'acme:app:1.0', 1), catalog)).toBe(true);
    expect(isRemediatingPatch(patch('acme:app:1.0', 'acme:app:2.0', 1), catalog)).toBe(false);
    expect(isRemediatingPatch(patch('unknown', 'acme:app:1.0', 1), catalog)).toBe(false);
  });
});
