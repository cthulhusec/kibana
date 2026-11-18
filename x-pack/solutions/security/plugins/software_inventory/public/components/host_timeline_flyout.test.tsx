/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { render, screen, within } from '@testing-library/react';
import { EuiProvider } from '@elastic/eui';
import { HostTimelineBody } from './host_timeline_flyout';
import { makeInterval, makeTimeline } from '../lib/history_fixtures';

const renderBody = (data: ReturnType<typeof makeTimeline>) =>
  render(
    <EuiProvider>
      <HostTimelineBody data={data} />
    </EuiProvider>
  );

describe('HostTimelineBody', () => {
  it('leads with the not vulnerable answer', () => {
    renderBody(
      makeTimeline({
        items: [
          {
            instance_id: 'i1',
            product: 'nginx',
            vendor: 'nginx',
            category: 'application',
            status: 'active',
            exposure_level: 'none',
            vulnerable_in_range: false,
            intervals: [makeInterval({ display_name: 'nginx', version: '1.27.0' })],
          },
        ],
      })
    );
    expect(screen.getByTestId('softwareInventoryTimelineHeadline')).toHaveTextContent(
      'Not vulnerable during this period'
    );
    expect(screen.queryByTestId('softwareInventoryTimelineWindow')).not.toBeInTheDocument();
  });

  it('leads with the vulnerable duration, first time, CVEs and patch marker', () => {
    renderBody(
      makeTimeline({
        vulnerable_in_range: true,
        vulnerable_duration_ms: (2 * 24 + 4) * 3_600_000,
        first_vulnerable_at: '2026-06-02T00:00:00.000Z',
        cve_ids: ['CVE-2021-44228'],
        items: [
          {
            instance_id: 'i1',
            product: 'log4j',
            vendor: 'apache',
            category: 'dependency',
            status: 'patched',
            exposure_level: 'high',
            vulnerable_in_range: true,
            intervals: [
              makeInterval({
                end: '2026-06-04T04:00:00.000Z',
                patched_to_version: '2.17.1',
                vulnerable_windows: [
                  {
                    start: '2026-06-02T00:00:00.000Z',
                    end: '2026-06-04T04:00:00.000Z',
                    cve_ids: ['CVE-2021-44228'],
                    max_cvss: 10,
                    known_exploited: true,
                  },
                ],
              }),
              makeInterval({ version: '2.17.1', start: '2026-06-04T04:00:00.000Z' }),
            ],
          },
        ],
      })
    );
    expect(screen.getByTestId('softwareInventoryTimelineHeadline')).toHaveTextContent(
      'Vulnerable for 2d 4h during this period'
    );
    expect(screen.getByTestId('softwareInventoryTimelineFirstVulnerable')).toBeInTheDocument();
    expect(
      within(screen.getByTestId('softwareInventoryTimelineCves')).getByText('CVE-2021-44228')
    ).toBeInTheDocument();
    expect(screen.getByTestId('softwareInventoryTimelinePatch')).toHaveTextContent(
      'Patched to 2.17.1'
    );
    expect(screen.getAllByTestId('softwareInventoryTimelineInterval')).toHaveLength(2);
  });

  it('labels open-ended intervals and windows as ongoing', () => {
    renderBody(
      makeTimeline({
        vulnerable_in_range: true,
        vulnerable_duration_ms: 3_600_000,
        items: [
          {
            instance_id: 'i1',
            product: 'log4j',
            vendor: 'apache',
            category: 'dependency',
            status: 'active',
            exposure_level: 'high',
            vulnerable_in_range: true,
            intervals: [
              makeInterval({
                vulnerable_windows: [
                  {
                    start: '2026-06-02T00:00:00.000Z',
                    cve_ids: ['CVE-2021-44228'],
                    known_exploited: false,
                  },
                ],
              }),
            ],
          },
        ],
      })
    );
    expect(screen.getByTestId('softwareInventoryTimelineWindow')).toHaveTextContent('ongoing');
    expect(screen.getByTestId('softwareInventoryTimelineInterval')).toHaveTextContent('ongoing');
  });
});
