/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import moment from 'moment';
import {
  EuiBadge,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTimeline,
  EuiTimelineItem,
  EuiTitle,
  useEuiTheme,
} from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import { KbnDangerCallout } from '@kbn/ui-callout';
import type {
  HostTimelineItem,
  HostTimelineResponse,
  TimelineInterval,
  VulnerableWindow,
} from '../../common/history';
import { useHostTimelineQuery } from '../hooks/use_software_inventory_queries';
import { formatDuration } from '../lib/duration';
import type { ResolvedPeriod } from '../lib/time_range';
import { CATEGORY_LABELS } from './labels';

interface FlyoutProps {
  hostKey: string;
  hostLabel: string;
  period: ResolvedPeriod;
  onClose: () => void;
}

const formatTime = (iso: string): string => moment(iso).format('lll');

const ONGOING = i18n.translate('xpack.softwareInventory.hostTimeline.ongoingLabel', {
  defaultMessage: 'ongoing',
});

const rangeText = (start: string, end: string | undefined): string =>
  i18n.translate('xpack.softwareInventory.hostTimeline.rangeLabel', {
    defaultMessage: '{start} to {end}',
    values: { start: formatTime(start), end: end ? formatTime(end) : ONGOING },
  });

const WindowPanel: React.FC<{ window: VulnerableWindow }> = ({ window: vulnerableWindow }) => (
  <EuiPanel
    color="danger"
    paddingSize="s"
    hasShadow={false}
    data-test-subj="softwareInventoryTimelineWindow"
  >
    <EuiText size="s">
      <strong>
        {i18n.translate('xpack.softwareInventory.hostTimeline.vulnerableWindowLabel', {
          defaultMessage: 'Vulnerable: {range}',
          values: { range: rangeText(vulnerableWindow.start, vulnerableWindow.end) },
        })}
      </strong>
    </EuiText>
    <EuiSpacer size="xs" />
    <EuiFlexGroup gutterSize="xs" wrap responsive={false}>
      {vulnerableWindow.cve_ids.map((id) => (
        <EuiFlexItem grow={false} key={id}>
          <EuiBadge color="hollow">{id}</EuiBadge>
        </EuiFlexItem>
      ))}
      {vulnerableWindow.max_cvss !== undefined ? (
        <EuiFlexItem grow={false}>
          <EuiBadge color="danger">
            {i18n.translate('xpack.softwareInventory.hostTimeline.maxCvssBadge', {
              defaultMessage: 'CVSS {score}',
              values: { score: vulnerableWindow.max_cvss },
            })}
          </EuiBadge>
        </EuiFlexItem>
      ) : null}
      {vulnerableWindow.known_exploited ? (
        <EuiFlexItem grow={false}>
          <EuiBadge color="danger">
            {i18n.translate('xpack.softwareInventory.hostTimeline.kevBadge', {
              defaultMessage: 'Known exploited',
            })}
          </EuiBadge>
        </EuiFlexItem>
      ) : null}
    </EuiFlexGroup>
  </EuiPanel>
);

const IntervalItem: React.FC<{ interval: TimelineInterval }> = ({ interval }) => {
  const { euiTheme } = useEuiTheme();
  const isVulnerable = interval.vulnerable_windows.length > 0;
  return (
    <EuiTimelineItem
      icon={isVulnerable ? 'warning' : 'check'}
      iconAriaLabel={
        isVulnerable
          ? i18n.translate('xpack.softwareInventory.hostTimeline.vulnerableIntervalAriaLabel', {
              defaultMessage: 'Vulnerable version',
            })
          : i18n.translate('xpack.softwareInventory.hostTimeline.cleanIntervalAriaLabel', {
              defaultMessage: 'Not vulnerable',
            })
      }
      css={{ color: isVulnerable ? euiTheme.colors.danger : undefined }}
      data-test-subj="softwareInventoryTimelineInterval"
    >
      <EuiText size="s">
        <strong>
          {i18n.translate('xpack.softwareInventory.hostTimeline.intervalTitle', {
            defaultMessage: '{name} {version}',
            values: { name: interval.display_name, version: interval.version },
          })}
        </strong>
      </EuiText>
      <EuiText size="xs" color="subdued">
        {rangeText(interval.start, interval.end)}
      </EuiText>
      {interval.vulnerable_windows.map((w) => (
        <React.Fragment key={`${w.start}-${w.end ?? 'open'}`}>
          <EuiSpacer size="xs" />
          <WindowPanel window={w} />
        </React.Fragment>
      ))}
      {interval.patched_to_version && interval.end ? (
        <>
          <EuiSpacer size="xs" />
          <EuiBadge
            color="success"
            iconType="check"
            data-test-subj="softwareInventoryTimelinePatch"
          >
            {i18n.translate('xpack.softwareInventory.hostTimeline.patchedToBadge', {
              defaultMessage: 'Patched to {version} on {date}',
              values: { version: interval.patched_to_version, date: formatTime(interval.end) },
            })}
          </EuiBadge>
        </>
      ) : null}
    </EuiTimelineItem>
  );
};

const ItemSection: React.FC<{ item: HostTimelineItem }> = ({ item }) => (
  <div data-test-subj="softwareInventoryTimelineItem">
    <EuiTitle size="xs">
      <h4>
        {i18n.translate('xpack.softwareInventory.hostTimeline.itemTitle', {
          defaultMessage: '{product} ({category})',
          values: { product: item.product, category: CATEGORY_LABELS[item.category] },
        })}
      </h4>
    </EuiTitle>
    {item.install_path ? (
      <EuiText size="xs" color="subdued">
        {item.install_path}
      </EuiText>
    ) : null}
    <EuiSpacer size="s" />
    <EuiTimeline>
      {item.intervals.map((interval) => (
        <IntervalItem key={`${interval.software_id}-${interval.start}`} interval={interval} />
      ))}
    </EuiTimeline>
  </div>
);

export const HostTimelineBody: React.FC<{ data: HostTimelineResponse }> = ({ data }) => (
  <>
    <EuiPanel
      hasBorder
      color={data.vulnerable_in_range ? 'danger' : 'success'}
      data-test-subj="softwareInventoryTimelineHeadline"
    >
      <EuiTitle size="s">
        <h3>
          {data.vulnerable_in_range
            ? i18n.translate('xpack.softwareInventory.hostTimeline.vulnerableHeadline', {
                defaultMessage: 'Vulnerable for {duration} during this period',
                values: { duration: formatDuration(data.vulnerable_duration_ms) },
              })
            : i18n.translate('xpack.softwareInventory.hostTimeline.notVulnerableHeadline', {
                defaultMessage: 'Not vulnerable during this period',
              })}
        </h3>
      </EuiTitle>
      {data.first_vulnerable_at ? (
        <EuiText size="s" data-test-subj="softwareInventoryTimelineFirstVulnerable">
          {i18n.translate('xpack.softwareInventory.hostTimeline.firstVulnerableDescription', {
            defaultMessage: 'First vulnerable: {time}',
            values: { time: formatTime(data.first_vulnerable_at) },
          })}
        </EuiText>
      ) : null}
      {data.cve_ids.length > 0 ? (
        <>
          <EuiSpacer size="s" />
          <EuiFlexGroup
            gutterSize="xs"
            wrap
            responsive={false}
            data-test-subj="softwareInventoryTimelineCves"
          >
            {data.cve_ids.map((id) => (
              <EuiFlexItem grow={false} key={id}>
                <EuiBadge color="hollow">{id}</EuiBadge>
              </EuiFlexItem>
            ))}
          </EuiFlexGroup>
        </>
      ) : null}
    </EuiPanel>
    {data.items.map((item) => (
      <React.Fragment key={item.instance_id}>
        <EuiSpacer />
        <ItemSection item={item} />
      </React.Fragment>
    ))}
  </>
);

export const HostTimelineFlyout: React.FC<FlyoutProps> = ({
  hostKey,
  hostLabel,
  period,
  onClose,
}) => {
  const { data, isLoading, error } = useHostTimelineQuery(hostKey, period);

  const renderBody = (): React.ReactNode => {
    if (isLoading) {
      return <EuiLoadingSpinner size="xl" data-test-subj="softwareInventoryTimelineLoading" />;
    }
    if (error || !data) {
      return (
        <KbnDangerCallout
          announceOnMount
          data-test-subj="softwareInventoryTimelineError"
          title={i18n.translate('xpack.softwareInventory.hostTimeline.errorTitle', {
            defaultMessage: 'Unable to load the host timeline',
          })}
        >
          {error?.message}
        </KbnDangerCallout>
      );
    }
    return <HostTimelineBody data={data} />;
  };

  return (
    <EuiFlyout
      onClose={onClose}
      size="m"
      ownFocus
      aria-labelledby="softwareInventoryTimelineFlyoutTitle"
      data-test-subj="softwareInventoryTimelineFlyout"
    >
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="m">
          <h2 id="softwareInventoryTimelineFlyoutTitle">
            {i18n.translate('xpack.softwareInventory.hostTimeline.title', {
              defaultMessage: 'Timeline for {host}',
              values: { host: hostLabel },
            })}
          </h2>
        </EuiTitle>
        <EuiText size="xs" color="subdued">
          {rangeText(period.from, period.to)}
        </EuiText>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>{renderBody()}</EuiFlyoutBody>
    </EuiFlyout>
  );
};
