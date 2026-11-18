/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo, useState } from 'react';
import moment from 'moment';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiCopy,
  EuiDescriptionList,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiLink,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
  type EuiBasicTableColumn,
} from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import { KbnDangerCallout, KbnInfoCallout, KbnWarningCallout } from '@kbn/ui-callout';
import { useKibana } from '@kbn/kibana-react-plugin/public';
import type { SharePluginStart } from '@kbn/share-plugin/public';
import type {
  CatalogEntry,
  CveDetail,
  InstanceDoc,
  RemediationCaveat,
  VersionHistoryItem,
} from '../../common/types';
import { useCatalogDetailQuery } from '../hooks/use_software_inventory_queries';
import { buildHuntQuery } from '../lib/hunt_query';
import type { ResolvedPeriod } from '../lib/time_range';
import { HostTimelineFlyout } from './host_timeline_flyout';
import { ExposureBadge, StatusBadge } from './badges';
import { CATEGORY_LABELS } from './labels';

export const DISCOVER_LOCATOR_ID = 'DISCOVER_APP_LOCATOR';
export const NVD_URL = 'https://nvd.nist.gov/vuln/detail/';

interface Props {
  softwareId: string;
  /** Range the host timeline covers; the timeline action is hidden without it. */
  period?: ResolvedPeriod;
  onClose: () => void;
}

const hostColumns = (
  onTimeline: ((row: InstanceDoc) => void) | undefined
): Array<EuiBasicTableColumn<InstanceDoc>> => [
  {
    name: i18n.translate('xpack.softwareInventory.flyout.hostColumn', { defaultMessage: 'Host' }),
    render: (row: InstanceDoc) => row.host.name ?? row.host.id,
  },
  {
    name: i18n.translate('xpack.softwareInventory.flyout.statusColumn', {
      defaultMessage: 'Status',
    }),
    render: (row: InstanceDoc) => <StatusBadge status={row.status} />,
  },
  {
    name: i18n.translate('xpack.softwareInventory.flyout.exposureColumn', {
      defaultMessage: 'Exposure',
    }),
    render: (row: InstanceDoc) => (
      <ExposureBadge level={row.exposure.level} score={row.exposure.score} />
    ),
  },
  {
    name: i18n.translate('xpack.softwareInventory.flyout.installPathColumn', {
      defaultMessage: 'Install path',
    }),
    render: (row: InstanceDoc) => row.install_path ?? '-',
  },
  {
    name: i18n.translate('xpack.softwareInventory.flyout.lastSeenColumn', {
      defaultMessage: 'Last seen',
    }),
    render: (row: InstanceDoc) => moment(row.last_seen).fromNow(),
  },
  ...(onTimeline
    ? [
        {
          name: i18n.translate('xpack.softwareInventory.flyout.actionsColumn', {
            defaultMessage: 'Actions',
          }),
          actions: [
            {
              name: i18n.translate('xpack.softwareInventory.flyout.timelineActionLabel', {
                defaultMessage: 'Timeline',
              }),
              description: i18n.translate(
                'xpack.softwareInventory.flyout.timelineActionDescription',
                { defaultMessage: 'Show the vulnerability timeline for this host' }
              ),
              type: 'icon' as const,
              icon: 'clock' as const,
              onClick: onTimeline,
              'data-test-subj': 'softwareInventoryHostTimelineAction',
            },
          ],
        },
      ]
    : []),
];

const historyColumns: Array<EuiBasicTableColumn<VersionHistoryItem>> = [
  {
    field: 'version',
    name: i18n.translate('xpack.softwareInventory.flyout.versionColumn', {
      defaultMessage: 'Version',
    }),
  },
  {
    field: 'first_seen',
    name: i18n.translate('xpack.softwareInventory.flyout.firstSeenColumn', {
      defaultMessage: 'First seen',
    }),
    render: (value: string) => moment(value).format('lll'),
  },
  {
    field: 'last_seen',
    name: i18n.translate('xpack.softwareInventory.flyout.versionLastSeenColumn', {
      defaultMessage: 'Last seen',
    }),
    render: (value: string) => moment(value).format('lll'),
  },
];

const NO_VALUE = '-';

const cveColumns: Array<EuiBasicTableColumn<CveDetail>> = [
  {
    field: 'id',
    name: i18n.translate('xpack.softwareInventory.flyout.remediation.cveIdColumn', {
      defaultMessage: 'CVE',
    }),
    render: (id: string) => (
      <EuiLink href={`${NVD_URL}${id}`} target="_blank" external>
        {id}
      </EuiLink>
    ),
  },
  {
    field: 'cvss',
    name: i18n.translate('xpack.softwareInventory.flyout.remediation.cvssColumn', {
      defaultMessage: 'CVSS',
    }),
    render: (cvss: number | undefined) => cvss ?? NO_VALUE,
  },
  {
    field: 'known_exploited',
    name: i18n.translate('xpack.softwareInventory.flyout.remediation.kevColumn', {
      defaultMessage: 'Known exploited',
    }),
    render: (knownExploited: boolean) =>
      knownExploited ? (
        <EuiBadge color="danger">
          {i18n.translate('xpack.softwareInventory.flyout.remediation.kevBadge', {
            defaultMessage: 'Known exploited',
          })}
        </EuiBadge>
      ) : (
        NO_VALUE
      ),
  },
  {
    field: 'published',
    name: i18n.translate('xpack.softwareInventory.flyout.remediation.publishedColumn', {
      defaultMessage: 'Published',
    }),
    render: (published: string | undefined) =>
      published ? moment.utc(published).format('ll') : NO_VALUE,
  },
  {
    field: 'fixed_in',
    name: i18n.translate('xpack.softwareInventory.flyout.remediation.fixedInColumn', {
      defaultMessage: 'Fixed in',
    }),
    render: (fixedIn: string | undefined) =>
      fixedIn ??
      i18n.translate('xpack.softwareInventory.flyout.remediation.noKnownFix', {
        defaultMessage: 'No known fix',
      }),
  },
];

const CAVEAT_TITLES: Record<RemediationCaveat, string> = {
  distro_backports: i18n.translate(
    'xpack.softwareInventory.flyout.remediation.distroBackportsTitle',
    { defaultMessage: 'Distribution backports may apply' }
  ),
  low_version_confidence: i18n.translate(
    'xpack.softwareInventory.flyout.remediation.lowVersionConfidenceTitle',
    { defaultMessage: 'Version comparison may be inaccurate' }
  ),
};

const caveatDescription = (caveat: RemediationCaveat, version: string): string =>
  caveat === 'distro_backports'
    ? i18n.translate('xpack.softwareInventory.flyout.remediation.distroBackportsDescription', {
        defaultMessage:
          'This is an OS package. Distributions such as Debian, Ubuntu and Red Hat often backport security fixes without changing the upstream version, so some of these CVEs may already be fixed in the installed package. Check the distribution security advisory before you upgrade.',
      })
    : i18n.translate('xpack.softwareInventory.flyout.remediation.lowVersionConfidenceDescription', {
        defaultMessage:
          'The version {version} has non-numeric parts, such as a patch suffix, an epoch or a tilde, so it cannot be compared reliably with NVD version ranges.',
        values: { version },
      });

const recommendationText = (entry: CatalogEntry, unfixedCount: number): string => {
  if (entry.fully_remediated === undefined) {
    return i18n.translate('xpack.softwareInventory.flyout.remediation.legacyExplanation', {
      defaultMessage:
        'An earlier enrichment run computed this version, so it may not resolve every CVE. It is recomputed on the next CVE check.',
    });
  }
  if (unfixedCount === 0) {
    return i18n.translate('xpack.softwareInventory.flyout.remediation.fullExplanation', {
      defaultMessage:
        'The lowest version that resolves all {count, plural, one {# known CVE} other {# known CVEs}} on the current release branch.',
      values: { count: entry.cve_count },
    });
  }
  return i18n.translate('xpack.softwareInventory.flyout.remediation.partialExplanation', {
    defaultMessage:
      'The lowest version that resolves the {fixable, plural, one {# CVE} other {# CVEs}} with a known fix on the current release branch. It does not resolve the {unfixed, plural, one {# CVE} other {# CVEs}} with no known fix.',
    values: { fixable: Math.max(0, entry.cve_count - unfixedCount), unfixed: unfixedCount },
  });
};

const CveLinks: React.FC<{ ids: readonly string[]; testSubj: string }> = ({ ids, testSubj }) => (
  <EuiFlexGroup gutterSize="s" wrap data-test-subj={testSubj}>
    {ids.map((id) => (
      <EuiFlexItem grow={false} key={id}>
        <EuiLink href={`${NVD_URL}${id}`} target="_blank" external>
          {id}
        </EuiLink>
      </EuiFlexItem>
    ))}
  </EuiFlexGroup>
);

const RemediationSection: React.FC<{ entry: CatalogEntry }> = ({ entry }) => {
  const unfixed = entry.unfixed_cve_ids ?? [];
  const details = entry.cve_details ?? [];
  const caveats = entry.remediation_caveat ?? [];
  const showLatest =
    entry.latest_known_fix !== undefined && entry.latest_known_fix !== entry.fixed_in;

  const summary = (): React.ReactNode => {
    if (!entry.cve_checked_at) {
      return i18n.translate('xpack.softwareInventory.flyout.remediation.notChecked', {
        defaultMessage: 'CVE data for this version has not been checked yet.',
      });
    }
    if (entry.cve_count === 0) {
      return i18n.translate('xpack.softwareInventory.flyout.remediation.noCves', {
        defaultMessage: 'No known CVEs affect this version. No update is needed.',
      });
    }
    if (!entry.fixed_in) {
      return i18n.translate('xpack.softwareInventory.flyout.remediation.noFixedVersion', {
        defaultMessage: 'No fixed version is known for the CVEs that affect this version.',
      });
    }
    return (
      <>
        <EuiTitle size="xxs">
          <h4>
            {i18n.translate('xpack.softwareInventory.flyout.remediation.recommendedTitle', {
              defaultMessage: 'Recommended minimal safe version',
            })}
          </h4>
        </EuiTitle>
        <EuiText size="m" data-test-subj="softwareInventoryMinimalSafeVersion">
          <strong>{entry.fixed_in}</strong>
        </EuiText>
        <EuiText size="s" color="subdued">
          {recommendationText(entry, unfixed.length)}
        </EuiText>
      </>
    );
  };

  return (
    <div data-test-subj="softwareInventoryRemediation">
      <EuiTitle size="xs">
        <h3>
          {i18n.translate('xpack.softwareInventory.flyout.remediation.title', {
            defaultMessage: 'Remediation',
          })}
        </h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      <EuiPanel hasBorder paddingSize="m">
        <EuiText size="s">{summary()}</EuiText>
        {showLatest ? (
          <>
            <EuiSpacer size="s" />
            <EuiText size="s" data-test-subj="softwareInventoryLatestKnownFix">
              {i18n.translate('xpack.softwareInventory.flyout.remediation.latestKnownFix', {
                defaultMessage:
                  'Alternative: latest known fix {version}. This is the highest fixed version NVD lists for this product, usually on a newer release branch. It is not necessarily the latest release.',
                values: { version: entry.latest_known_fix },
              })}
            </EuiText>
          </>
        ) : null}
      </EuiPanel>

      {unfixed.length > 0 ? (
        <>
          <EuiSpacer size="s" />
          <KbnWarningCallout
            announceOnMount
            size="s"
            data-test-subj="softwareInventoryUnfixedCallout"
            title={i18n.translate('xpack.softwareInventory.flyout.remediation.unfixedTitle', {
              defaultMessage:
                'Unfixed: no known fix for {count, plural, one {# CVE} other {# CVEs}}',
              values: { count: unfixed.length },
            })}
          >
            <CveLinks ids={unfixed} testSubj="softwareInventoryUnfixedCves" />
          </KbnWarningCallout>
        </>
      ) : null}

      {caveats.map((caveat) => (
        <React.Fragment key={caveat}>
          <EuiSpacer size="s" />
          <KbnInfoCallout
            size="s"
            data-test-subj={`softwareInventoryCaveat-${caveat}`}
            title={CAVEAT_TITLES[caveat]}
          >
            {caveatDescription(caveat, entry.version)}
          </KbnInfoCallout>
        </React.Fragment>
      ))}

      <EuiSpacer />
      <EuiTitle size="xs">
        <h3>
          {i18n.translate('xpack.softwareInventory.flyout.cvesTitle', {
            defaultMessage: 'CVEs',
          })}
        </h3>
      </EuiTitle>
      <EuiSpacer size="s" />
      {details.length > 0 ? (
        <>
          {entry.cve_count > details.length ? (
            <>
              <EuiText size="s" color="subdued">
                {i18n.translate('xpack.softwareInventory.flyout.remediation.truncatedCves', {
                  defaultMessage: 'Showing the {shown} highest-scoring of {total} CVEs.',
                  values: { shown: details.length, total: entry.cve_count },
                })}
              </EuiText>
              <EuiSpacer size="s" />
            </>
          ) : null}
          <EuiBasicTable
            tableCaption={i18n.translate('xpack.softwareInventory.flyout.remediation.cveCaption', {
              defaultMessage: 'CVEs that affect this version, with the version that fixes each',
            })}
            data-test-subj="softwareInventoryCveTable"
            items={details}
            columns={cveColumns}
          />
        </>
      ) : entry.cve_ids.length === 0 ? (
        <EuiText size="s">
          {i18n.translate('xpack.softwareInventory.flyout.noCvesDescription', {
            defaultMessage: 'No known CVEs.',
          })}
        </EuiText>
      ) : (
        <CveLinks ids={entry.cve_ids} testSubj="softwareInventoryCveList" />
      )}
    </div>
  );
};

export const DetailFlyout: React.FC<Props> = ({ softwareId, period, onClose }) => {
  const [timelineHost, setTimelineHost] = useState<InstanceDoc | undefined>();
  const { services } = useKibana<{ share?: SharePluginStart }>();
  const { data, isLoading, error } = useCatalogDetailQuery(softwareId);

  const huntQuery = useMemo(
    () => (data ? buildHuntQuery(data.instances.map((i) => i.host.name ?? i.host.id)) : undefined),
    [data]
  );

  const openInDiscover = async (): Promise<void> => {
    if (!huntQuery) return;
    const locator = services.share?.url.locators.get(DISCOVER_LOCATOR_ID);
    await locator?.navigate({ query: { esql: huntQuery } });
  };
  const canOpenDiscover = Boolean(services.share?.url.locators.get(DISCOVER_LOCATOR_ID));

  const evidence = data?.instances.flatMap((instance) =>
    instance.exposure.evidence.map((item) => ({
      host: instance.host.name ?? instance.host.id,
      ...item,
    }))
  );
  const history = data?.instances
    .flatMap((i) => i.version_history)
    .sort((a, b) => b.last_seen.localeCompare(a.last_seen));

  const renderBody = (): React.ReactNode => {
    if (isLoading) {
      return <EuiLoadingSpinner size="xl" data-test-subj="softwareInventoryFlyoutLoading" />;
    }
    if (error || !data) {
      return (
        <KbnDangerCallout
          announceOnMount
          data-test-subj="softwareInventoryFlyoutError"
          title={i18n.translate('xpack.softwareInventory.flyout.errorTitle', {
            defaultMessage: 'Unable to load software details',
          })}
        >
          {error?.message}
        </KbnDangerCallout>
      );
    }
    const { entry, instances } = data;
    return (
      <>
        <EuiDescriptionList
          type="column"
          compressed
          listItems={[
            {
              title: i18n.translate('xpack.softwareInventory.flyout.vendorLabel', {
                defaultMessage: 'Vendor',
              }),
              description: entry.vendor,
            },
            {
              title: i18n.translate('xpack.softwareInventory.flyout.categoryLabel', {
                defaultMessage: 'Category',
              }),
              description: CATEGORY_LABELS[entry.category] ?? entry.category,
            },
            {
              title: i18n.translate('xpack.softwareInventory.flyout.cpeLabel', {
                defaultMessage: 'CPE',
              }),
              description: entry.cpe ?? '-',
            },
            {
              title: i18n.translate('xpack.softwareInventory.flyout.maxCvssLabel', {
                defaultMessage: 'Max CVSS',
              }),
              description: entry.max_cvss ?? '-',
            },
            {
              title: i18n.translate('xpack.softwareInventory.flyout.knownExploitedLabel', {
                defaultMessage: 'Known exploited',
              }),
              description: entry.known_exploited
                ? i18n.translate('xpack.softwareInventory.flyout.yesLabel', {
                    defaultMessage: 'Yes',
                  })
                : i18n.translate('xpack.softwareInventory.flyout.noLabel', {
                    defaultMessage: 'No',
                  }),
            },
            {
              title: i18n.translate('xpack.softwareInventory.flyout.fixedInLabel', {
                defaultMessage: 'Minimal safe version',
              }),
              description: entry.fixed_in ?? NO_VALUE,
            },
          ]}
        />

        <EuiSpacer />
        <RemediationSection entry={entry} />

        <EuiSpacer />
        <EuiTitle size="xs">
          <h3>
            {i18n.translate('xpack.softwareInventory.flyout.evidenceTitle', {
              defaultMessage: 'Exposure evidence',
            })}
          </h3>
        </EuiTitle>
        <EuiSpacer size="s" />
        <EuiBasicTable
          tableCaption={i18n.translate('xpack.softwareInventory.flyout.evidenceCaption', {
            defaultMessage: 'Exposure evidence per instance',
          })}
          data-test-subj="softwareInventoryEvidenceTable"
          items={evidence ?? []}
          columns={[
            {
              field: 'host',
              name: i18n.translate('xpack.softwareInventory.flyout.evidenceHostColumn', {
                defaultMessage: 'Host',
              }),
            },
            {
              field: 'signal',
              name: i18n.translate('xpack.softwareInventory.flyout.evidenceSignalColumn', {
                defaultMessage: 'Signal',
              }),
            },
            {
              field: 'detail',
              name: i18n.translate('xpack.softwareInventory.flyout.evidenceDetailColumn', {
                defaultMessage: 'Detail',
              }),
            },
            {
              field: 'weight',
              name: i18n.translate('xpack.softwareInventory.flyout.evidenceWeightColumn', {
                defaultMessage: 'Weight',
              }),
            },
          ]}
          noItemsMessage={i18n.translate('xpack.softwareInventory.flyout.noEvidenceMessage', {
            defaultMessage: 'No exposure evidence.',
          })}
        />

        <EuiSpacer />
        <EuiTitle size="xs">
          <h3>
            {i18n.translate('xpack.softwareInventory.flyout.affectedHostsTitle', {
              defaultMessage: 'Affected hosts ({count})',
              values: { count: instances.length },
            })}
          </h3>
        </EuiTitle>
        <EuiSpacer size="s" />
        <EuiBasicTable
          tableCaption={i18n.translate('xpack.softwareInventory.flyout.hostsCaption', {
            defaultMessage: 'Affected hosts',
          })}
          data-test-subj="softwareInventoryHostsTable"
          items={instances}
          columns={hostColumns(period ? setTimelineHost : undefined)}
        />

        <EuiSpacer />
        <EuiTitle size="xs">
          <h3>
            {i18n.translate('xpack.softwareInventory.flyout.versionHistoryTitle', {
              defaultMessage: 'Version history',
            })}
          </h3>
        </EuiTitle>
        <EuiSpacer size="s" />
        <EuiBasicTable
          tableCaption={i18n.translate('xpack.softwareInventory.flyout.historyCaption', {
            defaultMessage: 'Version history',
          })}
          data-test-subj="softwareInventoryHistoryTable"
          items={history ?? []}
          columns={historyColumns}
          noItemsMessage={i18n.translate('xpack.softwareInventory.flyout.noHistoryMessage', {
            defaultMessage: 'No version changes recorded.',
          })}
        />

        <EuiSpacer />
        <EuiTitle size="xs">
          <h3>
            {i18n.translate('xpack.softwareInventory.flyout.huntTitle', {
              defaultMessage: 'Hunt',
            })}
          </h3>
        </EuiTitle>
        <EuiSpacer size="s" />
        {huntQuery ? (
          <>
            <EuiText size="s">
              <pre data-test-subj="softwareInventoryHuntQuery">{huntQuery}</pre>
            </EuiText>
            <EuiSpacer size="s" />
            <EuiFlexGroup gutterSize="s" responsive={false}>
              {canOpenDiscover ? (
                <EuiFlexItem grow={false}>
                  <EuiButton
                    size="s"
                    iconType="discoverApp"
                    onClick={openInDiscover}
                    data-test-subj="softwareInventoryOpenInDiscover"
                  >
                    {i18n.translate('xpack.softwareInventory.flyout.openInDiscoverButtonLabel', {
                      defaultMessage: 'Open in Discover',
                    })}
                  </EuiButton>
                </EuiFlexItem>
              ) : null}
              <EuiFlexItem grow={false}>
                <EuiCopy textToCopy={huntQuery}>
                  {(copy) => (
                    <EuiButton
                      size="s"
                      iconType="copy"
                      onClick={copy}
                      data-test-subj="softwareInventoryCopyHuntQuery"
                    >
                      {i18n.translate('xpack.softwareInventory.flyout.copyQueryButtonLabel', {
                        defaultMessage: 'Copy query',
                      })}
                    </EuiButton>
                  )}
                </EuiCopy>
              </EuiFlexItem>
            </EuiFlexGroup>
          </>
        ) : null}
      </>
    );
  };

  return (
    <EuiFlyout
      onClose={onClose}
      size="l"
      ownFocus
      aria-labelledby="softwareInventoryFlyoutTitle"
      data-test-subj="softwareInventoryFlyout"
    >
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="m">
          <h2 id="softwareInventoryFlyoutTitle">
            {data
              ? i18n.translate('xpack.softwareInventory.flyout.title', {
                  defaultMessage: '{name} {version}',
                  values: { name: data.entry.display_name, version: data.entry.version },
                })
              : i18n.translate('xpack.softwareInventory.flyout.loadingTitle', {
                  defaultMessage: 'Software details',
                })}
          </h2>
        </EuiTitle>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>{renderBody()}</EuiFlyoutBody>
      {timelineHost && period ? (
        <HostTimelineFlyout
          hostKey={timelineHost.host.key}
          hostLabel={timelineHost.host.name ?? timelineHost.host.id}
          period={period}
          onClose={() => setTimelineHost(undefined)}
        />
      ) : null}
    </EuiFlyout>
  );
};
