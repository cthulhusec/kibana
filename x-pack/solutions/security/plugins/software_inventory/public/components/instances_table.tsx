/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import moment from 'moment';
import {
  EuiBasicTable,
  EuiBadge,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLink,
  EuiText,
  type CriteriaWithPagination,
  type EuiBasicTableColumn,
} from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import type { InstanceRow, SoftwareCategory } from '../../common/types';
import type { InstanceSortField } from '../api/client';
import type { TableState } from '../lib/filters';
import { ExposureBadge, StatusBadge } from './badges';
import { CATEGORY_LABELS, PERIOD_LABELS } from './labels';

export const PAGE_SIZE_OPTIONS = [10, 25, 50, 100];

interface Props {
  items: InstanceRow[];
  total: number;
  tableState: TableState;
  loading: boolean;
  /** Adds the period columns. */
  isPeriodScoped?: boolean;
  onTableChange: (next: TableState) => void;
  onSelect: (row: InstanceRow) => void;
}

const formatRelative = (iso: string | undefined): string => (iso ? moment(iso).fromNow() : '-');

const vulnerableInPeriodColumn: EuiBasicTableColumn<InstanceRow> = {
  name: PERIOD_LABELS.vulnerableInPeriodColumn,
  'data-test-subj': 'softwareInventoryVulnerableInPeriodColumn',
  render: (row: InstanceRow) =>
    row.vulnerable_in_range === undefined ? (
      '-'
    ) : row.vulnerable_in_range ? (
      <EuiBadge color="danger">{PERIOD_LABELS.vulnerableBadge}</EuiBadge>
    ) : (
      <EuiBadge color="hollow">{PERIOD_LABELS.notVulnerableBadge}</EuiBadge>
    ),
};

const columns = (
  onSelect: (row: InstanceRow) => void,
  isPeriodScoped: boolean
): Array<EuiBasicTableColumn<InstanceRow>> => [
  {
    field: 'software.display_name',
    name: i18n.translate('xpack.softwareInventory.table.softwareColumn', {
      defaultMessage: 'Software',
    }),
    render: (_: string, row: InstanceRow) => (
      <EuiLink onClick={() => onSelect(row)} data-test-subj="softwareInventorySoftwareLink">
        {i18n.translate('xpack.softwareInventory.table.softwareNameVersion', {
          defaultMessage: '{name} {version}',
          values: { name: row.software.display_name, version: row.software.version },
        })}
      </EuiLink>
    ),
  },
  {
    field: 'host.name',
    name: i18n.translate('xpack.softwareInventory.table.hostColumn', { defaultMessage: 'Host' }),
    sortable: true,
    render: (_: string | undefined, row: InstanceRow) => row.host.name ?? row.host.id,
  },
  {
    field: 'software.category',
    name: i18n.translate('xpack.softwareInventory.table.categoryColumn', {
      defaultMessage: 'Category',
    }),
    render: (category: SoftwareCategory) => CATEGORY_LABELS[category] ?? category,
  },
  {
    field: 'status',
    name: i18n.translate('xpack.softwareInventory.table.statusColumn', {
      defaultMessage: 'Status',
    }),
    render: (_: string, row: InstanceRow) => (
      // Stacked: a badge never wraps, so a long "patched from" badge beside the status badge
      // would overflow into the next column.
      <EuiFlexGroup direction="column" gutterSize="xs" alignItems="flexStart" responsive={false}>
        <EuiFlexItem grow={false}>
          <StatusBadge status={row.status} />
        </EuiFlexItem>
        {row.previous_software_id ? (
          <EuiFlexItem grow={false}>
            <EuiText size="xs" color="subdued" data-test-subj="softwareInventoryPatchedFrom">
              {i18n.translate('xpack.softwareInventory.table.patchedFromLabel', {
                defaultMessage: 'Patched from {from} → {to}',
                values: {
                  from:
                    row.version_history.find((v) => v.version !== row.software.version)?.version ??
                    row.previous_software_id,
                  to: row.software.version,
                },
              })}
            </EuiText>
          </EuiFlexItem>
        ) : null}
      </EuiFlexGroup>
    ),
  },
  {
    field: 'exposure.score',
    name: i18n.translate('xpack.softwareInventory.table.exposureColumn', {
      defaultMessage: 'Exposure',
    }),
    sortable: true,
    render: (_: number, row: InstanceRow) => (
      <ExposureBadge level={row.exposure.level} score={row.exposure.score} />
    ),
  },
  {
    field: 'software.cve_count',
    name: i18n.translate('xpack.softwareInventory.table.cvesColumn', { defaultMessage: 'CVEs' }),
    render: (_: number, row: InstanceRow) =>
      row.software.cve_count === 0
        ? '0'
        : i18n.translate('xpack.softwareInventory.table.cveCountMaxCvss', {
            defaultMessage: '{count} (max CVSS {cvss})',
            values: { count: row.software.cve_count, cvss: row.software.max_cvss ?? '-' },
          }),
  },
  {
    field: 'software.known_exploited',
    name: i18n.translate('xpack.softwareInventory.table.knownExploitedColumn', {
      defaultMessage: 'Known exploited',
    }),
    render: (_: boolean, row: InstanceRow) =>
      row.software.known_exploited ? (
        <EuiBadge color="danger" data-test-subj="softwareInventoryKnownExploited">
          {i18n.translate('xpack.softwareInventory.table.knownExploitedBadge', {
            defaultMessage: 'KEV',
          })}
        </EuiBadge>
      ) : null,
  },
  {
    field: 'software.fixed_in',
    name: i18n.translate('xpack.softwareInventory.table.fixedInColumn', {
      defaultMessage: 'Fixed in',
    }),
    render: (_: string | undefined, row: InstanceRow) => row.software.fixed_in ?? '-',
  },
  {
    field: 'last_seen',
    name: i18n.translate('xpack.softwareInventory.table.lastSeenColumn', {
      defaultMessage: 'Last seen',
    }),
    sortable: true,
    render: (_: string, row: InstanceRow) => (
      <EuiText size="s">{formatRelative(row.last_seen)}</EuiText>
    ),
  },
  ...(isPeriodScoped ? [vulnerableInPeriodColumn] : []),
];

/**
 * Row type whose keys also include the server's nested sort paths (e.g. `exposure.score`),
 * which the table's sorting API requires to be keys of the row.
 */
type SortableRow = InstanceRow &
  Partial<Record<Exclude<InstanceSortField, keyof InstanceRow>, never>>;

const INSTANCE_SORT_FIELDS: readonly string[] = [
  'last_seen',
  'first_seen',
  'version_changed_at',
  'exposure.score',
  'host.name',
] satisfies InstanceSortField[];

const isInstanceSortField = (field: PropertyKey | undefined): field is InstanceSortField =>
  typeof field === 'string' && INSTANCE_SORT_FIELDS.includes(field);

export const InstancesTable: React.FC<Props> = ({
  items,
  total,
  tableState,
  loading,
  isPeriodScoped = false,
  onTableChange,
  onSelect,
}) => {
  const handleChange = ({ page, sort }: CriteriaWithPagination<SortableRow>): void => {
    onTableChange({
      pageIndex: page.index,
      pageSize: page.size,
      sortField: isInstanceSortField(sort?.field) ? sort.field : tableState.sortField,
      sortDirection: sort?.direction ?? tableState.sortDirection,
    });
  };

  return (
    <EuiBasicTable<SortableRow>
      data-test-subj="softwareInventoryTable"
      tableCaption={i18n.translate('xpack.softwareInventory.table.caption', {
        defaultMessage: 'Software instances',
      })}
      items={items}
      itemId="id"
      columns={columns(onSelect, isPeriodScoped)}
      loading={loading}
      pagination={{
        pageIndex: tableState.pageIndex,
        pageSize: tableState.pageSize,
        totalItemCount: total,
        pageSizeOptions: PAGE_SIZE_OPTIONS,
      }}
      sorting={{
        sort: { field: tableState.sortField, direction: tableState.sortDirection },
      }}
      onChange={handleChange}
      noItemsMessage={i18n.translate('xpack.softwareInventory.table.noItemsMessage', {
        defaultMessage: 'No software instances match your filters.',
      })}
    />
  );
};
