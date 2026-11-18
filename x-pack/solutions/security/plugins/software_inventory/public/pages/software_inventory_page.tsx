/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState } from 'react';
import { EuiPageTemplate, EuiSpacer } from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import { KbnDangerCallout } from '@kbn/ui-callout';
import {
  DEFAULT_TABLE_STATE,
  EMPTY_FILTERS,
  hasActiveFilters,
  toFindInstancesParams,
  type FilterState,
  type TableState,
} from '../lib/filters';
import {
  useInstancesQuery,
  useSummaryQuery,
  useTrendsQuery,
} from '../hooks/use_software_inventory_queries';
import { SummaryStats } from '../components/summary_stats';
import { FilterBar } from '../components/filter_bar';
import { InstancesTable } from '../components/instances_table';
import { DetailFlyout } from '../components/detail_flyout';
import { InventoryEmptyState } from '../components/empty_state';
import { PeriodControls } from '../components/period_controls';
import { TrendsSection } from '../components/trends_section';
import { DEFAULT_TIME_RANGE, resolveTimeRange, type TimeRangeInput } from '../lib/time_range';

export const SoftwareInventoryPage: React.FC = () => {
  const [filters, setFilters] = useState<FilterState>(EMPTY_FILTERS);
  const [tableState, setTableState] = useState<TableState>(DEFAULT_TABLE_STATE);
  const [selectedSoftwareId, setSelectedSoftwareId] = useState<string | undefined>();

  const [range, setRange] = useState<TimeRangeInput>(DEFAULT_TIME_RANGE);
  const [isCurrentInventory, setIsCurrentInventory] = useState(false);
  // Resolved on change and refresh only, so a relative range such as `now-30d` keeps stable
  // query keys between renders.
  const [resolution, setResolution] = useState(() => resolveTimeRange(DEFAULT_TIME_RANGE));
  const period = resolution.status === 'ok' ? resolution.period : undefined;
  const tablePeriod = isCurrentInventory ? undefined : period;
  const isPeriodScoped = tablePeriod !== undefined;

  const summary = useSummaryQuery();
  const trends = useTrendsQuery(period);
  const instances = useInstancesQuery(
    toFindInstancesParams(filters, tableState, tablePeriod),
    isCurrentInventory || period !== undefined
  );

  const onFiltersChange = (next: FilterState): void => {
    setFilters(next);
    setTableState((prev) => ({ ...prev, pageIndex: 0 }));
  };

  const isEmpty =
    instances.data !== undefined && instances.data.total === 0 && !hasActiveFilters(filters);

  const renderContent = (): React.ReactNode => {
    if (instances.error) {
      return (
        <KbnDangerCallout
          announceOnMount
          data-test-subj="softwareInventoryError"
          title={i18n.translate('xpack.softwareInventory.page.errorTitle', {
            defaultMessage: 'Unable to load software inventory',
          })}
        >
          {instances.error.message}
        </KbnDangerCallout>
      );
    }
    if (isEmpty) {
      return <InventoryEmptyState />;
    }
    return (
      <>
        <FilterBar filters={filters} onChange={onFiltersChange} isPeriodScoped={isPeriodScoped} />
        <EuiSpacer />
        <InstancesTable
          items={instances.data?.items ?? []}
          total={instances.data?.total ?? 0}
          tableState={tableState}
          loading={instances.isLoading || instances.isFetching}
          isPeriodScoped={isPeriodScoped}
          onTableChange={setTableState}
          onSelect={(row) => setSelectedSoftwareId(row.software_id)}
        />
      </>
    );
  };

  return (
    <EuiPageTemplate restrictWidth={false} data-test-subj="softwareInventoryPage">
      <EuiPageTemplate.Header
        pageTitle={i18n.translate('xpack.softwareInventory.page.title', {
          defaultMessage: 'Software inventory',
        })}
      />
      <EuiPageTemplate.Section>
        <PeriodControls
          range={range}
          resolution={resolution}
          isCurrentInventory={isCurrentInventory}
          onRangeChange={(next) => {
            setRange(next);
            setResolution(resolveTimeRange(next));
            setTableState((prev) => ({ ...prev, pageIndex: 0 }));
          }}
          onRefresh={() => setResolution(resolveTimeRange(range))}
          onCurrentInventoryChange={(next) => {
            setIsCurrentInventory(next);
            setTableState((prev) => ({ ...prev, pageIndex: 0 }));
          }}
        />
        <EuiSpacer />
        <SummaryStats summary={summary.data} loading={summary.isLoading} />
        <EuiSpacer />
        {period ? (
          <>
            <TrendsSection data={trends.data} isLoading={trends.isLoading} error={trends.error} />
            <EuiSpacer />
          </>
        ) : null}
        {renderContent()}
      </EuiPageTemplate.Section>
      {selectedSoftwareId ? (
        <DetailFlyout
          softwareId={selectedSoftwareId}
          period={period}
          onClose={() => setSelectedSoftwareId(undefined)}
        />
      ) : null}
    </EuiPageTemplate>
  );
};
