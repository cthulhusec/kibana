/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState } from 'react';
import {
  EuiButtonEmpty,
  EuiFieldNumber,
  EuiFieldSearch,
  EuiFilterButton,
  EuiFilterGroup,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiPopover,
  EuiSelectable,
  type EuiSelectableOption,
} from '@elastic/eui';
import { i18n } from '@kbn/i18n';
import type { FilterState } from '../lib/filters';
import { EMPTY_FILTERS, hasActiveFilters } from '../lib/filters';
import {
  CATEGORY_LABELS,
  EXPOSURE_LABELS,
  PERIOD_LABELS,
  SOURCE_LABELS,
  STATUS_LABELS,
} from './labels';

interface Props {
  filters: FilterState;
  onChange: (next: FilterState) => void;
  /** Shows the period-scoped filters. */
  isPeriodScoped?: boolean;
}

const PATCHED_WITHIN_PRESETS = [7, 30, 90] as const;

interface MultiSelectFilterProps<T extends string> {
  title: string;
  labels: Record<T, string>;
  selected: readonly T[];
  onChange: (next: T[]) => void;
  dataTestSubj: string;
}

const MultiSelectFilter = <T extends string>({
  title,
  labels,
  selected,
  onChange,
  dataTestSubj,
}: MultiSelectFilterProps<T>): React.ReactElement => {
  const [isOpen, setIsOpen] = useState(false);
  const keys = Object.keys(labels) as T[];
  const options: EuiSelectableOption[] = keys.map((key) => ({
    key,
    label: labels[key],
    checked: selected.includes(key) ? 'on' : undefined,
    'data-test-subj': `${dataTestSubj}-option-${key}`,
  }));

  return (
    <EuiPopover
      aria-label={title}
      button={
        <EuiFilterButton
          iconType="chevronSingleDown"
          onClick={() => setIsOpen((open) => !open)}
          isSelected={isOpen}
          hasActiveFilters={selected.length > 0}
          numActiveFilters={selected.length}
          numFilters={keys.length}
          data-test-subj={dataTestSubj}
        >
          {title}
        </EuiFilterButton>
      }
      isOpen={isOpen}
      closePopover={() => setIsOpen(false)}
      panelPaddingSize="none"
    >
      <EuiSelectable
        aria-label={title}
        options={options}
        onChange={(next) => onChange(next.filter((o) => o.checked === 'on').map((o) => o.key as T))}
      >
        {(list) => <div style={{ width: 240 }}>{list}</div>}
      </EuiSelectable>
    </EuiPopover>
  );
};

export const FilterBar: React.FC<Props> = ({ filters, onChange, isPeriodScoped = false }) => {
  const [isCvePopoverOpen, setIsCvePopoverOpen] = useState(false);
  const [isPatchedPopoverOpen, setIsPatchedPopoverOpen] = useState(false);
  const set = <K extends keyof FilterState>(key: K, value: FilterState[K]): void =>
    onChange({ ...filters, [key]: value });

  const minCveTitle = i18n.translate('xpack.softwareInventory.filters.minCveCountLabel', {
    defaultMessage: 'Min CVE count',
  });
  const patchedTitle = i18n.translate('xpack.softwareInventory.filters.patchedWithinLabel', {
    defaultMessage: 'Patched within',
  });
  const patchedOptions: EuiSelectableOption[] = PATCHED_WITHIN_PRESETS.map((days) => ({
    key: String(days),
    label: i18n.translate('xpack.softwareInventory.filters.patchedWithinDaysOptionLabel', {
      defaultMessage: 'Last {days} days',
      values: { days },
    }),
    checked: filters.patchedWithinDays === String(days) ? 'on' : undefined,
    'data-test-subj': `softwareInventoryPatchedWithinFilter-option-${days}`,
  }));

  return (
    <EuiFlexGroup gutterSize="m" wrap alignItems="center" data-test-subj="softwareInventoryFilters">
      <EuiFlexItem grow={2}>
        <EuiFieldSearch
          fullWidth
          isClearable
          value={filters.search}
          onChange={(e) => set('search', e.target.value)}
          placeholder={i18n.translate('xpack.softwareInventory.filters.searchPlaceholder', {
            defaultMessage: 'Search software or host',
          })}
          aria-label={i18n.translate('xpack.softwareInventory.filters.searchAriaLabel', {
            defaultMessage: 'Search software or host',
          })}
          data-test-subj="softwareInventorySearch"
        />
      </EuiFlexItem>
      <EuiFlexItem grow={false}>
        <EuiFilterGroup>
          <MultiSelectFilter
            title={i18n.translate('xpack.softwareInventory.filters.categoryLabel', {
              defaultMessage: 'Category',
            })}
            labels={CATEGORY_LABELS}
            selected={filters.category}
            onChange={(next) => set('category', next)}
            dataTestSubj="softwareInventoryCategoryFilter"
          />
          <MultiSelectFilter
            title={i18n.translate('xpack.softwareInventory.filters.sourceLabel', {
              defaultMessage: 'Source',
            })}
            labels={SOURCE_LABELS}
            selected={filters.source}
            onChange={(next) => set('source', next)}
            dataTestSubj="softwareInventorySourceFilter"
          />
          <MultiSelectFilter
            title={i18n.translate('xpack.softwareInventory.filters.statusLabel', {
              defaultMessage: 'Status',
            })}
            labels={STATUS_LABELS}
            selected={filters.status}
            onChange={(next) => set('status', next)}
            dataTestSubj="softwareInventoryStatusFilter"
          />
          <MultiSelectFilter
            title={i18n.translate('xpack.softwareInventory.filters.exposureLabel', {
              defaultMessage: 'Exposure level',
            })}
            labels={EXPOSURE_LABELS}
            selected={filters.exposureLevel}
            onChange={(next) => set('exposureLevel', next)}
            dataTestSubj="softwareInventoryExposureFilter"
          />
          <EuiPopover
            aria-label={minCveTitle}
            button={
              <EuiFilterButton
                iconType="chevronSingleDown"
                onClick={() => setIsCvePopoverOpen((open) => !open)}
                isSelected={isCvePopoverOpen}
                hasActiveFilters={filters.minCveCount !== ''}
                data-test-subj="softwareInventoryMinCveFilter"
              >
                {minCveTitle}
              </EuiFilterButton>
            }
            isOpen={isCvePopoverOpen}
            closePopover={() => setIsCvePopoverOpen(false)}
          >
            <EuiFormRow label={minCveTitle}>
              <EuiFieldNumber
                min={0}
                value={filters.minCveCount}
                onChange={(e) => set('minCveCount', e.target.value)}
                data-test-subj="softwareInventoryMinCveInput"
              />
            </EuiFormRow>
          </EuiPopover>
          <EuiPopover
            aria-label={patchedTitle}
            button={
              <EuiFilterButton
                iconType="chevronSingleDown"
                onClick={() => setIsPatchedPopoverOpen((open) => !open)}
                isSelected={isPatchedPopoverOpen}
                hasActiveFilters={filters.patchedWithinDays !== ''}
                data-test-subj="softwareInventoryPatchedWithinFilter"
              >
                {patchedTitle}
              </EuiFilterButton>
            }
            isOpen={isPatchedPopoverOpen}
            closePopover={() => setIsPatchedPopoverOpen(false)}
            panelPaddingSize="none"
          >
            <EuiSelectable
              aria-label={patchedTitle}
              singleSelection="always"
              options={patchedOptions}
              onChange={(next) => {
                const picked = next.find((o) => o.checked === 'on');
                set('patchedWithinDays', picked?.key ?? '');
                setIsPatchedPopoverOpen(false);
              }}
            >
              {(list) => <div style={{ width: 200 }}>{list}</div>}
            </EuiSelectable>
          </EuiPopover>
          <EuiFilterButton
            hasActiveFilters={filters.knownExploited}
            isToggle
            isSelected={filters.knownExploited}
            onClick={() => set('knownExploited', !filters.knownExploited)}
            data-test-subj="softwareInventoryKnownExploitedFilter"
          >
            {i18n.translate('xpack.softwareInventory.filters.knownExploitedLabel', {
              defaultMessage: 'Known exploited',
            })}
          </EuiFilterButton>
          {isPeriodScoped ? (
            <EuiFilterButton
              hasActiveFilters={filters.vulnerableInRange}
              isToggle
              isSelected={filters.vulnerableInRange}
              onClick={() => set('vulnerableInRange', !filters.vulnerableInRange)}
              data-test-subj="softwareInventoryVulnerableInRangeFilter"
            >
              {PERIOD_LABELS.vulnerableDuringPeriod}
            </EuiFilterButton>
          ) : null}
        </EuiFilterGroup>
      </EuiFlexItem>
      {hasActiveFilters(filters) ? (
        <EuiFlexItem grow={false}>
          <EuiButtonEmpty
            size="s"
            iconType="cross"
            onClick={() => onChange(EMPTY_FILTERS)}
            data-test-subj="softwareInventoryClearFilters"
          >
            {i18n.translate('xpack.softwareInventory.filters.clearFiltersButtonLabel', {
              defaultMessage: 'Clear filters',
            })}
          </EuiButtonEmpty>
        </EuiFlexItem>
      ) : null}
    </EuiFlexGroup>
  );
};
