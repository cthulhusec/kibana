/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export const PLUGIN_ID = 'softwareInventory' as const;
export const PLUGIN_NAME = 'Software inventory';
export const APP_PATH = '/software_inventory';
export const EXPERIMENTAL_FLAG = 'softwareInventoryEnabled' as const;

export const API_BASE = '/internal/software_inventory' as const;
export const API_VERSION = '1' as const;
export const INSTANCES_URL = `${API_BASE}/instances` as const;
export const SUMMARY_URL = `${API_BASE}/summary` as const;
export const CATALOG_DETAIL_URL = `${API_BASE}/catalog/{id}` as const;
export const TRENDS_URL = `${API_BASE}/trends` as const;
export const HOST_TIMELINE_URL = `${API_BASE}/hosts/{host_key}/timeline` as const;

/**
 * Plain (non-data-stream) indices; the plugin creates them at start. The `.kibana-` prefix matches
 * the pattern the `kibana_system` internal user is already granted access to.
 */
export const CATALOG_INDEX = '.kibana-software-inventory-catalog' as const;
export const INSTANCES_INDEX = '.kibana-software-inventory-instances' as const;
/** Append-only log of instance state transitions (see `InventoryEvent`). */
export const EVENTS_INDEX = '.kibana-software-inventory-events' as const;
/** One document per UTC day of inventory counts (see `DailyRollup`). Document id = `YYYY-MM-DD`. */
export const ROLLUPS_INDEX = '.kibana-software-inventory-rollups' as const;

/** Owner id for managed workflows registered by this plugin. */
export const MANAGED_WORKFLOW_OWNER_ID = 'softwareInventory' as const;

/** Custom workflow step ids implemented in server code. Workflow YAML only calls these. */
export const STEP_INGEST_CANDIDATES = 'softwareInventory.ingestCandidates' as const;
export const STEP_ENRICH_CVES = 'softwareInventory.enrichCves' as const;
export const STEP_SCORE_EXPOSURE = 'softwareInventory.scoreExposure' as const;
export const STEP_MARK_STALE = 'softwareInventory.markStale' as const;
/** Writes (or overwrites) today's `DailyRollup`; idempotent per UTC day. */
export const STEP_SNAPSHOT_ROLLUP = 'softwareInventory.snapshotRollup' as const;

/** Managed workflow ids (definitions live in kbn-workflows/managed/definitions/software_inventory). */
export const WORKFLOW_IDS = {
  discoverOsquery: 'system-security-software-inventory-discover-osquery',
  discoverIntegrations: 'system-security-software-inventory-discover-integrations',
  discoverLogs: 'system-security-software-inventory-discover-logs',
  enrichCves: 'system-security-software-inventory-enrich-cves',
  scoreExposure: 'system-security-software-inventory-score-exposure',
} as const;

export const DEFAULT_STALE_AFTER_DAYS = 30;
export const MAX_PAGE_SIZE = 100;
export const MAX_CANDIDATES_PER_CALL = 5000;

/** Longest `from`..`to` range the history routes accept. */
export const MAX_HISTORY_RANGE_DAYS = 366;

/**
 * Precision threshold for `cardinality` aggregations that count distinct software. Counts below it
 * are close to exact; the Elasticsearch maximum is 40000. The default of 3000 reported 5124 for
 * 5060 distinct versions, so a larger inventory's totals would drift.
 */
export const CARDINALITY_PRECISION_THRESHOLD = 40000;
