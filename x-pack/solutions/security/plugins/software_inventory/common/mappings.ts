/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { MappingTypeMapping } from '@elastic/elasticsearch/lib/api/types';

export const CATALOG_MAPPINGS: MappingTypeMapping = {
  dynamic: 'strict',
  properties: {
    '@timestamp': { type: 'date' },
    id: { type: 'keyword' },
    vendor: { type: 'keyword' },
    product: { type: 'keyword' },
    version: { type: 'keyword' },
    display_name: { type: 'keyword', fields: { text: { type: 'text' } } },
    category: { type: 'keyword' },
    cpe: { type: 'keyword' },
    cpe_match_confidence: { type: 'float' },
    cve_count: { type: 'integer' },
    max_cvss: { type: 'float' },
    known_exploited: { type: 'boolean' },
    fixed_in: { type: 'keyword' },
    latest_known_fix: { type: 'keyword' },
    fully_remediated: { type: 'boolean' },
    unfixed_cve_ids: { type: 'keyword' },
    remediation_caveat: { type: 'keyword' },
    cve_details: {
      type: 'nested',
      properties: {
        id: { type: 'keyword' },
        cvss: { type: 'float' },
        published: { type: 'date' },
        fixed_in: { type: 'keyword' },
        known_exploited: { type: 'boolean' },
      },
    },
    first_published: { type: 'date' },
    cve_ids: { type: 'keyword' },
    cve_checked_at: { type: 'date' },
    cve_check_failed: { type: 'boolean' },
  },
};

export const INSTANCES_MAPPINGS: MappingTypeMapping = {
  dynamic: 'strict',
  properties: {
    '@timestamp': { type: 'date' },
    id: { type: 'keyword' },
    host: {
      properties: {
        key: { type: 'keyword' },
        id: { type: 'keyword' },
        name: { type: 'keyword' },
      },
    },
    software_id: { type: 'keyword' },
    previous_software_id: { type: 'keyword' },
    version_changed_at: { type: 'date' },
    version_history: {
      // Nested so a query can correlate software_id with first_seen/last_seen of ONE entry.
      type: 'nested',
      properties: {
        version: { type: 'keyword' },
        software_id: { type: 'keyword' },
        first_seen: { type: 'date' },
        last_seen: { type: 'date' },
      },
    },
    install_path: { type: 'keyword' },
    sources: { type: 'keyword' },
    status: { type: 'keyword' },
    first_seen: { type: 'date' },
    last_seen: { type: 'date' },
    exposure: {
      properties: {
        level: { type: 'keyword' },
        score: { type: 'integer' },
        evidence: {
          type: 'object',
          properties: {
            signal: { type: 'keyword' },
            detail: { type: 'keyword' },
            weight: { type: 'float' },
          },
        },
      },
    },
  },
};

export const EVENTS_MAPPINGS: MappingTypeMapping = {
  dynamic: 'strict',
  properties: {
    '@timestamp': { type: 'date' },
    instance_id: { type: 'keyword' },
    host: {
      properties: {
        key: { type: 'keyword' },
        id: { type: 'keyword' },
        name: { type: 'keyword' },
      },
    },
    type: { type: 'keyword' },
    source: { type: 'keyword' },
    software_id: { type: 'keyword' },
    previous_software_id: { type: 'keyword' },
    from_version: { type: 'keyword' },
    to_version: { type: 'keyword' },
    cve_count_before: { type: 'integer' },
    cve_count_after: { type: 'integer' },
    max_cvss_before: { type: 'float' },
    max_cvss_after: { type: 'float' },
    known_exploited_before: { type: 'boolean' },
    known_exploited_after: { type: 'boolean' },
  },
};

export const ROLLUPS_MAPPINGS: MappingTypeMapping = {
  dynamic: 'strict',
  properties: {
    '@timestamp': { type: 'date' },
    total_instances: { type: 'integer' },
    total_software: { type: 'integer' },
    vulnerable_instances: { type: 'integer' },
    critical_instances: { type: 'integer' },
    high_instances: { type: 'integer' },
    exposed_instances: { type: 'integer' },
    known_exploited_instances: { type: 'integer' },
    exposed_and_vulnerable_instances: { type: 'integer' },
    new_instances: { type: 'integer' },
    patched_instances: { type: 'integer' },
    removed_instances: { type: 'integer' },
    categories: {
      properties: {
        application: { type: 'integer' },
        dependency: { type: 'integer' },
        appliance: { type: 'integer' },
        os_package: { type: 'integer' },
        other: { type: 'integer' },
      },
    },
  },
};
