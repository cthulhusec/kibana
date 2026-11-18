/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Index template and data stream for the synthetic logs (see "Data stream and mappings" in
 * docs/discovery_test_plan.md). The template maps every field the workflows read, so ES|QL never
 * fails with `Unknown column` even when no document carries a field.
 */

import type { EsClient, JsonObject } from '../clients';

export const SYNTHETIC_TEMPLATE_NAME = 'logs-softwareinventory.synthetic';
export const SYNTHETIC_DATA_STREAM = 'logs-softwareinventory.synthetic-default';
export const SYNTHETIC_DATASET = 'softwareinventory.synthetic';

export const SYNTHETIC_TEMPLATE = {
  index_patterns: ['logs-softwareinventory.synthetic-*'],
  priority: 200,
  data_stream: {},
  composed_of: ['logs@mappings', 'logs@settings', 'ecs@mappings'],
  template: {
    mappings: {
      properties: {
        host: { properties: { id: { type: 'keyword' }, name: { type: 'keyword' } } },
        observer: {
          properties: {
            hostname: { type: 'keyword' },
            serial_number: { type: 'keyword' },
            ip: { type: 'ip' },
            vendor: { type: 'keyword' },
            product: { type: 'keyword' },
            version: { type: 'keyword' },
          },
        },
        service: { properties: { name: { type: 'keyword' }, version: { type: 'keyword' } } },
        source: { properties: { ip: { type: 'ip' } } },
        network: { properties: { direction: { type: 'keyword' } } },
        event: { properties: { dataset: { type: 'keyword' } } },
      },
    },
  },
} as const;

/** Fields the template must map; checked against `_simulate_index` output. */
export const REQUIRED_MAPPED_FIELDS = [
  'host.id',
  'host.name',
  'observer.hostname',
  'observer.serial_number',
  'observer.ip',
  'observer.vendor',
  'observer.product',
  'observer.version',
  'service.name',
  'service.version',
  'source.ip',
  'network.direction',
] as const;

export interface TemplateSimulation {
  readonly indexMode?: string;
  readonly missingFields: readonly string[];
}

interface MappingNode {
  type?: string;
  properties?: Record<string, MappingNode>;
}

const hasField = (properties: Record<string, MappingNode> | undefined, path: string): boolean => {
  const [head, ...rest] = path.split('.');
  const node = properties?.[head];
  if (!node) return false;
  return rest.length === 0 ? true : hasField(node.properties, rest.join('.'));
};

/** Pure part of the read-only simulation check; exported for tests. */
export const evaluateSimulation = (response: JsonObject): TemplateSimulation => {
  const template = response.template as {
    settings?: { index?: { mode?: string } };
    mappings?: { properties?: Record<string, MappingNode> };
  };
  return {
    indexMode: template?.settings?.index?.mode,
    missingFields: REQUIRED_MAPPED_FIELDS.filter(
      (field) => !hasField(template?.mappings?.properties, field)
    ),
  };
};

/**
 * Read-only: simulates the data stream's settings and mappings as if the template were installed
 * (`POST _index_template/_simulate_index/<name>` with the template as body).
 */
export const simulateTemplate = async (es: EsClient): Promise<TemplateSimulation> => {
  const { body } = await es.request<JsonObject>(
    'POST',
    `/_index_template/_simulate_index/${SYNTHETIC_DATA_STREAM}`,
    { body: SYNTHETIC_TEMPLATE }
  );
  return evaluateSimulation(body);
};

/** Writes the template (idempotent) and creates the data stream when missing. */
export const ensureSyntheticDataStream = async (
  es: EsClient
): Promise<{ templateCreated: boolean; dataStreamCreated: boolean }> => {
  const templateExisted = await es.exists(`/_index_template/${SYNTHETIC_TEMPLATE_NAME}`);
  await es.request('PUT', `/_index_template/${SYNTHETIC_TEMPLATE_NAME}`, {
    body: SYNTHETIC_TEMPLATE,
  });
  const dataStreamExisted = await es.exists(`/_data_stream/${SYNTHETIC_DATA_STREAM}`);
  if (!dataStreamExisted) {
    await es.request('PUT', `/_data_stream/${SYNTHETIC_DATA_STREAM}`);
  }
  return { templateCreated: !templateExisted, dataStreamCreated: !dataStreamExisted };
};

/** Deletes the data stream and then the template; both are optional (idempotent). */
export const deleteSyntheticDataStream = async (
  es: EsClient
): Promise<{ dataStreamDeleted: boolean; templateDeleted: boolean }> => {
  const ds = await es.request('DELETE', `/_data_stream/${SYNTHETIC_DATA_STREAM}`, {
    allowStatuses: [404],
  });
  const template = await es.request('DELETE', `/_index_template/${SYNTHETIC_TEMPLATE_NAME}`, {
    allowStatuses: [404],
  });
  return { dataStreamDeleted: ds.status !== 404, templateDeleted: template.status !== 404 };
};
