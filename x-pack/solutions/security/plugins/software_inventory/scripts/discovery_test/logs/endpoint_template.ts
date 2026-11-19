/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Data stream and template for the synthetic Elastic Defend process events that `discover-endpoint`
 * reads (see the DE section of docs/discovery_test_plan.md). The data stream name matches the
 * workflow's `logs-endpoint.events.process-*` pattern.
 *
 * When the Endpoint package template (`logs-endpoint.events.process`) is installed, the data stream
 * uses its real mappings. Otherwise the harness installs a minimal template with a higher priority
 * that maps only the fields the workflow reads. The harness only ever deletes the template it
 * names here, so the Endpoint package template is never touched.
 */

import type { EsClient } from '../clients';

export const ENDPOINT_DATA_STREAM = 'logs-endpoint.events.process-sisynthetic';
export const ENDPOINT_PATTERN = 'logs-endpoint.events.process-*';
export const ENDPOINT_TEMPLATE_NAME = 'logs-softwareinventory.endpoint-synthetic';
/** Name of the template the Endpoint package installs. */
export const ENDPOINT_PACKAGE_TEMPLATE_NAME = 'logs-endpoint.events.process';
export const ENDPOINT_DATASET = 'endpoint.events.process';

const keyword = { type: 'keyword' } as const;

export const ENDPOINT_TEMPLATE = {
  index_patterns: [`${ENDPOINT_DATA_STREAM}*`],
  priority: 300,
  data_stream: {},
  composed_of: ['logs@mappings', 'logs@settings', 'ecs@mappings'],
  template: {
    mappings: {
      properties: {
        host: { properties: { id: keyword, name: keyword } },
        process: {
          properties: {
            executable: keyword,
            name: keyword,
            pe: { properties: { company: keyword, product: keyword, file_version: keyword } },
            code_signature: { properties: { subject_name: keyword } },
          },
        },
        event: { properties: { dataset: keyword, action: keyword } },
      },
    },
  },
} as const;

/** Names of every data stream that matches the workflow's `logs-endpoint.events.process-*`. */
export const listEndpointDataStreams = async (es: EsClient): Promise<string[]> => {
  const { body } = await es.request<{ data_streams?: Array<{ name: string }> }>(
    'GET',
    `/_data_stream/${ENDPOINT_PATTERN}`,
    { allowStatuses: [404] }
  );
  return (body?.data_streams ?? []).map(({ name }) => name);
};

/**
 * Creates the data stream when missing. Installs the minimal template only when the Endpoint
 * package template is absent.
 */
export const ensureEndpointDataStream = async (
  es: EsClient
): Promise<{
  templateCreated: boolean;
  dataStreamCreated: boolean;
  usedPackageTemplate: boolean;
}> => {
  const usedPackageTemplate = await es.exists(`/_index_template/${ENDPOINT_PACKAGE_TEMPLATE_NAME}`);
  let templateCreated = false;
  if (!usedPackageTemplate) {
    templateCreated = !(await es.exists(`/_index_template/${ENDPOINT_TEMPLATE_NAME}`));
    await es.request('PUT', `/_index_template/${ENDPOINT_TEMPLATE_NAME}`, {
      body: ENDPOINT_TEMPLATE,
    });
  }
  const dataStreamCreated = !(await es.exists(`/_data_stream/${ENDPOINT_DATA_STREAM}`));
  if (dataStreamCreated) {
    await es.request('PUT', `/_data_stream/${ENDPOINT_DATA_STREAM}`);
  }
  return { templateCreated, dataStreamCreated, usedPackageTemplate };
};

/** Deletes the data stream, then the harness template; both are optional (idempotent). */
export const deleteEndpointDataStream = async (
  es: EsClient
): Promise<{ dataStreamDeleted: boolean; templateDeleted: boolean }> => {
  const ds = await es.request('DELETE', `/_data_stream/${ENDPOINT_DATA_STREAM}`, {
    allowStatuses: [404],
  });
  const template = await es.request('DELETE', `/_index_template/${ENDPOINT_TEMPLATE_NAME}`, {
    allowStatuses: [404],
  });
  return { dataStreamDeleted: ds.status !== 404, templateDeleted: template.status !== 404 };
};
