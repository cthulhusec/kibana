/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Logger } from '@kbn/logging';
import { DEFAULT_SPACE_ID } from '@kbn/core-spaces-common';
import type { WorkflowsExtensionsServerPluginStart } from '@kbn/workflows-extensions/server';
import { MANAGED_WORKFLOW_OWNER_ID, WORKFLOW_IDS } from '../../../common/constants';

const errorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

/**
 * Installs the global software inventory workflows in one `_bulk` pass, then lets Workflows
 * reconcile orphans. Reconciliation is skipped when any install failed, so a partial boot never
 * deletes workflows that were installed earlier.
 */
export const installManagedWorkflows = async ({
  workflowsExtensions,
  logger,
}: {
  workflowsExtensions: WorkflowsExtensionsServerPluginStart;
  logger: Logger;
}): Promise<void> => {
  const client = await workflowsExtensions.initManagedWorkflowsClient(MANAGED_WORKFLOW_OWNER_ID);
  let canReconcile = true;
  try {
    // Installed in the default space, not the global space: the workflows scheduler skips
    // scheduled triggers on global workflows (elastic/security-team#17380), so global installs
    // would never run. The POC therefore runs in the default space only.
    const { failed } = await client.installMany(
      Object.values(WORKFLOW_IDS).map((id) => ({ id, spaceId: DEFAULT_SPACE_ID }))
    );
    for (const { id, error } of failed) {
      canReconcile = false;
      logger.error(
        `Failed to install managed software inventory workflow "${id}": ${error.message}`
      );
    }
  } catch (error) {
    canReconcile = false;
    logger.error(`Failed to install managed software inventory workflows: ${errorMessage(error)}`);
  }

  if (!canReconcile) {
    logger.warn('Software inventory managed workflow reconciliation skipped after failed installs');
    return;
  }
  try {
    await client.ready();
    logger.info('Software inventory managed workflows initialized');
  } catch (error) {
    logger.warn(
      `Software inventory managed workflow reconciliation failed: ${errorMessage(error)}`
    );
  }
};
