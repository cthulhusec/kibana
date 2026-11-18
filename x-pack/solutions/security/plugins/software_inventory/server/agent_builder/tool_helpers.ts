/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import { ToolResultType } from '@kbn/agent-builder-common/tools/tool_result';
import type { BuiltinSkillBoundedTool } from '@kbn/agent-builder-server/skills';
import type { HasReadAccess } from './access';

const ACCESS_DENIED_MESSAGE =
  'You need the Software inventory read privilege to use this tool. Ask an administrator to grant it.';

export interface SoftwareInventoryToolDeps {
  getEsClient: () => Promise<ElasticsearchClient>;
  hasReadAccess: HasReadAccess;
  logger: Logger;
}

export type ToolHandlerReturn = Awaited<ReturnType<BuiltinSkillBoundedTool['handler']>>;

export const errorResult = (message: string): ToolHandlerReturn => ({
  results: [{ type: ToolResultType.error, data: { message } }],
});

export const dataResult = (data: Record<string, unknown>): ToolHandlerReturn => ({
  results: [{ type: ToolResultType.other, data }],
});

/** Checks the read privilege, then runs the tool; failures become a generic error result. */
export const withGuard = async (
  { hasReadAccess, logger }: SoftwareInventoryToolDeps,
  request: Parameters<HasReadAccess>[0],
  toolName: string,
  run: () => Promise<ToolHandlerReturn>
): Promise<ToolHandlerReturn> => {
  if (!(await hasReadAccess(request))) return errorResult(ACCESS_DENIED_MESSAGE);
  try {
    return await run();
  } catch (error) {
    logger.error(`${toolName} failed: ${error instanceof Error ? error.message : String(error)}`);
    return errorResult('The software inventory query failed. Try again or narrow the filters.');
  }
};
