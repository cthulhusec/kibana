/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { WorkflowsExtensionsPublicPluginSetup } from '@kbn/workflows-extensions/public';

const loadDefinitions = () => import('./step_definitions');

/**
 * Registers the editor-side definitions of the software inventory steps. Loaders keep the zod
 * schemas out of the page-load bundle.
 */
export const registerSoftwareInventoryPublicSteps = (
  workflowsExtensions: WorkflowsExtensionsPublicPluginSetup
): void => {
  workflowsExtensions.registerStepDefinition(() =>
    loadDefinitions().then((m) => m.ingestCandidatesPublicStepDefinition)
  );
  workflowsExtensions.registerStepDefinition(() =>
    loadDefinitions().then((m) => m.enrichCvesPublicStepDefinition)
  );
  workflowsExtensions.registerStepDefinition(() =>
    loadDefinitions().then((m) => m.scoreExposurePublicStepDefinition)
  );
  workflowsExtensions.registerStepDefinition(() =>
    loadDefinitions().then((m) => m.markStalePublicStepDefinition)
  );
  workflowsExtensions.registerStepDefinition(() =>
    loadDefinitions().then((m) => m.snapshotRollupPublicStepDefinition)
  );
};
