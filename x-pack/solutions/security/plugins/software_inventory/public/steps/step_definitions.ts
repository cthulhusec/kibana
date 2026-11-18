/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createPublicStepDefinition } from '@kbn/workflows-extensions/public';
import {
  enrichCvesStepCommonDefinition,
  ingestCandidatesStepCommonDefinition,
  markStaleStepCommonDefinition,
  scoreExposureStepCommonDefinition,
  snapshotRollupStepCommonDefinition,
} from '../../common/step_definitions';

export const ingestCandidatesPublicStepDefinition = createPublicStepDefinition({
  ...ingestCandidatesStepCommonDefinition,
});
export const enrichCvesPublicStepDefinition = createPublicStepDefinition({
  ...enrichCvesStepCommonDefinition,
});
export const scoreExposurePublicStepDefinition = createPublicStepDefinition({
  ...scoreExposureStepCommonDefinition,
});
export const markStalePublicStepDefinition = createPublicStepDefinition({
  ...markStaleStepCommonDefinition,
});
export const snapshotRollupPublicStepDefinition = createPublicStepDefinition({
  ...snapshotRollupStepCommonDefinition,
});
