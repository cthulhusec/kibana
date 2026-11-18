/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

export { ingestCandidates } from './ingest_candidates';
export { markStale } from './mark_stale';
export { normalizeCandidate, normalizeSoftware, cleanVersion } from './normalize_candidate';
export type { NormalizedCandidate, NormalizedSoftware } from './normalize_candidate';
export { buildHostKey, buildInstanceId } from '../../lib/instance_identity';
