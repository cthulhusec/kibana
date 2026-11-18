/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

// Server and scripts only: this module uses node `crypto`, so browser code must not import it.
import { createHash } from 'crypto';
import { normalizeToken } from '../../common/normalize';

/** Prefix of Fleet policy-level pseudo-hosts. They never match a real host. */
export const POLICY_HOST_PREFIX = 'policy:';

/**
 * Canonical host identity shared by every discovery source: the lower-cased host name, or the
 * lower-cased host id when no name is known.
 */
export const buildHostKey = ({ hostName, hostId }: { hostName?: string; hostId: string }): string =>
  (hostName?.trim() || hostId.trim()).toLowerCase();

export const isPolicyHostKey = (hostKey: string): boolean => hostKey.startsWith(POLICY_HOST_PREFIX);

/** Deterministic instance id: sha256 hex of host key, vendor, product, and install path. */
export const buildInstanceId = ({
  hostKey,
  vendor,
  product,
  installPath,
}: {
  hostKey: string;
  vendor: string;
  product: string;
  installPath?: string;
}): string =>
  createHash('sha256')
    .update(
      [hostKey, vendor, product, installPath ?? ''].map((part) => normalizeToken(part)).join('|')
    )
    .digest('hex');
