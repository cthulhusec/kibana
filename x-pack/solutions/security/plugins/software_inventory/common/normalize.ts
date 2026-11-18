/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Lower-case, trim, collapse whitespace/punctuation runs to a single underscore. Hyphens are kept,
 * because NVD CPE names use them (`7-zip`, `pan-os`).
 */
export const normalizeToken = (value: string): string =>
  value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9.+-]+/g, '_')
    .replace(/_*-_*/g, '-')
    .replace(/^[_-]+|[_-]+$/g, '');

export const buildCatalogId = (vendor: string, product: string, version: string): string =>
  `${normalizeToken(vendor)}:${normalizeToken(product)}:${normalizeToken(version)}`;
