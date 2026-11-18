/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import fs from 'fs';
import path from 'path';

// EUI ships no type declaration for its icon map, so load it with an explicit type.
const { typeToPathMap } = jest.requireActual<{ typeToPathMap: Record<string, string> }>(
  '@elastic/eui/lib/components/icon/icon_map'
);
const KNOWN_ICONS: ReadonlySet<string> = new Set(Object.keys(typeToPathMap));
const SOURCE_FILE = /\.tsx?$/;
const TEST_FILE = /\.test\.tsx?$/;
// Matches `iconType="name"`, `euiIconType: 'name'`, `iconType: 'name'`.
const ICON_USAGE = /(?:iconType|euiIconType)\s*[=:]\s*\{?\s*["']([A-Za-z0-9_]+)["']/g;

const listSourceFiles = (dir: string): string[] =>
  fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) return listSourceFiles(fullPath);
    return SOURCE_FILE.test(entry.name) && !TEST_FILE.test(entry.name) ? [fullPath] : [];
  });

describe('icon names', () => {
  it('only uses icon names that exist in the installed EUI version', () => {
    const missing = listSourceFiles(__dirname).flatMap((file) =>
      Array.from(fs.readFileSync(file, 'utf8').matchAll(ICON_USAGE))
        .map((match) => match[1])
        .filter((name) => !KNOWN_ICONS.has(name))
        .map((name) => `${path.relative(__dirname, file)}: ${name}`)
    );

    expect(missing).toEqual([]);
  });

  it('detects a removed icon name (guards the guard)', () => {
    expect(KNOWN_ICONS.has('arrowDown')).toBe(false);
  });
});
