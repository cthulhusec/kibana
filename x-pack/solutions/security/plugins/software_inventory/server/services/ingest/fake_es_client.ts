/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { elasticsearchServiceMock } from '@kbn/core-elasticsearch-server-mocks';
import type {
  BulkRequest,
  MgetRequest,
  QueryDslQueryContainer,
  SearchRequest,
  UpdateByQueryRequest,
} from '@elastic/elasticsearch/lib/api/types';

type Doc = Record<string, unknown>;
type Store = Map<string, Map<string, Doc>>;

const getPath = (doc: Doc, path: string): unknown =>
  path.split('.').reduce<unknown>((value, key) => {
    if (value === null || typeof value !== 'object') {
      return undefined;
    }
    return (value as Doc)[key];
  }, doc);

const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : [value]);

const matchesClause = (doc: Doc, clause: QueryDslQueryContainer | undefined): boolean => {
  if (!clause) {
    return true;
  }
  if (clause.term) {
    return Object.entries(clause.term).every(([field, expected]) => {
      const value = typeof expected === 'object' && expected !== null ? expected.value : expected;
      return asArray(getPath(doc, field)).includes(value);
    });
  }
  if (clause.terms) {
    return Object.entries(clause.terms).every(([field, expected]) => {
      const values = asArray(getPath(doc, field));
      return Array.isArray(expected) && expected.some((item) => values.includes(item));
    });
  }
  if (clause.range) {
    return Object.entries(clause.range).every(([field, bounds]) => {
      const value = Date.parse(String(getPath(doc, field)));
      const { lt } = bounds as { lt?: string };
      return lt === undefined || value < Date.parse(lt);
    });
  }
  if (clause.bool) {
    const filter = asArray(clause.bool.filter ?? []) as QueryDslQueryContainer[];
    const mustNot = asArray(clause.bool.must_not ?? []) as QueryDslQueryContainer[];
    return (
      filter.every((c) => matchesClause(doc, c)) && !mustNot.some((c) => matchesClause(doc, c))
    );
  }
  throw new Error(`Fake ES does not support query ${JSON.stringify(clause)}`);
};

const indexStore = (store: Store, index: string): Map<string, Doc> => {
  const existing = store.get(index);
  if (existing) {
    return existing;
  }
  const created = new Map<string, Doc>();
  store.set(index, created);
  return created;
};

/**
 * In-memory stand-in for the handful of Elasticsearch APIs the ingest service uses. Supports
 * `term`, `terms`, `range.lt`, and `bool` filter / must_not queries.
 */
export const createFakeEsClient = () => {
  const store: Store = new Map();
  let generatedIds = 0;
  const esClient = elasticsearchServiceMock.createElasticsearchClient();

  esClient.mget.mockImplementation((async ({ index, ids }: MgetRequest) => {
    const docs = indexStore(store, String(index));
    return {
      docs: (ids as string[]).map((id) => {
        const source = docs.get(id);
        return source
          ? { _index: index, _id: id, found: true, _source: structuredClone(source) }
          : { _index: index, _id: id, found: false };
      }),
    };
  }) as never);

  esClient.search.mockImplementation((async ({
    index,
    query,
    size = 10,
    search_after: after,
  }: SearchRequest) => {
    const docs = [...indexStore(store, String(index)).entries()]
      .filter(([, doc]) => (query ? matchesClause(doc, query) : true))
      .sort(([a], [b]) => a.localeCompare(b));
    const start = after ? docs.findIndex(([id]) => id > String(after[0])) : 0;
    const page = start < 0 ? [] : docs.slice(start, start + size);
    return {
      hits: {
        hits: page.map(([id, doc]) => ({
          _index: index,
          _id: id,
          _source: structuredClone(doc),
          sort: [id],
        })),
      },
    };
  }) as never);

  esClient.bulk.mockImplementation((async ({ operations = [] }: BulkRequest) => {
    const items: Array<Record<string, { _id: string; status: number; error?: { type: string } }>> =
      [];
    for (let i = 0; i < operations.length; i += 2) {
      const action = operations[i] as Record<string, { _index: string; _id?: string }>;
      const body = operations[i + 1] as Doc;
      const [type, { _index: index, _id: requestedId }] = Object.entries(action)[0];
      generatedIds += 1;
      const id = requestedId ?? `generated-${generatedIds}`;
      const docs = indexStore(store, index);
      if (type === 'create' && docs.has(id)) {
        items.push({
          create: { _id: id, status: 409, error: { type: 'version_conflict_engine_exception' } },
        });
      } else if (type === 'update') {
        docs.set(id, { ...(docs.get(id) ?? {}), ...(body.doc as Doc) });
        items.push({ update: { _id: id, status: 200 } });
      } else {
        docs.set(id, structuredClone(body));
        items.push({ [type]: { _id: id, status: 201 } });
      }
    }
    return { errors: items.some((item) => Object.values(item)[0].error), items, took: 1 };
  }) as never);

  esClient.updateByQuery.mockImplementation((async ({
    index,
    query,
    script,
  }: UpdateByQueryRequest) => {
    const scriptParams =
      typeof script === 'object' && 'params' in script ? script.params : undefined;
    const params = { status: scriptParams?.status, now: scriptParams?.now };
    let updated = 0;
    for (const [id, doc] of indexStore(store, String(index))) {
      if (!query || matchesClause(doc, query)) {
        indexStore(store, String(index)).set(id, {
          ...doc,
          status: params.status,
          '@timestamp': params.now,
        });
        updated += 1;
      }
    }
    return { updated };
  }) as never);

  return {
    esClient,
    getDoc: <T>(index: string, id: string): T | undefined =>
      indexStore(store, index).get(id) as T | undefined,
    getAll: <T>(index: string): T[] => [...indexStore(store, index).values()] as T[],
    putDoc: (index: string, id: string, doc: object): void => {
      indexStore(store, index).set(id, structuredClone(doc) as Doc);
    },
  };
};
