/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Removes everything the harness creates, and only that:
 * - instances and events whose `host.key` is synthetic (`synth-`, `policy:synth-`, TEST-NET IPs);
 * - catalog entries that only synthetic data uses: invented `synth-` vendors or products, the
 *   catalog ids the fixtures produce, and ids referenced by synthetic instances. An id referenced
 *   by any non-synthetic instance or present in the demo seed is never deleted;
 * - unless `syntheticOnly`: the synthetic logs data stream and template, and `si-test-*` workflows.
 * Every step is idempotent and reports a count. Demo documents that `enrich-cves` or
 * `score-exposure` modified are restored by `restore` (the demo seed with `--clean`), not here.
 */

import { CATALOG_INDEX, EVENTS_INDEX, INSTANCES_INDEX } from '../../common/constants';
import type { InstanceDoc } from '../../common/types';
import { generateSeedData } from '../seed/generate_seed_data';
import type { EsClient, KibanaClient } from './clients';
import { R1, R2_LINUX, ALL_OSQUERY_FIXTURES } from './fixtures/osquery';
import { ALL_FLEET_FIXTURES } from './fixtures/fleet';
import { EXPECTED_PHASE_A_CANDIDATES, EXPECTED_PHASE_B_CANDIDATE } from './logs/generate_logs';
import {
  SYNTHETIC_DATA_STREAM,
  SYNTHETIC_TEMPLATE_NAME,
  deleteSyntheticDataStream,
} from './logs/template';
import {
  SYNTHETIC_CATALOG_TOKEN_PREFIX,
  SYNTHETIC_EXACT_HOST_KEYS,
  SYNTHETIC_HOST_KEY_PREFIXES,
  TEST_WORKFLOW_ID_PREFIX,
} from './ids';

const PAGE_SIZE = 1000;
const TERMS_CHUNK = 10_000;

/** Matches documents (instances, events) with a synthetic `host.key`. */
export const syntheticHostKeyQuery = () => ({
  bool: {
    should: [
      ...SYNTHETIC_HOST_KEY_PREFIXES.map((prefix) => ({ prefix: { 'host.key': prefix } })),
      { terms: { 'host.key': [...SYNTHETIC_EXACT_HOST_KEYS] } },
    ],
    minimum_should_match: 1,
  },
});

/** Matches catalog entries with an invented `synth-` vendor or product. */
export const syntheticCatalogTokenQuery = () => ({
  bool: {
    should: [
      { prefix: { vendor: SYNTHETIC_CATALOG_TOKEN_PREFIX } },
      { prefix: { product: SYNTHETIC_CATALOG_TOKEN_PREFIX } },
    ],
    minimum_should_match: 1,
  },
});

/** Catalog ids the fixtures and synthetic logs produce (real product names included). */
export const KNOWN_SYNTHETIC_CATALOG_IDS: readonly string[] = [
  ...new Set([
    ...Object.values(R1).flatMap((fixture) => fixture.expected.catalogIds ?? []),
    ...(R2_LINUX.expected.catalogIds ?? []),
    ...ALL_OSQUERY_FIXTURES.flatMap((fixture) => fixture.expected.catalogIds ?? []),
    ...ALL_FLEET_FIXTURES.flatMap((fixture) => fixture.expected.instances.map((i) => i.catalogId)),
    ...EXPECTED_PHASE_A_CANDIDATES.map((candidate) => candidate.catalogId),
    EXPECTED_PHASE_B_CANDIDATE.catalogId,
  ]),
].sort();

/** Every catalog id an instance references (current, previous, and history). */
export const collectSoftwareIds = (
  doc: Pick<InstanceDoc, 'software_id' | 'previous_software_id' | 'version_history'>
): string[] => [
  doc.software_id,
  ...(doc.previous_software_id ? [doc.previous_software_id] : []),
  ...(doc.version_history ?? []).flatMap((item) => (item.software_id ? [item.software_id] : [])),
];

/** Pure: candidate ids minus protected ids, deduplicated and sorted. */
export const selectCatalogIdsToDelete = ({
  candidates,
  protectedIds,
}: {
  candidates: Iterable<string>;
  protectedIds: Iterable<string>;
}): string[] => {
  const keep = new Set(protectedIds);
  return [...new Set(candidates)].filter((id) => !keep.has(id)).sort();
};

export const seedCatalogIds = (): string[] =>
  generateSeedData(new Date()).catalog.map(({ id }) => id);

const chunk = <T>(items: readonly T[], size: number): T[][] =>
  Array.from({ length: Math.ceil(items.length / size) }, (_, index) =>
    items.slice(index * size, (index + 1) * size)
  );

type SoftwareIdFields = Pick<
  InstanceDoc,
  'software_id' | 'previous_software_id' | 'version_history'
>;

/** Catalog ids referenced by the instances that match `query`, paging with `search_after`. */
const referencedSoftwareIds = async (es: EsClient, query: object): Promise<Set<string>> => {
  const ids = new Set<string>();
  let searchAfter: Array<string | number> | undefined;
  for (;;) {
    const page = await es.search<SoftwareIdFields>(INSTANCES_INDEX, {
      size: PAGE_SIZE,
      query,
      sort: [{ id: 'asc' }],
      _source: ['software_id', 'previous_software_id', 'version_history.software_id'],
      ...(searchAfter ? { search_after: searchAfter } : {}),
    });
    const { hits } = page.hits;
    if (hits.length === 0) return ids;
    for (const hit of hits) {
      if (hit._source) collectSoftwareIds(hit._source).forEach((id) => ids.add(id));
    }
    searchAfter = hits[hits.length - 1].sort;
    if (!searchAfter || hits.length < PAGE_SIZE) return ids;
  }
};

const idsMatching = async (es: EsClient, index: string, query: object): Promise<string[]> => {
  const ids: string[] = [];
  let searchAfter: Array<string | number> | undefined;
  for (;;) {
    const page = await es.search<{ id: string }>(index, {
      size: PAGE_SIZE,
      query,
      sort: [{ id: 'asc' }],
      _source: ['id'],
      ...(searchAfter ? { search_after: searchAfter } : {}),
    });
    const { hits } = page.hits;
    hits.forEach((hit) => ids.push(hit._id));
    searchAfter = hits[hits.length - 1]?.sort;
    if (!searchAfter || hits.length < PAGE_SIZE) return ids;
  }
};

/** Catalog ids that cleanup would delete right now (read-only). */
export const planCatalogDeletion = async (es: EsClient): Promise<string[]> => {
  const nonSyntheticQuery = { bool: { must_not: [syntheticHostKeyQuery()] } };
  const [bySynthetic, byOthers, tokenMatches] = await Promise.all([
    referencedSoftwareIds(es, syntheticHostKeyQuery()),
    referencedSoftwareIds(es, nonSyntheticQuery),
    idsMatching(es, CATALOG_INDEX, syntheticCatalogTokenQuery()),
  ]);
  const existingKnown = await idsMatching(es, CATALOG_INDEX, {
    terms: { id: [...KNOWN_SYNTHETIC_CATALOG_IDS] },
  });
  return selectCatalogIdsToDelete({
    candidates: [...tokenMatches, ...existingKnown, ...bySynthetic],
    protectedIds: [...byOthers, ...seedCatalogIds()],
  });
};

/** All `si-test-*` saved workflows (paged). */
export const listTestWorkflowIds = async (kibana: KibanaClient): Promise<string[]> => {
  const ids: string[] = [];
  for (let page = 1; ; page++) {
    const { results, total } = await kibana.listWorkflows({ page, size: 100 });
    results
      .filter(({ id }) => id.startsWith(TEST_WORKFLOW_ID_PREFIX))
      .forEach(({ id }) => ids.push(id));
    if (results.length === 0 || page * 100 >= total) return ids;
  }
};

export interface CleanupReport {
  readonly instancesDeleted: number;
  readonly eventsDeleted: number;
  readonly catalogDeleted: number;
  readonly dataStreamDeleted?: boolean;
  readonly templateDeleted?: boolean;
  readonly workflowsDeleted?: readonly string[];
}

export const cleanup = async (
  es: EsClient,
  kibana: KibanaClient,
  { syntheticOnly }: { syntheticOnly: boolean }
): Promise<CleanupReport> => {
  // Plan catalog deletions before the instances that reference them are gone.
  const catalogIds = await planCatalogDeletion(es);
  const instancesDeleted = await es.deleteByQuery(INSTANCES_INDEX, syntheticHostKeyQuery());
  const eventsDeleted = await es.deleteByQuery(EVENTS_INDEX, syntheticHostKeyQuery());
  let catalogDeleted = 0;
  for (const ids of chunk(catalogIds, TERMS_CHUNK)) {
    catalogDeleted += await es.deleteByQuery(CATALOG_INDEX, { terms: { id: ids } });
  }
  if (syntheticOnly) return { instancesDeleted, eventsDeleted, catalogDeleted };

  const { dataStreamDeleted, templateDeleted } = await deleteSyntheticDataStream(es);
  const workflowIds = await listTestWorkflowIds(kibana);
  for (const id of workflowIds) await kibana.deleteWorkflow(id, { force: true });
  return {
    instancesDeleted,
    eventsDeleted,
    catalogDeleted,
    dataStreamDeleted,
    templateDeleted,
    workflowsDeleted: workflowIds,
  };
};

export interface ResidueReport {
  readonly syntheticInstances: number;
  readonly syntheticEvents: number;
  readonly syntheticCatalogIds: readonly string[];
  readonly dataStreamExists: boolean;
  readonly templateExists: boolean;
  readonly testWorkflows: readonly string[];
}

/** Read-only: what cleanup would still remove (RG-3 and RG-6 use this). */
export const findSyntheticResidue = async (
  es: EsClient,
  kibana: KibanaClient
): Promise<ResidueReport> => {
  const [
    syntheticInstances,
    syntheticEvents,
    syntheticCatalogIds,
    dataStreamExists,
    templateExists,
    testWorkflows,
  ] = await Promise.all([
    es.count(INSTANCES_INDEX, syntheticHostKeyQuery()),
    es.count(EVENTS_INDEX, syntheticHostKeyQuery()),
    planCatalogDeletion(es),
    es.exists(`/_data_stream/${SYNTHETIC_DATA_STREAM}`),
    es.exists(`/_index_template/${SYNTHETIC_TEMPLATE_NAME}`),
    listTestWorkflowIds(kibana),
  ]);
  return {
    syntheticInstances,
    syntheticEvents,
    syntheticCatalogIds,
    dataStreamExists,
    templateExists,
    testWorkflows,
  };
};

export const isResidueEmpty = (residue: ResidueReport): boolean =>
  residue.syntheticInstances === 0 &&
  residue.syntheticEvents === 0 &&
  residue.syntheticCatalogIds.length === 0 &&
  !residue.dataStreamExists &&
  !residue.templateExists &&
  residue.testWorkflows.length === 0;
