/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { elasticsearchServiceMock, httpServerMock } from '@kbn/core/server/mocks';
import { loggingSystemMock } from '@kbn/core/server/mocks';
import type { ToolHandlerReturn } from '@kbn/agent-builder-server';
import { ToolResultType } from '@kbn/agent-builder-common/tools/tool_result';
import {
  createBuildHuntQueriesTool,
  createFindInstancesTool,
  createSoftwareDetailTool,
  createSummaryTool,
} from './tools';
import { createHasReadAccess } from './access';
import { createSoftwareInventorySkill } from './software_inventory_skill';

const hits = (docs: unknown[], total = docs.length) =>
  ({
    hits: { total: { value: total, relation: 'eq' }, hits: docs.map((_source) => ({ _source })) },
  } as never);

/** Returns the `data` payload of the first result of a standard tool response. */
const firstResultData = (out: ToolHandlerReturn): Record<string, unknown> => {
  if (!('results' in out)) {
    throw new Error('Expected a standard tool response');
  }
  return Object.fromEntries<unknown>(Object.entries(out.results[0].data));
};

const setup = (allowed = true) => {
  const es = elasticsearchServiceMock.createElasticsearchClient();
  const hasReadAccess = jest.fn().mockResolvedValue(allowed);
  const deps = {
    getEsClient: jest.fn().mockResolvedValue(es),
    hasReadAccess,
    logger: loggingSystemMock.createLogger(),
  };
  const context = { request: httpServerMock.createKibanaRequest() } as never;
  return { es, deps, context, hasReadAccess };
};

const entry = {
  id: 's1',
  vendor: 'f5',
  product: 'nginx',
  version: '1.2',
  category: 'application',
  cve_count: 2,
  known_exploited: true,
  cve_ids: ['CVE-1'],
};
const instance = {
  id: 'i1',
  host: { id: 'h1', name: 'web-1' },
  software_id: 's1',
  status: 'active',
  last_seen: '2026-01-01T00:00:00.000Z',
  exposure: { level: 'high', score: 80, evidence: [] },
};

describe('software inventory tools', () => {
  it('find_instances returns compact rows and always excludes removed instances', async () => {
    const { es, deps, context } = setup();
    es.search
      .mockResolvedValueOnce(hits([{ id: 's1' }]))
      .mockResolvedValueOnce(hits([instance], 30))
      .mockResolvedValueOnce(hits([entry]));

    const tool = createFindInstancesTool(deps);
    const out = await tool.handler({ product: 'nginx', version: '1.2', per_page: 1 }, context);

    expect(es.search.mock.calls[1][0]).toMatchObject({ size: 1 });
    expect(JSON.stringify(es.search.mock.calls[1][0])).toContain('"active","patched","stale"');
    const [result] = (out as { results: Array<{ type: string; data: Record<string, unknown> }> })
      .results;
    expect(result.type).toBe(ToolResultType.other);
    expect(result.data).toMatchObject({ total: 30, returned: 1, truncated: true });
    expect((result.data.items as Array<Record<string, unknown>>)[0]).toMatchObject({
      host: 'web-1',
      product: 'nginx',
      version: '1.2',
      exposure_level: 'high',
      known_exploited: true,
    });
  });

  it('refuses every tool without the read privilege and never touches Elasticsearch', async () => {
    const { es, deps, context } = setup(false);
    const calls = [
      createFindInstancesTool(deps).handler({}, context),
      createSummaryTool(deps).handler({}, context),
      createSoftwareDetailTool(deps).handler({ software_id: 's1' }, context),
      createBuildHuntQueriesTool(deps).handler({ software_id: 's1' }, context),
    ];
    for (const out of await Promise.all(calls)) {
      expect((out as { results: Array<{ type: string }> }).results[0].type).toBe(
        ToolResultType.error
      );
    }
    expect(es.search).not.toHaveBeenCalled();
    expect(deps.getEsClient).not.toHaveBeenCalled();
  });

  it('returns an error result instead of throwing when Elasticsearch fails', async () => {
    const { es, deps, context } = setup();
    es.search.mockRejectedValue(new Error('boom .kibana-software-inventory-instances'));
    const out = await createSummaryTool(deps).handler({}, context);
    const [result] = (out as { results: Array<{ type: string; data: { message: string } }> })
      .results;
    expect(result.type).toBe(ToolResultType.error);
    expect(result.data.message).not.toContain('.software-inventory');
  });

  it('software_detail returns an error for an unknown id', async () => {
    const { es, deps, context } = setup();
    es.search.mockResolvedValue(hits([]));
    const out = await createSoftwareDetailTool(deps).handler({ software_id: 'nope' }, context);
    expect((out as { results: Array<{ type: string }> }).results[0].type).toBe(
      ToolResultType.error
    );
  });

  it('software_detail returns patch guidance and per-CVE details', async () => {
    const { es, deps, context } = setup();
    const remediated = {
      ...entry,
      fixed_in: '1.27.1',
      latest_known_fix: '1.28.0',
      fully_remediated: false,
      unfixed_cve_ids: ['CVE-2'],
      remediation_caveat: ['distro_backports'],
      first_published: '2024-08-14',
      cve_details: [
        {
          id: 'CVE-1',
          cvss: 7.5,
          published: '2024-08-14',
          fixed_in: '1.27.1',
          known_exploited: true,
        },
        { id: 'CVE-2', known_exploited: false },
      ],
    };
    es.search.mockResolvedValueOnce(hits([remediated])).mockResolvedValueOnce(hits([instance]));
    const data = firstResultData(
      await createSoftwareDetailTool(deps).handler({ software_id: 's1' }, context)
    );
    expect(data.entry).toMatchObject({
      fixed_in: '1.27.1',
      minimal_safe_version: '1.27.1',
      latest_known_fix: '1.28.0',
      fully_remediated: false,
      unfixed_cve_ids: ['CVE-2'],
      remediation_caveat: ['distro_backports'],
      cve_details: remediated.cve_details,
    });
  });

  it('find_instances rows include the minimal safe version', async () => {
    const { es, deps, context } = setup();
    es.search
      .mockResolvedValueOnce(hits([{ id: 's1' }]))
      .mockResolvedValueOnce(hits([instance]))
      .mockResolvedValueOnce(hits([{ ...entry, fixed_in: '2.0', fully_remediated: true }]));
    const data = firstResultData(
      await createFindInstancesTool(deps).handler({ product: 'nginx' }, context)
    );
    expect((data.items as Array<Record<string, unknown>>)[0]).toMatchObject({
      minimal_safe_version: '2.0',
      fully_remediated: true,
    });
  });

  it('build_hunt_queries scopes queries to the hosts of a software id', async () => {
    const { es, deps, context } = setup();
    es.search
      .mockResolvedValueOnce(hits([entry]))
      .mockResolvedValueOnce(
        hits([instance, { ...instance, id: 'i2', host: { id: 'h2', name: 'web-2' } }])
      );
    const out = await createBuildHuntQueriesTool(deps).handler({ software_id: 's1' }, context);
    const data = firstResultData(out);
    expect(data.scoped_hosts).toEqual(['web-1', 'web-2']);
    const queries = data.queries as Array<{ name: string; esql: string }>;
    expect(queries.map(({ name }) => name)).toEqual(['host_activity', 'process', 'network']);
    expect(queries[0].esql).toContain('host.name IN ("web-1", "web-2")');
  });

  it('build_hunt_queries requires software_id or product', async () => {
    const { deps, context } = setup();
    const out = await createBuildHuntQueriesTool(deps).handler({}, context);
    expect((out as { results: Array<{ type: string }> }).results[0].type).toBe(
      ToolResultType.error
    );
  });
});

describe('createHasReadAccess', () => {
  const request = httpServerMock.createKibanaRequest();

  it('fails closed without the security plugin', async () => {
    await expect(createHasReadAccess(undefined)(request)).resolves.toBe(false);
    await expect(createHasReadAccess(() => undefined)(request)).resolves.toBe(false);
  });

  it('checks the read api privilege', async () => {
    const check = jest.fn().mockResolvedValue({ hasAllRequested: true });
    const security = {
      authz: {
        actions: { api: { get: (name: string) => `api:${name}` } },
        checkPrivilegesDynamicallyWithRequest: jest.fn().mockReturnValue(check),
      },
    };
    await expect(createHasReadAccess(() => security as never)(request)).resolves.toBe(true);
    expect(check).toHaveBeenCalledWith({ kibana: ['api:software_inventory_read'] });
  });
});

describe('createSoftwareInventorySkill', () => {
  it('gates availability on the read privilege and exposes read-only inline tools', async () => {
    const { deps } = setup(false);
    const skill = createSoftwareInventorySkill(deps);
    const result = await skill.availability?.handler({
      request: httpServerMock.createKibanaRequest(),
    } as never);
    expect(result?.status).toBe('unavailable');
    const tools = await skill.getInlineTools?.();
    expect(tools?.map(({ id }) => id)).toEqual([
      'security.software_inventory.find_instances',
      'security.software_inventory.summary',
      'security.software_inventory.software_detail',
      'security.software_inventory.build_hunt_queries',
      'security.software_inventory.host_vulnerability_timeline',
      'security.software_inventory.inventory_trends',
    ]);
  });
});
