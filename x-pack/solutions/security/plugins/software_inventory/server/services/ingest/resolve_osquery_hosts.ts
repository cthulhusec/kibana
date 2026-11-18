/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import type { RawCandidate } from '../../../common/types';
import { chunk } from './chunk';

/** Fleet agent documents are keyed by agent id. */
export const FLEET_AGENTS_INDEX = '.fleet-agents';
const AGENT_IDS_CHUNK_SIZE = 500;
/** `osquery.runQuery` targets at most 1000 agents, so this bounds the lookups of one call. */
const MAX_AGENT_IDS = 1000;

interface FleetAgentHost {
  local_metadata?: { host?: { hostname?: string; name?: string; id?: string } };
}

export interface ResolvedAgentHost {
  hostName?: string;
  hostId?: string;
}

const nonEmpty = (value: string | undefined): string | undefined => {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
};

/** Reads the host name and host id Fleet recorded for each agent id. */
const loadAgentHosts = async (
  esClient: ElasticsearchClient,
  agentIds: readonly string[]
): Promise<Map<string, ResolvedAgentHost>> => {
  const hosts = new Map<string, ResolvedAgentHost>();
  for (const idsChunk of chunk(agentIds, AGENT_IDS_CHUNK_SIZE)) {
    const { docs } = await esClient.mget<FleetAgentHost>({
      index: FLEET_AGENTS_INDEX,
      ids: idsChunk,
      _source: [
        'local_metadata.host.hostname',
        'local_metadata.host.name',
        'local_metadata.host.id',
      ],
    });
    for (const doc of docs) {
      if (!('found' in doc) || !doc.found) {
        continue;
      }
      const host = doc._source?.local_metadata?.host;
      const hostName = nonEmpty(host?.hostname) ?? nonEmpty(host?.name);
      const hostId = nonEmpty(host?.id);
      hosts.set(doc._id, {
        ...(hostName ? { hostName } : {}),
        ...(hostId ? { hostId } : {}),
      });
    }
  }
  return hosts;
};

/**
 * Osquery rows identify the host by Elastic Agent id (`host_id`) and agent name (`host_name`).
 * Logs identify it by `host.name` / `host.id`, so this replaces both with the host name and id
 * Fleet recorded for the agent. Rows whose agent is not found, or every row when the lookup
 * fails, keep the reported values: the agent name, which defaults to the host name, else the
 * agent id.
 */
export const resolveOsqueryHosts = async ({
  esClient,
  logger,
  candidates,
}: {
  esClient: ElasticsearchClient;
  logger: Logger;
  candidates: readonly RawCandidate[];
}): Promise<RawCandidate[]> => {
  const agentIds = [
    ...new Set(
      candidates.map(({ host_id: hostId }) => hostId?.trim()).filter((id): id is string => !!id)
    ),
  ].slice(0, MAX_AGENT_IDS);
  if (agentIds.length === 0) {
    return [...candidates];
  }

  let hosts: Map<string, ResolvedAgentHost>;
  try {
    hosts = await loadAgentHosts(esClient, agentIds);
  } catch (error) {
    logger.warn(
      `Software inventory could not resolve Osquery agent hosts; using agent names: ${
        (error as Error).message
      }`
    );
    return [...candidates];
  }

  return candidates.map((candidate) => {
    const resolved = hosts.get(candidate.host_id?.trim());
    if (!resolved) {
      return candidate;
    }
    return {
      ...candidate,
      ...(resolved.hostId ? { host_id: resolved.hostId } : {}),
      ...(resolved.hostName ? { host_name: resolved.hostName } : {}),
    };
  });
};
