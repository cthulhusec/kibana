/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import http from 'http';
import type { IncomingMessage, ServerResponse } from 'http';
import type { AddressInfo, Socket } from 'net';
import {
  CPE_RULES,
  DEFAULT_MODE,
  EMPTY_BODY,
  KEV_BODY,
  KEV_NAMES,
  MODE_PRESETS,
  NVD_NAMES,
} from './fixtures';
import type { KevMode, NvdMode, StubMode } from './fixtures';

export type { StubMode } from './fixtures';

export interface RecordedRequest {
  at: string;
  method: string;
  path: string;
  query: Record<string, string>;
  /** HTTP status sent. `0` means no response: the socket was destroyed or left hanging. */
  status: number;
}

export interface NvdStub {
  url: string;
  port: number;
  requests: () => RecordedRequest[];
  reset: () => void;
  setMode: (mode: StubMode) => void;
  close: () => Promise<void>;
}

const NVD_PATH = '/rest/json/cves/2.0';
const KEV_PATH = '/kev.json';

const readBody = async (req: IncomingMessage): Promise<string> => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
};

const sendJson = (res: ServerResponse, status: number, body: unknown): number => {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(payload);
  return status;
};

const parseMode = (body: unknown): StubMode | string => {
  if (typeof body !== 'object' || body === null) return 'body must be a JSON object';
  const { preset, nvd, kev, slowMs } = body as Record<string, unknown>;
  if (preset !== undefined) {
    if (typeof preset !== 'string' || !(preset in MODE_PRESETS)) {
      return `unknown preset; use one of ${Object.keys(MODE_PRESETS).join(', ')}`;
    }
    return MODE_PRESETS[preset];
  }
  if (nvd !== undefined && (typeof nvd !== 'string' || !NVD_NAMES.includes(nvd))) {
    return `unknown nvd mode; use one of ${NVD_NAMES.join(', ')}`;
  }
  if (kev !== undefined && (typeof kev !== 'string' || !KEV_NAMES.includes(kev))) {
    return `unknown kev mode; use one of ${KEV_NAMES.join(', ')}`;
  }
  if (slowMs !== undefined && (typeof slowMs !== 'number' || slowMs < 0)) {
    return 'slowMs must be a non-negative number';
  }
  return {
    ...(nvd !== undefined ? { nvd: nvd as NvdMode } : {}),
    ...(kev !== undefined ? { kev: kev as KevMode } : {}),
    ...(slowMs !== undefined ? { slowMs } : {}),
  };
};

export const startNvdStub = async ({
  port,
  host = '127.0.0.1',
}: {
  port: number;
  host?: string;
}): Promise<NvdStub> => {
  let log: RecordedRequest[] = [];
  let mode: Required<StubMode> = { ...DEFAULT_MODE };
  /** Requests seen per CPE, for `sequence` rules. Reset with the log. */
  let cpeHits = new Map<string, number>();
  const sockets = new Set<Socket>();
  const timers = new Set<NodeJS.Timeout>();

  const record = (
    req: IncomingMessage,
    path: string,
    query: Record<string, string>,
    status: number
  ): void => {
    log.push({ at: new Date().toISOString(), method: req.method ?? 'GET', path, query, status });
  };

  const delayed = (ms: number, fn: () => void): void => {
    const timer = setTimeout(() => {
      timers.delete(timer);
      fn();
    }, ms);
    timers.add(timer);
  };

  const handleNvd = (
    req: IncomingMessage,
    res: ServerResponse,
    query: Record<string, string>
  ): void => {
    const record_ = (status: number) => record(req, NVD_PATH, query, status);
    const cpe = query.cpeName ?? '';
    const hits = (cpeHits.get(cpe) ?? 0) + 1;
    cpeHits.set(cpe, hits);

    if (mode.nvd === 'offline') {
      record_(0);
      req.socket.destroy();
      return;
    }
    if (mode.nvd === 'hang') {
      record_(0);
      return;
    }
    if (mode.nvd === 'always-403' || mode.nvd === 'always-429' || mode.nvd === 'always-500') {
      record_(sendJson(res, Number(mode.nvd.slice(-3)), { message: 'stub failure' }));
      return;
    }
    if (mode.nvd === 'malformed') {
      record_(sendJson(res, 200, '{"vulnerabilities": [{"cve": '));
      return;
    }
    if (mode.nvd === 'slow') {
      const { slowMs } = mode;
      delayed(slowMs, () => {
        if (!res.writableEnded && !res.destroyed) record_(sendJson(res, 200, EMPTY_BODY));
      });
      return;
    }

    const rule = CPE_RULES[cpe];
    if (!rule) {
      record_(sendJson(res, 200, EMPTY_BODY));
    } else if (rule.kind === 'hang') {
      record_(0);
    } else if (rule.kind === 'status') {
      record_(sendJson(res, rule.status, { message: 'stub failure' }));
    } else if (rule.kind === 'sequence') {
      record_(
        hits <= rule.statuses.length
          ? sendJson(res, rule.statuses[hits - 1], { message: 'stub failure' })
          : sendJson(res, 200, rule.then)
      );
    } else {
      record_(sendJson(res, 200, rule.body));
    }
  };

  const handleKev = (req: IncomingMessage, res: ServerResponse): void => {
    const done = (status: number) => record(req, KEV_PATH, {}, status);
    switch (mode.kev) {
      case 'status-500':
        done(sendJson(res, 500, { message: 'stub failure' }));
        return;
      case 'malformed':
        done(sendJson(res, 200, '{"vulnerabilities": ['));
        return;
      case 'hang':
        done(0);
        return;
      case 'slow':
        delayed(mode.slowMs, () => {
          if (!res.writableEnded && !res.destroyed) done(sendJson(res, 200, KEV_BODY));
        });
        return;
      default:
        done(sendJson(res, 200, KEV_BODY));
    }
  };

  const handleControl = async (
    req: IncomingMessage,
    res: ServerResponse,
    pathname: string
  ): Promise<void> => {
    if (pathname === '/_stub/requests' && req.method === 'GET') {
      sendJson(res, 200, log);
    } else if (pathname === '/_stub/reset' && req.method === 'POST') {
      log = [];
      cpeHits = new Map();
      mode = { ...DEFAULT_MODE };
      sendJson(res, 200, { ok: true });
    } else if (pathname === '/_stub/mode' && req.method === 'POST') {
      let body: unknown;
      try {
        body = JSON.parse((await readBody(req)) || '{}');
      } catch {
        sendJson(res, 400, { error: 'invalid JSON' });
        return;
      }
      const parsed = parseMode(body);
      if (typeof parsed === 'string') {
        sendJson(res, 400, { error: parsed });
        return;
      }
      mode = { ...mode, ...parsed };
      sendJson(res, 200, mode);
    } else {
      sendJson(res, 404, { error: 'not found' });
    }
  };

  const server = http.createServer((req, res) => {
    const parsedUrl = new URL(req.url ?? '/', 'http://stub.local');
    const { pathname } = parsedUrl;
    const query: Record<string, string> = {};
    parsedUrl.searchParams.forEach((value, key) => {
      query[key] = value;
    });

    if (pathname.startsWith('/_stub/')) {
      void handleControl(req, res, pathname);
    } else if (pathname === NVD_PATH && req.method === 'GET') {
      handleNvd(req, res, query);
    } else if (pathname === KEV_PATH && req.method === 'GET') {
      handleKev(req, res);
    } else {
      record(req, pathname, query, sendJson(res, 404, { error: 'not found' }));
    }
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  const { port: actualPort } = server.address() as AddressInfo;

  return {
    url: `http://${host}:${actualPort}`,
    port: actualPort,
    requests: () => [...log],
    reset: () => {
      log = [];
      cpeHits = new Map();
      mode = { ...DEFAULT_MODE };
    },
    setMode: (next) => {
      mode = { ...mode, ...next };
    },
    close: async () => {
      timers.forEach(clearTimeout);
      timers.clear();
      sockets.forEach((socket) => socket.destroy());
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    },
  };
};
