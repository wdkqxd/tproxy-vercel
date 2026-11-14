import type { IncomingMessage, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import type { RawData, WebSocket, WebSocketServer } from "ws";

import { loadConfig, type RelayConfig } from "../config.js";
import { BRIDGE_PERMISSIONS_POLICY, renderBridgePage } from "../protocol/bridge-page.js";
import { isCanonicalCapability } from "../protocol/capability.js";
import { encodeFrame, FrameType, parseHello } from "../protocol/frame.js";
import { Tokens } from "../protocol/token.js";
import { RelayError, Session } from "./session.js";

const WELCOME = encodeFrame(FrameType.WELCOME, 0);
const WS_OPEN = 1;

function bearer(value: string | undefined): string | null {
  const match = /^Bearer ([A-Za-z0-9_-]{20,100})$/.exec(value ?? "");
  return match ? match[1] : null;
}

function isBinaryContentType(value: string | undefined): boolean {
  return value === "application/octet-stream";
}

function hostOf(req: IncomingMessage): string {
  const raw = req.headers["x-forwarded-host"] ?? req.headers.host ?? "";
  return String(raw).split(",")[0].trim().replace(/:\d+$/, "").toLowerCase();
}

async function readBody(req: IncomingMessage, limit: number): Promise<Buffer | null> {
  const declared = Number(req.headers["content-length"] ?? 0);
  if (Number.isFinite(declared) && declared > limit) return null;
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for await (const chunk of req) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      total += buffer.length;
      if (total > limit) return null;
      chunks.push(buffer);
    }
  } catch {
    return null;
  }
  return Buffer.concat(chunks);
}

function toBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.concat(data);
  return Buffer.from(data);
}

export class Relay {
  private readonly config: RelayConfig;
  private readonly tokens: Tokens;

  constructor(config: RelayConfig) {
    this.config = config;
    this.tokens = new Tokens(config.tokenKey);
  }

  handle(req: IncomingMessage, res: ServerResponse): void {
    void this.route(req, res).catch(() => {
      if (!res.writableEnded && !res.destroyed) {
        this.send(
          res,
          500,
          { "Content-Type": "text/plain; charset=utf-8" },
          "Internal Server Error\n",
        );
      }
    });
  }

  handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer, wss: WebSocketServer): void {
    const header = req.headers["sec-websocket-protocol"];
    const protocols =
      typeof header === "string" ? header.split(",").map((value) => value.trim()) : [];
    const protocol =
      protocols.length === 1 && protocols[0].startsWith("tproxy-v1.") ? protocols[0] : null;
    if (!protocol || !this.tokens.verifySession(protocol.slice("tproxy-v1.".length))) {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => this.serveWebSocket(ws));
  }

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (hostOf(req) !== this.config.hostname) {
      return this.notFound(res);
    }

    const url = new URL(req.url ?? "/", "https://relay.invalid");
    const path = this.stripBasePath(url.pathname);
    const bridgeValues = url.searchParams.getAll("bridge");

    const entryPath = path === "/" || path === "/api" || path === "/api/index";
    const exactBridge =
      entryPath && bridgeValues.length === 1 && url.search === `?bridge=${bridgeValues[0]}`;
    if (
      exactBridge &&
      isCanonicalCapability(bridgeValues[0]) &&
      bridgeValues[0] === this.config.capability
    ) {
      return this.serveBridge(res);
    }
    if (bridgeValues.includes(this.config.capability)) {
      return this.notFound(res);
    }

    if (this.isSessionRequest(req, path)) {
      return this.serveSession(req, res);
    }
    return this.notFound(res);
  }

  private stripBasePath(pathname: string): string {
    if (!this.config.basePath) return pathname;
    const prefix = `/${this.config.basePath}`;
    if (pathname === prefix) return "/";
    if (pathname.startsWith(`${prefix}/`)) return pathname.slice(prefix.length);
    return pathname;
  }

  private isSessionRequest(req: IncomingMessage, path: string): boolean {
    if (path === "/api/v1/session") return true;
    // vercel rewrites all paths here; fall back to headers
    if (path !== "/api" && path !== "/api/index") return false;
    if (!req.headers.authorization) return false;
    if (req.method === "DELETE") return true;
    return req.method === "POST" && req.headers["content-type"] !== undefined;
  }

  private serveBridge(res: ServerResponse): void {
    const bootstrap = this.tokens.issueBootstrap();
    const page = renderBridgePage({
      hostname: this.config.hostname,
      basePath: this.config.basePath,
      bootstrap,
      carrierMode: "websocket",
      batchBytes: 2 * 1024 * 1024,
    });
    this.send(
      res,
      200,
      {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": page.csp,
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-DNS-Prefetch-Control": "off",
        "Permissions-Policy": BRIDGE_PERMISSIONS_POLICY,
      },
      page.body,
    );
  }

  private async serveSession(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === "DELETE") {
      if (req.headers["content-type"] !== undefined) return this.notFound(res);
      const body = await readBody(req, 1);
      if (body?.length !== 0) return this.notFound(res);
      const token = bearer(req.headers.authorization);
      if (!token || !this.tokens.verifySession(token)) return this.notFound(res);
      return this.send(res, 204, {});
    }

    if (req.method !== "POST" || !isBinaryContentType(req.headers["content-type"])) {
      return this.notFound(res);
    }
    const bootstrap = bearer(req.headers.authorization);
    if (!bootstrap || !this.tokens.verifyBootstrap(bootstrap)) {
      return this.notFound(res);
    }
    const body = await readBody(req, 64);
    if (!body || body.length === 0) return this.notFound(res);
    try {
      parseHello(body);
    } catch {
      return this.notFound(res);
    }

    const token = this.tokens.issueSession();
    this.send(
      res,
      200,
      {
        "Content-Type": "application/octet-stream",
        "X-Session-Token": token,
        "X-Carrier-Mode": "websocket",
        "X-Down-Cursor": "0",
      },
      WELCOME,
    );
  }

  private serveWebSocket(ws: WebSocket): void {
    const session = new Session(this.config.secretKey);
    let closed = false;
    let chain = Promise.resolve();

    const shutdown = (notify: boolean) => {
      if (closed) return;
      closed = true;
      session.close();
      if (notify) ws.close();
    };

    ws.on("message", (data, isBinary) => {
      if (!isBinary) {
        shutdown(true);
        return;
      }
      const body = toBuffer(data);
      if (body.length === 0) {
        shutdown(true);
        return;
      }
      chain = chain.then(async () => {
        const deadline = Date.now() + 30_000;
        while (!closed) {
          try {
            session.processUp(body);
            return;
          } catch (error) {
            if (error instanceof RelayError && error.code === "backpressure") {
              if (Date.now() > deadline) {
                shutdown(true);
                return;
              }
              await new Promise((resolve) => setTimeout(resolve, 50));
              continue;
            }
            shutdown(true);
            return;
          }
        }
      });
    });

    ws.on("close", () => shutdown(false));
    ws.on("error", () => shutdown(false));

    void (async () => {
      while (!closed) {
        try {
          const body = await session.poll(this.config.pollMs);
          if (closed) return;
          if (!body) {
            if (ws.readyState === WS_OPEN) ws.ping();
            continue;
          }
          if (ws.readyState !== WS_OPEN) {
            shutdown(false);
            return;
          }
          ws.send(body);
        } catch {
          shutdown(true);
          return;
        }
      }
    })();
  }

  private notFound(res: ServerResponse): void {
    this.send(res, 404, {});
  }

  private send(
    res: ServerResponse,
    status: number,
    headers: Record<string, string>,
    body?: string | Uint8Array,
  ): void {
    if (res.writableEnded || res.destroyed) return;
    res.statusCode = status;
    res.setHeader("Cache-Control", "no-store");
    for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
    res.end(body);
  }
}

let cachedRelay: Relay | null = null;

export function getRelay(): Relay {
  if (!cachedRelay) {
    cachedRelay = new Relay(loadConfig(process.env));
  }
  return cachedRelay;
}
