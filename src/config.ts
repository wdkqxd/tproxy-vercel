import {
  decodeSecret,
  deriveCapability,
  validateBasePath,
  validateHostname,
} from "./protocol/capability.js";
import { decodeTokenKey } from "./protocol/token.js";

export interface RelayConfig {
  hostname: string;
  basePath: string;
  capability: string;
  secretKey: Buffer;
  tokenKey: Buffer;
  pollMs: number;
}

export const LIMITS = {
  maxFramePayload: 1024 * 1024,
  carrierBatchBytes: 2 * 1024 * 1024,
  maxStreams: 32,
  maxPendingBytes: 8 * 1024 * 1024,
  maxWriteBytes: 8 * 1024 * 1024,
  maxClosedStreams: 4096,
  backendDialMs: 10_000,
} as const;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export function loadConfig(env: Record<string, string | undefined>): RelayConfig {
  const hostname = (env.TPROXY_HOST ?? "").trim().toLowerCase();
  if (!hostname) throw new ConfigError("TPROXY_HOST is required");
  validateHostname(hostname);

  const basePath = (env.TPROXY_BASE_PATH ?? "").trim();
  validateBasePath(basePath);

  const secret = decodeSecret(env.TPROXY_SECRET ?? "");
  const capability = deriveCapability(hostname, basePath, secret);
  const secretKey = Buffer.from(secret.length === 17 ? secret.subarray(1) : secret);
  secret.fill(0);

  const pollMs = Number(env.TPROXY_LONG_POLL_MS ?? 25000);
  if (!Number.isInteger(pollMs) || pollMs < 1000 || pollMs > 55_000) {
    throw new ConfigError("TPROXY_LONG_POLL_MS must be between 1000 and 55000");
  }

  return {
    hostname,
    basePath,
    capability,
    secretKey,
    tokenKey: decodeTokenKey(env.TPROXY_TOKEN_KEY),
    pollMs,
  };
}
