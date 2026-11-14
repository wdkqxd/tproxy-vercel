import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const TOKEN_KEY_BYTES = 32;
const BOOTSTRAP_TTL_SECONDS = 120;
const SESSION_TTL_SECONDS = 900;

export class Tokens {
  private readonly key: Buffer;

  constructor(key: Buffer) {
    if (key.length !== TOKEN_KEY_BYTES) throw new Error("token key must be 32 bytes");
    this.key = key;
  }

  issueBootstrap(): string {
    return this.issue("bootstrap", BOOTSTRAP_TTL_SECONDS);
  }

  verifyBootstrap(token: string): boolean {
    return this.verify(token, "bootstrap");
  }

  issueSession(): string {
    return this.issue("session", SESSION_TTL_SECONDS);
  }

  verifySession(token: string): boolean {
    return this.verify(token, "session");
  }

  private issue(context: string, ttlSeconds: number): string {
    const value = Buffer.alloc(10);
    value.writeUInt32BE(Math.floor(Date.now() / 1000) + ttlSeconds, 0);
    randomBytes(6).copy(value, 4);
    return Buffer.concat([value, this.mac(context, value)]).toString("base64url");
  }

  private verify(token: string, context: string): boolean {
    const decoded = Buffer.from(token, "base64url");
    if (decoded.length !== 26) return false;
    if (decoded.readUInt32BE(0) < Math.floor(Date.now() / 1000)) return false;
    return timingSafeEqual(decoded.subarray(10), this.mac(context, decoded.subarray(0, 10)));
  }

  private mac(context: string, value: Buffer): Buffer {
    return createHmac("sha256", this.key)
      .update(`${context}\x00`)
      .update(value)
      .digest()
      .subarray(0, 16);
  }
}

export function decodeTokenKey(value: string | undefined): Buffer {
  const trimmed = (value ?? "").trim();
  if (!trimmed) throw new Error("TPROXY_TOKEN_KEY is required");
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return Buffer.from(trimmed, "hex");
  for (const encoding of ["base64url", "base64"] as const) {
    const decoded = Buffer.from(trimmed, encoding);
    if (decoded.length === 32) return decoded;
  }
  throw new Error("TPROXY_TOKEN_KEY must decode to 32 bytes");
}
