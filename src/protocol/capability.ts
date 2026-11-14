import { createHmac } from "node:crypto";

// v1 is frozen, don't touch
const CAPABILITY_CONTEXT = "tdesktop-web-proxy-bridge-v1\n";
const CAPABILITY_CONTEXT_V2 = "tdesktop-web-proxy-bridge-v2\n";

export function deriveCapability(hostname: string, basePath: string, secret: Uint8Array): string {
  const context =
    basePath === ""
      ? CAPABILITY_CONTEXT + hostname
      : `${CAPABILITY_CONTEXT_V2}${hostname}\n${basePath}`;
  return createHmac("sha256", secret).update(context, "utf8").digest("base64url");
}

export function decodeSecret(value: string): Buffer {
  const trimmed = value.trim();
  let decoded: Buffer;
  if (/^[0-9a-fA-F]{32}$/.test(trimmed) || /^[0-9a-fA-F]{34}$/.test(trimmed)) {
    decoded = Buffer.from(trimmed, "hex");
  } else {
    let parsed: Buffer | null = null;
    for (const encoding of ["base64url", "base64"] as const) {
      try {
        parsed = Buffer.from(trimmed, encoding);
      } catch {
        parsed = null;
      }
      if (parsed && (parsed.length === 16 || parsed.length === 17)) break;
    }
    if (!parsed) {
      throw new Error("secret must decode to 16 bytes, optionally prefixed with dd");
    }
    decoded = parsed;
  }
  if (decoded.length !== 16 && decoded.length !== 17) {
    throw new Error("secret must decode to 16 bytes, optionally prefixed with dd");
  }
  if (decoded.length === 17 && decoded[0] !== 0xdd) {
    throw new Error("17-byte secret must use the dd prefix");
  }
  return decoded;
}

export function isCanonicalCapability(value: string): boolean {
  if (value.length !== 43) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === 32 && decoded.toString("base64url") === value;
}

export function validateHostname(host: string): void {
  if (!host || host.length > 253 || host.endsWith(".") || /[:/@?#[\]\s]/.test(host)) {
    throw new Error("TPROXY_HOST must be a bare DNS hostname");
  }
  if (!host.includes(".") || /^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    throw new Error("TPROXY_HOST must be a DNS name, not an IP address");
  }
  for (const label of host.split(".")) {
    if (!label || label.length > 63 || label.startsWith("-") || label.endsWith("-")) {
      throw new Error("TPROXY_HOST has an invalid DNS label");
    }
    if (!/^[a-z0-9-]+$/.test(label)) {
      throw new Error("TPROXY_HOST must be lowercase ASCII/IDNA");
    }
  }
}

export function validateBasePath(path: string): void {
  if (path === "") return;
  if (path.length > 128 || path.startsWith("/") || path.endsWith("/")) {
    throw new Error("TPROXY_BASE_PATH must not start or end with a slash");
  }
  for (const segment of path.split("/")) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(segment)) {
      throw new Error("TPROXY_BASE_PATH segments must match [A-Za-z0-9][A-Za-z0-9_-]*");
    }
  }
}

export function basePrefix(basePath: string): string {
  return basePath === "" ? "/" : `/${basePath}/`;
}
