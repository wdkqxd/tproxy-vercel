import {
  type Cipheriv,
  createCipheriv,
  createDecipheriv,
  createHash,
  type Decipheriv,
  randomBytes,
} from "node:crypto";
import net from "node:net";

import { LIMITS } from "../config.js";
import { resolveDc } from "./dc.js";

const TAG_ABRIDGED = 0xefefefef;
const TAG_INTERMEDIATE = 0xeeeeeeee;
const TAG_PADDED = 0xdddddddd;
const PROTO_TAGS = new Set([TAG_ABRIDGED, TAG_INTERMEDIATE, TAG_PADDED]);

// ascii prefixes a client must not start with
const RESERVED_PREFIXES = new Set([
  0x44414548,
  0x54534f50,
  0x20544547,
  0x4954504f,
  TAG_PADDED,
  TAG_INTERMEDIATE,
  0x02010316,
]);

export interface BackendHost {
  readonly closed: boolean;
  readAllowance(id: number): number;
  onBackendData(id: number, data: Uint8Array): boolean;
  onBackendWritten(id: number, bytes: number): void;
  onBackendClosed(id: number, backend: Backend): void;
}

interface ClientHandshake {
  protoTag: Buffer;
  dcId: number;
  fromClient: Decipheriv;
  toClient: Cipheriv;
}

function sha256(...parts: Uint8Array[]): Buffer {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

export function parseClientHandshake(header: Buffer, secret: Buffer): ClientHandshake {
  if (header.length !== 64) throw new Error("short handshake");

  const key = sha256(header.subarray(8, 40), secret);
  const iv = header.subarray(40, 56);
  const fromClient = createDecipheriv("aes-256-ctr", key, iv);

  // header decryption advances the keystream by 64 bytes
  const plain = fromClient.update(header);
  const protoTag = plain.subarray(56, 60);
  const tag = plain.readUInt32LE(56);
  if (!PROTO_TAGS.has(tag)) throw new Error("unknown transport tag");

  const reversed = Buffer.from(header.subarray(8, 56)).reverse();
  const encryptKey = sha256(reversed.subarray(0, 32), secret);
  const toClient = createCipheriv("aes-256-ctr", encryptKey, reversed.subarray(32, 48));

  return {
    protoTag: Buffer.from(protoTag),
    dcId: plain.readInt16LE(60),
    fromClient,
    toClient,
  };
}

interface DcHandshake {
  header: Buffer;
  toDc: Cipheriv;
  fromDc: Decipheriv;
}

export function createDcHandshake(protoTag: Buffer): DcHandshake {
  for (;;) {
    const header = randomBytes(64);
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
    if (header[0] === 0xef) continue;
    if (RESERVED_PREFIXES.has(view.getUint32(0, true))) continue;
    if (view.getInt32(4, true) === 0) continue;

    header.set(protoTag, 56);

    // raw keys, no proxy secret, so the dc sees a normal client
    const toDc = createCipheriv("aes-256-ctr", header.subarray(8, 40), header.subarray(40, 56));
    const reversed = Buffer.from(header.subarray(8, 56)).reverse();
    const fromDc = createDecipheriv(
      "aes-256-ctr",
      reversed.subarray(0, 32),
      reversed.subarray(32, 48),
    );

    // only the last 8 bytes go back to the wire, the rest is keystream
    const encrypted = toDc.update(header);
    header.set(encrypted.subarray(56, 64), 56);

    return { header, toDc, fromDc };
  }
}

function dialAny(addresses: string[], timeoutMs: number): Promise<net.Socket> {
  return new Promise<net.Socket>((resolve, reject) => {
    const attempt = (index: number) => {
      if (index >= addresses.length) {
        reject(new Error("no reachable datacenter"));
        return;
      }
      const separator = addresses[index].lastIndexOf(":");
      const host = addresses[index].slice(0, separator);
      const port = Number(addresses[index].slice(separator + 1));

      const socket = net.createConnection({ host, port });
      const timer = setTimeout(() => {
        socket.destroy();
        attempt(index + 1);
      }, timeoutMs);
      socket.once("connect", () => {
        clearTimeout(timer);
        socket.setNoDelay(true);
        socket.on("error", () => {});
        resolve(socket);
      });
      socket.once("error", () => {
        clearTimeout(timer);
        attempt(index + 1);
      });
    };
    attempt(0);
  });
}

function wait(waiters: Set<() => void>, close: Promise<void>): Promise<void> {
  return new Promise<void>((resolve) => {
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      waiters.delete(done);
      resolve();
    };
    waiters.add(done);
    void close.then(done);
  });
}

export class Backend {
  readonly id: number;

  private readonly host: BackendHost;
  private readonly secret: Buffer;
  private socket: net.Socket | null = null;
  private closed = false;
  private incoming = Buffer.alloc(0);
  private readBuffer = Buffer.alloc(0);
  private paused = false;
  private toDc: Cipheriv | null = null;
  private fromDc: Decipheriv | null = null;
  private fromClient: Decipheriv | null = null;
  private toClient: Cipheriv | null = null;
  private readonly waiters = new Set<() => void>();
  private readonly closePromise: Promise<void>;
  private resolveClose!: () => void;

  constructor(host: BackendHost, id: number, secret: Buffer) {
    this.host = host;
    this.id = id;
    this.secret = secret;
    this.closePromise = new Promise<void>((resolve) => {
      this.resolveClose = resolve;
    });
  }

  async start(): Promise<void> {
    try {
      const header = await this.takeBytes(64);
      if (!header || this.closed || this.host.closed) return;

      const handshake = parseClientHandshake(header, this.secret);
      const socket = await dialAny(resolveDc(handshake.dcId), LIMITS.backendDialMs);
      if (this.closed || this.host.closed) {
        socket.destroy();
        return;
      }

      this.socket = socket;
      const dc = createDcHandshake(handshake.protoTag);
      this.toDc = dc.toDc;
      this.fromDc = dc.fromDc;
      this.fromClient = handshake.fromClient;
      this.toClient = handshake.toClient;

      if (!(await this.writeAll(socket, dc.header))) return;
      this.host.onBackendWritten(this.id, 64);

      const readDone = this.readLoop(socket);
      const writeDone = this.writeLoop(socket);
      await readDone;
      this.close();
      await writeDone;
    } catch {
      // any failure is just a close for this stream
    } finally {
      this.close();
      this.host.onBackendClosed(this.id, this);
    }
  }

  enqueue(data: Uint8Array): void {
    if (this.closed) return;
    this.incoming =
      this.incoming.length > 0 ? Buffer.concat([this.incoming, data]) : Buffer.from(data);
    this.wake();
  }

  resume(): void {
    if (this.paused && this.socket) {
      this.paused = false;
      this.socket.resume();
      this.pump();
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.resolveClose();
    this.wake();
    const socket = this.socket;
    this.socket = null;
    socket?.destroy();
  }

  private wake(): void {
    if (this.waiters.size === 0) return;
    const pending = [...this.waiters];
    this.waiters.clear();
    for (const resolve of pending) resolve();
  }

  private async takeBytes(count: number): Promise<Buffer | null> {
    while (!this.closed && !this.host.closed) {
      if (this.incoming.length >= count) {
        const result = Buffer.from(this.incoming.subarray(0, count));
        this.incoming = this.incoming.subarray(count);
        return result;
      }
      await wait(this.waiters, this.closePromise);
    }
    return null;
  }

  private async writeLoop(socket: net.Socket): Promise<void> {
    while (!this.closed && !this.host.closed) {
      if (this.incoming.length > 0) {
        const chunk = this.incoming;
        this.incoming = Buffer.alloc(0);
        const encrypted = this.toDc!.update(this.fromClient!.update(chunk));
        if (!(await this.writeAll(socket, encrypted))) return;
        this.host.onBackendWritten(this.id, chunk.length);
        continue;
      }
      await wait(this.waiters, this.closePromise);
    }
  }

  private readLoop(socket: net.Socket): Promise<void> {
    return new Promise<void>((resolve) => {
      let finished = false;
      const finish = () => {
        if (finished) return;
        finished = true;
        socket.off("data", onData);
        socket.off("error", finish);
        socket.off("end", finish);
        socket.off("close", finish);
        resolve();
      };
      const onData = (chunk: Buffer) => {
        if (this.closed) return;
        this.readBuffer =
          this.readBuffer.length > 0
            ? Buffer.concat([this.readBuffer, this.fromDc!.update(chunk)])
            : this.fromDc!.update(chunk);
        this.pump();
      };
      socket.on("data", onData);
      socket.on("error", finish);
      socket.on("end", finish);
      socket.on("close", finish);
      socket.resume();
    });
  }

  private pump(): void {
    const socket = this.socket;
    if (!socket || this.closed || !this.toClient) return;
    while (this.readBuffer.length > 0) {
      const allowance = this.host.readAllowance(this.id);
      if (allowance <= 0) {
        if (!this.paused) {
          this.paused = true;
          socket.pause();
        }
        return;
      }
      const size = Math.min(allowance, this.readBuffer.length);
      const piece = this.readBuffer.subarray(0, size);
      this.readBuffer = this.readBuffer.subarray(size);
      const encrypted = this.toClient.update(piece);
      if (!this.host.onBackendData(this.id, encrypted)) {
        this.close();
        return;
      }
    }
    if (this.paused) {
      this.paused = false;
      socket.resume();
    }
  }

  private writeAll(socket: net.Socket, data: Uint8Array): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      let settled = false;
      const done = (value: boolean) => {
        if (settled) return;
        settled = true;
        socket.off("close", onClose);
        resolve(value);
      };
      const onClose = () => done(false);
      socket.once("close", onClose);
      socket.write(data, (error) => done(!error));
    });
  }
}
