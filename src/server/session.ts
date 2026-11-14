import { LIMITS } from "../config.js";
import {
  DATA_CHUNK,
  encodeFrame,
  type Frame,
  FrameType,
  HEADER_SIZE,
  INITIAL_STREAM_WINDOW,
  MAX_BATCH_FRAMES,
  MAX_STREAM_ID,
  parseFrames,
  validateClientShape,
  windowAmount,
  windowPayload,
} from "../protocol/frame.js";
import { Backend } from "./backend.js";

const MAX_UINT32 = 0xffffffff;

export type RelayErrorCode = "backpressure" | "protocol" | "closed";

export class RelayError extends Error {
  readonly code: RelayErrorCode;

  constructor(code: RelayErrorCode) {
    super(code);
    this.name = "RelayError";
    this.code = code;
  }
}

interface Stream {
  backend: Backend;
  receiveWindow: number;
  sendCredit: number;
  windowBacklog: number;
  queuedWriteBytes: number;
}

export class Session {
  closed = false;

  private readonly secretKey: Buffer;
  private readonly streams = new Map<number, Stream>();
  private readonly closedStreams = new Set<number>();
  private readonly closedOrder: number[] = [];
  private readonly pollWaiters = new Set<() => void>();

  private pending: Uint8Array[] = [];
  private pendingBytes = 0;
  private writeBytes = 0;

  constructor(secretKey: Buffer) {
    this.secretKey = secretKey;
  }

  processUp(body: Uint8Array): void {
    if (this.closed) throw new RelayError("closed");

    let frames: Frame[];
    try {
      frames = parseFrames(body, LIMITS.maxFramePayload);
      for (const frame of frames) validateClientShape(frame);
    } catch {
      this.fail();
      throw new RelayError("protocol");
    }
    if (!this.validateBatch(frames)) {
      this.fail();
      throw new RelayError("protocol");
    }

    let incomingBytes = 0;
    const live = new Set(this.streams.keys());
    for (const frame of frames) {
      if (frame.streamId === 0) continue;
      if (frame.type === FrameType.OPEN) live.add(frame.streamId);
      else if (frame.type === FrameType.DATA && live.has(frame.streamId)) {
        incomingBytes += frame.payload.length;
      } else if (frame.type === FrameType.CLOSE) live.delete(frame.streamId);
    }
    if (this.writeBytes + incomingBytes > LIMITS.maxWriteBytes) {
      throw new RelayError("backpressure");
    }

    this.applyBatch(frames);
  }

  private validateBatch(frames: Frame[]): boolean {
    const live = new Map<number, { receiveWindow: number; sendCredit: number }>();
    for (const [id, stream] of this.streams) {
      live.set(id, { receiveWindow: stream.receiveWindow, sendCredit: stream.sendCredit });
    }
    const closedInBatch = new Set<number>();

    for (const frame of frames) {
      if (frame.streamId === 0) {
        if (frame.type !== FrameType.PONG) return false;
        continue;
      }
      const id = frame.streamId;
      const wasClosed = this.closedStreams.has(id) || closedInBatch.has(id);
      const state = live.get(id);

      switch (frame.type) {
        case FrameType.OPEN:
          if (state || wasClosed) return false;
          live.set(id, {
            receiveWindow: INITIAL_STREAM_WINDOW,
            sendCredit: INITIAL_STREAM_WINDOW,
          });
          break;
        case FrameType.DATA:
          if (wasClosed) continue;
          if (!state || frame.payload.length > state.receiveWindow) return false;
          state.receiveWindow -= frame.payload.length;
          break;
        case FrameType.WINDOW:
          if (wasClosed) continue;
          if (!state) return false;
          try {
            state.sendCredit = Math.min(MAX_UINT32, state.sendCredit + windowAmount(frame.payload));
          } catch {
            return false;
          }
          break;
        case FrameType.CLOSE:
          if (wasClosed) continue;
          if (!state) return false;
          live.delete(id);
          closedInBatch.add(id);
          break;
        default:
          return false;
      }
    }
    return true;
  }

  private applyBatch(frames: Frame[]): void {
    for (const frame of frames) {
      const id = frame.streamId;
      if (id === 0) continue;

      switch (frame.type) {
        case FrameType.OPEN: {
          if (this.streams.size >= LIMITS.maxStreams) {
            this.rememberClosed(id);
            this.enqueue(FrameType.CLOSE, id);
            continue;
          }
          const backend = new Backend(this, id, this.secretKey);
          this.streams.set(id, {
            backend,
            receiveWindow: INITIAL_STREAM_WINDOW,
            sendCredit: INITIAL_STREAM_WINDOW,
            windowBacklog: 0,
            queuedWriteBytes: 0,
          });
          void backend.start();
          break;
        }
        case FrameType.DATA: {
          if (this.closedStreams.has(id)) continue;
          const stream = this.streams.get(id);
          if (!stream) continue;
          const data = new Uint8Array(frame.payload);
          stream.backend.enqueue(data);
          stream.queuedWriteBytes += data.length;
          stream.receiveWindow -= data.length;
          this.writeBytes += data.length;
          break;
        }
        case FrameType.WINDOW: {
          if (this.closedStreams.has(id)) continue;
          const stream = this.streams.get(id);
          if (!stream) continue;
          stream.sendCredit = Math.min(MAX_UINT32, stream.sendCredit + windowAmount(frame.payload));
          stream.backend.resume();
          break;
        }
        case FrameType.CLOSE: {
          if (this.closedStreams.has(id)) continue;
          this.closeStream(id);
          break;
        }
        default:
          break;
      }
    }
  }

  async poll(timeoutMs: number): Promise<Uint8Array | null> {
    const deadline = Date.now() + timeoutMs;
    while (true) {
      if (this.closed) throw new RelayError("closed");
      if (this.pending.length > 0) return this.takeBatch();
      const remaining = deadline - Date.now();
      if (remaining <= 0) return null;
      await this.wait(remaining);
    }
  }

  private takeBatch(): Uint8Array {
    let size = 0;
    let count = 0;
    while (count < this.pending.length && count < MAX_BATCH_FRAMES) {
      const next = this.pending[count].length;
      if (count !== 0 && size + next > LIMITS.carrierBatchBytes) break;
      size += next;
      count += 1;
    }
    const body = new Uint8Array(size);
    let offset = 0;
    for (let index = 0; index < count; index += 1) {
      body.set(this.pending[index], offset);
      offset += this.pending[index].length;
    }
    this.pending = this.pending.slice(count);
    this.pendingBytes -= size;
    return body;
  }

  private enqueue(type: number, id: number, payload?: Uint8Array): boolean {
    if (this.closed) return false;
    const frame = encodeFrame(type, id, payload);
    if (this.pendingBytes + frame.length > LIMITS.maxPendingBytes) return false;
    this.pending.push(frame);
    this.pendingBytes += frame.length;
    this.wakePollers();
    return true;
  }

  private wait(timeoutMs: number): Promise<void> {
    return new Promise<void>((resolve) => {
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        this.pollWaiters.delete(done);
        clearTimeout(timer);
        resolve();
      };
      this.pollWaiters.add(done);
      const timer = setTimeout(done, Math.max(1, timeoutMs));
    });
  }

  private wakePollers(): void {
    if (this.pollWaiters.size === 0) return;
    const waiters = [...this.pollWaiters];
    this.pollWaiters.clear();
    for (const resolve of waiters) resolve();
  }

  readAllowance(id: number): number {
    const stream = this.streams.get(id);
    if (this.closed || !stream) return 0;
    if (this.pendingBytes + DATA_CHUNK + HEADER_SIZE > LIMITS.maxPendingBytes) return 0;
    return Math.min(stream.sendCredit, DATA_CHUNK);
  }

  onBackendData(id: number, data: Uint8Array): boolean {
    const stream = this.streams.get(id);
    if (this.closed || !stream || data.length > stream.sendCredit) return false;
    stream.sendCredit -= data.length;
    return this.enqueue(FrameType.DATA, id, data);
  }

  onBackendWritten(id: number, bytes: number): void {
    const stream = this.streams.get(id);
    if (this.closed || !stream) return;
    this.writeBytes -= bytes;
    stream.queuedWriteBytes -= bytes;
    stream.receiveWindow = Math.min(INITIAL_STREAM_WINDOW, stream.receiveWindow + bytes);
    stream.windowBacklog += bytes;
    this.flushWindows(id);
  }

  onBackendClosed(id: number, backend: Backend): void {
    const stream = this.streams.get(id);
    if (!this.closed && stream && stream.backend === backend) {
      this.writeBytes -= stream.queuedWriteBytes;
      this.streams.delete(id);
      this.rememberClosed(id);
      this.enqueue(FrameType.CLOSE, id);
    }
    backend.close();
  }

  private flushWindows(id: number): void {
    const stream = this.streams.get(id);
    if (!stream || stream.windowBacklog === 0) return;
    if (this.enqueue(FrameType.WINDOW, id, windowPayload(stream.windowBacklog))) {
      stream.windowBacklog = 0;
    }
  }

  private closeStream(id: number): void {
    const stream = this.streams.get(id);
    if (!stream) return;
    this.writeBytes -= stream.queuedWriteBytes;
    this.streams.delete(id);
    this.rememberClosed(id);
    stream.backend.close();
  }

  private rememberClosed(id: number): void {
    if (id < 1 || id > MAX_STREAM_ID || this.closedStreams.has(id)) return;
    this.closedStreams.add(id);
    this.closedOrder.push(id);
    if (this.closedOrder.length > LIMITS.maxClosedStreams) {
      const evicted = this.closedOrder.shift();
      if (evicted !== undefined) this.closedStreams.delete(evicted);
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const stream of this.streams.values()) stream.backend.close();
    this.streams.clear();
    this.pending = [];
    this.pendingBytes = 0;
    this.wakePollers();
  }

  private fail(): void {
    this.close();
  }
}
