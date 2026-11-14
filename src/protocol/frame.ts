// type:u8 | stream_id:u24 | length:u32 | payload
export const HEADER_SIZE = 8;
export const MAX_PAYLOAD = 1024 * 1024;
export const INITIAL_STREAM_WINDOW = 4 * 1024 * 1024;
export const DATA_CHUNK = 64 * 1024;
export const MAX_STREAM_ID = 0xffffff;
export const MAX_BATCH_FRAMES = 4096;

export const FrameType = {
  OPEN: 0x01,
  DATA: 0x02,
  CLOSE: 0x03,
  WINDOW: 0x04,
  PING: 0x05,
  PONG: 0x06,
  HELLO: 0x10,
  WELCOME: 0x11,
  BYE: 0x1f,
} as const;

export type FrameTypeValue = (typeof FrameType)[keyof typeof FrameType];

export interface Frame {
  type: number;
  streamId: number;
  payload: Uint8Array;
}

export class FrameError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FrameError";
  }
}

export function encodeFrame(type: number, streamId: number, payload?: Uint8Array): Uint8Array {
  if (streamId < 0 || streamId > MAX_STREAM_ID) {
    throw new FrameError("stream id exceeds 24 bits");
  }
  const body = payload ?? new Uint8Array(0);
  const result = new Uint8Array(HEADER_SIZE + body.length);
  const view = new DataView(result.buffer);
  view.setUint8(0, type);
  view.setUint8(1, (streamId >>> 16) & 0xff);
  view.setUint8(2, (streamId >>> 8) & 0xff);
  view.setUint8(3, streamId & 0xff);
  view.setUint32(4, body.length);
  result.set(body, HEADER_SIZE);
  return result;
}

export function parseFrames(input: Uint8Array, maxPayload: number = MAX_PAYLOAD): Frame[] {
  const limit = maxPayload > 0 && maxPayload <= MAX_PAYLOAD ? maxPayload : MAX_PAYLOAD;
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const frames: Frame[] = [];
  let offset = 0;
  while (offset < input.byteLength) {
    if (frames.length === MAX_BATCH_FRAMES) {
      throw new FrameError("frame batch contains too many frames");
    }
    if (input.byteLength - offset < HEADER_SIZE) {
      throw new FrameError("incomplete frame");
    }
    const length = view.getUint32(offset + 4);
    if (length > limit) {
      throw new FrameError("frame payload exceeds limit");
    }
    const end = offset + HEADER_SIZE + length;
    if (end > input.byteLength) {
      throw new FrameError("incomplete frame");
    }
    frames.push({
      type: view.getUint8(offset),
      streamId:
        (view.getUint8(offset + 1) << 16) |
        (view.getUint8(offset + 2) << 8) |
        view.getUint8(offset + 3),
      payload: input.subarray(offset + HEADER_SIZE, end),
    });
    offset = end;
  }
  if (frames.length === 0) {
    throw new FrameError("empty frame batch");
  }
  return frames;
}

export function parseHello(input: Uint8Array): void {
  const frames = parseFrames(input);
  if (frames.length !== 1) {
    throw new FrameError("HELLO must be the only frame");
  }
  const value = frames[0];
  if (
    value.type !== FrameType.HELLO ||
    value.streamId !== 0 ||
    value.payload.length !== 1 ||
    value.payload[0] !== 1
  ) {
    throw new FrameError("invalid HELLO frame");
  }
}

export function windowAmount(payload: Uint8Array): number {
  if (payload.length !== 4) {
    throw new FrameError("WINDOW payload must be four bytes");
  }
  const value = new DataView(payload.buffer, payload.byteOffset, 4).getUint32(0);
  if (value === 0) {
    throw new FrameError("WINDOW delta must be nonzero");
  }
  return value;
}

export function windowPayload(amount: number): Uint8Array {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, amount);
  return result;
}

export function validateClientShape(value: Frame): void {
  if (value.streamId === 0) {
    if (value.type !== FrameType.PONG || value.payload.length > 64) {
      throw new FrameError(`frame type ${value.type} is invalid on stream zero`);
    }
    return;
  }
  switch (value.type) {
    case FrameType.OPEN:
    case FrameType.CLOSE:
      if (value.payload.length !== 0) {
        throw new FrameError("frame requires an empty payload");
      }
      break;
    case FrameType.DATA:
      if (value.payload.length === 0) {
        throw new FrameError("DATA payload must be nonempty");
      }
      break;
    case FrameType.WINDOW:
      windowAmount(value.payload);
      break;
    default:
      throw new FrameError(`frame type ${value.type} is invalid client-to-relay`);
  }
}
