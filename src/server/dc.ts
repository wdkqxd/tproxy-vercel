// ip list from telegram clients
export const DC_ADDRESSES: Record<number, string[]> = {
  1: ["149.154.175.50:443", "149.154.175.53:443"],
  2: ["149.154.167.51:443", "95.161.76.100:443"],
  3: ["149.154.175.100:443"],
  4: ["149.154.167.91:443"],
  5: ["149.154.171.5:443", "91.108.56.130:443"],
  203: ["91.105.192.100:443"],
};

// fallback for unknown ids
export const DEFAULT_DC = 2;

export function resolveDc(dcId: number): string[] {
  // negative = media, direct mode has no field for it
  const absolute = Math.abs(dcId);
  return DC_ADDRESSES[absolute] ?? DC_ADDRESSES[DEFAULT_DC];
}
