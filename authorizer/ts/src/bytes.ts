const enc = new TextEncoder();

export function utf8(s: string): Uint8Array {
  return enc.encode(s);
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.byteLength;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}

export function u16beBytes(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
    throw new Error(`u16beBytes: out of range: ${n}`);
  }
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

export function u32beBytes(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new Error(`u32beBytes: out of range: ${n}`);
  }
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/**
 * 8-byte big-endian encoding of a `u64`. Takes a `bigint` so the full unsigned
 * 64-bit range is exact (a `number` is only safe to 2^53). MUST match the Rust
 * crate's `u64::to_be_bytes`.
 */
export function u64beBytes(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffffffffffffffffn) {
    throw new Error(`u64beBytes: out of range: ${n}`);
  }
  const out = new Uint8Array(8);
  let v = n;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

const B64URL_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_LOOKUP = (() => {
  const t = new Int8Array(256).fill(-1);
  for (let i = 0; i < B64URL_ALPHA.length; i++) t[B64URL_ALPHA.charCodeAt(i)] = i;
  return t;
})();

function alpha(i: number): string {
  // Index is always masked to 0..63, so B64URL_ALPHA[i] is defined.
  return B64URL_ALPHA[i]!;
}

export function bytesToB64Url(b: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 3 <= b.length; i += 3) {
    const x = (b[i]! << 16) | (b[i + 1]! << 8) | b[i + 2]!;
    out += alpha((x >> 18) & 0x3f) + alpha((x >> 12) & 0x3f) + alpha((x >> 6) & 0x3f) + alpha(x & 0x3f);
  }
  const rem = b.length - i;
  if (rem === 1) {
    const x = b[i]! << 16;
    out += alpha((x >> 18) & 0x3f) + alpha((x >> 12) & 0x3f);
  } else if (rem === 2) {
    const x = (b[i]! << 16) | (b[i + 1]! << 8);
    out += alpha((x >> 18) & 0x3f) + alpha((x >> 12) & 0x3f) + alpha((x >> 6) & 0x3f);
  }
  return out;
}

export function b64UrlToBytes(s: string): Uint8Array {
  const norm = s.replace(/=+$/, "");
  const len = norm.length;
  const fullGroups = Math.floor(len / 4);
  const rem = len - fullGroups * 4;
  if (rem === 1) throw new Error("b64UrlToBytes: invalid length");
  const out = new Uint8Array(fullGroups * 3 + (rem === 0 ? 0 : rem - 1));
  let outOff = 0;
  let i = 0;
  for (; i + 4 <= len; i += 4) {
    const a = B64URL_LOOKUP[norm.charCodeAt(i)]!;
    const b = B64URL_LOOKUP[norm.charCodeAt(i + 1)]!;
    const c = B64URL_LOOKUP[norm.charCodeAt(i + 2)]!;
    const d = B64URL_LOOKUP[norm.charCodeAt(i + 3)]!;
    if ((a | b | c | d) < 0) throw new Error("b64UrlToBytes: invalid character");
    out[outOff++] = (a << 2) | (b >> 4);
    out[outOff++] = ((b & 0x0f) << 4) | (c >> 2);
    out[outOff++] = ((c & 0x03) << 6) | d;
  }
  if (rem === 2) {
    const a = B64URL_LOOKUP[norm.charCodeAt(i)]!;
    const b = B64URL_LOOKUP[norm.charCodeAt(i + 1)]!;
    if ((a | b) < 0) throw new Error("b64UrlToBytes: invalid character");
    out[outOff++] = (a << 2) | (b >> 4);
  } else if (rem === 3) {
    const a = B64URL_LOOKUP[norm.charCodeAt(i)]!;
    const b = B64URL_LOOKUP[norm.charCodeAt(i + 1)]!;
    const c = B64URL_LOOKUP[norm.charCodeAt(i + 2)]!;
    if ((a | b | c) < 0) throw new Error("b64UrlToBytes: invalid character");
    out[outOff++] = (a << 2) | (b >> 4);
    out[outOff++] = ((b & 0x0f) << 4) | (c >> 2);
  }
  return out;
}
