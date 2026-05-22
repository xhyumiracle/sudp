import { describe, expect, it } from "vitest";
import { deriveWrappingKey } from "../src/index.js";

describe("deriveWrappingKey", () => {
  const userKey = new Uint8Array(32).fill(0x22);
  const prfSalt = new Uint8Array(32).fill(0x33);
  const cid = new Uint8Array([10, 20, 30, 40]);

  it("returns 32 bytes", async () => {
    const wc = await deriveWrappingKey(userKey, prfSalt, cid);
    expect(wc.byteLength).toBe(32);
  });

  it("is deterministic in its inputs", async () => {
    const a = await deriveWrappingKey(userKey, prfSalt, cid);
    const b = await deriveWrappingKey(userKey, prfSalt, cid);
    expect(a).toEqual(b);
  });

  it("changes when userKey changes", async () => {
    const a = await deriveWrappingKey(userKey, prfSalt, cid);
    const b = await deriveWrappingKey(new Uint8Array(32).fill(0x44), prfSalt, cid);
    expect(a).not.toEqual(b);
  });

  it("changes when salt changes", async () => {
    const a = await deriveWrappingKey(userKey, prfSalt, cid);
    const b = await deriveWrappingKey(userKey, new Uint8Array(32).fill(0x55), cid);
    expect(a).not.toEqual(b);
  });

  it("changes when credentialId changes", async () => {
    const a = await deriveWrappingKey(userKey, prfSalt, cid);
    const b = await deriveWrappingKey(userKey, prfSalt, new Uint8Array([99]));
    expect(a).not.toEqual(b);
  });

  it("changes when wrapVersion changes", async () => {
    const a = await deriveWrappingKey(userKey, prfSalt, cid, 1);
    const b = await deriveWrappingKey(userKey, prfSalt, cid, 2);
    expect(a).not.toEqual(b);
  });
});
