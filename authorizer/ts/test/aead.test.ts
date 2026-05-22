import { describe, expect, it } from "vitest";
import {
  aeadOpen,
  aeadSeal,
  DS_SEAL,
  DS_WRAP,
  sealAd,
  utf8,
  wrapBindingAd,
  WRAP_VERSION,
} from "../src/index.js";

describe("AEAD round-trip and AAD shapes", () => {
  const key = new Uint8Array(32).fill(0x11);
  const plaintext = utf8("the lazy dog jumps over...");

  it("seals and opens with matching AAD", () => {
    const aad = sealAd();
    const sealed = aeadSeal(key, plaintext, aad);
    expect(sealed.byteLength).toBe(plaintext.byteLength + 24 + 16); // nonce + ct + tag
    const opened = aeadOpen(key, sealed, aad);
    expect(opened).toEqual(plaintext);
  });

  it("rejects ciphertext when AAD differs", () => {
    const sealed = aeadSeal(key, plaintext, sealAd());
    expect(() => aeadOpen(key, sealed, sealAd(2))).toThrow();
  });

  it("rejects tampered ciphertext", () => {
    const sealed = aeadSeal(key, plaintext, sealAd());
    sealed[30] ^= 0xff;
    expect(() => aeadOpen(key, sealed, sealAd())).toThrow();
  });

  it("each seal uses a fresh random nonce", () => {
    const a = aeadSeal(key, plaintext, sealAd());
    const b = aeadSeal(key, plaintext, sealAd());
    expect(a.slice(0, 24)).not.toEqual(b.slice(0, 24));
  });

  it("wrapBindingAd has the canonical shape DS_WRAP ‖ cid ‖ ver_be", () => {
    const cid = new Uint8Array([1, 2, 3, 4]);
    const ad = wrapBindingAd(cid, 0x0102);
    const expected = new Uint8Array(DS_WRAP.byteLength + cid.byteLength + 2);
    expected.set(DS_WRAP, 0);
    expected.set(cid, DS_WRAP.byteLength);
    expected[DS_WRAP.byteLength + cid.byteLength] = 0x01;
    expected[DS_WRAP.byteLength + cid.byteLength + 1] = 0x02;
    expect(ad).toEqual(expected);
  });

  it("sealAd has the canonical shape DS_SEAL ‖ ver_be", () => {
    const ad = sealAd();
    const expected = new Uint8Array(DS_SEAL.byteLength + 2);
    expected.set(DS_SEAL, 0);
    expected[DS_SEAL.byteLength] = (WRAP_VERSION >> 8) & 0xff;
    expected[DS_SEAL.byteLength + 1] = WRAP_VERSION & 0xff;
    expect(ad).toEqual(expected);
  });
});
