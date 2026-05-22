import { describe, expect, it } from "vitest";
import { b64UrlToBytes, bytesToB64Url, concatBytes, u16beBytes, utf8 } from "../src/index.js";

describe("byte helpers", () => {
  it("base64url round-trips for arbitrary lengths", () => {
    for (let len = 0; len < 64; len++) {
      const src = new Uint8Array(len);
      for (let i = 0; i < len; i++) src[i] = (i * 7 + 13) & 0xff;
      const s = bytesToB64Url(src);
      const dec = b64UrlToBytes(s);
      expect(dec).toEqual(src);
      expect(s.includes("=")).toBe(false);
      expect(s.includes("+")).toBe(false);
      expect(s.includes("/")).toBe(false);
    }
  });

  it("base64url accepts padded input as well", () => {
    expect(b64UrlToBytes("AQID")).toEqual(new Uint8Array([1, 2, 3]));
    expect(b64UrlToBytes("AQI=")).toEqual(new Uint8Array([1, 2]));
    expect(b64UrlToBytes("AQ==")).toEqual(new Uint8Array([1]));
  });

  it("u16beBytes encodes big-endian", () => {
    expect(u16beBytes(0x0001)).toEqual(new Uint8Array([0x00, 0x01]));
    expect(u16beBytes(0xffff)).toEqual(new Uint8Array([0xff, 0xff]));
    expect(u16beBytes(0x1234)).toEqual(new Uint8Array([0x12, 0x34]));
  });

  it("u16beBytes rejects out-of-range values", () => {
    expect(() => u16beBytes(-1)).toThrow();
    expect(() => u16beBytes(0x10000)).toThrow();
    expect(() => u16beBytes(1.5)).toThrow();
  });

  it("concatBytes joins in order", () => {
    expect(concatBytes(utf8("ab"), utf8("cd"), utf8("ef"))).toEqual(utf8("abcdef"));
    expect(concatBytes()).toEqual(new Uint8Array(0));
  });
});
