import { describe, expect, it } from "vitest";
import { canonicalize, utf8 } from "../src/index.js";

const decode = (b: Uint8Array): string => new TextDecoder().decode(b);

describe("canonicalize", () => {
  it("sorts object keys lexicographically", () => {
    const out = decode(canonicalize({ b: 1, a: 2, c: 3 }));
    expect(out).toBe('{"a":2,"b":1,"c":3}');
  });

  it("recurses into nested objects and arrays", () => {
    const out = decode(canonicalize({ z: [3, { y: 2, x: 1 }], a: true }));
    expect(out).toBe('{"a":true,"z":[3,{"x":1,"y":2}]}');
  });

  it("renders null and undefined identically", () => {
    expect(decode(canonicalize(null))).toBe("null");
    expect(decode(canonicalize(undefined))).toBe("null");
  });

  it("rejects floats", () => {
    expect(() => canonicalize({ x: 1.5 })).toThrow(/float/);
    expect(() => canonicalize([0.1])).toThrow(/float/);
  });

  it("rejects non-finite numbers", () => {
    expect(() => canonicalize({ x: Number.NaN })).toThrow();
    expect(() => canonicalize({ x: Infinity })).toThrow();
  });

  it("escapes strings the same as JSON.stringify", () => {
    const out = decode(canonicalize({ msg: 'hello "world"\nnewline' }));
    expect(out).toBe('{"msg":"hello \\"world\\"\\nnewline"}');
  });

  it("produces stable output regardless of input key order", () => {
    const a = canonicalize({ a: 1, b: 2, c: 3 });
    const b = canonicalize({ c: 3, b: 2, a: 1 });
    expect(a).toEqual(b);
  });

  it("encodes utf8 strings as bytes", () => {
    const out = canonicalize({ greet: "你好" });
    // We mainly check round-trip via decode here; the byte length
    // depends on the UTF-8 encoding being applied.
    expect(decode(out)).toBe('{"greet":"你好"}');
    expect(out).toEqual(utf8('{"greet":"你好"}'));
  });
});
