import { describe, expect, it } from "vitest";
import { computeBinding, DS_BIND, sha256 } from "../src/index.js";

describe("computeBinding", () => {
  const r = new Uint8Array(32).fill(0xab);
  const op = {
    act: { type: "use", target: "env.api_key", scope: {} },
    bind: { redeemer: "T", recipient: null },
    valid: { iat: 1_700_000_000, exp: null, multiplicity: "one" },
  };

  it("produces a 32-byte digest", async () => {
    const beta = await computeBinding(DS_BIND, r, op);
    expect(beta.byteLength).toBe(32);
  });

  it("is deterministic for the same inputs", async () => {
    const a = await computeBinding(DS_BIND, r, op);
    const b = await computeBinding(DS_BIND, r, op);
    expect(a).toEqual(b);
  });

  it("changes when the operation changes", async () => {
    const a = await computeBinding(DS_BIND, r, op);
    const b = await computeBinding(DS_BIND, r, { ...op, act: { ...op.act, target: "env.other" } });
    expect(a).not.toEqual(b);
  });

  it("changes when r changes", async () => {
    const a = await computeBinding(DS_BIND, r, op);
    const b = await computeBinding(DS_BIND, new Uint8Array(32).fill(0xcd), op);
    expect(a).not.toEqual(b);
  });

  it("changes when the domain changes", async () => {
    const a = await computeBinding(DS_BIND, r, op);
    const b = await computeBinding(new TextEncoder().encode("sudp/v1/other"), r, op);
    expect(a).not.toEqual(b);
  });

  it("sha256 of empty input matches the well-known constant", async () => {
    const h = await sha256(new Uint8Array(0));
    const hex = Array.from(h).map((x) => x.toString(16).padStart(2, "0")).join("");
    expect(hex).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});
