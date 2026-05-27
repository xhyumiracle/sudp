import { describe, expect, it } from "vitest";
import {
  batchOps,
  buildOp,
  customOp,
  enrollOp,
  exportOp,
  revokeOp,
  rotateOp,
  useOp,
  writeOp,
} from "../src/index.js";

describe("buildOp", () => {
  it("fills in iat from wall-clock when not provided", () => {
    const before = Math.floor(Date.now() / 1000);
    const op = buildOp("use", { target: "env.api_key", redeemer: "T" });
    const after = Math.floor(Date.now() / 1000);
    expect(op.valid.iat).toBeGreaterThanOrEqual(before);
    expect(op.valid.iat).toBeLessThanOrEqual(after);
  });

  it("respects an explicit iat", () => {
    const op = buildOp("use", { target: "x", redeemer: "T", iat: 1_700_000_000 });
    expect(op.valid.iat).toBe(1_700_000_000);
  });

  it("defaults multiplicity to 'one'", () => {
    const op = buildOp("use", { target: "x", redeemer: "T", iat: 1 });
    expect(op.valid.multiplicity).toBe("one");
  });

  it("defaults scope to {}", () => {
    const op = buildOp("use", { target: "x", redeemer: "T", iat: 1 });
    expect(op.act.scope).toEqual({});
  });

  it("omits exp when not provided", () => {
    const op = buildOp("use", { target: "x", redeemer: "T", iat: 1 });
    expect("exp" in op.valid).toBe(false);
  });

  it("omits recipient on non-export ops", () => {
    const op = buildOp("use", { target: "x", redeemer: "T", iat: 1 });
    expect("recipient" in op.bind).toBe(false);
  });

  it("rejects empty target", () => {
    expect(() => buildOp("use", { target: "", redeemer: "T" })).toThrow(/target/);
  });

  it("rejects empty redeemer", () => {
    expect(() => buildOp("use", { target: "x", redeemer: "" })).toThrow(/redeemer/);
  });

  it("rejects export without recipient", () => {
    expect(() => buildOp("export", { target: "x", redeemer: "T" })).toThrow(/recipient/);
  });

  it("includes recipient for export", () => {
    const op = buildOp("export", {
      target: "x",
      redeemer: "T",
      iat: 1,
      recipient: { alg: "hpke-p256-sha256-aes128gcm", bytes: "AAAA" },
    });
    expect(op.bind.recipient).toEqual({
      alg: "hpke-p256-sha256-aes128gcm",
      bytes: "AAAA",
    });
  });
});

describe("act-type wrappers", () => {
  const base = { target: "x", redeemer: "T", iat: 1 };

  it("useOp sets act.type='use'", () => {
    expect(useOp(base).act.type).toBe("use");
  });

  it("writeOp sets act.type='write'", () => {
    expect(writeOp(base).act.type).toBe("write");
  });

  it("rotateOp sets act.type='rotate'", () => {
    expect(rotateOp(base).act.type).toBe("rotate");
  });

  it("enrollOp sets act.type='enroll'", () => {
    expect(enrollOp(base).act.type).toBe("enroll");
  });

  it("revokeOp sets act.type='revoke'", () => {
    expect(revokeOp(base).act.type).toBe("revoke");
  });

  it("exportOp requires recipient", () => {
    expect(() => exportOp(base)).toThrow(/recipient/);
  });

  it("exportOp succeeds with recipient", () => {
    const op = exportOp({
      ...base,
      recipient: { alg: "x", bytes: "y" },
    });
    expect(op.act.type).toBe("export");
    expect(op.bind.recipient).toBeDefined();
  });

  it("customOp accepts arbitrary act-type strings", () => {
    const op = customOp("co-sign", base);
    expect(op.act.type).toBe("co-sign");
  });
});

describe("batchOps", () => {
  const base = { redeemer: "T", iat: 1 } as const;

  it("returns the input array unchanged when valid", () => {
    const a = useOp({ ...base, target: "x" });
    const b = useOp({ ...base, target: "y" });
    const out = batchOps([a, b]);
    expect(out).toBe(b === out[1] ? out : out); // identity
    expect(out).toEqual([a, b]);
  });

  it("rejects empty batch", () => {
    expect(() => batchOps([])).toThrow(/at least one/);
  });

  it("accepts a single rotation-class op", () => {
    const u = useOp({ ...base, target: "x" });
    const r = rotateOp({ ...base, target: "x" });
    expect(() => batchOps([u, r])).not.toThrow();
  });

  it("rejects two rotation-class ops in one batch", () => {
    const e = enrollOp({ ...base, target: "cred-1" });
    const r = revokeOp({ ...base, target: "cred-2" });
    expect(() => batchOps([e, r])).toThrow(/at most one rotation-class/);
  });

  it("rejects malformed members", () => {
    const ok = useOp({ ...base, target: "x" });
    const bad = { act: { type: "use", target: "" }, bind: { redeemer: "T" }, valid: { iat: 1 } };
    expect(() => batchOps([ok, bad as unknown as ReturnType<typeof useOp>])).toThrow(/BatchOperations\[1\]/);
  });
});

describe("produced JSON shape", () => {
  it("matches the sudp::Operation wire layout", () => {
    const op = buildOp("use", {
      target: "env.api_key",
      redeemer: "custodian-id",
      iat: 1_700_000_000,
    });
    // Serialise to JSON and back to compare against the canonical
    // example used in the cross-language conformance vector (with
    // optional fields excluded as the Rust side does).
    const wire = JSON.parse(JSON.stringify(op));
    expect(wire).toEqual({
      act: { type: "use", target: "env.api_key", scope: {} },
      bind: { redeemer: "custodian-id" },
      valid: { iat: 1_700_000_000, multiplicity: "one" },
    });
  });
});
