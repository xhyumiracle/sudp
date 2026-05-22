import { describe, expect, it } from "vitest";
import {
  isBuiltinActType,
  useOp,
  validateGrant,
  validateOperation,
} from "../src/index.js";

describe("validateOperation", () => {
  const valid = useOp({ target: "x", redeemer: "T", iat: 1 });

  it("accepts well-formed Operation", () => {
    expect(() => validateOperation(valid)).not.toThrow();
  });

  it("rejects non-object", () => {
    expect(() => validateOperation(null)).toThrow();
    expect(() => validateOperation("op")).toThrow();
    expect(() => validateOperation([])).toThrow();
  });

  it("rejects missing act", () => {
    const bad = { ...valid };
    delete (bad as { act?: unknown }).act;
    expect(() => validateOperation(bad)).toThrow(/act/);
  });

  it("rejects empty act.target", () => {
    const bad = { ...valid, act: { ...valid.act, target: "" } };
    expect(() => validateOperation(bad)).toThrow(/target/);
  });

  it("rejects empty bind.redeemer", () => {
    const bad = { ...valid, bind: { redeemer: "" } };
    expect(() => validateOperation(bad)).toThrow(/redeemer/);
  });

  it("rejects export without recipient", () => {
    const bad = { ...valid, act: { ...valid.act, type: "export" as const } };
    expect(() => validateOperation(bad)).toThrow(/recipient/);
  });

  it("accepts export with well-formed recipient", () => {
    const good = {
      ...valid,
      act: { ...valid.act, type: "export" as const },
      bind: {
        redeemer: "T",
        recipient: { alg: "x", bytes: "AAAA" },
      },
    };
    expect(() => validateOperation(good)).not.toThrow();
  });

  it("rejects negative iat", () => {
    const bad = { ...valid, valid: { ...valid.valid, iat: -1 } };
    expect(() => validateOperation(bad)).toThrow(/iat/);
  });

  it("rejects unknown multiplicity", () => {
    const bad = { ...valid, valid: { ...valid.valid, multiplicity: "many" } };
    expect(() => validateOperation(bad)).toThrow(/multiplicity/);
  });

  it("accepts multiplicity 'unbounded' structurally (sudp rejects later)", () => {
    const ok = { ...valid, valid: { ...valid.valid, multiplicity: "unbounded" as const } };
    expect(() => validateOperation(ok)).not.toThrow();
  });
});

describe("validateGrant", () => {
  const op = useOp({ target: "x", redeemer: "T", iat: 1 });
  const grant = {
    o: op,
    r: "AAAA",
    credential_id: "BBBB",
    wrapping_key: "CCCC",
    assertion: { credentialId: "BBBB", signature: "ZZZZ" },
  };

  it("accepts a well-formed grant", () => {
    expect(() => validateGrant(grant)).not.toThrow();
  });

  it("rejects missing wrapping_key", () => {
    const bad = { ...grant };
    delete (bad as { wrapping_key?: unknown }).wrapping_key;
    expect(() => validateGrant(bad)).toThrow(/wrapping_key/);
  });

  it("rejects missing assertion", () => {
    const bad = { ...grant };
    delete (bad as { assertion?: unknown }).assertion;
    expect(() => validateGrant(bad)).toThrow(/assertion/);
  });

  it("delegates Operation shape errors", () => {
    const bad = { ...grant, o: { ...grant.o, act: { ...grant.o.act, target: "" } } };
    expect(() => validateGrant(bad)).toThrow(/target/);
  });
});

describe("isBuiltinActType", () => {
  it("returns true for built-ins", () => {
    for (const t of ["use", "export", "write", "rotate", "enroll", "revoke"]) {
      expect(isBuiltinActType(t)).toBe(true);
    }
  });

  it("returns false for custom strings", () => {
    expect(isBuiltinActType("co-sign")).toBe(false);
    expect(isBuiltinActType("stream-decrypt")).toBe(false);
  });
});
