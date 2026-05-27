import { describe, expect, it } from "vitest";
import {
  enrollOp,
  exportOp,
  isBuiltinActType,
  isRotationClassActType,
  revokeOp,
  rotateOp,
  useOp,
  validateBatchGrant,
  validateBatchOperations,
  validateGrant,
  validateOperation,
  writeOp,
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

describe("isRotationClassActType", () => {
  it("returns true for state-mutating built-ins", () => {
    for (const t of ["write", "rotate", "enroll", "revoke"]) {
      expect(isRotationClassActType(t)).toBe(true);
    }
  });

  it("returns false for non-rotation built-ins", () => {
    expect(isRotationClassActType("use")).toBe(false);
    expect(isRotationClassActType("export")).toBe(false);
  });

  it("returns false for custom strings (not rotation-class by default)", () => {
    expect(isRotationClassActType("co-sign")).toBe(false);
  });
});

describe("validateBatchOperations", () => {
  const base = { redeemer: "T", iat: 1 } as const;
  const u = (t: string) => useOp({ ...base, target: t });

  it("accepts a well-formed multi-op batch", () => {
    expect(() => validateBatchOperations([u("a"), u("b"), u("c")])).not.toThrow();
  });

  it("rejects empty batch", () => {
    expect(() => validateBatchOperations([])).toThrow(/at least one/);
  });

  it("rejects non-array", () => {
    expect(() => validateBatchOperations({} as unknown)).toThrow(/array/);
  });

  it("accepts exactly one rotation-class op alongside non-rotation ops", () => {
    expect(() => validateBatchOperations([
      u("a"),
      writeOp({ ...base, target: "cred", scope: { v: "new" } }),
      u("b"),
    ])).not.toThrow();
  });

  it("rejects two rotation-class ops in the same batch", () => {
    expect(() => validateBatchOperations([
      rotateOp({ ...base, target: "x" }),
      enrollOp({ ...base, target: "cred-2" }),
    ])).toThrow(/at most one rotation-class/);
  });

  it("rejects export without recipient inside batch", () => {
    // Build the bad op directly — exportOp() refuses to construct it.
    const badExport = {
      act: { type: "export", target: "x", scope: {} },
      bind: { redeemer: "T" },
      valid: { iat: 1, multiplicity: "one" },
    };
    expect(() => validateBatchOperations([u("a"), badExport as never]))
      .toThrow(/BatchOperations\[1\].*recipient/s);
  });

  it("annotates the offending index", () => {
    expect(() => validateBatchOperations([
      u("a"),
      u("b"),
      { act: { type: "use", target: "" }, bind: { redeemer: "T" }, valid: { iat: 1 } },
    ])).toThrow(/BatchOperations\[2\]/);
  });
});

describe("validateBatchGrant", () => {
  const ops = [
    useOp({ target: "a", redeemer: "T", iat: 1 }),
    useOp({ target: "b", redeemer: "T", iat: 1 }),
  ];
  const grant = {
    ops,
    r: "AAAA",
    credential_id: "BBBB",
    wrapping_key: "CCCC",
    assertion: { tag: "ZZZZ" },
  };

  it("accepts a well-formed batch grant", () => {
    expect(() => validateBatchGrant(grant)).not.toThrow();
  });

  it("rejects missing wrapping_key", () => {
    const bad = { ...grant };
    delete (bad as { wrapping_key?: unknown }).wrapping_key;
    expect(() => validateBatchGrant(bad)).toThrow(/wrapping_key/);
  });

  it("delegates batch-shape errors", () => {
    const bad = { ...grant, ops: [...ops, ops[0]!, rotateOp({ target: "x", redeemer: "T", iat: 1 }), enrollOp({ target: "y", redeemer: "T", iat: 1 })] };
    expect(() => validateBatchGrant(bad)).toThrow(/at most one rotation-class/);
  });
});
