import { describe, expect, it } from "vitest";
import { canonicalize, computeBinding, DS_BIND } from "../src/index.js";

const decode = (b: Uint8Array): string => new TextDecoder().decode(b);
const toHex = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

/**
 * Pinned conformance vectors. These shapes are what the Rust crate also
 * produces — any divergence here is a wire-incompatibility bug. Add a new
 * row whenever the canonical encoder or β formula gains a new code path.
 *
 * The vectors are intentionally literal (no generator), so a future drift
 * on either side fails loudly with a clear diff.
 */
describe("conformance vectors", () => {
  it("canonical: empty object", () => {
    expect(decode(canonicalize({}))).toBe("{}");
  });

  it("canonical: nested ordering", () => {
    const op = {
      act: { type: "use", target: "env.api_key", scope: {} },
      bind: { redeemer: "custodian-id" },
      valid: { iat: 1_700_000_000, multiplicity: "one" },
    };
    expect(decode(canonicalize(op))).toBe(
      '{"act":{"scope":{},"target":"env.api_key","type":"use"},"bind":{"redeemer":"custodian-id"},"valid":{"iat":1700000000,"multiplicity":"one"}}',
    );
  });

  it("canonical: array of objects keeps array order, sorts object keys", () => {
    expect(decode(canonicalize([{ b: 2, a: 1 }, { d: 4, c: 3 }]))).toBe(
      '[{"a":1,"b":2},{"c":3,"d":4}]',
    );
  });

  it("β: deterministic SHA-256 over (DS_BIND ‖ 0x00 ‖ r ‖ H(canonical(o)))", async () => {
    const r = new Uint8Array(32); // all-zero
    const op = {
      act: { type: "use", target: "env.api_key", scope: {} },
      bind: { redeemer: "custodian-id" },
      valid: { iat: 1_700_000_000, multiplicity: "one" },
    };
    const beta = await computeBinding(DS_BIND, r, op);
    // Anchor: this hex MUST match the Rust crate's canonical β for the
    // same inputs. If you regenerate it, also bump the Rust-side anchor
    // test in the same commit so the two sides stay locked.
    expect(beta.byteLength).toBe(32);
    expect(toHex(beta)).toMatchInlineSnapshot(
      `"6c43ba079b5316ac73e8f35e3ce59bfdefb9dee1fc964fcb39406c26169be954"`,
    );
  });
});
