import { describe, expect, it } from "vitest";
import {
  aeadEncrypt,
  canonicalize,
  computeBatchBinding,
  computeBinding,
  deriveWrappingKey,
  DS_BIND,
  DS_WRAP,
  sealAd,
  wrapBindingAd,
  WRAP_VERSION,
} from "../src/index.js";

const decode = (b: Uint8Array): string => new TextDecoder().decode(b);
const toHex = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

/**
 * Pinned conformance vectors against the Rust custodian crate.
 *
 * Every assertion in this file has a matching `assert_eq!` on the Rust side
 * (see `custodian/rust/src/beta.rs` and `custodian/rust/src/primitives/kdf.rs`).
 * If you change either side, change both — the two are intentionally
 * load-bearing against each other.
 *
 * Coverage:
 *  - canonical JSON encoder shapes (key sorting, nesting)
 *  - β formula and DS_BIND value (via beta.rs anchor)
 *  - deriveWrappingKey HKDF-info shape (via kdf.rs anchor)
 *  - AEAD-as-wrap raw encrypt with fixed nonce (via kdf.rs anchor)
 *  - wrap_ad / seal_ad byte layout (no Rust anchor needed — both sides
 *    construct from the same DS constants + u16-BE version)
 */
describe("conformance vectors", () => {
  // ─── canonical JSON ───────────────────────────────────────────────────

  it("canonical: empty object", () => {
    expect(decode(canonicalize({}))).toBe("{}");
  });

  it("canonical: nested ordering matches Rust's canonical_bytes", () => {
    const op = {
      act: { type: "use", target: "env.api_key", scope: {} },
      bind: { redeemer: "custodian-id" },
      valid: { iat: 1_700_000_000, multiplicity: "one" },
    };
    expect(decode(canonicalize(op))).toBe(
      '{"act":{"scope":{},"target":"env.api_key","type":"use"},"bind":{"redeemer":"custodian-id"},"valid":{"iat":1700000000,"multiplicity":"one"}}',
    );
  });

  it("canonical: array order kept, object keys sorted", () => {
    expect(decode(canonicalize([{ b: 2, a: 1 }, { d: 4, c: 3 }]))).toBe(
      '[{"a":1,"b":2},{"c":3,"d":4}]',
    );
  });

  // ─── β = SHA-256(DS_BIND ‖ r ‖ H(canonical(o))) ──────────────────────

  it("β: matches Rust's compute_beta_for_op for the same inputs", async () => {
    const r = new Uint8Array(32); // all-zero
    const op = {
      act: { type: "use", target: "env.api_key", scope: {} },
      bind: { redeemer: "custodian-id" },
      valid: { iat: 1_700_000_000, multiplicity: "one" },
    };
    const beta = await computeBinding(DS_BIND, r, op);
    expect(beta.byteLength).toBe(32);
    // Anchored against `beta_matches_ts_authorizer_conformance_vector`
    // in custodian/rust/src/beta.rs.
    expect(toHex(beta)).toBe(
      "6c43ba079b5316ac73e8f35e3ce59bfdefb9dee1fc964fcb39406c26169be954",
    );
  });

  // ─── Batch β = SHA-256(DS_BIND ‖ r ‖ H(canonical(ops))) ──────────────

  it("batch β: matches Rust's compute_beta_from_canonical over BatchOperations", async () => {
    const r = new Uint8Array(32); // all-zero
    const op = (target: string) => ({
      act: { type: "use", target, scope: {} },
      bind: { redeemer: "custodian-id" },
      valid: { iat: 1_700_000_000, multiplicity: "one" },
    });
    const ops = [op("env.api_key"), op("env.refresh_token")];
    const beta = await computeBatchBinding(DS_BIND, r, ops);
    expect(beta.byteLength).toBe(32);
    // Anchored against
    // `batch_beta_matches_ts_authorizer_conformance_vector`
    // in custodian/rust/src/beta.rs.
    expect(toHex(beta)).toBe(
      "e066d4be3f6761a995491222d7bb7896cc13944c1f460233e082b3f21f95059f",
    );
  });

  // ─── deriveWrappingKey: HKDF info = DS_WRAP ‖ cid ‖ ver_be ───────────

  it("deriveWrappingKey: matches Rust's derive_wrapping_key for the same inputs", async () => {
    const userKey = new Uint8Array(32).fill(0x22);
    const prfSalt = new Uint8Array(32).fill(0x33);
    const cid = new Uint8Array([10, 20, 30, 40]);
    const wc = await deriveWrappingKey(userKey, prfSalt, cid, 1);
    expect(wc.byteLength).toBe(32);
    // Anchored against
    // `derive_wrapping_key_matches_ts_authorizer_conformance_vector`
    // in custodian/rust/src/primitives/kdf.rs.
    expect(toHex(wc)).toBe(
      "957e05e935d84cebfa408361f358cb408956f845ddea025f38b83dccd491cd90",
    );
  });

  // ─── AEAD-as-wrap raw encrypt with fixed nonce ───────────────────────

  it("aeadEncrypt: matches Rust's ChaCha20Poly1305::encrypt for the same inputs", () => {
    const key = new Uint8Array(32).fill(0x11);
    const nonce = new Uint8Array(24).fill(0x22);
    const plaintext = new TextEncoder().encode("the lazy dog jumps over...");
    const cid = new Uint8Array(8).fill(0xaa);
    const ad = wrapBindingAd(cid, 1);
    const out = aeadEncrypt(key, nonce, plaintext, ad);
    // Anchored against `aead_matches_ts_authorizer_conformance_vector`
    // in custodian/rust/src/primitives/kdf.rs.
    expect(toHex(out)).toBe(
      "f70f822c30d89eedc5297bac9d13d48f42e4e3bb63fb88ca4e6581fb03f4812766f6b8776d301bef7135",
    );
  });

  // ─── wrap_ad / seal_ad byte layout ───────────────────────────────────

  it("wrap_ad: DS_WRAP ‖ cid ‖ ver_be (u16 big-endian)", () => {
    const cid = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const ad = wrapBindingAd(cid, 0x0102);
    // Equivalent of WrapBinding { credential_id: cid, version: 0x0102 }
    //   .to_canonical_ad() in custodian/rust/src/primitives/wrap.rs.
    expect(toHex(ad)).toBe(
      // hex("sudp/v1/wrap") = 73756470 2f76312f 77726170
      "73756470" + "2f76312f" + "77726170" + "01020304" + "0102",
    );
  });

  it("seal_ad: DS_SEAL ‖ ver_be (u16 big-endian)", () => {
    const ad = sealAd(WRAP_VERSION);
    // Equivalent of `phases::setup::seal_ad(CURRENT_VERSION)` in
    // custodian/rust/src/phases/setup.rs.
    expect(toHex(ad)).toBe(
      // hex("sudp/v1/seal") = 73756470 2f76312f 7365616c, ver = 0x0001
      "73756470" + "2f76312f" + "7365616c" + "0001",
    );
  });

  it("WRAP_VERSION matches Rust CURRENT_VERSION = 1", () => {
    expect(WRAP_VERSION).toBe(1);
  });

  it("DS_WRAP literal", () => {
    expect(decode(DS_WRAP)).toBe("sudp/v1/wrap");
  });
});
