/**
 * Protocol-flow walkthrough — the Authorizer side, end to end.
 *
 * This file is both a **runnable example** and a **conformance test**. It
 * walks the Authorizer (`A`) through the same three-phase scenario the Rust
 * `examples/end_to_end.rs` walks through from the Custodian (`T`) side:
 *
 *   Phase I.  Setup  — Authorizer derives `y_c → W_c`, wraps the state key
 *                       `K` under `W_c`, seals the protected state `M`
 *                       under `K`. The outputs become the per-credential
 *                       fields of the Custodian's persistent `SealedState`.
 *
 *   Phase II. Grant  — Custodian issues a fresh `r`. Authorizer computes
 *                       canonical(o), β = H(DS_BIND ‖ r ‖ H(canonical(o))),
 *                       and assembles the Grant artifact the Custodian will
 *                       redeem. (Signing β is the authenticator's job and
 *                       is out of scope for this package — a real flow uses
 *                       a WebAuthn `navigator.credentials.get(...)` call
 *                       with `challenge = β`.)
 *
 *   Phase III. Use   — Custodian-side; see `examples/end_to_end.rs` in the
 *                       Rust crate. The Custodian unwraps `K` with `W_c`,
 *                       opens `M`, extracts `s_o`, runs the action.
 *
 * Every intermediate byte string asserted below is byte-locked against the
 * Rust side: change either side and this test, plus its Rust twin, fail
 * together. See the top-level README for the protocol context and the
 * cross-language alignment table.
 */

import { describe, expect, it } from "vitest";
import {
  aeadEncrypt,
  canonicalize,
  computeBinding,
  deriveWrappingKey,
  DS_BIND,
  sealAd,
  utf8,
  wrapBindingAd,
  WRAP_VERSION,
} from "../src/index.js";

const toHex = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

describe("protocol flow (Authorizer side)", () => {
  // ─── Fixed scenario inputs ────────────────────────────────────────────
  //
  // A real deployment supplies these from: WebAuthn (y_c via PRF, cid via
  // assertion), CSPRNG (prf_salt, K, AEAD nonces), and the tool-call
  // adapter (the Operation). Here they are pinned so the test is
  // reproducible.

  const userKey = new Uint8Array(32).fill(0x22); // y_c
  const prfSalt = new Uint8Array(32).fill(0x33); // η_c
  const credentialId = new Uint8Array([10, 20, 30, 40]); // cid_c
  const stateKey = new Uint8Array(32).fill(0x77); // K (state-encryption key)
  const aeadNonce = new Uint8Array(24).fill(0x22); // deterministic for the vector

  // Plaintext "protected state" M. The Custodian only ever sees `Σ`
  // (the sealed form) at rest; M is only reconstructed under
  // authorizer-driven `W_c`.
  const protectedState = new TextEncoder().encode(
    '{"env.api_key":"the-actual-secret"}',
  );

  // The operation R asks A to authorize.
  const op = {
    act: { type: "use", target: "env.api_key", scope: {} },
    bind: { redeemer: "custodian-id" },
    valid: { iat: 1_700_000_000, multiplicity: "one" },
  };

  // Phase II.1 freshness from the Custodian (pretend the Custodian
  // already issued it). All-zero `r` keeps the test reproducible — a real
  // Custodian samples 32 random bytes from a CSPRNG.
  const r = new Uint8Array(32);

  // ─── Phase I — Setup ──────────────────────────────────────────────────

  it("derives W_c with the canonical SUDP info shape", async () => {
    const wc = await deriveWrappingKey(userKey, prfSalt, credentialId, WRAP_VERSION);
    expect(wc.byteLength).toBe(32);
    expect(toHex(wc)).toBe(
      "957e05e935d84cebfa408361f358cb408956f845ddea025f38b83dccd491cd90",
    );
  });

  it("wraps K under W_c with AAD = DS_WRAP ‖ cid ‖ ver_be", async () => {
    const wc = await deriveWrappingKey(userKey, prfSalt, credentialId, WRAP_VERSION);
    const wrapAd = wrapBindingAd(credentialId, WRAP_VERSION);
    // Use deterministic nonce so the test asserts on stable bytes.
    const wrapped = aeadEncrypt(wc, aeadNonce, stateKey, wrapAd);
    // 32-byte plaintext → 32-byte ciphertext + 16-byte tag = 48 bytes
    expect(wrapped.byteLength).toBe(48);
    // The hex below is the K̂_c bytes the Custodian persists in Σ.
    expect(toHex(wrapped)).toBe(
      "1654a17cee894637be9b32a9ea9c50e0bea0c2e21df3062f7325914b007f0ab7" +
        "7883c77743184e2cd6b669f1f32fab45",
    );
  });

  it("seals M under K with AAD = DS_SEAL ‖ ver_be", async () => {
    const sealedBody = aeadEncrypt(stateKey, aeadNonce, protectedState, sealAd(WRAP_VERSION));
    // |M| = 35 bytes → ciphertext+tag = 35 + 16 = 51 bytes
    expect(sealedBody.byteLength).toBe(protectedState.byteLength + 16);
    expect(toHex(sealedBody)).toBe(
      "f2b573289d94f83c5bf89c38c1552a6837ec280c7f00134ad7d84847f285f7" +
        "ecb8c489e9ee4fa3166df14ae365fe73fb132018",
    );
  });

  // ─── Phase II — Grant construction ────────────────────────────────────

  it("computes canonical(o) and β for the operation", async () => {
    const canonicalOp = canonicalize(op);
    expect(new TextDecoder().decode(canonicalOp)).toBe(
      '{"act":{"scope":{},"target":"env.api_key","type":"use"},"bind":{"redeemer":"custodian-id"},"valid":{"iat":1700000000,"multiplicity":"one"}}',
    );

    const beta = await computeBinding(DS_BIND, r, op);
    expect(toHex(beta)).toBe(
      "6c43ba079b5316ac73e8f35e3ce59bfdefb9dee1fc964fcb39406c26169be954",
    );
  });

  it("assembles the wire shape of a Grant artifact", async () => {
    // The Custodian's `Grant<Auth>` (Rust) accepts these fields:
    //   o, r, credential_id, wrapping_key, assertion, opt
    //
    // `assertion` is authenticator-specific (a WebAuthn `PublicKeyCredential`
    // assertion bundle, an HSM signature blob, etc.). This package does NOT
    // produce `assertion` — that's the Authenticator's job (see the
    // `@sudp/authorizer/webauthn` subpath for the WebAuthn adapter that
    // extracts assertion bytes after `navigator.credentials.get`).

    const wc = await deriveWrappingKey(userKey, prfSalt, credentialId, WRAP_VERSION);

    const grant = {
      o: op,
      // r typically arrives base64-encoded over the wire; bytes here for
      // illustration.
      r: Array.from(r),
      credential_id: Array.from(credentialId),
      wrapping_key: Array.from(wc),
      // assertion would be: { credentialId, authenticatorData, clientDataJSON, signature }
      // produced by the WebAuthn ceremony with `challenge = β`.
      assertion: "<authenticator-specific>",
      opt: null,
    };

    // The Custodian-side `redeem_grant` (Rust) recomputes β, verifies the
    // assertion against the credential's stored public key, looks up the
    // credential's sealed K̂_c, unwraps it with grant.wrapping_key (== W_c
    // above), and uses K to decrypt the sealed body. If any of the bytes
    // above are wrong by a single bit, redemption fails with
    // `AuthorizationInvalid` or `SealDecryptionFailed`.

    expect(grant.wrapping_key).toHaveLength(32);
    expect(grant.r).toHaveLength(32);
    expect(grant.credential_id).toEqual([10, 20, 30, 40]);
  });
});
