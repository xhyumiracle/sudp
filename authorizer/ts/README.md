# @sudp-protocol/authorizer

> Authorizer-side primitives for **SUDP** — the Secret-Use Delegation Protocol.

The Authorizer is the party that authorizes a secret-backed operation by
signing the binding hash `β = SHA-256(DS_BIND ‖ r ‖ H(canonical(o)))`
with an authenticator. This package ships the carrier-agnostic crypto the
Authorizer needs, plus an optional WebAuthn adapter.

The Rust counterpart that runs in the Custodian is the
[`sudp` crate](../../custodian/rust/) in the same repository. Both sides
must agree byte-for-byte on canonical encoding, β, the AEAD-as-wrap AAD
shapes, and the wrap-key derivation.

## Layout

```
@sudp-protocol/authorizer            ← carrier-agnostic protocol primitives
  canonicalize, sha256,
  computeBinding, computeBatchBinding,
  deriveWrappingKey, wrapBindingAd, sealAd,
  aeadSeal, aeadOpen, aeadEncrypt, base64url helpers,
  sealRecord, unsealRecord, recordAad, deriveItemKey,   ← per-record (per-item) seal
  DS_BIND / DS_WRAP / DS_SEAL / DS_ITEM constants

@sudp-protocol/authorizer/webauthn   ← WebAuthn-specific adapter
  prfToUserKey(prfOutput) → 32-byte y_c
  assertionToWire(assertion) → wire-shape assertion
```

Other authenticator realisations (YubiKey static, secure-enclave, HSM,
mock) bring their own adapters and do **not** touch the WebAuthn subpath.
The core remains agnostic of how `y_c` was produced.

## Usage sketch

```ts
import {
  computeBinding,
  DS_BIND,
  deriveWrappingKey,
  wrapBindingAd,
  aeadSeal,
} from "@sudp-protocol/authorizer";
import { prfToUserKey, assertionToWire } from "@sudp-protocol/authorizer/webauthn";

// 1) Authorizer-side: compute the binding hash β.
const beta = await computeBinding(DS_BIND, rFreshness, operation);

// 2) Run the WebAuthn ceremony with `beta` as the challenge. The PRF
//    extension returns raw bytes — turn them into the 32-byte y_c.
const cred = (await navigator.credentials.get({
  publicKey: {
    challenge: beta,
    extensions: { prf: { eval: { first: prfSalt } } },
    /* ... rpId, allowCredentials, userVerification: "required", etc. */
  } as PublicKeyCredentialRequestOptions,
})) as PublicKeyCredential;

const prfOut = new Uint8Array(
  (cred.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } })
    .prf!.results!.first!,
);
const yc = await prfToUserKey(prfOut);

// 3) Derive W_c and use it to wrap key material destined for the custodian.
const Wc = await deriveWrappingKey(yc, prfSalt, credentialId);
const wrapped = aeadSeal(Wc, plaintext, wrapBindingAd(credentialId));

// 4) Ship `{ assertionToWire(cred), wrapped, ... }` to the custodian as
//    part of the grant.
```

For batch grants, swap `computeBinding` for `computeBatchBinding(DS_BIND, r, ops)` — same math, one signature covers `ops = (o_1, …, o_n)`.

For **per-item vaults** (a vault stored as many independently-encrypted records
instead of one blob), seal/open a single record with `sealRecord(k, ctx, pt)` /
`unsealRecord(k, ctx, sealed)`, where `ctx: SealCtx` is `{ domain, vault, id,
version }`. sudp binds `ctx` into the AEAD AAD (anti cross-vault / cross-id /
version-mismatch); the record body, id derivation, and conflict resolution are
the caller's. Byte-identical to the Rust crate's `seal_record` — see the
[conformance map](../../README.md#cross-language-alignment).

## End-to-end protocol walkthrough

For how this package fits with the Rust Custodian and the Requester
across all three phases:

- Runnable, three-process demo over HTTP:
  [`../../examples/protocol-demo/`](../../examples/protocol-demo/).
- Byte-level conformance map: the [top-level
  README](../../README.md#cross-language-alignment).
- Authorizer-side walkthrough as a conformance test:
  [`test/protocol_flow.test.ts`](test/protocol_flow.test.ts).

## Status

Pre-1.0, alongside the Rust crate. Wire format and trait shapes may move
before the 1.0 cut. See the
[top-level README](https://github.com/xhyumiracle/sudp) and the
[Rust crate's CHANGELOG](../../custodian/rust/CHANGELOG.md).

## License

Apache-2.0. See [LICENSE](../../LICENSE).
