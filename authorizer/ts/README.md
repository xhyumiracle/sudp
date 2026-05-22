# @sudp/authorizer

> Authorizer-side primitives for **SUDP** — the Secret-Use Delegation Protocol.

The Authorizer is the party that authorizes a secret-backed operation by
signing the binding hash `β = SHA-256(DS_BIND ‖ 0x00 ‖ r ‖ H(canonical(o)))`
with an authenticator. This package ships the carrier-agnostic crypto the
Authorizer needs, plus an optional WebAuthn adapter.

The Rust counterpart that runs in the Custodian is the
[`sudp` crate](../../custodian/rust/) in the same repository. Both sides
must agree byte-for-byte on canonical encoding, β, the AEAD-as-wrap AAD
shapes, and the wrap-key derivation.

## Layout

```
@sudp/authorizer            ← carrier-agnostic protocol primitives
  canonicalize, sha256, computeBinding,
  deriveWrappingKey, wrapBindingAd, sealAd,
  aeadSeal, aeadOpen, base64url helpers,
  DS_BIND / DS_WRAP / DS_SEAL constants

@sudp/authorizer/webauthn   ← WebAuthn-specific adapter
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
} from "@sudp/authorizer";
import { prfToUserKey, assertionToWire } from "@sudp/authorizer/webauthn";

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

## Why a separate package?

Until v0.1, every SUDP deployment manually re-implemented the canonical
encoder, β formula, and AAD shapes on the Authorizer side, kept in
byte-for-byte sync with the Rust crate by hand. That works until it
doesn't — silent drift is the failure mode. This package is the single
source of truth for the TS side, paired with a conformance suite that
checks it agrees with the Rust crate on golden vectors.

## End-to-end protocol walkthrough

For how this package fits with the Rust custodian across all three
phases — including a byte-level conformance map — see
[**EXAMPLES.md**](../../EXAMPLES.md) at the repo root. A complete
Authorizer-side walkthrough that doubles as a conformance test lives in
[`test/protocol_flow.test.ts`](test/protocol_flow.test.ts).

## Status

Pre-1.0, alongside the Rust crate. Wire format and trait shapes may move
before the 1.0 cut. See the
[top-level README](https://github.com/xhyumiracle/sudp) and the
[Rust crate's CHANGELOG](../../custodian/rust/CHANGELOG.md).

## License

Apache-2.0. See [LICENSE](../../LICENSE).
