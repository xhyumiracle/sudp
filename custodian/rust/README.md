# sudp

> Rust implementation of the **Custodian** (`T`) role of the
> [Secret-Use Delegation Protocol](https://github.com/xhyumiracle/sudp).

[![crates.io](https://img.shields.io/crates/v/sudp.svg)](https://crates.io/crates/sudp)
[![docs.rs](https://img.shields.io/docsrs/sudp)](https://docs.rs/sudp)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)

The Custodian holds the secret-bearing sealed state `Σ` and dispatches
one authorized use at a time. It never persists reusable authority over
the secret: every redemption requires a fresh single-shot grant signed
by an Authorizer-side authenticator. The Requester (typically an LLM /
agent runtime) can be fully compromised without giving up `s` or any
reusable artifact derived from it.

Protocol overview, byte-anchored cross-language conformance, and a
runnable three-role demo live at the
[repo root](https://github.com/xhyumiracle/sudp). Formal definition:
[arXiv:2604.24920](https://arxiv.org/abs/2604.24920).

## Install

```toml
[dependencies]
sudp = "~0.1"
```

MSRV: **1.85** (transitive `base64ct` 1.8+ requires edition 2024).

## Minimal usage

```rust
use sudp::prelude::*;

// Standard primitive profile + WebAuthn as the authenticator.
let mut custodian: Custodian<StdPrimitives, WebAuthn> = Custodian::new("custodian-id");

// Phase I — build Σ₀ from an initial M and one enrolled passkey.
let sealed = custodian.setup(
    protected_state,    // ProtectedState (M₀)
    enrollment,         // WebAuthnEnrollment
    prf_salt,           // η_c, 32 bytes
    wrapping_key,       // W_c, derived at A from the PRF extension
    &auth_context,
)?;

// Phase II.1 — T issues a fresh r; A signs β = H(DS_bind ‖ r ‖ H(o)).
let r = custodian.issue_freshness();
// ... client sends the signed Grant back to T ...

// Phase II.3 — redeem.
let redeemed = custodian.redeem_grant(grant, &auth_context, &sealed, now_unix)?;

// Phase III.1 — use s_o inside T's boundary; R never sees it.
let response = custodian.execute_use(&redeemed, &sealed, |target, s_o| {
    Ok(call_external(target, s_o))
})?;
```

Runnable variants:

- `cargo run --example end_to_end` — single process, mock authenticator.
- [`tests/e2e.rs`](tests/e2e.rs) — adversarial cases (tampering, replay,
  rotation lockout, revocation).
- [`examples/protocol-demo/`](../../examples/protocol-demo/) at the repo
  root — full three-role flow over HTTP with the TypeScript Authorizer
  and Requester.

## Per-record sealing (per-item vaults)

For deployments that store a vault as **many independently-encrypted records**
(one ciphertext per item) instead of a single `SealedState` blob — the model
that makes multi-device concurrent writes safe — use the per-record codec
directly:

```rust
use sudp::{seal_record, unseal_record, SealCtx, StdPrimitives};

let ctx = SealCtx {
    domain:  "item",              // purpose separation ("item" / "keyset" / …)
    vault:   vault_id,            // anti cross-vault splice
    id:      &record_id,          // opaque; callers typically store HMAC_K(name)
    version: &seq.to_be_bytes(),  // opaque, monotonic-per-id ordering value
};
let sealed = seal_record::<StdPrimitives>(&k, &ctx, plaintext)?; // suite ‖ nonce ‖ ct ‖ tag
let opened = unseal_record::<StdPrimitives>(&k, &ctx, &sealed)?; // rejects any ctx mismatch
```

The crate builds the AEAD associated data from `SealCtx` and binds it to the
ciphertext, so a record can't be opened under a different vault / id / version /
domain. The per-record AEAD key is HKDF-derived from `k` under a dedicated label
(key separation from any `HMAC_K(name)` id derivation). Everything *above* the
codec is the caller's: id derivation, version comparison, conflict resolution,
tombstones, GC, the record set. `version` is **opaque** — a server-assigned
sequence + CAS, a version-vector, an HLC, or LWW all sit on top unchanged.
Binding `version` detects a version/ciphertext *mismatch*, not rollback; keep a
monotonic per-id version store and enforce freshness there.
`@sudp-protocol/authorizer` mirrors this as `sealRecord` / `unsealRecord`,
byte-anchored by shared conformance vectors.

## The `Custodian<S, A, F>` façade

```text
Custodian<S, A, F>
//        │  │  │
//        │  │  └── FreshnessStore  — `r`-token pool (in-memory, Redis, ...)
//        │  └───── Authenticator   — WebAuthn, HSM, mock-for-tests, ...
//        └──────── PrimitiveSuite  — Hash + Kdf + Aead + Wrap + Csprng
```

Phase methods:

| Phase | Methods |
|-------|---------|
| I  — setup / enroll / revoke | `setup`, `execute_enroll`, `execute_revoke` |
| II — grant request + redemption | `issue_freshness`, `build_conveyance`, `redeem_grant`, `redeem_batch` |
| III — bounded use | `execute_use`, `execute_export`, `execute_lifecycle` |

Wire types: `Operation`, `Grant<A>`, `RedeemedGrant<A>`, `SealedState`,
`ProtectedState`, `BatchOperations`, `BatchGrant<A>`. Per-record codec:
`SealCtx`, `seal_record`, `unseal_record`, `record_aad`.

## Feature flags

| Feature           | Default | Pulls in                                              |
|-------------------|---------|-------------------------------------------------------|
| `std-primitives`  | ✓       | `sha2`, `hkdf`, `chacha20poly1305`, `rand`            |
| `webauthn`        | ✓       | `p256`, ES256/P-256 assertion verifier                |
| `json-canonical`  | ✓       | reserved; JCS canonical encoder is always on          |
| `hpke`            | ✗       | `hpke`, `rand_core` 0.9; exposes `HpkeDhKem<…>`       |

Bring your own primitives:

```toml
sudp = { version = "0.1", default-features = false }
```

## Customizing primitives

Three swap granularities, pick whichever fits.

**1. Use the standard profile** — `StdPrimitives` bundles SHA-256,
HKDF-SHA-256, XChaCha20-Poly1305 (AEAD + AEAD-as-wrap), and `OsRng`.

```rust
let custodian: Custodian<StdPrimitives, WebAuthn> = Custodian::new("...");
```

**2. Replace a single primitive** — implement one trait, assemble a
`PrimitiveSuite`:

```rust
struct HsmAead;
impl Aead for HsmAead { /* delegate to your HSM */ }

struct MySuite;
impl PrimitiveSuite for MySuite {
    type Hash   = Sha256;                 // standard
    type Kdf    = HkdfSha256;             // standard
    type Aead   = HsmAead;                // custom
    type Wrap   = AeadWrap<HsmAead>;      // reuse the wrap shape
    type Csprng = OsCsprng;               // standard
}
```

**3. Bring your own everything** — implement every trait (FIPS-validated
stack, post-quantum experiment, AES-KW without AEAD, ...). The protocol
logic in `phases/` only sees `S::Hash`, `S::Aead`, etc. — no built-in
primitive is hardcoded.

The [`Authenticator`](src/primitives/auth.rs) trait is a separate axis
because it carries more associated types and is swapped much more often
than the crypto bundle (tests / HSMs / OS credential mediators). The
default `webauthn` feature ships ES256/P-256 with the PRF extension.

The freshness store is the third axis (`F: FreshnessStore`); default is
an in-memory pool, swap in a database-backed store as needed.

## Out of scope

- HTTP / transport (TLS 1.3, cross-device handshake).
- Tool-call → `Operation` compilation (per-tool adapter).
- Trusted rendering at `A` (the crate emits canonical bytes; UI is the
  deployment's job).
- Persistence of `SealedState` (atomicity is a deployment invariant).
- Rotation of the authority-bearing secret at `E` (deployment policy).

## License

Apache-2.0. See [LICENSE](../../LICENSE).
