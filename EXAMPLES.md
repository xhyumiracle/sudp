# Protocol walkthrough — the three roles in motion

How **Requester R**, **Authorizer A**, and **Custodian T** cooperate to
perform one authorized secret use. Per-role definitions and threat model
live in the [top-level README](README.md) and
[`custodian/rust/README.md`](custodian/rust/README.md) — this file shows
the data flow.

## Phase I — Setup (once per enrollment)

```
                   PRF / authenticator
                          │
                          ▼
                       y_c (32B)
                          │
              HKDF(salt=prf_salt,
                   info=DS_WRAP‖cid‖ver_be)
                          │
                          ▼
                       W_c (32B)
                          │
        K (32B, random) ──┴─► AEAD-seal ──► K̂_c
        M (plaintext)       ─► AEAD-seal ──► ciphertext  (under K)
                                              │
                                              ▼
                                  Σ row in Custodian state:
                                  (cid, η_c, K̂_c, ciphertext, ver)
```

| Step | Authorizer (TS) | Custodian (Rust) |
|------|-----------------|------------------|
| Derive `y_c` | `prfToUserKey` (`@sudp/authorizer/webauthn`) | not derived T-side |
| Derive `W_c` | `deriveWrappingKey` | `primitives::derive_wrapping_key` (reference / test parity) |
| Wrap `K` | `aeadEncrypt(W_c, nonce, K, wrapBindingAd(cid, ver))` | persists `K̂_c` in `SealedCredential` |
| Seal `M` | `aeadEncrypt(K, nonce, M, sealAd(ver))` | persists `ciphertext` in `SealedState` |
| Build `Σ` | sends to T | `Custodian::setup` |

## Phase II — Grant (per use)

```
   R                A                              T
   │                                               │
   │── propose o ─────────────────────────────────►│
   │                                               │  generate r
   │                                               │
   │◄──────── conveyance (o, r, {(cid, η_c)}) ─────│
   │                │                              │
   │                ▼                              │
   │   canonical(o)                                │
   │   β = H(DS_BIND ‖ r ‖ H(canonical(o)))        │
   │   authenticator signs β → σ                   │
   │   derives W_c from y_c                        │
   │                │                              │
   │                ▼                              │
   │      Grant = (o, r, cid, W_c, σ, opt)         │
   │                │                              │
   │◄─── grant ─────┘                              │
   │                                               │
   │── grant ─────────────────────────────────────►│
```

| Step | Authorizer (TS) | Custodian (Rust) |
|------|-----------------|------------------|
| Issue `r` | — | `Custodian::issue_freshness` |
| Build conveyance | — | `Custodian::build_conveyance` |
| `canonical(o)` | `canonicalize(op)` | `Operation::canonical_bytes()` |
| Compute `β` | `computeBinding(DS_BIND, r, op)` | `beta::compute_beta_for_op(DS_BIND, r, op)` |
| Sign β → σ | authenticator (e.g. WebAuthn `.get` with `challenge = β`) | — |
| Wire shape | `assertionToWire(cred)` (`@sudp/authorizer/webauthn`) | — |

## Phase III — Execution

```
   T receives Grant
   │  validate iat/exp, multiplicity, redeemer, recipient
   │  recompute β' = H(DS_BIND ‖ r ‖ H(canonical(o)))
   │  verify σ against pk_c (registry lookup by cid)
   │  unwrap K from K̂_c using W_c with AAD = DS_WRAP ‖ cid ‖ ver_be
   │  decrypt ciphertext under K with AAD = DS_SEAL ‖ ver_be → M
   │  s_o := M[o.act.target]
   │
   │  dispatch by o.act.kind:
   │    Use     →  closure receives s_o, returns ρ
   │    Export  →  KEM-seal s_o for bind.recipient
   │    Write / Rotate / Enroll / Revoke → produce next Σ'
   ▼
   R receives ρ (only what o authorized)
```

| Step | Custodian (Rust) |
|------|------------------|
| Validation + β recomputation | `phases::grant::redeem` |
| Unwrap `K` from `K̂_c` | `KeyWrap::unwrap` via `WrapBinding::to_canonical_ad()` |
| Open `M` under `K` | `Aead::open` with `seal_ad(version)` |
| Dispatch | `Custodian::execute_use` / `execute_export` / `execute_lifecycle` etc. |

## Runnable demonstrations

| Role focus | File | Run with |
|------------|------|----------|
| Custodian + mock Authorizer | [`custodian/rust/examples/end_to_end.rs`](custodian/rust/examples/end_to_end.rs) | `cargo run --example end_to_end` |
| Authorizer side | [`authorizer/ts/test/protocol_flow.test.ts`](authorizer/ts/test/protocol_flow.test.ts) | `npm test` |

## Cross-language alignment

Every byte string A produces and T expects MUST agree. The conformance
suite locks each primitive — and the role examples above use exactly the
same primitives, so any composite shape stays aligned by construction.

| Surface | Rust anchor | TS anchor |
|---------|-------------|-----------|
| `canonical(o)` | `Operation::canonical_bytes` unit tests | `conformance.test.ts: canonical: nested ordering` |
| `β` + `DS_BIND` | `beta_matches_ts_authorizer_conformance_vector` | `conformance.test.ts: β: matches Rust...` |
| `derive_wrapping_key` | `derive_wrapping_key_matches_ts_authorizer_conformance_vector` | `conformance.test.ts: deriveWrappingKey: matches Rust...` |
| AEAD encrypt (fixed nonce) | `aead_matches_ts_authorizer_conformance_vector` | `conformance.test.ts: aeadEncrypt: matches Rust...` |
| `wrap_ad` layout | `WrapBinding::to_canonical_ad` tests | `conformance.test.ts: wrap_ad: DS_WRAP ‖ cid ‖ ver_be` |
| `seal_ad` layout | `phases::setup::seal_ad` (setup tests) | `conformance.test.ts: seal_ad: DS_SEAL ‖ ver_be` |
| `WRAP_VERSION` ↔ `CURRENT_VERSION` | `state::CURRENT_VERSION = 1` | `conformance.test.ts: WRAP_VERSION matches Rust...` |

Run both halves; CI does the same on every push:

```bash
cd custodian/rust && cargo test
cd authorizer/ts  && npm test
```

Either side failing means the cross-language protocol invariant broke.
