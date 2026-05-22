# Protocol walkthrough — the three roles in motion

How **Requester R**, **Authorizer A**, and **Custodian T** cooperate to
perform one authorized secret use.

This file is the reading-order companion to the per-role implementations.
Code that demonstrates each role end-to-end lives next to the role's
package, and every byte-level shape A produces is locked against what T
expects (see [Cross-language alignment](#cross-language-alignment)).

## The three actors

- **Requester R** — an autonomous agent (LLM tool runtime, automated job)
  that proposes an operation `o`. May be fully compromised. Receives the
  result `ρ` of one authorized invocation, never the secret itself, never
  any reusable artifact.
- **Authorizer A** — the principal that approves `o` by signing
  `β = H(DS_BIND ‖ r ‖ H(canonical(o)))` with an authenticator. Typically
  a human pressing a passkey, but the role is species-neutral.
- **Custodian T** — the trusted process that holds the secret and only
  spends it on operations A has authorized. Persists sealed state `Σ`;
  `Σ` alone is insufficient to recover the protected state `M`.

## Data flow

Three phases. The diagrams show the bytes; the table beneath each phase
points at the code that produces or consumes them.

### Phase I — Setup (once per enrollment)

```
                   PRF / authenticator
                          │
                          ▼
                       y_c (32B)             ┐
                          │                  │  Authorizer side:
              HKDF(salt=prf_salt,            │  derives W_c, samples K,
                   info=DS_WRAP‖cid‖ver_be)  │  wraps K, seals M.
                          │                  │
                          ▼                  │
                       W_c (32B)             │
                          │                  │
        K (32B, random) ──┴─► AEAD-seal ──► K̂_c
        M (plaintext)       ─► AEAD-seal ──► ciphertext (under K)
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
| Persist `Σ` | sends to T | `Custodian::setup` builds `SealedState` |

### Phase II — Grant (per use)

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

### Phase III — Execution

```
   T receives Grant
   │
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
   │
   ▼
   R receives ρ (only what o authorized)
```

| Step | Custodian (Rust) |
|------|------------------|
| Validation + β recomputation | `phases::grant::redeem` |
| Unwrap `K` from `K̂_c` | `KeyWrap::unwrap` via `WrapBinding::to_canonical_ad()` |
| Open `M` under `K` | `Aead::open` with `seal_ad(version)` |
| Dispatch | `Custodian::execute_use` / `execute_export` / `execute_lifecycle` etc. |

R is structurally incapable of reading `s` once R is compromised: it has
no key material from any phase, the `r` it forwarded is single-shot, and
any tampering with `o` changes `H(o)`, changes `β`, and fails σ
verification at T.

## Runnable demonstrations

| Role focus | File | What it shows |
|------------|------|---------------|
| Custodian + mock Authorizer | [`custodian/rust/examples/end_to_end.rs`](custodian/rust/examples/end_to_end.rs) | Single-process Rust walk-through of all three phases with a deterministic mock authenticator. Run with `cargo run --example end_to_end`. |
| Authorizer side | [`authorizer/ts/test/protocol_flow.test.ts`](authorizer/ts/test/protocol_flow.test.ts) | TypeScript walk-through of Phase I + II producing each intermediate byte string. Run with `npm test`. |

## Cross-language alignment

Every byte string A produces and T expects MUST agree. The conformance
suite locks each pairwise primitive — and the role examples above use
exactly the same primitives, so any composite shape stays aligned by
construction.

| Surface | Rust anchor | TS anchor |
|---------|-------------|-----------|
| `canonical(o)` | `Operation::canonical_bytes` unit tests | `conformance.test.ts: canonical: nested ordering matches Rust` |
| `β` formula + `DS_BIND` | `beta_matches_ts_authorizer_conformance_vector` | `conformance.test.ts: β: matches Rust...` |
| `derive_wrapping_key` | `derive_wrapping_key_matches_ts_authorizer_conformance_vector` | `conformance.test.ts: deriveWrappingKey: matches Rust...` |
| AEAD encrypt (fixed nonce) | `aead_matches_ts_authorizer_conformance_vector` | `conformance.test.ts: aeadEncrypt: matches Rust...` |
| `wrap_ad` layout | `WrapBinding::to_canonical_ad` tests | `conformance.test.ts: wrap_ad: DS_WRAP ‖ cid ‖ ver_be` |
| `seal_ad` layout | `phases::setup::seal_ad` (used in setup tests) | `conformance.test.ts: seal_ad: DS_SEAL ‖ ver_be` |
| `WRAP_VERSION` ↔ `CURRENT_VERSION` | `state::CURRENT_VERSION = 1` | `conformance.test.ts: WRAP_VERSION matches Rust CURRENT_VERSION = 1` |

Run both halves to verify:

```bash
cd custodian/rust && cargo test
cd authorizer/ts  && npm test
```

CI runs both on every push. Either side failing means the cross-language
protocol invariant broke.

## What's out of scope here

- **Transport / wire**: this repo does not pick HTTP/RPC. R↔T and A↔T
  channels are deployment concerns. The bytes above travel over whatever
  the deployment chooses.
- **Authenticator-specific σ shape**: a real `assertion` field comes
  from WebAuthn / HSM / OS credential mediator; `@sudp/authorizer/webauthn`
  ships one such adapter, but the protocol is signer-agnostic.
- **Tool-call → `Operation` compilation**: the adapter that turns "the
  agent wants to call `send_email(...)`" into a canonical `Operation` is
  per-tool and lives outside the protocol core.
