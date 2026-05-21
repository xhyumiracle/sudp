# sudp

The **Secret-Use Delegation Protocol** — a protocol-level answer to capability-constrained
secret use for agentic systems.

`sudp` is a Rust implementation of the SUDP abstract protocol: the unit of delegation is the
*use* of a secret for one specific authorized operation `o`, not the secret itself. The
requester is delegated the right to **cause** an authorized use; the custodian is delegated
the right to **perform** that single use; reusable authority never crosses the requester
boundary.

This crate provides the protocol-native interface — operations, grants, the three protocol
phases, batch approval, and lifecycle (rotate/enroll/revoke/write) — over abstract
cryptographic traits and a standards-based default profile (HKDF-SHA-256 / XChaCha20-Poly1305 /
AEAD-as-wrap / WebAuthn with PRF extension).

## What's in scope

- Abstract primitive traits: `Hash`, `Kdf`, `Aead`, `KeyWrap`, `Kem`, `Csprng`, `Authenticator`.
- Standard primitive realisations behind `default-features`.
- Protocol types: `Operation`, `Grant`, `RedeemedGrant`, `SealedState`, `ProtectedState`,
  `BatchOperations`.
- Three phases as a `Custodian` façade: setup → grant validation → consumption dispatch.
- Lifecycle operations with per-write rotation discipline (§5.7).
- WebAuthn implementation of `Authenticator` (feature `webauthn`, on by default).

## What's out of scope (caller's responsibility)

- HTTP / transport (TLS 1.3, cross-device handshake).
- Tool-call → `Operation` compilation (adapter step, §6.3).
- Trusted rendering at `U` (the crate emits canonical bytes; UI rendering is the deployment's
  job).
- Persistence of `SealedState` (atomic write semantics required by §5.6 III.3).
- Authority-bearing secret rotation at `E` (deployment policy parameter).

## Quick taste

```rust,no_run
use sudp::prelude::*;

let mut custodian = Custodian::<WebAuthn, StdPrimitives>::new();

// Phase I: build initial sealed state with one enrolled passkey.
let sealed = custodian.setup(/* initial M */, /* first credential */)?;

// Phase II.1: agent requests authorization for operation o.
let r = custodian.issue_freshness();
let beta = compute_binding(DomainSeparator::Bind, &r, &operation);

// ... client computes σ = Sig_sk(β), derives W*, posts Grant ...

// Phase II.3: redeem.
let redeemed = custodian.redeem_grant(&grant, &webauthn_ctx)?;

// Phase III: dispatch by act type.
let response = custodian.execute_use(&redeemed, &sealed, |target, s_o| {
    /* call the environment with s_o */
    Ok(())
})?;
```

See `tests/` and `examples/` for end-to-end flows.

## Status

Pre-1.0. Wire format and trait shapes may move before the 1.0 cut.

## License

Apache-2.0.
