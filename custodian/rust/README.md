# sudp

> **Secret-Use Delegation Protocol** — protocol-level secret use for agentic systems, in Rust.

`sudp` lets an autonomous requester *propose* a secret-backed operation, an Authorizer *authorize*
exactly that operation, and a custodian *perform* it — without the requester ever seeing
reusable authority over the secret. The unit of delegation is one **use**, not the secret.

```text
                  ┌─────────────────────────┐
                  │   Authorizer  A         │
                  │   (passkey on a device) │
                  └────────────┬────────────┘
                               │  signs β over (DS ‖ r ‖ H(o))
                               ▼
   ┌──────────────┐      ┌───────────────┐       ┌──────────────┐
   │ Requester R  │ ─o─▶ │  Custodian T  │ ─s─▶  │ Environment  │
   │   (agent)    │      │  (this crate) │       │      E       │
   │              │◀ρ────│ holds sealed Σ│       │              │
   └──────────────┘      └───────────────┘       └──────────────┘
```

`R` (the agent / LLM tool runtime) never receives the secret `s`. `T` only spends `s` on
operations `A` has authorized. Reusable authority does not cross `R`'s boundary.

---

## Status

Pre-1.0. MSRV 1.85 (driven by transitive `base64ct` 1.8+ which requires edition 2024). Wire format and trait shapes may move before the 1.0 cut.

- 19 unit + 22 end-to-end tests pass (incl. HPKE export, cross-device envelope, custom act-type extension, lifecycle rotate/enroll/revoke, strict-recipient export, cross-language β conformance with `@sudp/authorizer`).
- `cargo clippy --all-targets` is clean.
- `cargo check --no-default-features` builds.

## Try it

```bash
cargo run --example end_to_end
```

Walks through Phase I (setup) → Phase II (issue freshness `r`, sign β at `A`, redeem at
`T`) → Phase III (`use` inside `T`'s boundary), with a mock authenticator so you don't
need a real passkey to see the shape.

## Minimal usage

```rust
use sudp::prelude::*;

// Pick the standard primitive profile + WebAuthn as the authenticator.
let mut custodian: Custodian<StdPrimitives, WebAuthn> = Custodian::new("custodian-id");

// Phase I — build Σ₀ from an initial M and one enrolled passkey.
let sealed = custodian.setup(
    protected_state,           // ProtectedState (M₀)
    enrollment,                // WebAuthnEnrollment
    prf_salt,                  // η_c, 32 bytes
    wrapping_key,              // W_c, derived at A from the PRF extension
    &auth_context,             // AuthenticatorContext { rp_id, origin, require_uv }
)?;

// Phase II.1 — issue a fresh r token. A signs β = H(DS_bind ‖ r ‖ H(o)).
let r = custodian.issue_freshness();
// ... client computes β, gets σ from the authenticator, sends Grant ...

// Phase II.3 — redeem the grant.
let redeemed = custodian.redeem_grant(grant, &auth_context, &sealed, now_unix)?;

// Phase III.1 — use the secret inside T's boundary; R never sees it.
let response = custodian.execute_use(&redeemed, &sealed, |target, s_o| {
    /* call the environment with s_o; return only what o authorizes */
    Ok(call_external(target, s_o))
})?;
```

See [`examples/end_to_end.rs`](examples/end_to_end.rs) for a runnable variant and
[`tests/e2e.rs`](tests/e2e.rs) for adversarial cases (tampering, replay, rotation
lockout, revocation).

---

## Concepts

- **Operation** `o = (act, bind, valid)` — the canonical A↔T contract. `act` carries the
  semantic class (`use`, `export`, `write`, `rotate`, `enroll`, `revoke`, or profile-defined
  `Custom`), the `target`, and adapter-canonicalized scope.
- **Grant** `G = (o, r, cid, W*, σ*, opt)` — the one-shot authorization artifact. `σ*`
  binds `β = H(DS_bind ‖ r ‖ H(o))`; `W*` arrives over the confidential `A → T` leg.
- **Sealed state** `Σ = (C, {(cid, η, K̂)}, Reg, ver)` — what `T` persists. `Σ` alone is
  insufficient to recover `M`; an authenticator invocation is required.
- **Custodian** — façade over the three phases: `setup`, `issue_freshness`,
  `build_conveyance`, `redeem_grant`, `execute_use`, `execute_export`,
  `execute_lifecycle`, `execute_enroll`, `execute_revoke`.

## Extensions

| Extension | Module | Default? |
|-----------|--------|---|
| **Batch approve** — single σ over `ops = (o_1, …, o_n)` | `sudp::batch` | ✓ |
| **Lifecycle**: `Write` / `Rotate` / `Enroll` / `Revoke` | `Custodian::execute_*` | ✓ |
| **Conveyance payload** `(o, r, {(cid_c, η_c)})` | `Custodian::build_conveyance` | ✓ |
| **Recipient-protected export** — standard `Kem + Kdf + Aead` composition | `sudp::phases::consumption::{seal_export, open_export}` | ✓ (closure-based) |
| **HPKE-DHKEM backend** — `DhKemP256HkdfSha256` realising `Kem` | `sudp::primitives::HpkeDhKem` | feature `hpke` |
| **Cross-device envelope** — `k_xd = KDF(ss; r, DS_xd_enc ‖ pk_A ‖ pk_T)` + AEAD with `AD = H(pk_A ‖ pk_T ‖ r)` | `sudp::xdevice` | ✓ |
| **Custom act types** — `ActType::Custom(String)`; β/σ verification stays generic, deployment dispatches | `sudp::ActType::Custom` | ✓ |

### What the cross-device module gives you

The crate ships the **symmetric envelope** primitives — KDF stitching plus an AEAD
sealing layer with channel-binding AD over `(pk_A, pk_T, r)`. It does *not* ship the
ECDH key-agreement primitive (caller picks `p256::ecdh`, `x25519-dalek`, an HSM, etc.
and passes the shared secret `ss` in) nor the `pk_T` trust establishment (signature
under a long-term key, OOB QR, PAKE — all profile choices). See
[`tests/e2e.rs`](tests/e2e.rs)'s `xdevice_envelope_round_trips_grant` for the full
shape with `p256::ecdh`.

## Customizing primitives

The crate exposes each cryptographic interface as a trait under
[`sudp::primitives`](src/primitives/mod.rs). Concrete deployments pick the granularity that
fits.

### Granularity 1 — use the standard profile

```rust
let custodian: Custodian<StdPrimitives, WebAuthn> = Custodian::new("...");
```

`StdPrimitives` bundles:

| Role     | Type                       | Backed by               |
|----------|----------------------------|-------------------------|
| `Hash`   | `Sha256`                   | `sha2`                  |
| `Kdf`    | `HkdfSha256`               | `hkdf`                  |
| `Aead`   | `ChaCha20Poly1305`         | `chacha20poly1305`      |
| `Wrap`   | `AeadWrap<ChaCha20Poly1305>` | AEAD-as-wrap, AD = `DS_wrap ‖ cid ‖ ver` |
| `Csprng` | `OsCsprng`                 | `rand::rngs::OsRng`     |

### Granularity 2 — replace a single primitive

Write your own type implementing one trait (e.g. an HSM-backed AEAD), then assemble a
`PrimitiveSuite`:

```rust
struct HsmAead;
impl Aead for HsmAead { /* delegate to your HSM */ }

struct MySuite;
impl PrimitiveSuite for MySuite {
    type Hash   = Sha256;                  // standard
    type Kdf    = HkdfSha256;              // standard
    type Aead   = HsmAead;                 // custom
    type Wrap   = AeadWrap<HsmAead>;       // reuse the wrap shape
    type Csprng = OsCsprng;                // standard
}

let custodian: Custodian<MySuite, WebAuthn> = Custodian::new("...");
```

### Granularity 3 — bring your own everything

Implement every trait (e.g. for a FIPS-validated stack, post-quantum experiment, or pure
AES-KW key wrap without AEAD), and you control the entire crypto surface. The protocol
logic in `phases/` only sees `S::Hash`, `S::Aead`, etc. — no built-in primitive is
hardcoded.

### Authenticator is a separate axis

[`Authenticator`](src/primitives/auth.rs) is the *Authorizer-side tamper-resistant module* and
its verifier. It is **not** inside `PrimitiveSuite` because it carries four associated
types (`Enrollment`, `Assertion`, `PublicKey`, `Context`) and is swapped much more often
than crypto primitives — for tests, for HSMs that aren't WebAuthn, for OS-credential
mediators.

```rust
//                   ▼ crypto bundle    ▼ Authorizer-side authenticator
let custodian: Custodian<StdPrimitives, WebAuthn>     = Custodian::new("...");
let custodian: Custodian<StdPrimitives, MockForTests> = Custodian::new("...");
let custodian: Custodian<StdPrimitives, HsmBackend>   = Custodian::new("...");
```

WebAuthn (ES256 / P-256 with the PRF extension) is shipped as the default backend;
write your own by implementing `verify_enrollment` and `verify_assertion`.

### Freshness store is the third axis

`Custodian<S, A, F>`'s third parameter is the `r`-token store. The default is an
in-memory single-process pool; swap in a Redis-backed store, a database, or anything else
that implements [`FreshnessStore`](src/freshness.rs).

---

## Feature flags

| Feature           | Default | Pulls in                                            |
|-------------------|---------|-----------------------------------------------------|
| `std-primitives`  | ✓       | `sha2`, `hkdf`, `chacha20poly1305`, `rand`          |
| `webauthn`        | ✓       | `p256`, ES256/P-256 assertion verifier              |
| `json-canonical`  | ✓       | reserved; JCS canonical encoder is always on        |
| `hpke`            | ✗       | `hpke`, `rand_core` 0.9; exposes `HpkeDhKem<…>` for the `Kem` trait + `DhKemP256HkdfSha256` type alias |

Disable both default features and bring your own primitives:

```toml
sudp = { version = "0.1", default-features = false }
```

---

## What's in scope

- Abstract primitive traits and a standards-based default profile.
- `Operation`, `Grant`, `RedeemedGrant`, `SealedState`, `ProtectedState`, `BatchOperations`.
- Custodian façade for Phases I / II / III, batch grants, and lifecycle ops with per-write
  rotation (peer-map recoverability).
- WebAuthn assertion / enrollment verification.

## What's out of scope

- HTTP / transport (TLS 1.3, cross-device handshake — these belong in the deployment).
- Tool-call → `Operation` compilation (the adapter step is per-tool and lives outside the
  protocol core).
- Trusted rendering at `A` (the crate emits canonical bytes; UI rendering is the
  deployment's job).
- Persistence of `SealedState` (atomicity is a deployment invariant).
- Rotation of the authority-bearing secret at `E` (deployment policy parameter).

## Threat model in one paragraph

If the requester `R` is fully compromised (prompt injection, tool-side content, scratchpad
rewriting, runtime shim), it cannot read the secret `s`, cannot derive any reusable
artifact from `s`, cannot replay an old grant (single-use `r` consumed at redemption),
and cannot substitute an operation past authorization (any tampering with `o` changes `β`
and fails signature verification). It can at most propose adversarial operations to `T`
and ask `A` to approve them. `sudp` does *not* protect against `A` approving a
dangerous-but-correctly-rendered operation, trusted-rendering failures inside `A`'s
client, or runtime compromise of `T` itself.

---

## License

Apache-2.0. See [LICENSE](LICENSE).
