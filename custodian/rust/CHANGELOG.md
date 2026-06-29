# Changelog

All notable changes to this crate are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html) — wire format and
trait shapes may still move before 1.0.

## [Unreleased]

### Added

- Cross-language batch-β conformance vector pinning `H(canonical(ops))` against `@sudp-protocol/authorizer`'s `computeBatchBinding`.
- `primitives::derive_wrapping_key<K: Kdf>(user_key, prf_salt, credential_id, version)`:
  convenience helper that produces the per-credential wrapping key
  `W_c = KDF(y_c; prf_salt, DS_WRAP ‖ credential_id ‖ ver_be)`. Matches the
  AEAD-as-wrap AAD layout, so deployments converge on the same shape on
  both ends. SUDP itself does not derive `W_c` (it arrives in the grant);
  this helper is for the Authorizer realisation that needs to produce it.
  `@sudp-protocol/authorizer`'s TypeScript `deriveWrappingKey` is byte-aligned with
  this function and verified by a shared conformance vector.
- AEAD-as-wrap raw-encrypt cross-language conformance vector pinning
  `ChaCha20Poly1305::encrypt(key, nonce, plaintext, ad)` against
  `@sudp-protocol/authorizer`'s `aeadEncrypt`.
- `Multiplicity` enum on `Valid` (`One` / `Unbounded`, default `One`).
  The abstract protocol enforces a multiplicity bound declared in
  `o.valid`; v0.1 implements only single-use (`One`). `Unbounded` is
  recognised on the wire but rejected at redemption with
  `Error::MultiplicityNotImplemented` — multi-use session bookkeeping
  under a single grant is deferred to a later release.
- `Valid::single_use(iat, exp)` helper constructor for the common
  single-use case.
- `Valid::check(now_unix, iat_skew_secs)`: per-`Valid` validity check so
  deployments can validate pre-built `Valid` values without round-
  tripping through a complete `Operation`. `Operation::check_validity`
  delegates to it.

### Removed

- `execute_export_to_requester` (and the `Custodian` façade method).
  `Export` operations now strictly require `bind.recipient = Some(pk)`,
  matching the abstract protocol's recipient-bound delivery contract.
  Deployments needing ownership-transfer-style flows (caller wants raw
  `s_o`) generate an ephemeral keypair, act as their own recipient,
  decap server-side, and forward the plaintext over their own
  confidential transport. This puts the "should the secret leave T's
  boundary" decision squarely on the deployment, rather than encoding
  it as a crate-level flag.

### Changed

- `phases::grant::validate_op_against` now enforces `Export →
  bind.recipient = Some(pk)` (paired with the removal above) and
  rejects `multiplicity = Unbounded`.
- **`β` is now domain-parametric.** `compute_beta`, `compute_beta_from_canonical`,
  and `compute_beta_for_op` take `domain: &[u8]` as their first argument
  instead of hardcoding `DS_BIND`. The default SUDP profile passes
  `DS_BIND` explicitly at the call site (built-in custodian redemption
  and batch verification both do this). Deployments that need
  pairwise-disjoint domains (distinct setup vs. standard ceremonies,
  etc.) pass their own domain bytes — any per-deployment separators
  (e.g. trailing `0x00`) are folded into the domain value itself, so
  the formula stays `H(domain ‖ r ‖ H(o))` on every call site.
- Terminology: party formerly called "User" (symbol `U`) is now
  consistently the **Authorizer** (symbol `A`) across crate-internal
  docs and identifiers. The on-the-wire grant shape is unchanged; this
  is purely a naming alignment with the protocol literature, where
  "User" was overloaded with the product-level end-user concept.
  WebAuthn-specific terms (`User Verification`, `User Present`) keep
  their FIDO-canonical spelling.

## [0.1.0] — 2026-05-21

Initial release.

### Added

- Abstract primitive traits: `Hash`, `Kdf`, `Aead`, `KeyWrap` (with typed
  `WrapBinding`), `Kem`, `Csprng`, `Authenticator`. Bundled via
  `PrimitiveSuite`.
- Standard primitive profile (`StdPrimitives`): SHA-256, HKDF-SHA-256,
  XChaCha20-Poly1305, AEAD-as-wrap, OS CSPRNG.
- Protocol types: `Operation { act, bind, valid }`, `Grant<A>`,
  `RedeemedGrant`, `SealedState`, `ProtectedState`, `BatchOperations`,
  `BatchGrant<A>`, `RedeemedBatch`.
- `Custodian<S, A, F>` façade for Phase I (`setup`), Phase II.1
  (`issue_freshness`, `build_conveyance`), Phase II.3 (`redeem_grant`,
  batch `redeem_batch`), and Phase III dispatch (`open`, `execute_use`,
  `execute_export`, `execute_lifecycle`, `execute_enroll`,
  `execute_revoke`).
- WebAuthn realisation of `Authenticator` (ES256/P-256 + PRF extension)
  under the default `webauthn` feature.
- HPKE-DHKEM realisation of `Kem` (`HpkeDhKem<K>` with
  `DhKemP256HkdfSha256` type alias) under the optional `hpke` feature.
- `xdevice` module: cross-device confidentiality envelope —
  `derive_session_key`, `seal_grant`, `open_grant`. Caller supplies the
  shared secret (ECDH / X25519 / HSM) and `pk_T` trust establishment.
- `ActType::Custom(String)` plus `#[non_exhaustive]` for profile-defined
  dispatch types per the "Extensibility of the dispatch vocabulary"
  clause.
- Phase III.2 standard composition helpers: `seal_export` / `open_export`
  implementing `(K_d, ct_d) ← Encap(pk); k_d ← KDF(K_d; ⊥, H(o));
  δ ← Enc_{k_d}(s_o; H(o))`.
- Per-write rotation discipline with default authenticator-map recoverability.

### Changed

- **Renamed `ProtectedState` fields and value type** for first-glance clarity:
  `peers` → `authenticators` (type alias `PeerMap` → `AuthenticatorMap`),
  `targets` → `secrets`, and value type `TargetValue` → `SecretValue`; accessors
  `target()` / `put_target()` / `remove_target()` →
  `secret()` / `put_secret()` / `remove_secret()`. The operation-side
  `Act.target` identifier is unchanged. This renames the sealed-state canonical
  JSON keys (`peers` → `authenticators`, `targets` → `secrets`), so states
  sealed by earlier code will not parse — a wire-format break, acceptable
  pre-1.0 with no migration path (re-seal from source).

### Security-relevant choices

- `RedeemedGrant` is consumed by value across all `execute_*` paths,
  enforcing one-shot-execution at the type-system level.
- `execute_revoke` refuses self-revocation (`CannotRevokeSelf`) and any
  revoke that would leave `Σ` with zero credentials (`WouldOrphanState`).
- `redeem_batch` rejects batches containing more than one rotation-class
  operation (`BatchMultipleRotationOps`) — a single authenticator
  invocation produces a single `W*_next` / `K'`.
- `Operation::canonical_bytes` and `BatchOperations::canonical_bytes`
  reject floating-point values in any nested position
  (`CanonicalFloatRejected`); floats have no byte-reproducible canonical
  form across endpoints and would otherwise be a substitution vector
  against `H(o)`.
- `ProtectedState::to_canonical` writes directly to a `Zeroizing<Vec<u8>>`
  without going through `serde_json::Value`. Secret plaintexts and authenticator
  wrapping keys no longer leak through non-zeroizing intermediates during
  serialization.
- `WrappingKey` and `SecretValue` zeroize their inner `Vec<u8>` on drop.
  `K` and `K'` are held in `Zeroizing<Vec<u8>>` while in the custodian
  boundary.
- AEAD-as-wrap binds `(credential_id, version)` as associated data via
  `WrapBinding`, implementing the defense-in-depth recommendation for
  AEAD-as-wrap profiles.
- WebAuthn assertion verification uses constant-time comparison for
  `origin`, `challenge` (= β), and `rpIdHash`. ECDSA-P256 verify runs
  through the `p256` crate (constant-time).
- Cross-device envelope AEAD AD = `H(pk_A ‖ pk_T ‖ r)`; substitution of
  either ephemeral public key fails authentication.

[Unreleased]: https://github.com/xhyumiracle/sudp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xhyumiracle/sudp/releases/tag/v0.1.0
