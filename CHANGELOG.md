# Changelog

All notable changes to this crate are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html) — wire format and
trait shapes may still move before 1.0.

## [Unreleased]

### Added

- `execute_export_to_requester` (and `Custodian::execute_export_to_requester`):
  paper §5.6 III.2 ownership-transfer mode. Used when the recipient *is*
  the requester `R` (SaaS deployments where agent talks to the custodian
  over TLS and consumes `s_o` directly). **NOT ASU-preserving** — the
  deployment is responsible for (1) surfacing the operation as
  ownership-transfer in `U`'s authorization UI and (2) transporting the
  returned bytes over an authenticated confidential channel. The crate
  documents these obligations heavily but cannot enforce them.
- `Valid::check(now_unix, iat_skew_secs)`: per-`Valid` validity check
  so deployments can validate pre-built `Valid` values without round-
  tripping through a complete `Operation`. `Operation::check_validity`
  delegates to it.

### Changed

- `phases::grant::validate_op_against` no longer rejects
  `ActType::Export + bind.recipient = None`. The recipient-mode choice
  (KEM-sealed vs ownership-transfer) is now enforced by the dispatch
  function the caller picks: `execute_export` requires
  `recipient = Some`, `execute_export_to_requester` requires
  `recipient = None`.

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
- `xdevice` module: paper §7.2 cross-device confidentiality envelope —
  `derive_session_key`, `seal_grant`, `open_grant`. Caller supplies the
  shared secret (ECDH / X25519 / HSM) and `pk_T` trust establishment.
- `ActType::Custom(String)` plus `#[non_exhaustive]` for profile-defined
  dispatch types per paper §5.6 ("Extensibility of the dispatch
  vocabulary").
- Phase III.2 standard composition helpers: `seal_export` / `open_export`
  implementing `(K_d, ct_d) ← Encap(pk); k_d ← KDF(K_d; ⊥, H(o));
  δ ← Enc_{k_d}(s_o; H(o))`.
- Per-write rotation discipline with default peer-map recoverability.

### Security-relevant choices

- `RedeemedGrant` is consumed by value across all `execute_*` paths,
  enforcing paper §6.4 one-shot-execution at the type-system level.
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
  without going through `serde_json::Value`. Target plaintexts and peer
  wrapping keys no longer leak through non-zeroizing intermediates during
  serialization.
- `WrappingKey` and `TargetValue` zeroize their inner `Vec<u8>` on drop.
  `K` and `K'` are held in `Zeroizing<Vec<u8>>` while in the custodian
  boundary.
- AEAD-as-wrap binds `(credential_id, version)` as associated data via
  `WrapBinding`, implementing the defense-in-depth recommendation of
  paper §5.3.
- WebAuthn assertion verification uses constant-time comparison for
  `origin`, `challenge` (= β), and `rpIdHash`. ECDSA-P256 verify runs
  through the `p256` crate (constant-time).
- Cross-device envelope AEAD AD = `H(pk_U ‖ pk_T ‖ r)`; substitution of
  either ephemeral public key fails authentication.

[Unreleased]: https://github.com/xhyumiracle/sudp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xhyumiracle/sudp/releases/tag/v0.1.0
