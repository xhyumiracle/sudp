# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · [SemVer](https://semver.org/).

## [Unreleased]

### Added

- Per-record seal/unseal — authorizer-side mirror of the Rust crate's per-item
  vault primitive: `sealRecord` / `unsealRecord` / `recordAad` / `deriveItemKey`,
  the `SealCtx` type, `DS_ITEM`, and `RECORD_SUITE_XCHACHA20POLY1305`. Byte-anchored
  against the Rust crate via shared conformance vectors (canonical AAD, HKDF item
  key, and sealed framing). Adds `u32beBytes` / `u64beBytes` byte helpers.

## [0.1.1] — 2026-05-23

### Added

- `computeBatchBinding(domain, r, ops)` — β over a batch, byte-aligned with the Rust crate's `compute_beta_from_canonical(domain, r, &BatchOperations(ops).canonical_bytes())`.
- Conformance vector pinning batch β against `sudp` Rust.

## [0.1.0] — 2026-05-22

Initial release. Carrier-agnostic Authorizer primitives (canonical JSON, β,
`deriveWrappingKey`, `wrap_ad`, `seal_ad`, `aeadSeal`/`aeadEncrypt`/`aeadOpen`,
`DS_BIND`/`DS_WRAP`/`DS_SEAL`) plus a `./webauthn` subpath (`prfToUserKey`,
`assertionToWire`). All primitives are byte-anchored against the Rust crate.
