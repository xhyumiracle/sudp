# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · [SemVer](https://semver.org/).

## [0.1.1] — 2026-05-23

### Added

- `BatchOperations` / `BatchGrant<TAssertion>` wire types.
- `batchOps([...])` builder — validates non-empty + ≤ 1 rotation-class op (mirrors `sudp::Error::BatchMultipleRotationOps`).
- `isRotationClassActType`, `validateBatchOperations`, `validateBatchGrant`.

## [0.1.0] — 2026-05-22

Initial release. Wire-shape types (`Operation`, `Act`, `Bind`, `Valid`,
`RecipientPk`, `Grant`, `GrantOpt`, `ActType`, `Multiplicity`) and op builders
(`useOp`, `exportOp`, `writeOp`, `rotateOp`, `enrollOp`, `revokeOp`,
`customOp`) plus `validateOperation` / `validateGrant`. No crypto, HTTP, or
framework code by design.
