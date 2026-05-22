//! Crate-level error type.

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// SUDP failure modes.
///
/// Errors are intentionally coarse-grained at the redemption boundary so as not
/// to leak which individual check (signature / binding / expiry / freshness)
/// failed; deployments needing finer telemetry can wrap this enum with their
/// own diagnostics.
#[derive(Debug, Error)]
pub enum Error {
    /// Phase II.3 step 1: `r` is absent from the freshness pool or has expired.
    #[error("freshness token unknown or expired")]
    FreshnessRejected,

    /// Operation `valid.expiry` has passed.
    #[error("operation expired")]
    OperationExpired,

    /// Operation `valid.iat` is too far in the future.
    #[error("operation iat in the future")]
    OperationIatSkew,

    /// `o.bind.redeemer` does not match this custodian's identity.
    #[error("operation redeemer mismatch")]
    RedeemerMismatch,

    /// Authorization evidence (signature over β) did not verify.
    #[error("authorization evidence did not verify")]
    AuthorizationInvalid,

    /// `credential_id` in the grant is not enrolled.
    #[error("unknown credential")]
    UnknownCredential,

    /// AEAD decryption of wrapped state / body / wrapped key failed.
    #[error("sealed-state decryption failed")]
    SealDecryptionFailed,

    /// The grant carried no `W*_next` for a rotation-class operation.
    #[error("rotation-class operation requires opt.wrapping_key_next")]
    MissingRotationKey,

    /// `o.bind.recipient` was unset on an export-class operation.
    #[error("export operation requires bind.recipient")]
    MissingRecipient,

    /// Attempted to revoke the credential that signed the very same grant.
    /// Paper-level fail-safe: the acting
    /// credential cannot be the target of its own revocation invocation;
    /// the user must authorize the revocation with a different credential.
    #[error("acting credential cannot revoke itself")]
    CannotRevokeSelf,

    /// Revocation would leave `Σ` with zero credentials, making the protected
    /// state permanently unrecoverable. Crate-level fail-safe.
    #[error("revocation would orphan the sealed state (last credential)")]
    WouldOrphanState,

    /// Batch grant contained more than one rotation-class operation. A single
    /// authenticator invocation produces a single `W*_next` and a single
    /// `K'`, so at most one rotation-class operation can be authorized per
    /// batch.
    #[error("batch must contain at most one rotation-class operation")]
    BatchMultipleRotationOps,

    /// Operation declared `multiplicity = Unbounded`. v0.1 implements only
    /// single-use semantics; multi-use session bookkeeping is deferred.
    #[error("multiplicity = Unbounded is not implemented in this version")]
    MultiplicityNotImplemented,

    /// A canonical-serialization path encountered a non-integer numeric
    /// value. Operation `scope` MUST NOT contain floats — `serde_json::Number`
    /// floating-point representations are not byte-for-byte reproducible
    /// across endpoints (NaN bit patterns, ±0, IEEE 754 round-trip), which
    /// would defeat operation binding.
    #[error("canonical encoding rejects float values")]
    CanonicalFloatRejected,

    /// Caller asked for a target that does not exist in the protected state.
    #[error("target not found in protected state: {0}")]
    TargetNotFound(String),

    /// A wire-format field was malformed (length, encoding, schema).
    #[error("malformed: {0}")]
    Malformed(&'static str),

    /// An invariant inside the crate was violated. Bug.
    #[error("internal invariant: {0}")]
    Internal(&'static str),

    /// Crypto primitive error surfaced from a backend (HKDF expand, AEAD, …).
    #[error("primitive: {0}")]
    Primitive(&'static str),

    /// Operation type does not support the requested dispatch path.
    #[error("operation type mismatch: {0}")]
    ActTypeMismatch(&'static str),

    /// A canonical-serialization step failed.
    #[error("canonical encoding: {0}")]
    Encoding(&'static str),
}
