//! `Operation` — the canonical U↔T contract.
//!
//! An authorized operation is the tuple `o = (act, bind, valid)`:
//!
//! - `act = (type, target, scope)` — what is approved.
//! - `bind = (redeemer, recipient)` — who may redeem and who receives.
//! - `valid = (expiry, multiplicity)` — validity window and multiplicity bound.
//!
//! Freshness is **not** in `o`; it is supplied by the single-use `r` token at
//! Phase II.1 and commits to `o` implicitly through `β = H(DS_bind ‖ r ‖ H(o))`.

use serde::{Deserialize, Serialize};

use crate::Result;

/// Semantic class of the secret-backed action. Drives Phase III dispatch.
///
/// Marked `#[non_exhaustive]` so future canonical variants can be added
/// without a breaking change, and so external profiles can use the
/// [`Custom`](ActType::Custom) variant to extend the dispatch vocabulary
/// per the "Extensibility of the dispatch vocabulary" clause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ActType {
    /// Non-extracting consumption: spend the secret inside `T`. Phase III.1.
    Use,
    /// Recipient-protected extraction. Phase III.2.
    Export,
    /// Mutate the protected state. Phase III.3.
    Write,
    /// Rotate the state-encryption key without changing `M`. Phase III.3.
    Rotate,
    /// Add a credential. Phase III.3.
    Enroll,
    /// Remove a credential. Phase III.3.
    Revoke,
    /// Profile-defined dispatch type.
    ///
    /// The string is the profile-specific type name (e.g. `"co-sign"`,
    /// `"stream-decrypt"`). Custom types preserve β/σ verification at
    /// Phase II.3 unchanged; the deployment is responsible for Phase III
    /// dispatch — sudp's built-in `execute_use`/`execute_export`/
    /// `execute_lifecycle` will reject them with `ActTypeMismatch`.
    ///
    /// Custom types are *not* treated as rotation-class by default. A
    /// profile that needs a rotation-class custom type must either use one
    /// of the canonical rotation variants (Write/Rotate/Enroll/Revoke) or
    /// intercept the grant before sudp's redemption layer.
    Custom(String),
}

impl ActType {
    /// True iff this act class mutates sealed state and therefore requires
    /// `W*_next` in [`crate::GrantOpt`].
    ///
    /// Returns `false` for [`Self::Custom`]; see the variant docs.
    pub fn is_rotation_class(&self) -> bool {
        matches!(
            self,
            ActType::Write | ActType::Rotate | ActType::Enroll | ActType::Revoke
        )
    }
}

/// What is approved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Act {
    /// Semantic class of the action.
    #[serde(rename = "type")]
    pub kind: ActType,
    /// Identifier of the protected object inside `M` (e.g. `"env.api_key"`).
    pub target: String,
    /// Canonicalised operation-specific constraints. The deployment populates
    /// this from the tool-call adapter.
    #[serde(default)]
    pub scope: serde_json::Value,
}

/// Redemption binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bind {
    /// Identifier of the party entitled to redeem (typically `T`'s id).
    pub redeemer: String,
    /// Intended recipient public key for extracting deliveries. Absent for
    /// non-export operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<RecipientPk>,
}

/// Recipient public key carried in `bind.recipient`. Opaque to the protocol
/// core; interpreted by the deployment's KEM implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientPk {
    /// KEM algorithm identifier (e.g. `"hpke-p256-sha256-aes128gcm"`).
    pub alg: String,
    /// Base64 of the public key bytes.
    pub bytes: String,
}

/// Operation multiplicity bound.
///
/// The abstract protocol enforces the multiplicity bound `U` declares in
/// `o.valid`. The canonical values are `One` (single-use) and `Unbounded`
/// (multi-use session).
///
/// **v0.1 implements only `One`.** `Unbounded` operations are recognised
/// on the wire but rejected at redemption with
/// [`Error::MultiplicityNotImplemented`](crate::Error::MultiplicityNotImplemented),
/// because the multi-consumption bookkeeping under a single grant is
/// deferred to a later release. The type-level one-shot enforcement on
/// `RedeemedGrant` (by-value consumption at every `execute_*` site) is
/// the v0.1 expression of single-use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Multiplicity {
    /// Single-use: at most one consumption per redeemed grant.
    #[default]
    One,
    /// Unbounded multi-use. Not implemented in v0.1.
    Unbounded,
}

/// Validity constraints.
///
/// The `iat` field is a **profile-level hardening guard**: the custodian
/// rejects grants whose claimed issue time is more than `iat_skew_secs` in
/// the future (see
/// [`RedeemInputs::iat_skew_secs`](crate::phases::grant::RedeemInputs)).
/// `iat` is not part of the abstract protocol contract; profiles that don't
/// want the skew guard set `iat = 0` and rely solely on `exp` plus the
/// freshness token `r` for replay resistance.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Valid {
    /// Issued-at, unix seconds. Profile-level hardening only (see struct
    /// docs).
    pub iat: u64,
    /// Expiry, unix seconds. `None` means "no explicit expiry" — the
    /// custodian's own policy bounds still apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Operation multiplicity bound (`One` by default).
    #[serde(default)]
    pub multiplicity: Multiplicity,
}

impl Valid {
    /// Build a single-use validity window.
    pub fn single_use(iat: u64, exp: Option<u64>) -> Self {
        Self {
            iat,
            exp,
            multiplicity: Multiplicity::One,
        }
    }

    /// Time-window check. Rejects if `exp` is in the past or `iat` is more
    /// than `iat_skew_secs` in the future.
    ///
    /// Lives on `Valid` (rather than only on `Operation`) so deployments can
    /// validate pre-built `Valid` values (grant inspection, request
    /// pre-flight) without round-tripping through a complete `Operation`.
    /// Does **not** inspect `multiplicity` — that bound is enforced at
    /// redemption time by [`crate::phases::grant::validate_op_against`].
    pub fn check(&self, now_unix: u64, iat_skew_secs: u64) -> Result<()> {
        if self.iat > now_unix + iat_skew_secs {
            return Err(crate::Error::OperationIatSkew);
        }
        if let Some(exp) = self.exp {
            if exp < now_unix {
                return Err(crate::Error::OperationExpired);
            }
        }
        Ok(())
    }
}

/// The canonical operation tuple.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    /// `act`: what is approved.
    pub act: Act,
    /// `bind`: redemption binding.
    pub bind: Bind,
    /// `valid`: validity window.
    pub valid: Valid,
}

impl Operation {
    /// Time-window check; delegates to [`Valid::check`].
    pub fn check_validity(&self, now_unix: u64, iat_skew_secs: u64) -> Result<()> {
        self.valid.check(now_unix, iat_skew_secs)
    }

    /// Convenience: render as canonical bytes.
    ///
    /// Both `U` and `T` must agree on these bytes. Built on the JCS-style
    /// encoder in [`crate::canonical`], in **strict** mode — float values
    /// anywhere inside `act.scope` are rejected with
    /// [`Error::CanonicalFloatRejected`](crate::Error::CanonicalFloatRejected).
    /// Floats have no byte-reproducible canonical form across endpoints; if
    /// they reached `H(o)` they'd be a substitution vector. Integers,
    /// strings, booleans, nulls, arrays, and nested objects are fine.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let v =
            serde_json::to_value(self).map_err(|_| crate::Error::Encoding("Operation→Value"))?;
        crate::canonical::canonicalize_strict(&v)
    }
}
