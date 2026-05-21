//! `Operation` — the canonical U↔T contract (paper §5.4).
//!
//! An authorized operation is the tuple `o = (act, bind, valid)`:
//!
//! - `act = (type, target, scope)` — what is approved.
//! - `bind = (redeemer, recipient)` — who may redeem and who receives.
//! - `valid = (expiry)` — validity window.
//!
//! Freshness is **not** in `o`; it is supplied by the single-use `r` token at
//! Phase II.1 and commits to `o` implicitly through `β = H(DS_bind ‖ r ‖ H(o))`.

use serde::{Deserialize, Serialize};

use crate::Result;

/// Semantic class of the secret-backed action. Drives Phase III dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
}

impl ActType {
    /// True iff this act class mutates sealed state and therefore requires
    /// `W*_next` in [`crate::GrantOpt`] (paper §5.6 III.3, §5.7).
    pub fn is_rotation_class(self) -> bool {
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
    /// this from the tool-call adapter (paper §6.3).
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

/// Validity constraints.
///
/// Paper Definition 1 defines `valid := (expiry)`. The `iat` field here is a
/// **profile-level hardening guard**: the custodian rejects grants whose
/// claimed issue time is more than `iat_skew_secs` in the future (see
/// [`RedeemInputs::iat_skew_secs`](crate::phases::grant::RedeemInputs)). `iat`
/// is not part of the abstract protocol contract; profiles that don't want
/// the skew guard set `iat = 0` and rely solely on `exp` plus the freshness
/// token `r` for replay resistance.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Valid {
    /// Issued-at, unix seconds. Profile-level hardening only (see struct
    /// docs).
    pub iat: u64,
    /// Expiry, unix seconds. `None` means "no explicit expiry" — the
    /// custodian's own policy bounds still apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
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
    /// Time-window check. Rejects if `exp` is in the past or `iat` is more
    /// than `iat_skew_secs` in the future.
    pub fn check_validity(&self, now_unix: u64, iat_skew_secs: u64) -> Result<()> {
        if self.valid.iat > now_unix + iat_skew_secs {
            return Err(crate::Error::OperationIatSkew);
        }
        if let Some(exp) = self.valid.exp {
            if exp < now_unix {
                return Err(crate::Error::OperationExpired);
            }
        }
        Ok(())
    }

    /// Convenience: render as canonical bytes (paper §5.4).
    ///
    /// Both `U` and `T` must agree on these bytes. Built on the JCS-style
    /// encoder in [`crate::canonical`].
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let v =
            serde_json::to_value(self).map_err(|_| crate::Error::Encoding("Operation→Value"))?;
        Ok(crate::canonical::canonicalize(&v))
    }
}
