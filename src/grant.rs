//! `Grant` and `RedeemedGrant`.
//!
//! The grant is the protocol artefact representing user authorization of `o`:
//!
//! ```text
//!     G := (o, r, cid_{c*}, W*, σ*, opt)
//! ```
//!
//! After Phase II.3 validation, the custodian's internal representation drops
//! `r` and `σ*` (consumed) and keeps the redeemed form:
//!
//! ```text
//!     ρ := (o, cid_{c*}, W*, opt)
//! ```

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::operation::Operation;
use crate::primitives::Authenticator;

/// Wrapping key `W*` carried in a grant.
///
/// **Confidential leg.** `U` must transmit this to `T` over a channel that
/// guarantees confidentiality. Any party observing `W*` can
/// unwrap `K̂_{c*}` from sealed state and decrypt `M`.
///
/// Length is profile-defined (32 bytes for the standard XChaCha20-Poly1305
/// AEAD-as-wrap profile).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct WrappingKey(#[serde(with = "crate::wire::b64bytes")] pub Vec<u8>);

impl core::fmt::Debug for WrappingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WrappingKey(<{} bytes redacted>)", self.0.len())
    }
}

impl WrappingKey {
    /// Borrow the underlying bytes. Used by the crypto layer; callers outside
    /// the crate generally do not need this.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Construct from raw bytes (e.g. after the client-side derivation).
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

/// Optional grant payload — only populated for rotation-class operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrantOpt {
    /// `W*_next` derived in the same authenticator invocation from
    /// `η^next_{c*}` (, last paragraph).
    ///
    /// Required for any [`crate::ActType::is_rotation_class`] operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapping_key_next: Option<WrappingKey>,
}

/// One-shot authorization artefact transmitted from `U` to `T`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Grant<A: Authenticator> {
    /// Operation contract.
    pub o: Operation,
    /// Server-issued freshness token (32 raw bytes).
    #[serde(with = "serde_bytes")]
    pub r: Vec<u8>,
    /// Acting credential id `cid_{c*}` (raw bytes).
    #[serde(with = "serde_bytes")]
    pub credential_id: Vec<u8>,
    /// Wrapping key `W*` carried over the confidential `U→T` leg.
    pub wrapping_key: WrappingKey,
    /// Authorization evidence `σ*` (assertion bundle, encoded per
    /// `A::Assertion`).
    pub assertion: A::Assertion,
    /// Optional payload (rotation `W*_next`).
    #[serde(default)]
    pub opt: GrantOpt,
}

/// Phase II.3 output (custodian-internal, ).
///
/// `r` and `σ*` have been consumed. The redeemed grant is what Phase III
/// inputs.
#[derive(Debug)]
pub struct RedeemedGrant {
    /// The accepted operation `o`.
    pub o: Operation,
    /// Acting credential id `cid_{c*}` (raw bytes).
    pub credential_id: Vec<u8>,
    /// Wrapping key `W*` carried by the grant (consumed at Phase III.0).
    pub wrapping_key: WrappingKey,
    /// Optional rotation payload (`W*_next`).
    pub opt: GrantOpt,
}

impl<A: Authenticator> Clone for Grant<A>
where
    A::Assertion: Clone,
{
    fn clone(&self) -> Self {
        Self {
            o: self.o.clone(),
            r: self.r.clone(),
            credential_id: self.credential_id.clone(),
            wrapping_key: self.wrapping_key.clone(),
            assertion: self.assertion.clone(),
            opt: self.opt.clone(),
        }
    }
}

mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(v);
        b64.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        use base64::Engine;
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}
