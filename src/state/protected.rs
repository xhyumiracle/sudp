//! Decrypted protected state `M` (paper §5.2, §5.7).
//!
//! `M` is what `T` transiently materialises inside its trusted boundary after
//! Phase III.0. It contains:
//!
//! - the authority-bearing service secrets `s_o := M[target]`,
//! - the in-state peer map `Peer := {cid_c → W_c}` for multi-credential
//!   recoverability (paper §5.7 default policy),
//! - deployment-specific auxiliary data.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::grant::WrappingKey;
use crate::Result;

/// Peer map: `{cid_c → W_c}` (paper §5.7 default recoverability policy).
///
/// `BTreeMap` keys are base64 strings (deterministic ordering on the wire).
/// The values are wrapping keys for credentials other than the acting one;
/// Phase III.3 uses them to rewrap the new `K'` under each peer credential.
pub type PeerMap = BTreeMap<String, WrappingKey>;

/// `M`: the decrypted protected state, accessible only inside `T`'s trusted
/// boundary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtectedState {
    /// `M[target] = s_o`. Keys are target identifiers, values are raw secret
    /// bytes (e.g. an API key or signing key).
    #[serde(default)]
    pub targets: BTreeMap<String, TargetValue>,
    /// `Peer = {cid → W_c}`, used by Phase III.3 for multi-credential rewrap.
    #[serde(default)]
    pub peers: PeerMap,
    /// Deployment-specific auxiliary state (vault metadata, deployment hints,
    /// …). Out-of-scope of the protocol; the crate just preserves it.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub aux: serde_json::Value,
}

/// Authority-bearing service secret `s_o`. Held as a length-prefixed byte
/// vector inside `M` so the protocol layer can be opaque to the secret's
/// semantics (API key, OAuth token, signing key, …).
#[derive(Clone, Default, Serialize, Deserialize, Zeroize)]
#[serde(transparent)]
pub struct TargetValue(#[serde(with = "crate::wire::b64bytes")] pub Vec<u8>);

impl core::fmt::Debug for TargetValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TargetValue(<{} bytes redacted>)", self.0.len())
    }
}

impl TargetValue {
    /// Borrow the secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Construct from raw bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

impl Drop for TargetValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ProtectedState {
    /// New empty state. Used at Phase I.2 setup before any targets are added.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up `s_o := M[target]` (paper §5.6 III.0). Returns an error if the
    /// target is absent.
    pub fn target(&self, name: &str) -> Result<&[u8]> {
        self.targets
            .get(name)
            .map(|v| v.as_bytes())
            .ok_or_else(|| crate::Error::TargetNotFound(name.to_string()))
    }

    /// Insert or replace a target value.
    pub fn put_target(&mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) {
        self.targets
            .insert(name.into(), TargetValue::from_bytes(value));
    }

    /// Remove a target.
    pub fn remove_target(&mut self, name: &str) -> Option<TargetValue> {
        self.targets.remove(name)
    }

    /// Serialise to canonical bytes for sealing under `K`.
    pub fn to_canonical(&self) -> Result<Vec<u8>> {
        let v = serde_json::to_value(self)
            .map_err(|_| crate::Error::Encoding("ProtectedState→Value"))?;
        Ok(crate::canonical::canonicalize(&v))
    }

    /// Parse from canonical bytes (after Phase III.0 decryption of `C`).
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|_| crate::Error::Encoding("ProtectedState canonical parse"))
    }
}
