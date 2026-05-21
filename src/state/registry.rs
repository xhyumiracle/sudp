//! `Reg = {cid_c → pk_c}` — credential public-key registry (paper §5.4 I.1).
//!
//! Reg is generic over the authenticator's public-key type so different
//! backends (WebAuthn, HSM, mock) can store their own canonical form.

use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::primitives::Authenticator;

/// Credential public-key registry.
///
/// Stored inside `Σ`. The serialised form keys by base64(credential_id) so the
/// on-disk layout is JSON-friendly.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Registry {
    /// `cid_c` (base64) → opaque public-key record encoded as JSON value.
    inner: BTreeMap<String, serde_json::Value>,
}

impl Registry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert `(cid, pk)`. Replaces any prior entry.
    pub fn insert<A: Authenticator>(
        &mut self,
        credential_id: &[u8],
        public_key: &A::PublicKey,
    ) -> crate::Result<()> {
        let key = base64::engine::general_purpose::STANDARD.encode(credential_id);
        let value = serde_json::to_value(public_key)
            .map_err(|_| crate::Error::Encoding("Authenticator::PublicKey→Value"))?;
        self.inner.insert(key, value);
        Ok(())
    }

    /// Look up the public-key record for a credential id.
    pub fn get<A: Authenticator>(
        &self,
        credential_id: &[u8],
    ) -> crate::Result<Option<A::PublicKey>> {
        let key = base64::engine::general_purpose::STANDARD.encode(credential_id);
        match self.inner.get(&key) {
            None => Ok(None),
            Some(v) => serde_json::from_value(v.clone())
                .map(Some)
                .map_err(|_| crate::Error::Encoding("Value→Authenticator::PublicKey")),
        }
    }

    /// Remove a credential. Returns true iff the entry was present.
    pub fn remove(&mut self, credential_id: &[u8]) -> bool {
        let key = base64::engine::general_purpose::STANDARD.encode(credential_id);
        self.inner.remove(&key).is_some()
    }

    /// Number of enrolled credentials.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff no credentials are enrolled.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}
