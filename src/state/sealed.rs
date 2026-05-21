//! On-disk sealed state representation.

use serde::{Deserialize, Serialize};

use super::registry::Registry;

/// Wrapping/encryption epoch identifier (`ver` in the paper).
pub type Version = u16;

/// Current wrapping epoch.
pub const CURRENT_VERSION: Version = 1;

/// Per-credential PRF salt `η_c` (paper §5.4 setup).
pub type PrfSalt = Vec<u8>;

/// Wrapped state key `K̂_c = Wrap_{W_c}(K)`.
pub type WrappedKey = Vec<u8>;

/// One credential's persistent entry inside `Σ`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedCredential {
    /// Credential id `cid_c` (raw bytes, base64-encoded on the wire).
    #[serde(with = "crate::wire::b64bytes")]
    pub credential_id: Vec<u8>,
    /// Current PRF salt `η_c`.
    #[serde(with = "crate::wire::b64bytes")]
    pub prf_salt: PrfSalt,
    /// Wrapped state key `K̂_c` (nonce ‖ ct ‖ tag, encoded per the AEAD profile).
    #[serde(with = "crate::wire::b64bytes")]
    pub wrapped_key: WrappedKey,
}

/// Persistent sealed state `Σ`.
///
/// `read`/`write_atomic` are deliberately not provided here — atomicity
/// (paper §5.6 III.3) is a deployment concern; the crate exposes typed
/// (de)serialisation only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedState {
    /// Wrapping epoch.
    pub version: Version,
    /// `Reg = {cid_c → pk_c}` for assertion verification.
    pub registry: Registry,
    /// `{(cid_c, η_c, K̂_c)}` for each enrolled credential.
    pub credentials: Vec<SealedCredential>,
    /// `C = Enc_K(M; DS_seal ‖ ver)`.
    #[serde(with = "crate::wire::b64bytes")]
    pub ciphertext: Vec<u8>,
}

impl SealedState {
    /// Locate the entry for `credential_id` (raw bytes).
    pub fn find_credential(&self, credential_id: &[u8]) -> Option<&SealedCredential> {
        self.credentials
            .iter()
            .find(|c| c.credential_id == credential_id)
    }

    /// Iterator over enrolled credential ids. Useful at Phase II.1 to build
    /// the conveyance `{(cid_c, η_c)}` payload.
    pub fn credential_iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.credentials
            .iter()
            .map(|c| (c.credential_id.as_slice(), c.prf_salt.as_slice()))
    }
}
