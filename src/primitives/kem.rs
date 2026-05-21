//! Key encapsulation mechanism for recipient-protected extraction
//! (paper §5.6 III.2, §7 Table 1).
//!
//! The standard profile is HPKE (DHKEM-P256 / HKDF-SHA-256 / AEAD). This crate
//! exposes the trait so deployments needing export can plug HPKE in via the
//! `hpke` crate. The default ships without a built-in HPKE implementation to
//! avoid pulling in HPKE for deployments that only do `use` and `lifecycle`.

/// KEM-specific failure modes.
#[derive(Debug, thiserror::Error)]
pub enum KemError {
    /// Recipient public key is malformed.
    #[error("malformed recipient public key")]
    BadRecipientKey,
    /// Encapsulation failed at the backend layer.
    #[error("encapsulation failed")]
    EncapFailed,
    /// Decapsulation failed at the backend layer.
    #[error("decapsulation failed")]
    DecapFailed,
}

/// `(Encap, Decap)`: IND-CCA2 secure KEM.
///
/// `Encap` produces an ephemeral encapsulated key `ct_d` and a shared secret
/// `K_d`. `Decap` recovers `K_d` from `ct_d` under the recipient's secret key.
pub trait Kem {
    /// Recipient public key (opaque to the protocol).
    type PublicKey;
    /// Recipient secret key (opaque to the protocol; never seen by `T`).
    type SecretKey;

    /// Encapsulation: returns `(K_d, ct_d)`.
    fn encap(pk: &Self::PublicKey) -> Result<(Vec<u8>, Vec<u8>), KemError>;

    /// Decapsulation: recovers `K_d` from `ct_d` under `sk`.
    fn decap(sk: &Self::SecretKey, ct: &[u8]) -> Result<Vec<u8>, KemError>;
}
