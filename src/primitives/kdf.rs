//! HKDF-style extract-then-expand KDF.

use crate::Result;

/// `KDF`: HKDF-style extract-then-expand with explicit domain separation in
/// `info`.
///
/// : `KDF(ikm; salt, info)`. The protocol passes domain-separation
/// labels through `info`, so concrete realisations MUST treat `info` as a
/// distinguisher between contexts (HKDF-SHA-256 already does).
pub trait Kdf {
    /// One-shot derivation. `okm` length determines output size.
    fn derive(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()>;

    /// Convenience returning a fixed-size 32-byte derivation.
    fn derive_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        Self::derive(ikm, salt, info, &mut out)?;
        Ok(out)
    }
}

/// HKDF-SHA-256 implementation of [`Kdf`] ( Table 1).
#[cfg(feature = "std-primitives")]
#[cfg_attr(docsrs, doc(cfg(feature = "std-primitives")))]
pub struct HkdfSha256;

#[cfg(feature = "std-primitives")]
impl Kdf for HkdfSha256 {
    fn derive(ikm: &[u8], salt: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
        let salt_opt = if salt.is_empty() { None } else { Some(salt) };
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(salt_opt, ikm);
        hk.expand(info, okm)
            .map_err(|_| crate::Error::Primitive("HKDF-SHA-256 expand"))
    }
}
