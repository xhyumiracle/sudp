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

/// HKDF-SHA-256 implementation of [`Kdf`] (standard profile, Table 1).
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

/// Derive the per-credential wrapping key `W_c` from an Authorizer-side
/// user-key `y_c` (32 bytes), using the canonical SUDP info shape that
/// mirrors the AEAD-as-wrap AAD:
///
/// ```text
///     W_c = KDF(y_c; prf_salt, DS_WRAP ‖ credential_id ‖ ver_be)
/// ```
///
/// This is a convenience helper. SUDP itself does not derive `W_c` — the
/// custodian receives it in the grant — but the default AEAD-as-wrap profile
/// pairs naturally with this info shape (the same label structure as
/// [`crate::primitives::WrapBinding::to_canonical_ad`]), so deployments that
/// don't have a strong opinion converge on it. The Authorizer-side
/// realisation in `@sudp/authorizer` produces byte-identical output.
pub fn derive_wrapping_key<K: Kdf>(
    user_key: &[u8],
    prf_salt: &[u8],
    credential_id: &[u8],
    version: u16,
) -> Result<[u8; 32]> {
    use crate::primitives::domain::DS_WRAP;
    let mut info = Vec::with_capacity(DS_WRAP.len() + credential_id.len() + 2);
    info.extend_from_slice(DS_WRAP);
    info.extend_from_slice(credential_id);
    info.extend_from_slice(&version.to_be_bytes());
    K::derive_32(user_key, prf_salt, &info)
}

#[cfg(all(test, feature = "std-primitives"))]
mod tests {
    use super::*;

    /// Cross-language conformance anchor. The same inputs fed into
    /// `@sudp/authorizer`'s `deriveWrappingKey` MUST produce the same 32
    /// bytes. If you regenerate this hex, also update the matching inline
    /// snapshot in `authorizer/ts/test/conformance.test.ts` in the same
    /// commit so the two sides stay locked.
    #[test]
    fn derive_wrapping_key_matches_ts_authorizer_conformance_vector() {
        let user_key = [0x22u8; 32];
        let prf_salt = [0x33u8; 32];
        let cid = [10u8, 20, 30, 40];
        let wc = derive_wrapping_key::<HkdfSha256>(&user_key, &prf_salt, &cid, 1).unwrap();
        let hex: String = wc.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "957e05e935d84cebfa408361f358cb408956f845ddea025f38b83dccd491cd90"
        );
    }

    /// AEAD-as-wrap byte-for-byte fixture: given a fixed key, nonce,
    /// plaintext, and AAD shape, sealing must produce the exact bytes
    /// `@sudp/authorizer`'s `aeadEncrypt` produces for the same inputs.
    #[test]
    fn aead_matches_ts_authorizer_conformance_vector() {
        use crate::primitives::{aead::Aead, ChaCha20Poly1305};
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 24];
        let plaintext = b"the lazy dog jumps over...";
        // wrapBindingAd(credentialId = [0xAA; 8], version = 0x0001)
        // = DS_WRAP ‖ [0xAA; 8] ‖ [0x00, 0x01]
        let mut ad = Vec::new();
        ad.extend_from_slice(crate::primitives::domain::DS_WRAP);
        ad.extend_from_slice(&[0xAAu8; 8]);
        ad.extend_from_slice(&1u16.to_be_bytes());

        let ct = ChaCha20Poly1305::encrypt(&key, &nonce, plaintext, &ad).unwrap();
        let hex: String = ct.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "f70f822c30d89eedc5297bac9d13d48f42e4e3bb63fb88ca4e6581fb03f4812766f6b8776d301bef7135"
        );
    }
}
