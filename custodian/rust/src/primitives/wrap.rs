//! Key-wrap interface specialised to key material.
//!
//! `Wrap` binds wrapping context primarily through the derivation of `W` (the
//! wrapping key). AEAD-as-wrap profiles additionally authenticate the same
//! domain-separation labels as associated data; AES-KW/KWP profiles omit the
//! associated data entirely. This trait carries the binding as a typed
//! [`WrapBinding`] so the AEAD-as-wrap default can honour the defense-in-depth
//! recommendation while AES-KW-style backends are free to ignore it.

use crate::Result;
use core::marker::PhantomData;

use super::aead::Aead;
use super::domain::DS_WRAP;

/// Wrapping-context binding: the per-credential `cid_c` and the
/// wrapping epoch `ver`.
///
/// Constructed at each `wrap` / `unwrap` call site so the type system makes
/// the binding fields explicit (no opaque `&[u8]` context blob). The trait
/// implementation decides how to use the binding (AEAD-as-wrap adds it to AD,
/// AES-KW backends ignore it).
#[derive(Debug, Clone, Copy)]
pub struct WrapBinding<'a> {
    /// Credential identifier `cid_c`.
    pub credential_id: &'a [u8],
    /// Wrapping epoch `ver`.
    pub version: u16,
}

impl<'a> WrapBinding<'a> {
    /// Build the canonical AD bytes: `DS_wrap ‖ cid ‖ ver_be`.
    ///
    /// AEAD-as-wrap implementors use this as the AEAD associated-data; any
    /// custom backend that wants the same defense-in-depth label gets it for
    /// free.
    pub fn to_canonical_ad(&self) -> Vec<u8> {
        let mut ad = Vec::with_capacity(DS_WRAP.len() + self.credential_id.len() + 2);
        ad.extend_from_slice(DS_WRAP);
        ad.extend_from_slice(self.credential_id);
        ad.extend_from_slice(&self.version.to_be_bytes());
        ad
    }
}

/// `(Wrap, Unwrap)`: key-wrap interface.
///
/// `key_material.len()` is implementation-defined; the standard SUDP profile
/// wraps a 32-byte state-encryption key `K`.
pub trait KeyWrap {
    /// Wrap a key under the wrapping key `w` and the per-call binding.
    fn wrap(w: &[u8], key_material: &[u8], binding: &WrapBinding<'_>) -> Result<Vec<u8>>;

    /// Unwrap a wrapped key. The same `binding` used at `wrap` time MUST be
    /// supplied; AEAD-as-wrap backends fail authentication if it differs.
    fn unwrap(w: &[u8], wrapped: &[u8], binding: &WrapBinding<'_>) -> Result<Vec<u8>>;
}

/// AEAD-as-wrap: instantiate `KeyWrap` from any [`Aead`] using the canonical
/// `DS_wrap ‖ cid ‖ ver_be` as the associated data.
///
/// This is the default profile when XChaCha20-Poly1305 is the AEAD. The
/// associated-data binding implements the paper's "AEAD-as-wrap profiles that
/// additionally authenticate the same domain-separation labels" hardening
/// recommendation.
pub struct AeadWrap<A: Aead>(PhantomData<A>);

impl<A: Aead> KeyWrap for AeadWrap<A> {
    fn wrap(w: &[u8], key_material: &[u8], binding: &WrapBinding<'_>) -> Result<Vec<u8>> {
        A::seal(w, key_material, &binding.to_canonical_ad())
    }

    fn unwrap(w: &[u8], wrapped: &[u8], binding: &WrapBinding<'_>) -> Result<Vec<u8>> {
        A::open(w, wrapped, &binding.to_canonical_ad())
    }
}

#[cfg(all(test, feature = "std-primitives"))]
mod tests {
    use super::*;
    use crate::primitives::aead::ChaCha20Poly1305;

    fn binding(cid: &[u8], ver: u16) -> WrapBinding<'_> {
        WrapBinding {
            credential_id: cid,
            version: ver,
        }
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let w = [0x33u8; 32];
        let k = [0x77u8; 32];
        let b = binding(b"cred-1", 1);
        let wrapped = AeadWrap::<ChaCha20Poly1305>::wrap(&w, &k, &b).unwrap();
        let unwrapped = AeadWrap::<ChaCha20Poly1305>::unwrap(&w, &wrapped, &b).unwrap();
        assert_eq!(unwrapped.as_slice(), &k);
    }

    #[test]
    fn wrong_w_fails() {
        let w1 = [0x01u8; 32];
        let w2 = [0x02u8; 32];
        let k = [0x77u8; 32];
        let b = binding(b"cred-1", 1);
        let wrapped = AeadWrap::<ChaCha20Poly1305>::wrap(&w1, &k, &b).unwrap();
        assert!(AeadWrap::<ChaCha20Poly1305>::unwrap(&w2, &wrapped, &b).is_err());
    }

    #[test]
    fn wrong_cid_fails_unwrap() {
        let w = [0x33u8; 32];
        let k = [0x77u8; 32];
        let b1 = binding(b"cred-A", 1);
        let b2 = binding(b"cred-B", 1);
        let wrapped = AeadWrap::<ChaCha20Poly1305>::wrap(&w, &k, &b1).unwrap();
        assert!(AeadWrap::<ChaCha20Poly1305>::unwrap(&w, &wrapped, &b2).is_err());
    }

    #[test]
    fn wrong_ver_fails_unwrap() {
        let w = [0x33u8; 32];
        let k = [0x77u8; 32];
        let b1 = binding(b"cred-A", 1);
        let b2 = binding(b"cred-A", 2);
        let wrapped = AeadWrap::<ChaCha20Poly1305>::wrap(&w, &k, &b1).unwrap();
        assert!(AeadWrap::<ChaCha20Poly1305>::unwrap(&w, &wrapped, &b2).is_err());
    }
}
