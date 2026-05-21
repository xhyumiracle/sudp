//! IND-CCA AEAD with associated-data authentication (paper §5.3).

use crate::Result;

/// `(Enc, Dec)`: AEAD interface.
///
/// All wrapped keys (`Wrap_W(K)`), sealed protected state (`Enc_K(M)`), and
/// delivery artefacts (`Enc_kd(s_o)`) go through this trait.
pub trait Aead {
    /// Key length in bytes.
    const KEY_LEN: usize;
    /// Nonce length in bytes.
    const NONCE_LEN: usize;
    /// Authentication-tag length in bytes.
    const TAG_LEN: usize;

    /// Encrypt `plaintext` under `key` with `nonce` and associated data `ad`.
    /// Returns `ciphertext ‖ tag` (length = `plaintext.len() + TAG_LEN`).
    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt and authenticate. Input is `ciphertext ‖ tag`.
    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>>;

    /// Generate a fresh nonce. Implementations must satisfy the uniqueness
    /// constraint of the underlying cipher (XChaCha20-Poly1305 admits random
    /// 24-byte nonces; AES-GCM requires a deterministic 96-bit nonce).
    fn fresh_nonce() -> Vec<u8>;

    /// One-shot seal: prepends a freshly sampled nonce. Returns
    /// `nonce ‖ ciphertext ‖ tag`.
    fn seal(key: &[u8], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::fresh_nonce();
        let mut ct = Self::encrypt(key, &nonce, plaintext, ad)?;
        let mut out = Vec::with_capacity(nonce.len() + ct.len());
        out.extend_from_slice(&nonce);
        out.append(&mut ct);
        Ok(out)
    }

    /// One-shot open: input is `nonce ‖ ciphertext ‖ tag`.
    fn open(key: &[u8], sealed: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < Self::NONCE_LEN + Self::TAG_LEN {
            return Err(crate::Error::Malformed("AEAD: sealed blob too short"));
        }
        let (nonce, ct) = sealed.split_at(Self::NONCE_LEN);
        Self::decrypt(key, nonce, ct, ad)
    }
}

/// XChaCha20-Poly1305 implementation of [`Aead`] (paper §7: AEAD profile).
///
/// 24-byte nonces (random nonces are safe), 16-byte tag, 32-byte key.
#[cfg(feature = "std-primitives")]
#[cfg_attr(docsrs, doc(cfg(feature = "std-primitives")))]
pub struct ChaCha20Poly1305;

#[cfg(feature = "std-primitives")]
impl Aead for ChaCha20Poly1305 {
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 24;
    const TAG_LEN: usize = 16;

    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::{Aead as _, KeyInit, Payload};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};

        if key.len() != Self::KEY_LEN {
            return Err(crate::Error::Primitive("XChaCha20: key length"));
        }
        if nonce.len() != Self::NONCE_LEN {
            return Err(crate::Error::Primitive("XChaCha20: nonce length"));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| crate::Error::Primitive("XChaCha20: key init"))?;
        cipher
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .map_err(|_| crate::Error::Primitive("XChaCha20: encrypt"))
    }

    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::{Aead as _, KeyInit, Payload};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};

        if key.len() != Self::KEY_LEN {
            return Err(crate::Error::Primitive("XChaCha20: key length"));
        }
        if nonce.len() != Self::NONCE_LEN {
            return Err(crate::Error::Primitive("XChaCha20: nonce length"));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| crate::Error::Primitive("XChaCha20: key init"))?;
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| crate::Error::SealDecryptionFailed)
    }

    fn fresh_nonce() -> Vec<u8> {
        use rand::RngCore;
        let mut n = vec![0u8; Self::NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut n);
        n
    }
}

#[cfg(all(test, feature = "std-primitives"))]
mod tests {
    use super::*;

    #[test]
    fn xchacha_roundtrip() {
        let key = [0x42u8; 32];
        let msg = b"hello sudp";
        let ad = b"sudp/v1/test";
        let sealed = ChaCha20Poly1305::seal(&key, msg, ad).unwrap();
        let opened = ChaCha20Poly1305::open(&key, &sealed, ad).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn xchacha_wrong_ad_fails() {
        let key = [0x42u8; 32];
        let sealed = ChaCha20Poly1305::seal(&key, b"hi", b"ad-a").unwrap();
        assert!(ChaCha20Poly1305::open(&key, &sealed, b"ad-b").is_err());
    }
}
