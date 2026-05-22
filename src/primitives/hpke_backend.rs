//! HPKE-DHKEM realisation of [`Kem`] (standard profile, Table 1).
//!
//! Wraps the RustCrypto [`hpke`] crate. The crate's `hpke::Kem` is the same
//! abstract shape as our [`Kem`] trait (encap returns `(SharedSecret, EncappedKey)`),
//! so the wrapper is mechanical.
//!
//! The default profile [`DhKemP256HkdfSha256`] matches  Table 1.
//! Other algorithm choices can be wired by parameterising [`HpkeDhKem`] with a
//! different `hpke::Kem` (e.g. `hpke::kem::X25519HkdfSha256`).

use core::marker::PhantomData;

use hpke::{Deserializable, Kem as HpkeKemTrait, Serializable};

use super::{Kem, KemError};

/// `Kem` realisation backed by an arbitrary `hpke::Kem` algorithm.
pub struct HpkeDhKem<K: HpkeKemTrait>(PhantomData<K>);

impl<K: HpkeKemTrait> Kem for HpkeDhKem<K> {
    type PublicKey = K::PublicKey;
    type SecretKey = K::PrivateKey;

    fn encap(pk: &Self::PublicKey) -> Result<(Vec<u8>, Vec<u8>), KemError> {
        // rand_core 0.9 OsRng impls `TryCryptoRng`; wrap in `UnwrapErr` to
        // expose the infallible `CryptoRng` interface hpke needs.
        let mut rng = rand_core_09::UnwrapErr(rand_core_09::OsRng);
        let (shared_secret, encapped_key) =
            K::encap(pk, None, &mut rng).map_err(|_| KemError::EncapFailed)?;
        Ok((shared_secret.0.to_vec(), encapped_key.to_bytes().to_vec()))
    }

    fn decap(sk: &Self::SecretKey, ct: &[u8]) -> Result<Vec<u8>, KemError> {
        let encapped = K::EncappedKey::from_bytes(ct).map_err(|_| KemError::BadRecipientKey)?;
        let shared_secret = K::decap(sk, None, &encapped).map_err(|_| KemError::DecapFailed)?;
        Ok(shared_secret.0.to_vec())
    }
}

/// Generate a fresh recipient keypair for [`DhKemP256HkdfSha256`].
///
/// Returned as `(secret_key, public_key)` — the secret key never leaves the
/// recipient's trust boundary; the public key is what `o.bind.recipient`
/// references.
pub fn gen_keypair<K: HpkeKemTrait>() -> (K::PrivateKey, K::PublicKey) {
    let mut rng = rand_core_09::UnwrapErr(rand_core_09::OsRng);
    K::gen_keypair(&mut rng)
}

/// Standard SUDP export-profile KEM (standard profile, Table 1): DHKEM-P256 / HKDF-SHA-256.
pub type DhKemP256HkdfSha256 = HpkeDhKem<hpke::kem::DhP256HkdfSha256>;
