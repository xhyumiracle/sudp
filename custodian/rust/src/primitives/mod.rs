//! Abstract cryptographic primitives and their standard
//! realisations.
//!
//! Every primitive is a trait so the protocol layer can be exercised with
//! deterministic mocks in tests, and so deployments can swap in HSM-backed,
//! TEE-backed, or alternative-algorithm implementations without touching
//! protocol code.

mod aead;
mod auth;
mod csprng;
pub mod domain;
mod hash;
mod kdf;
mod kem;
mod wrap;

#[cfg(feature = "hpke")]
#[cfg_attr(docsrs, doc(cfg(feature = "hpke")))]
mod hpke_backend;

pub use aead::Aead;
pub use auth::{Authenticator, AuthenticatorContext, EnrolledCredential};
pub use csprng::Csprng;
pub use domain::DomainSeparator;
pub use hash::Hash;
pub use kdf::Kdf;
pub use kem::{Kem, KemError};
pub use wrap::{KeyWrap, WrapBinding};

#[cfg(feature = "hpke")]
#[cfg_attr(docsrs, doc(cfg(feature = "hpke")))]
pub use hpke_backend::{gen_keypair, DhKemP256HkdfSha256, HpkeDhKem};

#[cfg(feature = "std-primitives")]
#[cfg_attr(docsrs, doc(cfg(feature = "std-primitives")))]
pub use aead::ChaCha20Poly1305;

#[cfg(feature = "std-primitives")]
#[cfg_attr(docsrs, doc(cfg(feature = "std-primitives")))]
pub use csprng::OsCsprng;

#[cfg(feature = "std-primitives")]
#[cfg_attr(docsrs, doc(cfg(feature = "std-primitives")))]
pub use hash::Sha256;

#[cfg(feature = "std-primitives")]
#[cfg_attr(docsrs, doc(cfg(feature = "std-primitives")))]
pub use kdf::HkdfSha256;

#[cfg(feature = "std-primitives")]
#[cfg_attr(docsrs, doc(cfg(feature = "std-primitives")))]
pub use wrap::AeadWrap;

/// Bundle of the standard primitive profile (Table 1).
///
/// `StdPrimitives` lets a deployment pick the whole standard profile in one
/// type parameter rather than naming each primitive individually. It groups:
///
/// - `Hash` = SHA-256
/// - `Kdf`  = HKDF-SHA-256
/// - `Aead` = XChaCha20-Poly1305
/// - `Wrap` = AEAD-as-wrap (over XChaCha20-Poly1305)
/// - `Csprng` = OS RNG
#[cfg(feature = "std-primitives")]
#[cfg_attr(docsrs, doc(cfg(feature = "std-primitives")))]
pub struct StdPrimitives;

#[cfg(feature = "std-primitives")]
impl PrimitiveSuite for StdPrimitives {
    type Hash = Sha256;
    type Kdf = HkdfSha256;
    type Aead = ChaCha20Poly1305;
    type Wrap = AeadWrap<ChaCha20Poly1305>;
    type Csprng = OsCsprng;
}

/// A bundle of primitive types the protocol layer parameterises over.
///
/// The custodian façade is generic over `PrimitiveSuite`; concrete deployments
/// either use the bundled [`StdPrimitives`] or define their own implementor of
/// this trait.
pub trait PrimitiveSuite {
    /// Collision-resistant hash.
    type Hash: Hash;
    /// HKDF-style extract-then-expand KDF.
    type Kdf: Kdf;
    /// IND-CCA AEAD with associated data.
    type Aead: Aead;
    /// Key-wrap interface ( — derivation binds context).
    type Wrap: KeyWrap;
    /// Cryptographically secure randomness source.
    type Csprng: Csprng;
}
