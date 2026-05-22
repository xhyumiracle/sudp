//! Cryptographically secure randomness source.

/// `CSPRNG`: cryptographically secure randomness source.
///
/// The protocol samples freshness tokens `r`, salts `η_c`, state-encryption
/// keys `K`, and (in the cross-device handshake) ECDH key pairs from this
/// interface. Implementations must produce uniform pseudorandom bytes.
pub trait Csprng {
    /// Fill `dst` with fresh random bytes.
    fn fill(dst: &mut [u8]);

    /// Generate a fresh `N`-byte array.
    fn random<const N: usize>() -> [u8; N] {
        let mut buf = [0u8; N];
        Self::fill(&mut buf);
        buf
    }

    /// Generate a fresh 32-byte value (common-case helper for keys/salts).
    fn random_32() -> [u8; 32] {
        Self::random::<32>()
    }
}

/// OS-backed CSPRNG (`getrandom`/`/dev/urandom` on Linux).
#[cfg(feature = "std-primitives")]
#[cfg_attr(docsrs, doc(cfg(feature = "std-primitives")))]
pub struct OsCsprng;

#[cfg(feature = "std-primitives")]
impl Csprng for OsCsprng {
    fn fill(dst: &mut [u8]) {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(dst);
    }
}
