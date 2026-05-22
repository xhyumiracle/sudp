//! Collision-resistant hash.

use crate::Result;

/// `H`: collision-resistant cryptographic hash.
///
/// Used for `H(o)` (canonical-operation digest) and the channel binding
/// `β = H(DS_bind ‖ r ‖ H(o))`.
pub trait Hash {
    /// Output length in bytes.
    const OUTPUT_LEN: usize;

    /// One-shot hash. Implementations should be constant-time over the input
    /// length (the standard `sha2` crate satisfies this).
    fn hash(data: &[u8]) -> [u8; 32];

    /// Two-argument convenience: `H(a ‖ b)`.
    fn hash2(a: &[u8], b: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(a.len() + b.len());
        buf.extend_from_slice(a);
        buf.extend_from_slice(b);
        Self::hash(&buf)
    }

    /// Hash a slice of byte slices in order, no separators (caller supplies any
    /// domain-separation bytes itself).
    fn hash_slices(parts: &[&[u8]]) -> [u8; 32] {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut buf = Vec::with_capacity(total);
        for p in parts {
            buf.extend_from_slice(p);
        }
        Self::hash(&buf)
    }

    /// Hash an input of unknown length into an arbitrary output buffer.
    /// For 256-bit hashes the output length must be `OUTPUT_LEN`.
    fn hash_into(data: &[u8], out: &mut [u8]) -> Result<()>;
}

/// SHA-256 implementation of [`Hash`] ( Table 1).
#[cfg(feature = "std-primitives")]
#[cfg_attr(docsrs, doc(cfg(feature = "std-primitives")))]
pub struct Sha256;

#[cfg(feature = "std-primitives")]
impl Hash for Sha256 {
    const OUTPUT_LEN: usize = 32;

    fn hash(data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(data).into()
    }

    fn hash_into(data: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() != Self::OUTPUT_LEN {
            return Err(crate::Error::Primitive("Sha256: out buffer length"));
        }
        out.copy_from_slice(&Self::hash(data));
        Ok(())
    }
}
