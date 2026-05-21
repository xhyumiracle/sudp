//! Channel binding `β` (paper §5.5).
//!
//! ```text
//!     β = H( DS_bind ‖ r ‖ H(o) )
//! ```
//!
//! Single-operation form uses `H(o)`; batch form (paper §6 "Batch extension")
//! uses `H(ops)`.

use crate::primitives::Hash;
use crate::Result;

/// Domain-separation label for `β`. Re-exported here so callers don't have to
/// reach into `primitives::domain`.
pub use crate::primitives::domain::DS_BIND;

/// Compute `β = H(DS_bind ‖ r ‖ op_hash)`.
///
/// `op_hash` is `H(canonical(o))` for a single operation, or `H(canonical(ops))`
/// for a batch.
pub fn compute_beta<H: Hash>(r: &[u8], op_hash: &[u8; 32]) -> [u8; 32] {
    H::hash_slices(&[DS_BIND, r, op_hash])
}

/// Compute `β` directly from canonical bytes of `o`.
///
/// Equivalent to `compute_beta(r, &H::hash(canonical_o))` but slightly more
/// ergonomic at the call site.
pub fn compute_beta_from_canonical<H: Hash>(r: &[u8], canonical_o: &[u8]) -> [u8; 32] {
    let op_hash = H::hash(canonical_o);
    compute_beta::<H>(r, &op_hash)
}

/// Compute `β` for a single [`crate::Operation`] using the crate's JCS-style
/// canonical encoder.
pub fn compute_beta_for_op<H: Hash>(r: &[u8], op: &crate::Operation) -> Result<[u8; 32]> {
    let canonical = op.canonical_bytes()?;
    Ok(compute_beta_from_canonical::<H>(r, &canonical))
}

/// Constant-time byte comparison (used by [`crate::Authenticator`] backends).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(all(test, feature = "std-primitives"))]
mod tests {
    use super::*;
    use crate::primitives::Sha256;
    use crate::{Act, ActType, Bind, Operation, Valid};

    fn op(target: &str) -> Operation {
        Operation {
            act: Act {
                kind: ActType::Use,
                target: target.into(),
                scope: serde_json::json!({}),
            },
            bind: Bind {
                redeemer: "T".into(),
                recipient: None,
            },
            valid: Valid { iat: 0, exp: None },
        }
    }

    #[test]
    fn beta_is_deterministic() {
        let r = [0xAAu8; 16];
        let o = op("x");
        let a = compute_beta_for_op::<Sha256>(&r, &o).unwrap();
        let b = compute_beta_for_op::<Sha256>(&r, &o).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn beta_changes_with_op() {
        let r = [0xAAu8; 16];
        let a = compute_beta_for_op::<Sha256>(&r, &op("x")).unwrap();
        let b = compute_beta_for_op::<Sha256>(&r, &op("y")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn beta_changes_with_r() {
        let o = op("x");
        let a = compute_beta_for_op::<Sha256>(&[0u8; 16], &o).unwrap();
        let b = compute_beta_for_op::<Sha256>(&[1u8; 16], &o).unwrap();
        assert_ne!(a, b);
    }
}
