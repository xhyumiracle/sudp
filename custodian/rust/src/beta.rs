//! Channel binding `β`.
//!
//! ```text
//!     β = H( domain ‖ r ‖ H(o) )
//! ```
//!
//! The `domain` argument is a profile-defined byte string. SUDP's canonical
//! domain is [`DS_BIND`]; deployments that need pairwise-disjoint domains
//! (e.g. distinct setup vs. standard ceremonies) pass their own bytes —
//! see [`crate::primitives::domain`] for the convention of folding any
//! separators or version tags into the domain value itself.
//!
//! Single-operation form uses `H(o)`; batch form uses `H(ops)`.

use crate::primitives::Hash;
use crate::Result;

/// SUDP's canonical domain-separation label for `β`. Re-exported here so
/// callers don't have to reach into `primitives::domain`.
pub use crate::primitives::domain::DS_BIND;

/// Compute `β = H(domain ‖ r ‖ op_hash)`.
///
/// `op_hash` is `H(canonical(o))` for a single operation, or
/// `H(canonical(ops))` for a batch. Pass [`DS_BIND`] as `domain` for the
/// default SUDP profile; deployment profiles may pass other bytes.
pub fn compute_beta<H: Hash>(domain: &[u8], r: &[u8], op_hash: &[u8; 32]) -> [u8; 32] {
    H::hash_slices(&[domain, r, op_hash])
}

/// Compute `β` directly from canonical bytes of `o`.
///
/// Equivalent to `compute_beta(domain, r, &H::hash(canonical_o))` but
/// slightly more ergonomic at the call site.
pub fn compute_beta_from_canonical<H: Hash>(
    domain: &[u8],
    r: &[u8],
    canonical_o: &[u8],
) -> [u8; 32] {
    let op_hash = H::hash(canonical_o);
    compute_beta::<H>(domain, r, &op_hash)
}

/// Compute `β` for a single [`crate::Operation`] using the crate's JCS-style
/// canonical encoder. Pass [`DS_BIND`] for the default SUDP profile.
pub fn compute_beta_for_op<H: Hash>(
    domain: &[u8],
    r: &[u8],
    op: &crate::Operation,
) -> Result<[u8; 32]> {
    let canonical = op.canonical_bytes()?;
    Ok(compute_beta_from_canonical::<H>(domain, r, &canonical))
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
            valid: Valid::single_use(0, None),
        }
    }

    #[test]
    fn beta_is_deterministic() {
        let r = [0xAAu8; 16];
        let o = op("x");
        let a = compute_beta_for_op::<Sha256>(DS_BIND, &r, &o).unwrap();
        let b = compute_beta_for_op::<Sha256>(DS_BIND, &r, &o).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn beta_changes_with_op() {
        let r = [0xAAu8; 16];
        let a = compute_beta_for_op::<Sha256>(DS_BIND, &r, &op("x")).unwrap();
        let b = compute_beta_for_op::<Sha256>(DS_BIND, &r, &op("y")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn beta_changes_with_r() {
        let o = op("x");
        let a = compute_beta_for_op::<Sha256>(DS_BIND, &[0u8; 16], &o).unwrap();
        let b = compute_beta_for_op::<Sha256>(DS_BIND, &[1u8; 16], &o).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn beta_changes_with_domain() {
        let r = [0xAAu8; 16];
        let o = op("x");
        let a = compute_beta_for_op::<Sha256>(DS_BIND, &r, &o).unwrap();
        let b = compute_beta_for_op::<Sha256>(b"profile/v1/other", &r, &o).unwrap();
        assert_ne!(a, b);
    }

    /// Cross-language conformance anchor. The same Operation and `r`
    /// fed into `@sudp-protocol/authorizer`'s `computeBinding(DS_BIND, r, op)`
    /// MUST produce the same 32-byte β. If you regenerate this hex,
    /// also update the matching inline snapshot in
    /// `authorizer/ts/test/conformance.test.ts` in the same commit so
    /// the two sides stay locked.
    #[test]
    fn beta_matches_ts_authorizer_conformance_vector() {
        let r = [0u8; 32];
        let o = Operation {
            act: Act {
                kind: ActType::Use,
                target: "env.api_key".into(),
                scope: serde_json::json!({}),
            },
            bind: Bind {
                redeemer: "custodian-id".into(),
                recipient: None,
            },
            valid: Valid::single_use(1_700_000_000, None),
        };

        let canonical = o.canonical_bytes().unwrap();
        let canonical_str = std::str::from_utf8(&canonical).unwrap();
        assert_eq!(
            canonical_str,
            "{\"act\":{\"scope\":{},\"target\":\"env.api_key\",\"type\":\"use\"},\
             \"bind\":{\"redeemer\":\"custodian-id\"},\
             \"valid\":{\"iat\":1700000000,\"multiplicity\":\"one\"}}",
            "canonical-encoder shape changed; TS conformance vector must change too"
        );

        let beta = compute_beta_for_op::<Sha256>(DS_BIND, &r, &o).unwrap();
        let hex: String = beta.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "6c43ba079b5316ac73e8f35e3ce59bfdefb9dee1fc964fcb39406c26169be954"
        );
    }

    /// Cross-language conformance anchor for batch β. Same shape as the
    /// single-op anchor above, but for `BatchOperations`. The TS side
    /// produces the same hex via `computeBatchBinding(DS_BIND, r, ops)`.
    #[test]
    fn batch_beta_matches_ts_authorizer_conformance_vector() {
        use crate::BatchOperations;

        let r = [0u8; 32];
        let op = |target: &str| Operation {
            act: Act {
                kind: ActType::Use,
                target: target.into(),
                scope: serde_json::json!({}),
            },
            bind: Bind {
                redeemer: "custodian-id".into(),
                recipient: None,
            },
            valid: Valid::single_use(1_700_000_000, None),
        };
        let ops = BatchOperations::new(vec![op("env.api_key"), op("env.refresh_token")]);

        let canonical = ops.canonical_bytes().unwrap();
        let canonical_str = std::str::from_utf8(&canonical).unwrap();
        assert_eq!(
            canonical_str,
            "[\
             {\"act\":{\"scope\":{},\"target\":\"env.api_key\",\"type\":\"use\"},\
             \"bind\":{\"redeemer\":\"custodian-id\"},\
             \"valid\":{\"iat\":1700000000,\"multiplicity\":\"one\"}},\
             {\"act\":{\"scope\":{},\"target\":\"env.refresh_token\",\"type\":\"use\"},\
             \"bind\":{\"redeemer\":\"custodian-id\"},\
             \"valid\":{\"iat\":1700000000,\"multiplicity\":\"one\"}}\
             ]",
            "batch canonical-encoder shape changed; TS conformance vector must change too"
        );

        let beta = compute_beta_from_canonical::<Sha256>(DS_BIND, &r, &canonical);
        let hex: String = beta.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "e066d4be3f6761a995491222d7bb7896cc13944c1f460233e082b3f21f95059f"
        );
    }
}
