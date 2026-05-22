//! Batch grant.
//!
//! The descriptor generalises from a single `o` to a list
//! `ops = (o_1, …, o_n)`:
//!
//! ```text
//!     β := H( DS_bind ‖ r ‖ H(ops) )
//! ```
//!
//! A single signature `σ` commits to the batch. `T` validates each `o_i`
//! under the II.3 obligations; the trusted-rendering obligation at `A`
//! extends to `Render(ops)`.
//!
//! Construction-wise this is identical to a single-op grant except that the
//! grant carries `BatchOperations` rather than `Operation`, and the protocol
//! computes `H(ops)` by hashing the canonical-bytes concatenation in array
//! order.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::beta::{compute_beta_from_canonical, DS_BIND};
use crate::freshness::FreshnessStore;
use crate::grant::{GrantOpt, RedeemedGrant, WrappingKey};
use crate::operation::Operation;
use crate::phases::grant::RedeemerPolicy;
use crate::primitives::{Authenticator, Hash, PrimitiveSuite};
use crate::state::SealedState;
use crate::Result;

/// `ops = (o_1, …, o_n)` — a batch of operations approved by a single
/// signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BatchOperations(pub Vec<Operation>);

impl BatchOperations {
    /// New batch.
    pub fn new(ops: Vec<Operation>) -> Self {
        Self(ops)
    }

    /// Length in operations.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True iff the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Canonical bytes: JCS-encoded JSON array of canonical operations.
    /// Strict mode — see [`crate::Operation::canonical_bytes`].
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let v = serde_json::to_value(self)
            .map_err(|_| crate::Error::Encoding("BatchOperations→Value"))?;
        crate::canonical::canonicalize_strict(&v)
    }
}

/// Batch grant: same shape as [`crate::Grant`] but the operation field is a
/// [`BatchOperations`].
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchGrant<A: Authenticator> {
    /// `ops`.
    pub ops: BatchOperations,
    /// Server-issued freshness token.
    #[serde(with = "crate::wire::b64bytes")]
    pub r: Vec<u8>,
    /// Acting credential id.
    #[serde(with = "crate::wire::b64bytes")]
    pub credential_id: Vec<u8>,
    /// `W*`.
    pub wrapping_key: WrappingKey,
    /// `σ*` over `β`.
    pub assertion: A::Assertion,
    /// Optional rotation payload (applies to any rotation-class member).
    #[serde(default)]
    pub opt: GrantOpt,
}

impl<A: Authenticator> Clone for BatchGrant<A>
where
    A::Assertion: Clone,
{
    fn clone(&self) -> Self {
        Self {
            ops: self.ops.clone(),
            r: self.r.clone(),
            credential_id: self.credential_id.clone(),
            wrapping_key: self.wrapping_key.clone(),
            assertion: self.assertion.clone(),
            opt: self.opt.clone(),
        }
    }
}

/// Redeemed batch (custodian-internal).
#[derive(Debug)]
pub struct RedeemedBatch {
    /// The accepted batch.
    pub ops: BatchOperations,
    /// Acting credential id.
    pub credential_id: Vec<u8>,
    /// `W*`.
    pub wrapping_key: WrappingKey,
    /// Rotation payload.
    pub opt: GrantOpt,
}

impl RedeemedBatch {
    /// Project the batch to a per-operation [`RedeemedGrant`] sequence so the
    /// caller can dispatch each `o_i` through the ordinary Phase III paths.
    ///
    /// `W*` and `opt` are cloned into each per-op view; rotation-class
    /// operations within the batch all use the same `W*_next` since the
    /// authenticator invocation is shared.
    pub fn per_op(&self) -> impl Iterator<Item = RedeemedGrant> + '_ {
        self.ops.0.iter().cloned().map(move |o| RedeemedGrant {
            o,
            credential_id: self.credential_id.clone(),
            wrapping_key: self.wrapping_key.clone(),
            opt: GrantOpt {
                wrapping_key_next: self.opt.wrapping_key_next.clone(),
            },
        })
    }
}

/// Inputs to batch redemption — mirrors [`crate::phases::grant::RedeemInputs`].
pub struct RedeemBatchInputs<'a, A: Authenticator> {
    /// The submitted batch grant.
    pub grant: BatchGrant<A>,
    /// Authenticator context.
    pub auth_context: &'a A::Context,
    /// Custodian identity policy.
    pub redeemer: RedeemerPolicy<'a>,
    /// `iat` skew tolerance in seconds.
    pub iat_skew_secs: u64,
    /// Current unix time.
    pub now_unix: u64,
}

/// Phase II.3 — redeem a batch grant.
///
/// Validity and bind-redeemer are checked for every `o_i`; β is computed once
/// over `H(ops)`; signature verification happens once. If any check on any
/// `o_i` fails, the whole batch is rejected and `r` is still consumed.
pub fn redeem_batch<S, A, F>(
    inputs: RedeemBatchInputs<'_, A>,
    freshness: &mut F,
    sealed: &SealedState,
) -> Result<RedeemedBatch>
where
    S: PrimitiveSuite,
    A: Authenticator,
    F: FreshnessStore,
{
    let RedeemBatchInputs {
        grant,
        auth_context,
        redeemer,
        iat_skew_secs,
        now_unix,
    } = inputs;

    // 1. Consume r.
    if !freshness.consume(&grant.r) {
        return Err(crate::Error::FreshnessRejected);
    }

    // 2. Validate every op through the shared batch helper (enforces ≤1
    //    rotation-class op, plus per-op rules from validate_op_against).
    let val_ctx = crate::phases::grant::OpValidationCtx {
        redeemer: &redeemer,
        iat_skew_secs,
        now_unix,
    };
    crate::phases::grant::validate_batch_ops(&grant.ops.0, &val_ctx)?;

    // 3. Rotation requirement: if a rotation-class op is in the batch
    //    (at most one, enforced above), opt.wrapping_key_next must be present.
    if grant.ops.0.iter().any(|o| o.act.kind.is_rotation_class())
        && grant.opt.wrapping_key_next.is_none()
    {
        return Err(crate::Error::MissingRotationKey);
    }

    // 4. Look up pk.
    let pk = sealed
        .registry
        .get::<A>(&grant.credential_id)?
        .ok_or(crate::Error::UnknownCredential)?;

    // 5. β = H(DS_bind ‖ r ‖ H(ops)).
    let ops_canonical = grant.ops.canonical_bytes()?;
    let beta = compute_beta_from_canonical::<S::Hash>(DS_BIND, &grant.r, &ops_canonical);

    // 6. Verify σ*.
    A::check_credential_binding(&grant.credential_id, &grant.assertion)?;
    A::verify_assertion(&pk, &beta, &grant.assertion, auth_context)
        .map_err(|_| crate::Error::AuthorizationInvalid)?;

    let _ = S::Hash::OUTPUT_LEN;

    Ok(RedeemedBatch {
        ops: grant.ops,
        credential_id: grant.credential_id,
        wrapping_key: grant.wrapping_key,
        opt: grant.opt,
    })
}

// Small helper used in marker-suppression patterns.
#[allow(dead_code)]
trait _BatchMarker: Zeroize + ZeroizeOnDrop {}
