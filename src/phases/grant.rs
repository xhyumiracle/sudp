//! Phase II — Authorization Grant (paper §5.5).
//!
//! II.1 (request) is two state-only operations: `T` issues `r` and prepares
//! the conveyance payload; both are handled by the [`FreshnessStore`](crate::FreshnessStore)
//! and direct field access on the sealed state. The crate's contribution here
//! is II.3: grant redemption.

use crate::beta::{compute_beta_for_op, constant_time_eq};
use crate::freshness::FreshnessStore;
use crate::grant::{Grant, RedeemedGrant};
use crate::operation::Operation;
use crate::primitives::{Authenticator, Hash, PrimitiveSuite};
use crate::state::SealedState;
use crate::Result;

/// Custodian identity check policy for `o.bind.redeemer`.
pub enum RedeemerPolicy<'a> {
    /// Enforce exact equality with the given custodian id.
    Equals(&'a str),
    /// Skip the check (single-tenant deployment, or check deferred).
    AnyAccepted,
}

/// Shared context for operation-level public-field validation
/// ([`validate_op_against`] / [`validate_batch_ops`]).
///
/// Centralises the pre-flight rules that both single-op redemption and batch
/// redemption need to enforce. New invariants should land in
/// [`validate_op_against`] so single + batch paths stay in lock-step.
pub struct OpValidationCtx<'a> {
    /// Custodian identity check policy.
    pub redeemer: &'a RedeemerPolicy<'a>,
    /// Maximum allowed `iat` skew, in seconds.
    pub iat_skew_secs: u64,
    /// Current unix time, in seconds. Inject at the call site for deterministic tests.
    pub now_unix: u64,
}

/// Validate `o` against the public-field rules. Pure / no crypto.
///
/// Rules enforced (in order):
/// 1. `o.valid` time window (expiry + `iat` skew).
/// 2. `o.bind.redeemer` matches the custodian's identity (or skipped).
///
/// Notes on rules **not** enforced here:
/// - Rotation-class `W*_next` presence depends on grant-level `opt`, not
///   on `o` alone; that check stays in the per-grant pipeline.
/// - `Export + bind.recipient = ?` is **not** validated here either: paper
///   §5.6 III.2 admits two export modes — KEM-sealed delivery
///   (`recipient = Some(KEM pubkey)`) and ownership-transfer to the
///   requester (`recipient = None`). The dispatch function chosen by the
///   caller ([`crate::phases::consumption::execute_export`] vs
///   [`crate::phases::consumption::execute_export_to_requester`])
///   enforces its own recipient requirement.
pub fn validate_op_against(o: &Operation, ctx: &OpValidationCtx<'_>) -> Result<()> {
    o.check_validity(ctx.now_unix, ctx.iat_skew_secs)?;
    if let RedeemerPolicy::Equals(expected) = ctx.redeemer {
        if !constant_time_eq(o.bind.redeemer.as_bytes(), expected.as_bytes()) {
            return Err(crate::Error::RedeemerMismatch);
        }
    }
    Ok(())
}

/// Validate a batch of operations.
///
/// In addition to per-op validation, enforces:
/// - non-empty;
/// - at most one rotation-class operation (a single authenticator invocation
///   produces a single `W*_next` / single `K'`; multiple rotation-class ops
///   in one batch are semantically incoherent).
pub fn validate_batch_ops(ops: &[Operation], ctx: &OpValidationCtx<'_>) -> Result<()> {
    if ops.is_empty() {
        return Err(crate::Error::Malformed("batch: empty ops"));
    }
    let rotation_count = ops
        .iter()
        .filter(|o| o.act.kind.is_rotation_class())
        .count();
    if rotation_count > 1 {
        return Err(crate::Error::BatchMultipleRotationOps);
    }
    for o in ops {
        validate_op_against(o, ctx)?;
    }
    Ok(())
}

/// Inputs to Phase II.3.
pub struct RedeemInputs<'a, A: Authenticator> {
    /// The submitted grant.
    pub grant: Grant<A>,
    /// Authenticator-specific verification context (rpId, origin, …).
    pub auth_context: &'a A::Context,
    /// Identity of this custodian instance (for `o.bind.redeemer`).
    pub redeemer: RedeemerPolicy<'a>,
    /// Maximum allowed `iat` skew, in seconds.
    pub iat_skew_secs: u64,
    /// Current unix time, in seconds. Inject the clock at the call site so
    /// tests are deterministic.
    pub now_unix: u64,
}

/// Phase II.3 — redeem `G` (paper §5.5 II.3).
///
/// Steps in order:
/// 1. Consume `r` from `S` (single-use; reject if absent or expired).
/// 2. Public-field pre-flight against `o` (cheap, no crypto):
///    expiry, redeemer, rotation `W*_next` presence, export recipient.
/// 3. Look up `pk_{cid_{c*}}` from `Reg` (reject if unknown credential).
/// 4. Recompute `β' := H(DS_bind ‖ r ‖ H(o))`.
/// 5. `check_credential_binding`: the assertion's embedded credential id
///    (where applicable) must match the grant's.
/// 6. Verify `σ*` over `β'` under `pk_{cid_{c*}}`.
///
/// On success, returns the [`RedeemedGrant`]. The freshness token is
/// **always** consumed at step 1, so a failure at steps 2–6 cannot be probed
/// against the same `r`.
pub fn redeem<S, A, F>(
    inputs: RedeemInputs<'_, A>,
    freshness: &mut F,
    sealed: &SealedState,
) -> Result<RedeemedGrant>
where
    S: PrimitiveSuite,
    A: Authenticator,
    F: FreshnessStore,
{
    let RedeemInputs {
        grant,
        auth_context,
        redeemer,
        iat_skew_secs,
        now_unix,
    } = inputs;

    // 1. Consume r (single-use).
    if !freshness.consume(&grant.r) {
        return Err(crate::Error::FreshnessRejected);
    }

    // 2. Public-field pre-flight against o. Cheap, no crypto; grouped here
    //    so a malformed grant is rejected before signature verification work.
    let val_ctx = OpValidationCtx {
        redeemer: &redeemer,
        iat_skew_secs,
        now_unix,
    };
    validate_op_against(&grant.o, &val_ctx)?;
    if grant.o.act.kind.is_rotation_class() && grant.opt.wrapping_key_next.is_none() {
        return Err(crate::Error::MissingRotationKey);
    }

    // 3. Look up pk_{cid_{c*}}.
    let pk = sealed
        .registry
        .get::<A>(&grant.credential_id)?
        .ok_or(crate::Error::UnknownCredential)?;

    // 4. Recompute β'.
    let beta = compute_beta_for_op::<S::Hash>(&grant.r, &grant.o)?;

    // 5. Authenticator-embedded credential-id check (no-op for backends with
    //    no embedded id).
    A::check_credential_binding(&grant.credential_id, &grant.assertion)?;

    // 6. Verify σ*.
    A::verify_assertion(&pk, &beta, &grant.assertion, auth_context)
        .map_err(|_| crate::Error::AuthorizationInvalid)?;

    let _ = S::Hash::OUTPUT_LEN; // touch S to keep the type-parameter live in older rustc.

    Ok(RedeemedGrant {
        o: grant.o,
        credential_id: grant.credential_id,
        wrapping_key: grant.wrapping_key,
        opt: grant.opt,
    })
}
