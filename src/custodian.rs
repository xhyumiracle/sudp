//! `Custodian` — façade over the three phases.
//!
//! Most deployments interact only with this type. It owns the freshness pool,
//! the authenticator-verification context, the redeemer-policy decision, and
//! the clock; it delegates crypto to the [`PrimitiveSuite`] and protocol logic
//! to the [`phases`] modules.
//!
//! Sealed-state persistence is intentionally **not** owned by `Custodian` —
//! atomic write semantics (paper §5.6 III.3) are a deployment concern. The
//! façade returns the new `SealedState` and leaves I/O to the caller.

use core::marker::PhantomData;

use crate::freshness::{FreshnessStore, FreshnessToken, InMemoryFreshness};
use crate::grant::{Grant, RedeemedGrant};
use crate::operation::Operation;
use crate::phases::{
    consumption::{
        add_credential_after_lifecycle, execute_export, execute_lifecycle, execute_use, open,
        remove_credential_after_lifecycle, ExportArtifact, LifecycleOutput, Mutation, OpenedState,
    },
    grant::{redeem, RedeemInputs, RedeemerPolicy},
    setup::{run as run_setup, SetupInputs, SetupOutputs},
};
use crate::primitives::{Authenticator, PrimitiveSuite};
use crate::state::{ProtectedState, SealedState};
use crate::Result;

use serde::{Deserialize, Serialize};

/// Phase II.1 conveyance payload `T → U` (paper §5.5 II.1).
///
/// Carries `(o, r, {(cid_c, η_c)})`. `o` is the operation `U` will render
/// and sign; `r` is the single-use freshness token; the credential list is
/// the public material `U` needs to drive the authenticator (allowList +
/// per-credential salt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConveyancePayload {
    /// The proposed operation.
    pub o: Operation,
    /// Freshness token (raw 32 bytes).
    #[serde(with = "crate::wire::b64bytes")]
    pub r: Vec<u8>,
    /// Public per-credential material `(cid_c, η_c)` for every enrolled
    /// credential.
    pub credentials: Vec<ConveyanceCredential>,
}

/// One credential's public material inside a [`ConveyancePayload`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConveyanceCredential {
    /// Credential identifier `cid_c`.
    #[serde(with = "crate::wire::b64bytes")]
    pub credential_id: Vec<u8>,
    /// PRF salt `η_c`.
    #[serde(with = "crate::wire::b64bytes")]
    pub prf_salt: Vec<u8>,
}

/// Custodian instance.
///
/// Type parameters:
/// - `S`: primitive suite (`Hash`, `Kdf`, `Aead`, `KeyWrap`, `Csprng`).
/// - `A`: authenticator backend (`Authenticator` trait — WebAuthn by default
///   via `passkey::WebAuthn`).
/// - `F`: freshness store. Defaults to in-memory.
pub struct Custodian<S, A, F = InMemoryFreshness<<S as PrimitiveSuite>::Csprng>>
where
    S: PrimitiveSuite,
    A: Authenticator,
    F: FreshnessStore,
{
    /// Identity of this custodian (used to check `o.bind.redeemer`). `None`
    /// disables the redeemer check (single-tenant deployment).
    pub identity: Option<String>,
    /// Maximum `iat` skew, in seconds. Defaults to 300.
    pub iat_skew_secs: u64,
    /// Freshness store `S` (paper §5.4 I.3).
    pub freshness: F,
    _marker: PhantomData<(S, A)>,
}

#[cfg(feature = "std-primitives")]
impl<S, A> Custodian<S, A>
where
    S: PrimitiveSuite<Csprng = crate::primitives::OsCsprng>,
    A: Authenticator,
{
    /// New custodian with an in-memory freshness pool. `identity` is
    /// `o.bind.redeemer`.
    pub fn new(identity: impl Into<String>) -> Self {
        Self {
            identity: Some(identity.into()),
            iat_skew_secs: 300,
            freshness: InMemoryFreshness::default(),
            _marker: PhantomData,
        }
    }
}

impl<S, A, F> Custodian<S, A, F>
where
    S: PrimitiveSuite,
    A: Authenticator,
    F: FreshnessStore,
{
    /// Custom-freshness-store constructor.
    pub fn with_freshness(identity: impl Into<String>, freshness: F) -> Self {
        Self {
            identity: Some(identity.into()),
            iat_skew_secs: 300,
            freshness,
            _marker: PhantomData,
        }
    }

    /// Disable the `o.bind.redeemer` check (e.g. single-tenant deployment).
    pub fn without_redeemer_check(mut self) -> Self {
        self.identity = None;
        self
    }

    /// Phase I — build `Σ_0`.
    pub fn setup(
        &self,
        protected: ProtectedState,
        enrollment: A::Enrollment,
        prf_salt: Vec<u8>,
        wrapping_key: crate::grant::WrappingKey,
        auth_context: &A::Context,
    ) -> Result<SealedState> {
        let out: SetupOutputs = run_setup::<S, A>(
            SetupInputs {
                protected,
                enrollment,
                prf_salt,
                wrapping_key,
            },
            auth_context,
        )?;
        Ok(out.sealed)
    }

    /// Phase II.1 — issue a fresh `r` token.
    pub fn issue_freshness(&mut self) -> FreshnessToken {
        self.freshness.issue()
    }

    /// Phase II.1 — one-shot conveyance helper.
    ///
    /// Issues a fresh `r` and returns the full payload `T → U`:
    /// `(o, r, {(cid_c, η_c)})` (paper §5.5 II.1). The caller forwards this
    /// payload to `U` over the authenticated channel; `U` uses the
    /// `credentials` list to drive an authenticator allowList and renders
    /// `o` before signing β.
    ///
    /// This is purely a convenience wrapper around [`Self::issue_freshness`]
    /// and [`SealedState::credential_iter`]; deployments that already track
    /// `r` and credential metadata separately can ignore it.
    pub fn build_conveyance(&mut self, o: Operation, sealed: &SealedState) -> ConveyancePayload {
        let r = self.freshness.issue();
        let credentials = sealed
            .credential_iter()
            .map(|(cid, salt)| ConveyanceCredential {
                credential_id: cid.to_vec(),
                prf_salt: salt.to_vec(),
            })
            .collect();
        ConveyancePayload {
            o,
            r: r.to_vec(),
            credentials,
        }
    }

    /// Phase II.3 — redeem a grant.
    pub fn redeem_grant(
        &mut self,
        grant: Grant<A>,
        auth_context: &A::Context,
        sealed: &SealedState,
        now_unix: u64,
    ) -> Result<RedeemedGrant> {
        let redeemer = match &self.identity {
            Some(id) => RedeemerPolicy::Equals(id.as_str()),
            None => RedeemerPolicy::AnyAccepted,
        };
        redeem::<S, A, F>(
            RedeemInputs {
                grant,
                auth_context,
                redeemer,
                iat_skew_secs: self.iat_skew_secs,
                now_unix,
            },
            &mut self.freshness,
            sealed,
        )
    }

    /// Phase III.0 — open the sealed state.
    pub fn open(&self, redeemed: &RedeemedGrant, sealed: &SealedState) -> Result<OpenedState> {
        open::<S>(redeemed, sealed)
    }

    /// Phase III.1 — `use`. Consumes `redeemed` to enforce one-shot
    /// execution (paper §6.4).
    pub fn execute_use<R, H>(
        &self,
        redeemed: RedeemedGrant,
        sealed: &SealedState,
        handler: H,
    ) -> Result<R>
    where
        H: FnOnce(&str, &[u8]) -> Result<R>,
    {
        execute_use::<S, H, R>(redeemed, sealed, handler)
    }

    /// Phase III.2 — `export`. Consumes `redeemed`.
    pub fn execute_export<H>(
        &self,
        redeemed: RedeemedGrant,
        sealed: &SealedState,
        seal_for_recipient: H,
    ) -> Result<ExportArtifact>
    where
        H: FnOnce(&[u8; 32], &[u8]) -> Result<ExportArtifact>,
    {
        execute_export::<S, H>(redeemed, sealed, seal_for_recipient)
    }

    /// Phase III.3 — lifecycle (write / rotate). For `enroll` and `revoke`
    /// use [`Self::execute_enroll`] / [`Self::execute_revoke`].
    ///
    /// Consumes `redeemed`. Returns only the new sealed state; the
    /// freshly-sampled `K'` is dropped (zeroized) immediately. If you need
    /// `K'` (e.g. to wrap an extra credential entry under it) call the free
    /// function [`crate::phases::consumption::execute_lifecycle`] directly.
    pub fn execute_lifecycle(
        &self,
        redeemed: RedeemedGrant,
        sealed: &SealedState,
        next_prf_salt: &[u8],
        mutation: Box<Mutation>,
    ) -> Result<SealedState> {
        Ok(execute_lifecycle::<S>(redeemed, sealed, next_prf_salt, mutation)?.sealed_state)
    }

    /// Phase III.3 — `enroll`: lifecycle followed by attaching the new
    /// credential to `Reg` and `Σ.credentials`.
    ///
    /// The new credential's wrapping key `W_+` enters `M.peers` inside the
    /// lifecycle mutation so subsequent rotations can rewrap `K` under it;
    /// the new credential's `K̂_+` is wrapped under the same `K'` produced
    /// by this lifecycle step (no re-open needed).
    #[allow(clippy::too_many_arguments)]
    pub fn execute_enroll(
        &self,
        redeemed: RedeemedGrant,
        sealed: &SealedState,
        next_prf_salt: &[u8],
        new_enrollment: A::Enrollment,
        new_prf_salt: Vec<u8>,
        new_wrapping_key: crate::grant::WrappingKey,
        auth_context: &A::Context,
    ) -> Result<SealedState> {
        let new_cred = A::verify_enrollment(&new_enrollment, auth_context)?;
        let new_credential_id = new_cred.credential_id;
        let new_public_key = new_cred.public_key;

        let new_wrapping_key_for_peer = new_wrapping_key.clone();
        let new_credential_id_for_peer = new_credential_id.clone();

        let LifecycleOutput {
            sealed_state,
            k_prime,
        } = execute_lifecycle::<S>(
            redeemed,
            sealed,
            next_prf_salt,
            Box::new(move |m: &mut ProtectedState| {
                let cid_b64 =
                    base64::engine::general_purpose::STANDARD.encode(&new_credential_id_for_peer);
                m.peers.insert(cid_b64, new_wrapping_key_for_peer);
                Ok(())
            }),
        )?;

        add_credential_after_lifecycle::<S, A>(
            sealed_state,
            new_credential_id,
            new_public_key,
            new_prf_salt,
            new_wrapping_key,
            &k_prime,
        )
    }

    /// Phase III.3 — `revoke`: lifecycle followed by removing the target
    /// credential from `Reg`, `Σ.credentials`, and `M.peers`.
    ///
    /// ## Crate-level fail-safes
    ///
    /// Two paper-level integrity invariants are enforced here before any
    /// state mutation:
    ///
    /// 1. **No self-revocation** ([`Error::CannotRevokeSelf`](crate::Error::CannotRevokeSelf)).
    ///    The acting credential (the one whose σ* signed `o`) cannot be the
    ///    target of its own revocation invocation — the user must authorize
    ///    a revoke with a *different* enrolled credential. This mirrors the
    ///    WebAuthn allowList pattern: the acting credential must not be in
    ///    the set of credentials being removed.
    /// 2. **No orphan state** ([`Error::WouldOrphanState`](crate::Error::WouldOrphanState)).
    ///    A revocation that would leave `Σ` with zero credentials makes the
    ///    protected state permanently unrecoverable. The crate refuses this
    ///    operation; the deployment must enroll at least one new credential
    ///    before retiring the last one.
    pub fn execute_revoke(
        &self,
        redeemed: RedeemedGrant,
        sealed: &SealedState,
        next_prf_salt: &[u8],
        revoked_credential_id: Vec<u8>,
    ) -> Result<SealedState> {
        // Fail-safe 1: acting credential cannot revoke itself.
        if revoked_credential_id == redeemed.credential_id {
            return Err(crate::Error::CannotRevokeSelf);
        }
        // Fail-safe 2: count the credentials that would survive the revoke.
        let survivors = sealed
            .credentials
            .iter()
            .filter(|c| c.credential_id != revoked_credential_id)
            .count();
        if survivors == 0 {
            return Err(crate::Error::WouldOrphanState);
        }

        let revoked_for_peer = revoked_credential_id.clone();
        let LifecycleOutput { sealed_state, .. } = execute_lifecycle::<S>(
            redeemed,
            sealed,
            next_prf_salt,
            Box::new(move |m: &mut ProtectedState| {
                let cid_b64 = base64::engine::general_purpose::STANDARD.encode(&revoked_for_peer);
                m.peers.remove(&cid_b64);
                Ok(())
            }),
        )?;
        Ok(remove_credential_after_lifecycle(
            sealed_state,
            &revoked_credential_id,
        ))
    }
}

use base64::Engine;
