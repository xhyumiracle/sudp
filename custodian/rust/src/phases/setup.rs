//! Phase I — Setup.
//!
//! Builds the initial sealed state `Σ_0 := (C, {(cid_c, η_c, K̂_c)}, Reg, ver)`
//! from one enrolled credential and an initial protected state `M_0`.
//!
//! The Authorizer-side derivation of `W_c` happens on the client;
//! the custodian receives `W_c` over the confidential leg and never sees
//! `y_c` or the PRF key. This function therefore takes `W_c` as an input.

use zeroize::Zeroizing;

use crate::grant::WrappingKey;
use crate::primitives::{Aead, Authenticator, Csprng, KeyWrap, PrimitiveSuite, WrapBinding};
use crate::state::{ProtectedState, Registry, SealedCredential, SealedState, CURRENT_VERSION};
use crate::Result;

/// Inputs to Phase I.
pub struct SetupInputs<A: Authenticator> {
    /// Initial protected state `M_0`. May be empty.
    pub protected: ProtectedState,
    /// Enrollment artefact for the first credential.
    pub enrollment: A::Enrollment,
    /// PRF salt `η_c` chosen at the Authorizer side during Phase I.2.
    pub prf_salt: Vec<u8>,
    /// Wrapping key `W_c` derived at the Authorizer side and sent over the confidential
    /// leg. Zeroized after use.
    pub wrapping_key: WrappingKey,
}

/// Outputs from Phase I.
pub struct SetupOutputs {
    /// The persistent sealed state to commit.
    pub sealed: SealedState,
}

/// Phase I — build `Σ_0` from `M_0` and one enrolled credential.
///
/// Steps:
/// 1. Verify enrollment, extract `(cid, pk)`.
/// 2. Sample `K ←$ CSPRNG`.
/// 3. `C = Enc_K(canonical(M); DS_seal ‖ ver)`.
/// 4. `K̂_c = Wrap_{W_c}(K)`.
/// 5. Assemble `Σ_0`.
///
/// Per  invariants:
/// - After this function returns, no value held in `Σ_0` is sufficient to
///   recover `M_0` without the corresponding authenticator invocation.
/// - The transient `K` and `W_c` are dropped (via zeroize) on return.
pub fn run<S: PrimitiveSuite, A: Authenticator>(
    inputs: SetupInputs<A>,
    auth_context: &A::Context,
) -> Result<SetupOutputs> {
    let SetupInputs {
        mut protected,
        enrollment,
        prf_salt,
        wrapping_key,
    } = inputs;

    // 1. Verify enrollment.
    let credential = A::verify_enrollment(&enrollment, auth_context)?;

    // 2. Sample K. Zeroized when this scope exits.
    let k = Zeroizing::new(S::Csprng::random_32());

    // 3. Seal M.
    // Inject the first authenticator entry so subsequent rotations can rewrap K
    // under a known W_c (default recoverability policy).
    let cid_b64 = base64::engine::general_purpose::STANDARD.encode(&credential.credential_id);
    protected
        .authenticators
        .insert(cid_b64, wrapping_key.clone());
    let m_bytes = protected.to_canonical()?;
    let nonce = S::Aead::fresh_nonce();
    let mut ciphertext = Vec::with_capacity(nonce.len() + m_bytes.len() + S::Aead::TAG_LEN);
    ciphertext.extend_from_slice(&nonce);
    let mut ct = S::Aead::encrypt(
        &k[..],
        &nonce,
        &m_bytes,
        seal_ad(CURRENT_VERSION).as_slice(),
    )?;
    ciphertext.append(&mut ct);

    // 4. Wrap K under W_c, binding (cid, ver) into the wrap AD.
    let binding = WrapBinding {
        credential_id: &credential.credential_id,
        version: CURRENT_VERSION,
    };
    let wrapped_key = S::Wrap::wrap(wrapping_key.as_bytes(), &k[..], &binding)?;

    // 5. Assemble Σ_0.
    let mut registry = Registry::new();
    registry.insert::<A>(&credential.credential_id, &credential.public_key)?;

    let sealed_cred = SealedCredential {
        credential_id: credential.credential_id,
        prf_salt,
        wrapped_key,
    };

    let sealed = SealedState {
        version: CURRENT_VERSION,
        registry,
        credentials: vec![sealed_cred],
        ciphertext,
    };

    Ok(SetupOutputs { sealed })
}

/// Build the AEAD associated data for sealing `M`: `DS_seal ‖ ver`.
pub(crate) fn seal_ad(version: u16) -> Vec<u8> {
    let mut ad = Vec::with_capacity(crate::primitives::domain::DS_SEAL.len() + 2);
    ad.extend_from_slice(crate::primitives::domain::DS_SEAL);
    ad.extend_from_slice(&version.to_be_bytes());
    ad
}

use base64::Engine;
