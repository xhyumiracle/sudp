//! Phase III — Grant Consumption (paper §5.6, §5.7).
//!
//! ```text
//!     III.0  unwrap K with W* ; M ← Dec_K(C) ; s_o := M[target]
//!     III.1  use:        present s_o to E ; return only Release(o) = ρ_out
//!     III.2  export:     emit π sealed under recipient pk
//!     III.3  lifecycle:  apply o to M ; sample K' ; reseal ; rewrap peers
//! ```
//!
//! Each dispatch path is a separate function so callers can pick exactly the
//! one matching `o.act.kind`. The [`crate::Custodian`] façade dispatches
//! automatically.

use base64::Engine;
use zeroize::Zeroizing;

use crate::grant::{RedeemedGrant, WrappingKey};
use crate::operation::ActType;
use crate::phases::setup::seal_ad;
use crate::primitives::{Aead, Csprng, Kdf, Kem, KeyWrap, PrimitiveSuite, WrapBinding};
use crate::state::{ProtectedState, SealedCredential, SealedState};
use crate::Result;

/// Phase III.0 — open the sealed state under the grant's `W*`.
///
/// Returns the decrypted protected state `M` together with `K` (held in a
/// [`Zeroizing`] buffer that wipes on drop). The caller MUST drop the returned
/// [`OpenedState`] as soon as it is no longer needed; `M.targets` carry
/// authority-bearing plaintext.
pub fn open<S: PrimitiveSuite>(
    redeemed: &RedeemedGrant,
    sealed: &SealedState,
) -> Result<OpenedState> {
    let entry = sealed
        .find_credential(&redeemed.credential_id)
        .ok_or(crate::Error::UnknownCredential)?;

    let binding = WrapBinding {
        credential_id: &redeemed.credential_id,
        version: sealed.version,
    };
    let k_bytes = S::Wrap::unwrap(
        redeemed.wrapping_key.as_bytes(),
        &entry.wrapped_key,
        &binding,
    )
    .map_err(|_| crate::Error::SealDecryptionFailed)?;
    if k_bytes.len() != S::Aead::KEY_LEN {
        return Err(crate::Error::SealDecryptionFailed);
    }
    let k = Zeroizing::new(k_bytes);

    let m_bytes = S::Aead::open(&k[..], &sealed.ciphertext, &seal_ad(sealed.version))?;
    let m = ProtectedState::from_canonical(&m_bytes)?;

    Ok(OpenedState { k, m })
}

/// Output of [`open`].
///
/// `k` is the unwrapped state-encryption key, held in [`Zeroizing`] so it
/// wipes on drop.
pub struct OpenedState {
    /// `K`, the state-encryption key (zeroized on drop).
    pub k: Zeroizing<Vec<u8>>,
    /// `M`, the decrypted protected state.
    pub m: ProtectedState,
}

// ── III.1 use ─────────────────────────────────────────────────────────────

/// Phase III.1 — `use`: hand `s_o` to a caller-supplied handler inside `T`'s
/// boundary (paper §5.6 III.1).
///
/// The handler runs against the authority-bearing secret bytes; it must not
/// store, log, or otherwise leak them. The crate guarantees only that the
/// handler is the only function that sees `s_o` from `M` for this operation.
///
/// `act.kind` MUST be `ActType::Use`.
pub fn execute_use<S, F, R>(redeemed: &RedeemedGrant, sealed: &SealedState, handler: F) -> Result<R>
where
    S: PrimitiveSuite,
    F: FnOnce(&str, &[u8]) -> Result<R>,
{
    if redeemed.o.act.kind != ActType::Use {
        return Err(crate::Error::ActTypeMismatch("expected ActType::Use"));
    }
    let opened = open::<S>(redeemed, sealed)?;
    let s_o = opened.m.target(&redeemed.o.act.target)?;
    handler(&redeemed.o.act.target, s_o)
}

// ── III.2 export ──────────────────────────────────────────────────────────

/// A recipient-protected delivery artefact π (paper §5.6 III.2).
#[derive(Debug, Clone)]
pub struct ExportArtifact {
    /// `ct_d` (encapsulated ephemeral key, KEM-specific bytes).
    pub encapsulated_key: Vec<u8>,
    /// `δ = Enc_{k_d}(s_o; H(o))`.
    pub sealed_payload: Vec<u8>,
}

/// Phase III.2 — `export`: seal `s_o` under a recipient public key.
///
/// The KEM and KDF stitching is realised by the caller via the `seal_for_recipient`
/// closure, so deployments can plug in HPKE (the standard profile) or any
/// IND-CCA2 KEM. The closure is invoked with:
/// - `op_hash`: `H(canonical(o))` so it can bind both KDF info and AEAD AD.
/// - `s_o`: the secret bytes to seal.
///
/// It returns the [`ExportArtifact`].
///
/// `act.kind` MUST be `ActType::Export` and `o.bind.recipient` MUST be Some.
pub fn execute_export<S, F>(
    redeemed: &RedeemedGrant,
    sealed: &SealedState,
    seal_for_recipient: F,
) -> Result<ExportArtifact>
where
    S: PrimitiveSuite,
    F: FnOnce(&[u8; 32], &[u8]) -> Result<ExportArtifact>,
{
    if redeemed.o.act.kind != ActType::Export {
        return Err(crate::Error::ActTypeMismatch("expected ActType::Export"));
    }
    if redeemed.o.bind.recipient.is_none() {
        return Err(crate::Error::MissingRecipient);
    }

    let opened = open::<S>(redeemed, sealed)?;
    let s_o = opened.m.target(&redeemed.o.act.target)?;

    let op_canonical = redeemed.o.canonical_bytes()?;
    let op_hash = <S::Hash as crate::primitives::Hash>::hash(&op_canonical);

    seal_for_recipient(&op_hash, s_o)
}

/// Paper §5.6 III.2 standard composition: `(K_d, ct_d) ← Encap(pk)`;
/// `k_d ← KDF(K_d; ⊥, H(o))`; `δ ← Enc_{k_d}(s_o; H(o))`.
///
/// Use this as the body of [`execute_export`]'s closure when you want the
/// paper-standard stitching of `Kem + Kdf + Aead`. Plug in any [`Kem`]
/// backend (the crate ships an HPKE-DHKEM realisation behind the `hpke`
/// feature; see `sudp::primitives::HpkeDhKem`).
pub fn seal_export<S: PrimitiveSuite, K: Kem>(
    recipient_pk: &K::PublicKey,
    op_hash: &[u8; 32],
    s_o: &[u8],
) -> Result<ExportArtifact> {
    let (k_d_raw, ct_d) =
        K::encap(recipient_pk).map_err(|_| crate::Error::Primitive("KEM encap failed"))?;
    let mut k_d = Zeroizing::new(vec![0u8; S::Aead::KEY_LEN]);
    S::Kdf::derive(&k_d_raw, &[], op_hash, &mut k_d)?;
    let payload = S::Aead::seal(&k_d, s_o, op_hash)?;
    Ok(ExportArtifact {
        encapsulated_key: ct_d,
        sealed_payload: payload,
    })
}

/// Recipient-side inverse of [`seal_export`].
///
/// Recovers `s_o` from a recipient-protected delivery using the recipient's
/// secret key. The recipient lives outside `T` and outside `R`'s trust
/// boundary — that's the whole point of `Phase III.2`.
pub fn open_export<S: PrimitiveSuite, K: Kem>(
    recipient_sk: &K::SecretKey,
    op_hash: &[u8; 32],
    artifact: &ExportArtifact,
) -> Result<Vec<u8>> {
    let k_d_raw = K::decap(recipient_sk, &artifact.encapsulated_key)
        .map_err(|_| crate::Error::Primitive("KEM decap failed"))?;
    let mut k_d = Zeroizing::new(vec![0u8; S::Aead::KEY_LEN]);
    S::Kdf::derive(&k_d_raw, &[], op_hash, &mut k_d)?;
    S::Aead::open(&k_d, &artifact.sealed_payload, op_hash)
}

// ── III.3 lifecycle ───────────────────────────────────────────────────────

/// Mutation closure for Phase III.3: transform `M` into `M'`.
///
/// The closure is the deployment-specific bridge between `o.act` and `M`:
/// for `write`, it patches the target value; for `rotate`, it is the identity;
/// for `enroll`, it adds an entry to the peer map; for `revoke`, it drops one.
pub type Mutation = dyn FnOnce(&mut ProtectedState) -> Result<()>;

/// Result of [`execute_lifecycle`]: the new sealed state together with the
/// freshly-sampled `K'` (zeroized on drop).
///
/// Most callers care only about `sealed_state` and drop the `k_prime` field
/// immediately. Enroll-style flows that need to wrap a brand-new credential
/// entry under `K'` consume `k_prime` before dropping.
pub struct LifecycleOutput {
    /// `Σ'` after the lifecycle update.
    pub sealed_state: SealedState,
    /// `K'` (zeroized on drop). Use only if you need to wrap additional
    /// per-credential entries under the new state key.
    pub k_prime: Zeroizing<Vec<u8>>,
}

/// Phase III.3 — lifecycle / state-update (paper §5.6 III.3, §5.7 default
/// recoverability policy).
///
/// Steps:
/// 1. Open the current sealed state.
/// 2. Apply `mutation` to `M` → `M'`.
/// 3. Sample fresh `K'`.
/// 4. Update the acting credential's salt to `η^next_{c*}` (from
///    `o.act.scope`) and rewrap `K'` under `W*_next`.
/// 5. Rewrap `K'` under every peer `W_c` from `M.peers`.
/// 6. Re-seal `M'` under `K'`.
/// 7. Build the new `Σ'`.
///
/// `act.kind` MUST be one of `Write`, `Rotate`, `Enroll`, `Revoke`.
/// `grant.opt.wrapping_key_next` MUST be present (checked by Phase II.3).
///
/// Returns both `Σ'` and `K'`; ordinary callers ignore `K'`.
pub fn execute_lifecycle<S: PrimitiveSuite>(
    redeemed: &RedeemedGrant,
    sealed: &SealedState,
    next_prf_salt: &[u8],
    mutation: Box<Mutation>,
) -> Result<LifecycleOutput> {
    if !redeemed.o.act.kind.is_rotation_class() {
        return Err(crate::Error::ActTypeMismatch(
            "expected Write|Rotate|Enroll|Revoke",
        ));
    }
    let w_next = redeemed
        .opt
        .wrapping_key_next
        .as_ref()
        .ok_or(crate::Error::MissingRotationKey)?;

    // 1–2. Open & mutate.
    let mut opened = open::<S>(redeemed, sealed)?;
    mutation(&mut opened.m)?;

    // 3. Sample K'. Zeroized on scope exit (and after move into LifecycleOutput,
    // zeroized on caller drop).
    let k_prime = Zeroizing::new(S::Csprng::random_32().to_vec());

    // 4–5. Build new credentials list.
    let acting_cid_b64 = base64::engine::general_purpose::STANDARD.encode(&redeemed.credential_id);
    let mut new_credentials = Vec::with_capacity(sealed.credentials.len());
    for cred in &sealed.credentials {
        if cred.credential_id == redeemed.credential_id {
            // Acting credential: rewrap K' under W*_next; advance salt.
            let binding = WrapBinding {
                credential_id: &cred.credential_id,
                version: sealed.version,
            };
            let wrapped = S::Wrap::wrap(w_next.as_bytes(), &k_prime[..], &binding)?;
            new_credentials.push(SealedCredential {
                credential_id: cred.credential_id.clone(),
                prf_salt: next_prf_salt.to_vec(),
                wrapped_key: wrapped,
            });
            // Update the in-state peer map with the new W_c for this credential.
            opened
                .m
                .peers
                .insert(acting_cid_b64.clone(), w_next.clone());
        } else {
            // Peer credential: rewrap K' under W_c from M.peers.
            //
            // Membership invariant: a credential remains in Σ iff it is still
            // in M.peers after `mutation`. Revocation expresses itself by
            // removing the credential from M.peers; we then drop it from
            // `new_credentials` here. The registry/credentials-list cleanup
            // that the revoke layer adds is for `Reg` only.
            let cid_b64 = base64::engine::general_purpose::STANDARD.encode(&cred.credential_id);
            let Some(w_c) = opened.m.peers.get(&cid_b64) else {
                continue;
            };
            let binding = WrapBinding {
                credential_id: &cred.credential_id,
                version: sealed.version,
            };
            let wrapped = S::Wrap::wrap(w_c.as_bytes(), &k_prime[..], &binding)?;
            new_credentials.push(SealedCredential {
                credential_id: cred.credential_id.clone(),
                prf_salt: cred.prf_salt.clone(),
                wrapped_key: wrapped,
            });
        }
    }

    // 6. Re-seal M' under K'.
    let m_prime_bytes = opened.m.to_canonical()?;
    let nonce = S::Aead::fresh_nonce();
    let mut ciphertext = Vec::with_capacity(nonce.len() + m_prime_bytes.len() + S::Aead::TAG_LEN);
    ciphertext.extend_from_slice(&nonce);
    let mut ct = S::Aead::encrypt(
        &k_prime[..],
        &nonce,
        &m_prime_bytes,
        &seal_ad(sealed.version),
    )?;
    ciphertext.append(&mut ct);

    // 7. Build Σ'. Registry carries over by default; enroll/revoke layers
    // adjust it via [`add_credential_after_lifecycle`] /
    // [`remove_credential_after_lifecycle`].
    let sealed_state = SealedState {
        version: sealed.version,
        registry: sealed.registry.clone(),
        credentials: new_credentials,
        ciphertext,
    };
    Ok(LifecycleOutput {
        sealed_state,
        k_prime,
    })
}

/// Phase III.3 enrollment helper (paper §5.7 "Lifecycle extensions").
///
/// Adds a new credential entry to `Σ'` after [`execute_lifecycle`] has run.
/// Inserts `(cid_+, pk_+)` into `Reg`, appends `(cid_+, η_+, K̂_+)` to
/// `Σ'.credentials`, and returns the updated state.
///
/// `k_prime` is the value produced by [`execute_lifecycle`]; the helper does
/// not re-open the state to recover it.
pub fn add_credential_after_lifecycle<S: PrimitiveSuite, A: crate::primitives::Authenticator>(
    mut state: SealedState,
    new_credential_id: Vec<u8>,
    new_public_key: A::PublicKey,
    new_prf_salt: Vec<u8>,
    new_wrapping_key: WrappingKey,
    k_prime: &Zeroizing<Vec<u8>>,
) -> Result<SealedState> {
    state
        .registry
        .insert::<A>(&new_credential_id, &new_public_key)?;
    let binding = WrapBinding {
        credential_id: &new_credential_id,
        version: state.version,
    };
    let wrapped = S::Wrap::wrap(new_wrapping_key.as_bytes(), &k_prime[..], &binding)?;
    state.credentials.push(SealedCredential {
        credential_id: new_credential_id,
        prf_salt: new_prf_salt,
        wrapped_key: wrapped,
    });
    Ok(state)
}

/// Phase III.3 revocation helper (paper §5.7 "Lifecycle extensions").
///
/// Removes a credential from `Reg`, from the credentials list, and from the
/// peer map (the peer-map removal must also happen inside the lifecycle
/// `mutation` so that `Σ'.ciphertext` reflects the change).
pub fn remove_credential_after_lifecycle(
    mut state: SealedState,
    removed_credential_id: &[u8],
) -> SealedState {
    state.registry.remove(removed_credential_id);
    state
        .credentials
        .retain(|c| c.credential_id != removed_credential_id);
    state
}
