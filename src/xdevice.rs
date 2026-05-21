//! Cross-device confidentiality envelope (paper §7.2).
//!
//! When `U` and `T` do not share a live TLS session — typical when the user
//! holds the passkey on a phone and the custodian runs on hosted
//! infrastructure — Phase II's `U → T` channel must be realised by an
//! alternative transport that supplies confidentiality (for `W*`) and
//! channel-binding (against substitution / replay).
//!
//! This module ships the **cryptographic core** of that realisation:
//!
//! 1. [`derive_session_key`] — the KDF stitching
//!    `k_xd = KDF(ss; r, DS_xd_enc ‖ pk_U ‖ pk_T)`.
//! 2. [`seal_grant`] / [`open_grant`] — the AEAD envelope over a [`Grant`]
//!    with `AD = H(pk_U ‖ pk_T ‖ r)`, channel-binding both ends and the
//!    freshness token.
//!
//! ## What is intentionally outside scope
//!
//! - The ECDH (or other) key-agreement step itself. The caller computes `ss`
//!   with whatever primitive is appropriate (`p256::ecdh`, `x25519-dalek`,
//!   an HSM, a PAKE) and passes the raw shared secret in. SUDP does not
//!   define a `KeyExchange` trait — paper §5.3 lists ECDH only in the §7.2
//!   profile, not the abstract primitive set.
//! - **`pk_T` trust establishment** — paper §7.2 ("Authenticated key
//!   agreement is required for confidentiality") lists four profile options
//!   (signature under `T`'s long-term key, binding to an existing
//!   authenticated orchestration session, an OOB channel like a QR code, or
//!   a mutually-authenticated PAKE). All of these are deployment choices;
//!   without `pk_T` authenticity the confidentiality argument does not hold
//!   regardless of what this module does.
//! - Multi-device passkey management, transport (HTTP / WebSocket /
//!   QR-polling), and any UI concern.
//!
//! These are deployment glue, not protocol crypto.

use crate::grant::Grant;
use crate::primitives::{domain::DS_XD_ENC, Aead, Authenticator, Hash, Kdf, PrimitiveSuite};
use crate::Result;

/// Derive the cross-device session key (paper §7.2):
/// `k_xd = KDF(ss; r, DS_xd_enc ‖ pk_U ‖ pk_T)`.
///
/// - `ss` — raw shared secret from the key-agreement step (e.g.
///   `p256::ecdh::SharedSecret::raw_secret_bytes()`).
/// - `r` — the freshness token also bound into the Phase II.3 β.
/// - `pk_u_bytes` / `pk_t_bytes` — wire-format public keys (e.g. SEC1
///   uncompressed, X25519 raw, etc.). The encoding is profile-defined; both
///   sides MUST agree.
///
/// Output length is the AEAD key length of the chosen primitive suite.
pub fn derive_session_key<S: PrimitiveSuite>(
    ss: &[u8],
    r: &[u8],
    pk_u_bytes: &[u8],
    pk_t_bytes: &[u8],
) -> Result<Vec<u8>> {
    let mut info = Vec::with_capacity(DS_XD_ENC.len() + pk_u_bytes.len() + pk_t_bytes.len());
    info.extend_from_slice(DS_XD_ENC);
    info.extend_from_slice(pk_u_bytes);
    info.extend_from_slice(pk_t_bytes);

    let mut k_xd = vec![0u8; S::Aead::KEY_LEN];
    S::Kdf::derive(ss, r, &info, &mut k_xd)?;
    Ok(k_xd)
}

/// The cross-device AEAD associated data: `H(pk_U ‖ pk_T ‖ r)` (paper §7.2).
///
/// Channel-binds both ephemeral public keys and the freshness token so that
/// any in-flight substitution fails AEAD authentication.
pub fn channel_binding_ad<S: PrimitiveSuite>(
    pk_u_bytes: &[u8],
    pk_t_bytes: &[u8],
    r: &[u8],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(pk_u_bytes.len() + pk_t_bytes.len() + r.len());
    buf.extend_from_slice(pk_u_bytes);
    buf.extend_from_slice(pk_t_bytes);
    buf.extend_from_slice(r);
    S::Hash::hash(&buf)
}

/// Seal a grant for cross-device transport (paper §7.2).
///
/// Output is the wire ciphertext `ct_G = Enc_{k_xd}(canonical(G); AD)`.
/// Caller is responsible for transporting `(pk_u_bytes, ct_G)` to `T`; `T`
/// already knows `r` from its freshness pool.
pub fn seal_grant<S: PrimitiveSuite, A: Authenticator>(
    grant: &Grant<A>,
    k_xd: &[u8],
    pk_u_bytes: &[u8],
    pk_t_bytes: &[u8],
    r: &[u8],
) -> Result<Vec<u8>> {
    let grant_bytes =
        serde_json::to_vec(grant).map_err(|_| crate::Error::Encoding("Grant→JSON"))?;
    let ad = channel_binding_ad::<S>(pk_u_bytes, pk_t_bytes, r);
    S::Aead::seal(k_xd, &grant_bytes, &ad)
}

/// Open a cross-device sealed grant on `T`'s side (paper §7.2).
///
/// `T` derives the same `k_xd` from its own end of the key agreement, then
/// runs the standard Phase II.3 redemption pipeline on the recovered Grant.
pub fn open_grant<S: PrimitiveSuite, A: Authenticator>(
    sealed: &[u8],
    k_xd: &[u8],
    pk_u_bytes: &[u8],
    pk_t_bytes: &[u8],
    r: &[u8],
) -> Result<Grant<A>> {
    let ad = channel_binding_ad::<S>(pk_u_bytes, pk_t_bytes, r);
    let grant_bytes = S::Aead::open(k_xd, sealed, &ad)?;
    serde_json::from_slice(&grant_bytes).map_err(|_| crate::Error::Encoding("JSON→Grant"))
}
