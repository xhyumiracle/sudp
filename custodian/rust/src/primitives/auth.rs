//! Authenticator interface — the Authorizer-side tamper-resistant module
//! and its custodian-side verifier.
//!
//! ## What this trait models, and what it does NOT
//!
//! Models each Authorizer-side credential `c` as a module `Aut_c` with
//! non-extractable internal keys producing
//! - one signature `σ ← Sig_{sk_c}(μ)` per user-verified invocation,
//! - and one or more PRF outputs `y_i ← PRF_c(η_i)`.
//!
//! Two of those three artefacts are produced **inside `Aut_c`** at the Authorizer's
//! device:
//!
//! - `sk_c` and the PRF key never leave the module.
//! - `y_c` and the derived wrapping key `W_c` exist transiently in the Authorizer's
//!   trusted client and reach `T` only as the wrapping-key field of a grant.
//!
//! The custodian `T` — which is what `sudp` mostly implements — therefore only
//! needs to do **one** thing in cryptographic terms: verify `σ` over `β` under
//! the credential's public key, plus the structural checks the WebAuthn (or
//! analogous) profile demands. That is exactly what this trait exposes.
//!
//! ### Where does PRF / wrapping-key derivation live, then?
//!
//! It lives at `A` (the Authorizer's client). The client does the PRF evaluation
//! inside the authenticator, derives `W_c` via HKDF in JavaScript / native
//! code, and sends `W_c` to `T` over the confidential leg as part of the
//! [`Grant`](crate::Grant). The crate provides helpers for the symmetric KDF
//! shape (so a Rust client embedding `sudp` can derive `W_c` identically) but
//! it never assumes the custodian holds raw PRF output — the PRF stays
//! authenticator-bound by design.
//!
//! ### Enrollment vs. assertion
//!
//! WebAuthn distinguishes `webauthn.create` (enrollment, releases
//! `(cid_c, pk_c)`) from `webauthn.get` (assertion, releases `σ` and the PRF
//! output). The protocol Phase I.1 is enrollment; Phases II.2 / II.3 are
//! assertion. This trait covers both:
//!
//! - [`Authenticator::verify_enrollment`] consumes an enrollment artefact and
//!   returns the canonical credential record `(cid, pk)` to be stored in `T`'s
//!   registry.
//! - [`Authenticator::verify_assertion`] verifies a Phase II.2 assertion
//!   against the credential's stored `pk_c` and the channel binding `β`.
//!
//! Custom authenticators (HSM-backed, OS-credential-mediator, mock) implement
//! both. The WebAuthn realisation lives in [`crate::passkey::webauthn`].

use serde::{de::DeserializeOwned, Serialize};

use crate::Result;

/// `Aut_c`: Authorizer-side tamper-resistant module + its custodian-side verifier.
///
/// All types are associated so that an authenticator backend chooses its own
/// wire formats. Wire-format choices that vary between deployments
/// (e.g. base64 vs. CBOR) belong in the backend, not in the protocol core.
pub trait Authenticator {
    /// The custodian-side enrollment payload (e.g. WebAuthn registration
    /// attestation, or a PEM public key).
    type Enrollment: Serialize + DeserializeOwned;

    /// The custodian-side assertion payload (e.g. WebAuthn assertion or any
    /// detached signature bundle).
    type Assertion: Serialize + DeserializeOwned;

    /// Canonical public key record stored in `T`'s registry. The protocol does
    /// not introspect this type beyond serialising it for persistence; the
    /// authenticator backend uses it to verify assertions.
    type PublicKey: Serialize + DeserializeOwned + Clone;

    /// Per-verification context (origin, rpId, expected user-verification
    /// flag, …). Backends with no contextual checks can use `()`.
    type Context;

    /// Phase I.1 — extract canonical `(credential_id, public_key)` from an
    /// enrollment payload and check the enrollment's own integrity.
    ///
    /// Returns the credential id as bytes and the verifier's canonical public
    /// key record. The caller persists both in the registry.
    fn verify_enrollment(
        enrollment: &Self::Enrollment,
        context: &Self::Context,
    ) -> Result<EnrolledCredential<Self::PublicKey>>;

    /// Phase II.3 — verify the authorization evidence `σ*` over the channel
    /// binding `β` under the stored credential public key.
    ///
    /// Concrete realisations must include all structural checks required by
    /// their profile (in WebAuthn: clientDataJSON type, origin, rpIdHash, UV
    /// flag, DER→raw signature parsing, ECDSA verify).
    fn verify_assertion(
        public_key: &Self::PublicKey,
        beta: &[u8; 32],
        assertion: &Self::Assertion,
        context: &Self::Context,
    ) -> Result<()>;

    /// Optional consistency check: the caller may submit the credential id
    /// claimed by the grant and the assertion's own embedded credential id
    /// (if any). Backends that embed `credential_id` inside the assertion
    /// (WebAuthn does) override this; the default trusts the grant.
    fn check_credential_binding(_credential_id: &[u8], _assertion: &Self::Assertion) -> Result<()> {
        Ok(())
    }
}

/// Result of [`Authenticator::verify_enrollment`].
#[derive(Debug, Clone)]
pub struct EnrolledCredential<P> {
    /// Public credential identifier (`cid_c`).
    pub credential_id: Vec<u8>,
    /// Custodian-canonical public key record for later assertion verification.
    pub public_key: P,
}

/// Convenience marker for `Authenticator::Context`. Wraps the typical WebAuthn
/// triple `(rp_id, origin, require_uv)` so deployments using a custom backend
/// have a ready type if they need it.
#[derive(Debug, Clone)]
pub struct AuthenticatorContext {
    /// WebAuthn relying-party ID (e.g. `example.com`).
    pub rp_id: String,
    /// Expected `clientDataJSON.origin` (e.g. `https://example.com`).
    pub origin: String,
    /// If true, the User Verification flag must be set on assertions.
    pub require_uv: bool,
}

impl AuthenticatorContext {
    /// Build a WebAuthn-style context.
    pub fn new(rp_id: impl Into<String>, origin: impl Into<String>, require_uv: bool) -> Self {
        Self {
            rp_id: rp_id.into(),
            origin: origin.into(),
            require_uv,
        }
    }
}
