//! WebAuthn realization of [`crate::primitives::Authenticator`] (feature
//! `webauthn`, on by default).
//!
//! Verifies WebAuthn assertions using ES256/P-256 (the standard SUDP profile
//! choice). The client-side derivation of `userKey` and `W_c` from the
//! WebAuthn PRF extension lives at `U` (the browser); this module only
//! consumes assertions on the custodian side, plus enrollment artefacts at
//! Phase I.

pub mod webauthn;

pub use webauthn::{WebAuthn, WebAuthnAssertion, WebAuthnEnrollment, WebAuthnPublicKey};
