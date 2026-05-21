//! Ergonomic re-exports for downstream callers.
//!
//! ```ignore
//! use sudp::prelude::*;
//! ```
//!
//! Brings the common protocol types and the standard primitive bundle into
//! scope.

pub use crate::batch::{BatchGrant, BatchOperations, RedeemedBatch};
pub use crate::beta::{compute_beta, compute_beta_for_op};
pub use crate::custodian::Custodian;
pub use crate::error::{Error, Result};
pub use crate::freshness::{FreshnessStore, InMemoryFreshness};
pub use crate::grant::{Grant, GrantOpt, RedeemedGrant, WrappingKey};
pub use crate::operation::{Act, ActType, Bind, Operation, RecipientPk, Valid};
pub use crate::phases::consumption::{ExportArtifact, OpenedState};
pub use crate::primitives::{
    Aead, Authenticator, AuthenticatorContext, Csprng, DomainSeparator, Hash, Kdf, KeyWrap,
    PrimitiveSuite, WrapBinding,
};
pub use crate::state::{
    PeerMap, PrfSalt, ProtectedState, Registry, SealedCredential, SealedState, Version, WrappedKey,
    CURRENT_VERSION,
};

#[cfg(feature = "std-primitives")]
pub use crate::primitives::{
    AeadWrap, ChaCha20Poly1305, HkdfSha256, OsCsprng, Sha256, StdPrimitives,
};

#[cfg(feature = "webauthn")]
pub use crate::passkey::{WebAuthn, WebAuthnAssertion, WebAuthnEnrollment, WebAuthnPublicKey};
