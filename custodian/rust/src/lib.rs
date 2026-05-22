//! # SUDP — Secret-Use Delegation Protocol
//!
//! Protocol-level secret use for agentic systems. The unit of delegation is the *use*
//! of a secret for one specific authorized operation `o`, not the secret itself.
//!
//! ## Crate layout
//!
//! - [`primitives`] — abstract crypto traits (`Hash`, `Kdf`, `Aead`, `KeyWrap`,
//!   `Kem`, `Csprng`, `Authenticator`) and standard realisations.
//! - [`operation`], [`grant`] — the A↔T contract (canonical `Operation`) and the
//!   one-shot authorization artifact (`Grant`, `RedeemedGrant`).
//! - [`state`] — sealed and protected state structures (`SealedState`,
//!   `ProtectedState`, the peer map).
//! - [`phases`] — Phase I (setup), Phase II (grant validation), Phase III
//!   (consumption dispatch).
//! - [`custodian`] — façade over the phases.
//! - [`batch`] — multi-op batch grant.
//! - [`canonical`] — JCS-style deterministic JSON encoding.
//! - [`passkey`] — WebAuthn realisation of [`primitives::Authenticator`]
//!   (feature `webauthn`).
//!
//! ## Trust model and scope
//!
//! `sudp` implements the abstract protocol and the standard cryptographic profile.
//! It does **not** speak HTTP, does not render `o` to humans, and does not perform
//! the environment call at `E`. The crate emits canonical bytes for `Render`,
//! verifies authorization evidence on `Grant`, gives the caller bounded access to
//! `s_o := M[o.act.target]`, and produces the new sealed state for lifecycle
//! operations. Everything that touches I/O lives in the deployment.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod batch;
pub mod beta;
pub mod canonical;
pub mod custodian;
pub mod error;
pub mod freshness;
pub mod grant;
pub mod operation;
pub mod phases;
pub mod primitives;
pub mod state;
pub mod wire;
pub mod xdevice;

#[cfg(feature = "webauthn")]
#[cfg_attr(docsrs, doc(cfg(feature = "webauthn")))]
pub mod passkey;

pub mod prelude;

pub use batch::{BatchGrant, BatchOperations, RedeemedBatch};
pub use custodian::{ConveyanceCredential, ConveyancePayload, Custodian};
pub use error::{Error, Result};
pub use freshness::{FreshnessStore, FreshnessToken, InMemoryFreshness};
pub use grant::{Grant, GrantOpt, RedeemedGrant, WrappingKey};
pub use operation::{Act, ActType, Bind, Multiplicity, Operation, RecipientPk, Valid};
pub use state::{
    PeerMap, PrfSalt, ProtectedState, Registry, SealedCredential, SealedState, Version, WrappedKey,
    CURRENT_VERSION,
};
