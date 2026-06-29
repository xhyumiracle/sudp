//! Persistent sealed state `Σ` and its decrypted form `M`.
//!
//! `Σ_0 := ( C, {(cid_c, η_c, K̂_c)}, Reg, ver )`
//!
//! - `C = Enc_K(M; DS_seal ‖ ver)` — sealed protected state.
//! - `K̂_c = Wrap_{W_c}(K)` — per-credential wrapped state key.
//! - `Reg = {cid_c → pk_c}` — verifier registry, populated at enrollment.
//! - `ver` — wrapping epoch identifier.

mod protected;
mod registry;
mod sealed;

pub use protected::{AuthenticatorMap, ProtectedState};
pub use registry::Registry;
pub use sealed::{PrfSalt, SealedCredential, SealedState, Version, WrappedKey, CURRENT_VERSION};
