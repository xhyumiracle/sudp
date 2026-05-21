//! Phase I (Setup), Phase II (Grant), Phase III (Consumption).
//!
//! Each phase is implemented as a small set of free functions over a
//! [`PrimitiveSuite`](crate::primitives::PrimitiveSuite). The [`Custodian`](crate::Custodian)
//! façade ties them together with state ownership and freshness bookkeeping;
//! using the free functions directly is useful for tests and for deployments
//! that want to manage freshness themselves.

pub mod consumption;
pub mod grant;
pub mod setup;
