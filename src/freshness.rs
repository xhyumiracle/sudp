//! Freshness pool `S` (paper §5.5).
//!
//! `T` initialises a bounded single-use pool of `(r, τ_r)` tokens at Phase I.3.
//! Each token is issued once at Phase II.1 and consumed exactly once at Phase
//! II.3. This module provides an in-memory implementation; deployments that
//! need cross-process freshness can implement [`FreshnessStore`] over Redis,
//! a database, etc.
//!
//! Each token is 32 random bytes (256-bit unique-by-birthday-paradox-up-to-2^128).

use core::time::Duration;
use std::collections::HashMap;
use std::time::Instant;

use crate::primitives::Csprng;

/// 32-byte freshness token.
pub type FreshnessToken = [u8; 32];

/// `S`: pluggable freshness pool.
///
/// `T` issues tokens at Phase II.1 and consumes them at Phase II.3. The pool
/// MUST enforce single-use semantics (one issue → at most one successful
/// consumption) and SHOULD enforce a short TTL (paper: "on the order of
/// minutes").
pub trait FreshnessStore {
    /// Issue a fresh `r`. Returns the 32-byte token.
    fn issue(&mut self) -> FreshnessToken;

    /// Consume a token. Returns true iff the token was issued, has not
    /// expired, and has not been consumed before. The store MUST remove or
    /// mark the entry on success so a replay returns false.
    fn consume(&mut self, token: &[u8]) -> bool;

    /// Drop expired and consumed entries.
    fn cleanup(&mut self);
}

/// In-memory single-process freshness pool.
///
/// Tokens are 32 random bytes, single-use, with TTL `default_ttl` (5 minutes
/// by default).
#[cfg(feature = "std-primitives")]
pub struct InMemoryFreshness<R: Csprng = crate::primitives::OsCsprng> {
    issued: HashMap<FreshnessToken, Instant>,
    default_ttl: Duration,
    _rng: core::marker::PhantomData<R>,
}

/// In-memory single-process freshness pool.
///
/// Tokens are 32 random bytes, single-use, with TTL `default_ttl` (5 minutes
/// by default).
#[cfg(not(feature = "std-primitives"))]
pub struct InMemoryFreshness<R: Csprng> {
    issued: HashMap<FreshnessToken, Instant>,
    default_ttl: Duration,
    _rng: core::marker::PhantomData<R>,
}

#[cfg(feature = "std-primitives")]
impl Default for InMemoryFreshness<crate::primitives::OsCsprng> {
    fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }
}

impl<R: Csprng> InMemoryFreshness<R> {
    /// Create a new freshness pool with the given default TTL.
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            issued: HashMap::new(),
            default_ttl,
            _rng: core::marker::PhantomData,
        }
    }

    /// Number of currently-live tokens (non-expired, non-consumed).
    pub fn live_count(&self) -> usize {
        let now = Instant::now();
        self.issued
            .values()
            .filter(|t| now.duration_since(**t) < self.default_ttl)
            .count()
    }
}

impl<R: Csprng> FreshnessStore for InMemoryFreshness<R> {
    fn issue(&mut self) -> FreshnessToken {
        let token = R::random_32();
        self.issued.insert(token, Instant::now());
        token
    }

    fn consume(&mut self, token: &[u8]) -> bool {
        if token.len() != 32 {
            return false;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(token);
        match self.issued.remove(&key) {
            Some(issued_at) => Instant::now().duration_since(issued_at) < self.default_ttl,
            None => false,
        }
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let ttl = self.default_ttl;
        self.issued
            .retain(|_, issued_at| now.duration_since(*issued_at) < ttl);
    }
}

#[cfg(all(test, feature = "std-primitives"))]
mod tests {
    use super::*;

    #[test]
    fn issue_and_consume() {
        let mut pool = InMemoryFreshness::default();
        let r = pool.issue();
        assert!(pool.consume(&r));
        assert!(!pool.consume(&r), "double-consume must fail");
    }

    #[test]
    fn unknown_token_rejected() {
        let mut pool = InMemoryFreshness::default();
        assert!(!pool.consume(&[0u8; 32]));
    }

    #[test]
    fn distinct_tokens() {
        let mut pool = InMemoryFreshness::default();
        let a = pool.issue();
        let b = pool.issue();
        assert_ne!(a, b);
    }
}
