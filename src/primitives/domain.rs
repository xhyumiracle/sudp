//! Stable, pairwise-disjoint domain-separation labels (paper §5.3).
//!
//! Every `info` or `ad` argument that needs domain separation carries one of
//! these labels. Labels are byte-literal constants with the `sudp/v1/` prefix
//! to forbid cross-context replay.

/// Wrapping-key derivation label.
///
/// Used in `W_c = KDF(y_c; η_c, DS_wrap ‖ cid ‖ ver)` (paper §5.2).
pub const DS_WRAP: &[u8] = b"sudp/v1/wrap";

/// Channel binding label.
///
/// Used in `β = H(DS_bind ‖ r ‖ H(o))` (paper §5.5).
pub const DS_BIND: &[u8] = b"sudp/v1/bind";

/// Protected-state sealing label.
///
/// Used as the AEAD `ad` for `C = Enc_K(M; DS_seal ‖ ver)`.
pub const DS_SEAL: &[u8] = b"sudp/v1/seal";

/// HPKE delivery-key derivation label (paper §5.6 III.2).
pub const DS_DELIVERY: &[u8] = b"sudp/v1/delivery";

/// Cross-device handshake AEAD label (paper §7.2).
pub const DS_XD_ENC: &[u8] = b"sudp/v1/xd-enc";

/// Convenience enum surfacing labels at the public API.
///
/// Callers normally use the raw `&'static [u8]` constants above; this enum
/// exists so consumers can build domain labels typed at the API surface
/// (e.g. when implementing custom primitives that want to log which label
/// was used).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum DomainSeparator {
    /// `DS_wrap` — wrapping-key derivation.
    Wrap,
    /// `DS_bind` — channel binding for β.
    Bind,
    /// `DS_seal` — protected-state AEAD associated-data.
    Seal,
    /// `DS_delivery` — HPKE delivery KDF info.
    Delivery,
    /// `DS_xd_enc` — cross-device handshake AEAD.
    XdEnc,
}

impl DomainSeparator {
    /// Byte-literal label for this domain.
    pub fn label(self) -> &'static [u8] {
        match self {
            DomainSeparator::Wrap => DS_WRAP,
            DomainSeparator::Bind => DS_BIND,
            DomainSeparator::Seal => DS_SEAL,
            DomainSeparator::Delivery => DS_DELIVERY,
            DomainSeparator::XdEnc => DS_XD_ENC,
        }
    }
}
