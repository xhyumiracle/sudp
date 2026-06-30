//! Per-record seal/unseal — the per-item vault primitive.
//!
//! This is the foundation for deployments that store a vault as **many
//! independently-encrypted small records** (one ciphertext per item) rather than
//! one monolithic [`super::SealedState`] blob. Each record is sealed under the
//! same vault key `K` but bound, via AEAD associated data, to a structured
//! [`SealCtx`] so that records can never be confused, swapped, or replayed
//! across vaults / ids / versions / domains.
//!
//! ## What sudp does and does NOT do here
//!
//! `seal_record` / `unseal_record` are a pure **byte-in / byte-out** codec:
//! sudp does not serialize the business record, does not derive the record id,
//! does not compare versions, does not merge conflicts, does not garbage-collect
//! tombstones, and does not manage the set of records. All of that is the
//! caller's concern (in SafeClaw's terms: the sync/merge layer). sudp only
//! guarantees that a sealed record opens **iff** it is presented under the exact
//! same `(domain, vault, id, version)` it was sealed with.
//!
//! ## What the AAD binding buys (and what it does not)
//!
//! The AEAD authenticates `SealCtx`, so `unseal_record` detects:
//! - **cross-vault splicing** — a record from vault A presented as vault B,
//! - **cross-id substitution** — passing record X's ciphertext as record Y,
//! - **version/ciphertext mismatch** — a ciphertext presented under a version it
//!   was not sealed with,
//! - **cross-domain confusion** — an `"item"` record opened as a `"keyset"`.
//!
//! It does **NOT** by itself prevent **rollback**: an attacker who can write the
//! record store and substitutes a strictly older *but still validly sealed*
//! record together with its matching older `version` produces a blob that opens
//! fine. Anti-rollback is the caller's job — keep a monotonic per-id version
//! store and reject any incoming `version` that is not strictly newer than the
//! highest already observed. sudp cannot and does not enforce freshness.
//!
//! ## Cross-language parity
//!
//! The same record may be sealed in the browser (JS) and opened by the daemon
//! (Rust), so the canonical AAD encoding ([`record_aad`]) and the key derivation
//! ([`derive_item_key`], private) MUST be byte-identical across Rust and
//! `@sudp-protocol/authorizer`. The conformance vectors at the bottom of this
//! file are pinned against matching assertions in
//! `authorizer/ts/test/conformance.test.ts`; change one side, change both.
//! (The *payload* bytes passed to `seal_record` are the caller's responsibility
//! to keep consistent across languages — sudp never looks inside them.)

use zeroize::Zeroizing;

use crate::primitives::domain::DS_ITEM;
use crate::primitives::{Aead, Kdf, PrimitiveSuite};
use crate::{Error, Result};

/// Suite/format tag for the per-record sealed layout.
///
/// Emitted as the first byte of every sealed blob **and** folded into the AAD,
/// so the wire format is downgrade-resistant and leaves room for future AEAD
/// agility (a new cipher/encoding would claim a new tag value) without ambiguity.
/// `0x01` = XChaCha20-Poly1305 + canonical AAD v1.
pub const RECORD_SUITE_XCHACHA20POLY1305: u8 = 0x01;

/// Structured sealing context for one record.
///
/// sudp builds the AEAD associated data from these fields; the caller MUST NOT
/// hand-assemble opaque AAD (that is the whole point — a structured, length-
/// prefixed context is the only reliable way to make cross-vault / cross-id /
/// version-mismatch tamper-evident).
pub struct SealCtx<'a> {
    /// Purpose separation within the per-record domain, e.g. `"item"` /
    /// `"keyset"`. Encoded as UTF-8 bytes in the AAD.
    pub domain: &'a str,
    /// Vault identifier. Binds the record to its vault (anti cross-vault splice).
    /// Defense-in-depth even when `K` is already per-vault: if `K` is ever shared
    /// across vault ids, this becomes the sole splicing guard.
    pub vault: &'a [u8],
    /// Opaque record id. The caller typically stores `HMAC_K(name)` here; sudp
    /// never interprets it. Binds the ciphertext to this id (anti X-as-Y).
    pub id: &'a [u8],
    /// Opaque, monotonic-per-id ordering value. sudp binds it into the AAD but
    /// **never interprets it** — its meaning (a server-assigned sequence number,
    /// a Lamport/HLC stamp, a version-vector, a hash-chain head, …) and the
    /// entire conflict-resolution strategy are the caller's. Recommended scalar
    /// encoding for the common case: `u64` big-endian (`&n.to_be_bytes()`).
    /// Binding it detects a version/ciphertext *mismatch*; it does NOT by itself
    /// prevent rollback — keep a monotonic per-id version store on your side and
    /// decide there what counts as "newer". Richer ordering keys may be bound
    /// here directly, or kept inside the sealed plaintext (also AEAD-
    /// authenticated) — caller's choice per their threat model.
    pub version: &'a [u8],
}

/// Append a length-prefixed field: `len_be(u32) ‖ bytes`.
fn push_lp(out: &mut Vec<u8>, field: &[u8], what: &'static str) -> Result<()> {
    let len = u32::try_from(field.len()).map_err(|_| Error::Malformed(what))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Build the canonical, length-prefixed associated data for a per-record seal:
///
/// ```text
/// AAD = suite(1 byte)
///     ‖ lp(DS_ITEM) ‖ lp(domain_utf8) ‖ lp(vault) ‖ lp(id) ‖ lp(version)
///
/// where  lp(x) = len_be(x.len() as u32, 4 bytes, big-endian) ‖ x
/// ```
///
/// Length-prefixing every variable field removes splicing ambiguity between
/// adjacent variable-length fields — without it, `vault="ab",id="c"` and
/// `vault="a",id="bc"` would produce identical bytes. MUST be byte-identical to
/// the authorizer-side `recordAad` in `@sudp-protocol/authorizer`.
pub fn record_aad(suite: u8, ctx: &SealCtx<'_>) -> Result<Vec<u8>> {
    let domain = ctx.domain.as_bytes();
    let mut aad = Vec::with_capacity(
        1 + 4
            + DS_ITEM.len()
            + 4
            + domain.len()
            + 4
            + ctx.vault.len()
            + 4
            + ctx.id.len()
            + 4
            + ctx.version.len(),
    );
    aad.push(suite);
    push_lp(&mut aad, DS_ITEM, "record AAD: label too long")?;
    push_lp(&mut aad, domain, "record AAD: domain too long")?;
    push_lp(&mut aad, ctx.vault, "record AAD: vault id too long")?;
    push_lp(&mut aad, ctx.id, "record AAD: record id too long")?;
    push_lp(&mut aad, ctx.version, "record AAD: version too long")?;
    Ok(aad)
}

/// Derive the per-record AEAD key `K_aead` from the vault key `k` with
/// domain-separated HKDF info (`DS_ITEM`), so `K_aead` never shares raw bytes
/// with any other use of `k` — in particular the caller's `HMAC_K(name)`
/// record-id derivation. (`HMAC-SHA-256` and `XChaCha20-Poly1305` have no known
/// cross-protocol interaction, so sharing raw `K` is not exploitable, but key
/// separation is cheap hygiene and `K_aead` costs one extra HKDF expand.)
fn derive_item_key<S: PrimitiveSuite>(k: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(S::Kdf::derive_32(k, &[], DS_ITEM)?))
}

/// Seal one record. Eats bytes, spits bytes. Output layout:
///
/// ```text
/// suite(1) ‖ nonce(24) ‖ ciphertext ‖ tag(16)
/// ```
///
/// The entire [`SealCtx`] (plus the suite tag) is authenticated as AEAD
/// associated data, so [`unseal_record`] rejects any record presented under a
/// different vault / id / version / domain.
pub fn seal_record<S: PrimitiveSuite>(
    k: &[u8],
    ctx: &SealCtx<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let k_aead = derive_item_key::<S>(k)?;
    let aad = record_aad(RECORD_SUITE_XCHACHA20POLY1305, ctx)?;
    let mut sealed = S::Aead::seal(&k_aead[..], plaintext, &aad)?;
    let mut out = Vec::with_capacity(1 + sealed.len());
    out.push(RECORD_SUITE_XCHACHA20POLY1305);
    out.append(&mut sealed);
    Ok(out)
}

/// Unseal one record. Returns the plaintext bytes, or a single opaque
/// verification failure ([`Error::SealDecryptionFailed`]) if anything in `ctx`
/// or the ciphertext fails to authenticate — AAD mismatch and tag mismatch are
/// deliberately indistinguishable (they are the same Poly1305 check). A
/// structurally malformed blob (empty / unknown suite) surfaces as
/// [`Error::Malformed`]; that is a pre-crypto check and leaks nothing about the
/// key or plaintext.
pub fn unseal_record<S: PrimitiveSuite>(
    k: &[u8],
    ctx: &SealCtx<'_>,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    let (&suite, body) = sealed
        .split_first()
        .ok_or(Error::Malformed("record: empty sealed blob"))?;
    if suite != RECORD_SUITE_XCHACHA20POLY1305 {
        return Err(Error::Malformed("record: unknown suite tag"));
    }
    let k_aead = derive_item_key::<S>(k)?;
    let aad = record_aad(suite, ctx)?;
    S::Aead::open(&k_aead[..], body, &aad)
}

#[cfg(all(test, feature = "std-primitives"))]
mod tests {
    use super::*;
    use crate::primitives::{Aead, ChaCha20Poly1305, StdPrimitives};

    fn ctx<'a>(domain: &'a str, vault: &'a [u8], id: &'a [u8], version: &'a [u8]) -> SealCtx<'a> {
        SealCtx {
            domain,
            vault,
            id,
            version,
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn roundtrip() {
        let k = [0x42u8; 32];
        let c = ctx("item", b"vault-1", b"id-abc", &[7]);
        let pt = b"a connect token";
        let sealed = seal_record::<StdPrimitives>(&k, &c, pt).unwrap();
        assert_eq!(sealed[0], RECORD_SUITE_XCHACHA20POLY1305);
        let opened = unseal_record::<StdPrimitives>(&k, &c, &sealed).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let k = [0x42u8; 32];
        let c = ctx("item", b"v", b"i", &[0]);
        let sealed = seal_record::<StdPrimitives>(&k, &c, b"").unwrap();
        assert_eq!(
            unseal_record::<StdPrimitives>(&k, &c, &sealed).unwrap(),
            b""
        );
    }

    #[test]
    fn empty_version_roundtrips() {
        // version is opaque caller bytes; even an empty version round-trips.
        let k = [0x42u8; 32];
        let c = ctx("item", b"v", b"id", b"");
        let sealed = seal_record::<StdPrimitives>(&k, &c, b"x").unwrap();
        assert_eq!(
            unseal_record::<StdPrimitives>(&k, &c, &sealed).unwrap(),
            b"x"
        );
    }

    #[test]
    fn wrong_vault_fails() {
        let k = [0x42u8; 32];
        let sealed =
            seal_record::<StdPrimitives>(&k, &ctx("item", b"vault-1", b"id", &[1]), b"x").unwrap();
        let bad =
            unseal_record::<StdPrimitives>(&k, &ctx("item", b"vault-2", b"id", &[1]), &sealed);
        assert!(matches!(bad, Err(Error::SealDecryptionFailed)));
    }

    #[test]
    fn wrong_id_fails() {
        let k = [0x42u8; 32];
        let sealed =
            seal_record::<StdPrimitives>(&k, &ctx("item", b"v", b"id-A", &[1]), b"x").unwrap();
        let bad = unseal_record::<StdPrimitives>(&k, &ctx("item", b"v", b"id-B", &[1]), &sealed);
        assert!(matches!(bad, Err(Error::SealDecryptionFailed)));
    }

    #[test]
    fn wrong_version_fails() {
        let k = [0x42u8; 32];
        let sealed =
            seal_record::<StdPrimitives>(&k, &ctx("item", b"v", b"id", &[1]), b"x").unwrap();
        let bad = unseal_record::<StdPrimitives>(&k, &ctx("item", b"v", b"id", &[2]), &sealed);
        assert!(matches!(bad, Err(Error::SealDecryptionFailed)));
    }

    #[test]
    fn version_length_extension_fails() {
        // lp(version) means [0x01] and [0x00,0x01] are distinct contexts.
        let k = [0x42u8; 32];
        let sealed =
            seal_record::<StdPrimitives>(&k, &ctx("item", b"v", b"id", &[1]), b"x").unwrap();
        let bad = unseal_record::<StdPrimitives>(&k, &ctx("item", b"v", b"id", &[0, 1]), &sealed);
        assert!(matches!(bad, Err(Error::SealDecryptionFailed)));
    }

    #[test]
    fn wrong_domain_fails() {
        let k = [0x42u8; 32];
        let sealed =
            seal_record::<StdPrimitives>(&k, &ctx("item", b"v", b"id", &[1]), b"x").unwrap();
        let bad = unseal_record::<StdPrimitives>(&k, &ctx("keyset", b"v", b"id", &[1]), &sealed);
        assert!(matches!(bad, Err(Error::SealDecryptionFailed)));
    }

    #[test]
    fn wrong_key_fails() {
        let sealed =
            seal_record::<StdPrimitives>(&[1u8; 32], &ctx("item", b"v", b"id", &[1]), b"x")
                .unwrap();
        let bad =
            unseal_record::<StdPrimitives>(&[2u8; 32], &ctx("item", b"v", b"id", &[1]), &sealed);
        assert!(matches!(bad, Err(Error::SealDecryptionFailed)));
    }

    #[test]
    fn empty_blob_is_malformed() {
        let bad = unseal_record::<StdPrimitives>(&[0u8; 32], &ctx("item", b"v", b"id", &[1]), b"");
        assert!(matches!(bad, Err(Error::Malformed(_))));
    }

    #[test]
    fn unknown_suite_is_malformed() {
        let k = [0x42u8; 32];
        let mut sealed =
            seal_record::<StdPrimitives>(&k, &ctx("item", b"v", b"id", &[1]), b"x").unwrap();
        sealed[0] = 0x02; // flip the suite tag
        let bad = unseal_record::<StdPrimitives>(&k, &ctx("item", b"v", b"id", &[1]), &sealed);
        assert!(matches!(bad, Err(Error::Malformed(_))));
    }

    #[test]
    fn lp_ambiguity_is_resolved() {
        // Without length prefixes, ("ab","c") and ("a","bc") for (vault,id)
        // would collide. With them, the two AADs differ.
        let a = record_aad(0x01, &ctx("item", b"ab", b"c", &[1])).unwrap();
        let b = record_aad(0x01, &ctx("item", b"a", b"bc", &[1])).unwrap();
        assert_ne!(a, b);
    }

    // ── Cross-language conformance anchors ──────────────────────────────────
    // Matching assertions live in authorizer/ts/test/conformance.test.ts.
    // Fixed inputs (no random nonce) so the bytes are deterministic.

    const CV_K: [u8; 32] = [0x11u8; 32];
    const CV_NONCE: [u8; 24] = [0x22u8; 24];
    const CV_DOMAIN: &str = "item";
    const CV_VAULT: &[u8] = b"vault-7";
    const CV_ID: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
    // Opaque version bytes — here the recommended u64-big-endian encoding of
    // 0x0102030405060708.
    const CV_VERSION: &[u8] = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    const CV_PT: &[u8] = b"the lazy dog jumps over...";

    fn cv_ctx() -> SealCtx<'static> {
        ctx(CV_DOMAIN, CV_VAULT, CV_ID, CV_VERSION)
    }

    #[test]
    fn conformance_record_aad() {
        // = suite(01)
        //   ‖ lp("sudp/v1/item") ‖ lp("item") ‖ lp("vault-7") ‖ lp(aabbccdd)
        //   ‖ lp(0102030405060708)
        let aad = record_aad(RECORD_SUITE_XCHACHA20POLY1305, &cv_ctx()).unwrap();
        assert_eq!(
            hex(&aad),
            "010000000c737564702f76312f6974656d000000046974656d000000077661756c742d3700000004aabbccdd000000080102030405060708"
        );
    }

    #[test]
    fn conformance_item_key() {
        // K_aead = HKDF-SHA256(ikm = K, salt = "", info = "sudp/v1/item")
        let k_aead = derive_item_key::<StdPrimitives>(&CV_K).unwrap();
        assert_eq!(
            hex(&k_aead[..]),
            "d9e525d7f8047ad0c47bc270f44e22a7a4038d2fb7df863924128481efe83823"
        );
    }

    #[test]
    fn conformance_sealed_fixed_nonce() {
        // Reconstruct the sealed blob deterministically with a fixed nonce
        // (seal_record itself samples a random nonce in production).
        let k_aead = derive_item_key::<StdPrimitives>(&CV_K).unwrap();
        let aad = record_aad(RECORD_SUITE_XCHACHA20POLY1305, &cv_ctx()).unwrap();
        let ct = ChaCha20Poly1305::encrypt(&k_aead[..], &CV_NONCE, CV_PT, &aad).unwrap();
        let mut sealed = Vec::new();
        sealed.push(RECORD_SUITE_XCHACHA20POLY1305);
        sealed.extend_from_slice(&CV_NONCE);
        sealed.extend_from_slice(&ct);
        assert_eq!(
            hex(&sealed),
            "0122222222222222222222222222222222222222222222222291131d0f0ef48770f42cb1bd5ef3915479ad080de28b148392796ccd6f88a3eeb1c5fe3a3bff54a793be"
        );
        // And it must open through the real public path.
        let opened = unseal_record::<StdPrimitives>(&CV_K, &cv_ctx(), &sealed).unwrap();
        assert_eq!(opened, CV_PT);
    }
}
