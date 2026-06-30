import { aeadOpen, aeadSeal } from "./aead.js";
import { concatBytes, u32beBytes, utf8 } from "./bytes.js";

/**
 * Per-record seal/unseal — the per-item vault primitive, authorizer-side mirror
 * of the Rust crate's `sudp::state::{seal_record, unseal_record}`.
 *
 * Eats bytes, spits bytes: the record's business structure, serialization,
 * id derivation, version comparison, merge, tombstones, and GC are ALL the
 * caller's concern. This module only seals one record under the vault key `K`
 * bound — via AEAD associated data — to a structured {@link SealCtx}, so a
 * record can never be opened under a different vault / id / version / domain.
 *
 * The AAD binding detects cross-vault splicing, cross-id substitution,
 * version/ciphertext mismatch, and cross-domain confusion. It does NOT by
 * itself prevent rollback (an attacker substituting a strictly older but
 * validly-sealed record with its matching older `version`) — keep a monotonic
 * per-id version store on the caller side, and put richer causal/merge metadata
 * (HLC, device id, …) INSIDE the plaintext so the AEAD authenticates it too.
 *
 * Every byte layout here (canonical AAD, HKDF info, sealed framing) MUST stay
 * byte-for-byte aligned with `custodian/rust/src/state/record.rs`; the
 * conformance vectors in `test/conformance.test.ts` are pinned against the Rust
 * `assert_eq!` anchors.
 */

/** Per-record (per-item) domain-separation label. */
export const DS_ITEM = utf8("sudp/v1/item");

/** Suite/format tag: `0x01` = XChaCha20-Poly1305 + canonical AAD v1. */
export const RECORD_SUITE_XCHACHA20POLY1305 = 0x01;

/**
 * Structured sealing context for one record. sudp builds the AEAD associated
 * data from these fields; callers MUST NOT hand-assemble opaque AAD.
 */
export interface SealCtx {
  /** Purpose separation within the per-record domain, e.g. `"item"` / `"keyset"`. */
  domain: string;
  /** Vault identifier (anti cross-vault splice). */
  vault: Uint8Array;
  /** Opaque record id — typically `HMAC_K(name)`; never interpreted (anti X-as-Y). */
  id: Uint8Array;
  /**
   * Opaque, monotonic-per-id ordering value. sudp binds it into the AAD but
   * never interprets it — meaning (server sequence number, Lamport/HLC stamp,
   * version-vector, …) and the whole conflict-resolution strategy are the
   * caller's. Recommended scalar encoding for the common case: `u64`
   * big-endian (`u64beBytes(n)`). Binds the ciphertext to a version (detects
   * mismatch, not rollback).
   */
  version: Uint8Array;
}

/** Length-prefixed field: `len_be(u32) ‖ bytes`. */
function lp(field: Uint8Array): Uint8Array {
  return concatBytes(u32beBytes(field.byteLength), field);
}

/**
 * Canonical, length-prefixed associated data for a per-record seal:
 *
 *     AAD = suite(1) ‖ lp(DS_ITEM) ‖ lp(domain_utf8) ‖ lp(vault) ‖ lp(id) ‖ lp(version)
 *     where lp(x) = len_be(x.length as u32, 4 bytes) ‖ x
 *
 * MUST be byte-identical to the Rust crate's `record_aad`.
 */
export function recordAad(suite: number, ctx: SealCtx): Uint8Array {
  return concatBytes(
    new Uint8Array([suite & 0xff]),
    lp(DS_ITEM),
    lp(utf8(ctx.domain)),
    lp(ctx.vault),
    lp(ctx.id),
    lp(ctx.version),
  );
}

/**
 * Derive the per-record AEAD key `K_aead` from the vault key `k`:
 *
 *     K_aead = HKDF-SHA-256(ikm = k, salt = "", info = DS_ITEM)
 *
 * Domain-separated so `K_aead` never shares raw bytes with the caller's
 * `HMAC_K(name)` record-id derivation. MUST match the Rust crate's
 * `derive_item_key`.
 */
export async function deriveItemKey(k: Uint8Array): Promise<Uint8Array> {
  const km = await crypto.subtle.importKey(
    "raw",
    k as unknown as ArrayBuffer,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0) as unknown as ArrayBuffer,
      info: DS_ITEM as unknown as ArrayBuffer,
    },
    km,
    256,
  );
  return new Uint8Array(bits);
}

/**
 * Seal one record. Output layout: `suite(1) ‖ nonce(24) ‖ ciphertext ‖ tag(16)`.
 * A fresh random 24-byte nonce is generated per call (Web Crypto).
 */
export async function sealRecord(
  k: Uint8Array,
  ctx: SealCtx,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const kAead = await deriveItemKey(k);
  const aad = recordAad(RECORD_SUITE_XCHACHA20POLY1305, ctx);
  const sealed = aeadSeal(kAead, plaintext, aad); // nonce ‖ ct ‖ tag
  const out = new Uint8Array(1 + sealed.byteLength);
  out[0] = RECORD_SUITE_XCHACHA20POLY1305;
  out.set(sealed, 1);
  return out;
}

/**
 * Unseal one record. Throws on any authentication failure (AAD mismatch and
 * tag mismatch are indistinguishable — the same Poly1305 check) or on a
 * structurally malformed blob (empty / unknown suite tag).
 */
export async function unsealRecord(
  k: Uint8Array,
  ctx: SealCtx,
  sealed: Uint8Array,
): Promise<Uint8Array> {
  if (sealed.byteLength < 1) {
    throw new Error("unsealRecord: empty sealed blob");
  }
  const suite = sealed[0]!;
  if (suite !== RECORD_SUITE_XCHACHA20POLY1305) {
    throw new Error("unsealRecord: unknown suite tag");
  }
  const kAead = await deriveItemKey(k);
  const aad = recordAad(suite, ctx);
  return aeadOpen(kAead, sealed.slice(1), aad);
}
