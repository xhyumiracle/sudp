import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

const XNONCE_LEN = 24;
const XTAG_LEN = 16;

/**
 * XChaCha20-Poly1305 raw encrypt with a caller-supplied nonce.
 *
 * Output is `ciphertext ‖ tag` (no nonce prefix). Use {@link aeadSeal} for
 * the standard SUDP wire format that prepends a freshly random nonce.
 *
 * MUST stay byte-for-byte aligned with the Rust crate's
 * `sudp::primitives::Aead::encrypt`.
 */
export function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (nonce.byteLength !== XNONCE_LEN) {
    throw new Error(`aeadEncrypt: nonce must be ${XNONCE_LEN} bytes, got ${nonce.byteLength}`);
  }
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

/**
 * XChaCha20-Poly1305 thin wrapper.
 *
 * Wire layout (MUST match `sudp::primitives::Aead::seal`):
 *
 *     nonce(24 bytes) ‖ ciphertext ‖ tag(16 bytes)
 *
 * The 24-byte nonce is freshly generated per call. The caller supplies the
 * canonical AAD (see {@link wrapBindingAd}, {@link sealAd}).
 */
export function aeadSeal(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const nonce = crypto.getRandomValues(new Uint8Array(XNONCE_LEN));
  const ct = aeadEncrypt(key, nonce, plaintext, aad);
  const out = new Uint8Array(XNONCE_LEN + ct.byteLength);
  out.set(nonce, 0);
  out.set(ct, XNONCE_LEN);
  return out;
}

/**
 * Counterpart to {@link aeadSeal}. Throws if the AAD/nonce/ciphertext are
 * not authentic under `key`.
 */
export function aeadOpen(
  key: Uint8Array,
  sealed: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (sealed.byteLength <= XNONCE_LEN + XTAG_LEN) {
    throw new Error("aeadOpen: sealed blob is too short");
  }
  const nonce = sealed.slice(0, XNONCE_LEN);
  const ct = sealed.slice(XNONCE_LEN);
  return xchacha20poly1305(key, nonce, aad).decrypt(ct);
}
