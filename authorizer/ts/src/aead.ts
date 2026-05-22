import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

const XNONCE_LEN = 24;
const XTAG_LEN = 16;

/**
 * XChaCha20-Poly1305 thin wrapper.
 *
 * Wire layout (MUST match `sudp::primitives::AeadWrap<ChaCha20Poly1305>`):
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
  const ct = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
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
