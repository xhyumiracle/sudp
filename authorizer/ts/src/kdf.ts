import { concatBytes, u16beBytes } from "./bytes.js";
import { DS_WRAP, WRAP_VERSION } from "./aad.js";

/**
 * Derive the per-credential wrapping key `W_c` from the Authorizer's
 * user-key `y_c` (a 32-byte secret produced by the authenticator).
 *
 *     W_c = HKDF-SHA-256(y_c, salt = prf_salt, info = DS_WRAP ‖ credId ‖ ver_be)
 *
 * `y_c` must arrive at the Authorizer side already shaped to 32 bytes; how
 * it is produced is authenticator-specific and outside the SUDP core (see
 * `./webauthn` for the WebAuthn PRF → y_c adapter, but custom authenticators
 * may provide y_c directly).
 *
 * MUST stay byte-for-byte aligned with the Rust crate's
 * `sudp::crypto::kdf::derive_wrapping_key`.
 */
export async function deriveWrappingKey(
  userKey: Uint8Array,
  prfSalt: Uint8Array,
  credentialId: Uint8Array,
  wrapVersion: number = WRAP_VERSION,
): Promise<Uint8Array> {
  const km = await crypto.subtle.importKey(
    "raw",
    userKey as unknown as ArrayBuffer,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const info = concatBytes(DS_WRAP, credentialId, u16beBytes(wrapVersion));
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: prfSalt as unknown as ArrayBuffer,
      info: info as unknown as ArrayBuffer,
    },
    km,
    256,
  );
  return new Uint8Array(bits);
}
