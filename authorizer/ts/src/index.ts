/**
 * `@sudp/authorizer` — Authorizer-side primitives for the
 * Secret-Use Delegation Protocol.
 *
 * This entry point is **carrier-agnostic**: it carries only the protocol
 * cryptography (canonical JSON, β computation, wrapping-key derivation,
 * AEAD-as-wrap) and intentionally does **not** know about WebAuthn,
 * passkeys, HTTP, or any specific authenticator.
 *
 * For the WebAuthn PRF → y_c adapter and assertion helpers, import from
 * `@sudp/authorizer/webauthn`.
 */

export {
  utf8,
  concatBytes,
  u16beBytes,
  bytesToB64Url,
  b64UrlToBytes,
} from "./bytes.js";

export { canonicalize } from "./canonical.js";
export { sha256 } from "./hash.js";
export { computeBinding, DS_BIND } from "./binding.js";
export { deriveWrappingKey } from "./kdf.js";
export { wrapBindingAd, sealAd, DS_WRAP, DS_SEAL, WRAP_VERSION } from "./aad.js";
export { aeadEncrypt, aeadSeal, aeadOpen } from "./aead.js";
