/**
 * `@sudp-protocol/authorizer/webauthn` — WebAuthn adapter for the Authorizer side.
 *
 * The core `@sudp-protocol/authorizer` package is intentionally **signer-agnostic**:
 * it accepts a 32-byte `userKey` (= `y_c`) and does not care how the
 * Authorizer obtained it. This subpath is the WebAuthn-specific glue:
 *
 *  - it runs HKDF over the raw PRF extension output to produce `y_c`;
 *  - it shapes a `PublicKeyCredential` assertion into the wire form the
 *    custodian expects.
 *
 * Other realisations (Yubikey static, secure-enclave, HSM, mock for tests)
 * live in their own adapters and never touch this file.
 */

import { utf8 } from "./bytes.js";

/**
 * Default HKDF `info` for WebAuthn PRF → userKey derivation. Identifies
 * this specific adapter on the wire.
 */
export const DEFAULT_PRF_INFO = utf8("sudp/v1/webauthn-prf-userkey");

/**
 * Options for {@link prfToUserKey}.
 */
export interface PrfToUserKeyOptions {
  /**
   * HKDF `info` parameter. Defaults to {@link DEFAULT_PRF_INFO}; deployments
   * that need to differentiate multiple WebAuthn-PRF surfaces under the same
   * custodian may override it.
   */
  readonly info?: Uint8Array;
  /**
   * HKDF `salt` parameter. Defaults to a 32-byte zero salt (extract-only
   * HKDF when the IKM is already uniform, per RFC 5869 §3.1).
   */
  readonly salt?: Uint8Array;
}

const DEFAULT_PRF_SALT = new Uint8Array(32);

/**
 * Derive a 32-byte `userKey` (= `y_c`) from the WebAuthn PRF extension's
 * raw first-output bytes.
 *
 *     y_c = HKDF-SHA-256(prfOutput, salt, info)
 *
 * The `info` string is what makes this adapter distinct from other ways of
 * producing `y_c` — picking the same `info` in a different authenticator
 * would lock you to compatible wire bytes.
 */
export async function prfToUserKey(
  prfOutput: Uint8Array,
  options?: PrfToUserKeyOptions,
): Promise<Uint8Array> {
  const info = options?.info ?? DEFAULT_PRF_INFO;
  const salt = options?.salt ?? DEFAULT_PRF_SALT;
  const km = await crypto.subtle.importKey(
    "raw",
    prfOutput as unknown as ArrayBuffer,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as unknown as ArrayBuffer,
      info: info as unknown as ArrayBuffer,
    },
    km,
    256,
  );
  return new Uint8Array(bits);
}

/**
 * Wire-shape of a WebAuthn assertion that the custodian's WebAuthn
 * `Authenticator` realisation can verify. Field names match the daemon's
 * expected wire format.
 */
export interface AssertionWire {
  readonly credentialId: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly clientDataJSON: Uint8Array;
  readonly signature: Uint8Array;
}

/**
 * Extract the four fields a custodian needs from a `PublicKeyCredential`
 * assertion.
 *
 * Note: this returns raw bytes. Callers that need base64url wire
 * encoding can run the fields through `bytesToB64Url` from the core
 * package.
 */
export function assertionToWire(
  assertion: PublicKeyCredential,
): AssertionWire {
  const r = assertion.response as AuthenticatorAssertionResponse;
  return {
    credentialId: new Uint8Array(assertion.rawId),
    authenticatorData: new Uint8Array(r.authenticatorData),
    clientDataJSON: new Uint8Array(r.clientDataJSON),
    signature: new Uint8Array(r.signature),
  };
}
