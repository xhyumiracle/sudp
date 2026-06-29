import { concatBytes, u16beBytes, utf8 } from "./bytes.js";

export const DS_WRAP = utf8("sudp/v1/wrap");
export const DS_SEAL = utf8("sudp/v1/seal");

/**
 * Current wrap version. Bumped together on both ends of the protocol if the
 * AAD shape ever changes.
 */
export const WRAP_VERSION = 0x0001;

/**
 * Canonical AAD for the AEAD-as-wrap profile:
 *
 *     DS_WRAP ‖ credentialId ‖ ver_be(u16, big-endian)
 *
 * Bound as associated data when sealing/opening `K̂_c` under `W_c`, so a
 * per-credential-wrapped record cannot be substituted across credentials or versions.
 */
export function wrapBindingAd(
  credentialId: Uint8Array,
  wrapVersion: number = WRAP_VERSION,
): Uint8Array {
  return concatBytes(DS_WRAP, credentialId, u16beBytes(wrapVersion));
}

/**
 * Canonical AAD for the sealed-body AEAD layer:
 *
 *     DS_SEAL ‖ ver_be(u16, big-endian)
 */
export function sealAd(wrapVersion: number = WRAP_VERSION): Uint8Array {
  return concatBytes(DS_SEAL, u16beBytes(wrapVersion));
}
