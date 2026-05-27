import { concatBytes, utf8 } from "./bytes.js";
import { canonicalize } from "./canonical.js";
import { sha256 } from "./hash.js";

/**
 * Domain separation tag for the Phase II.2 binding hash. Matches the Rust
 * crate's `sudp::primitives::domain::DS_BIND` byte-for-byte.
 *
 *     β = SHA-256(DS_BIND ‖ r ‖ SHA-256(canonical(o)))
 */
export const DS_BIND = utf8("sudp/v1/bind");

/**
 * Compute the binding hash `β` for a given operation, freshness `r`, and
 * domain separation tag.
 *
 *     β = SHA-256(domain ‖ r ‖ SHA-256(canonical(op)))
 *
 * The Authorizer signs `β` with its authenticator. The custodian recomputes
 * `β` from the redeemed grant's `(o, r)` and verifies the signature.
 *
 * Pass {@link DS_BIND} for the default profile; other domains may be used
 * by adjacent ceremonies (e.g. setup attestation) and live in the
 * deployment.
 */
export async function computeBinding(
  domain: Uint8Array,
  r: Uint8Array,
  op: unknown,
): Promise<Uint8Array> {
  const opHash = await sha256(canonicalize(op));
  return sha256(concatBytes(domain, r, opHash));
}

/**
 * Batch counterpart of {@link computeBinding}:
 *
 *     β = SHA-256(domain ‖ r ‖ SHA-256(canonical(ops)))
 *
 * where `ops` is a JSON array of operations. Byte-aligned with the Rust
 * crate's `compute_beta_from_canonical(domain, r, &BatchOperations(ops).canonical_bytes())`.
 *
 * Semantically identical to `computeBinding(domain, r, ops)` because the
 * canonical encoder treats arrays uniformly, but named separately so the
 * "batch" intent is explicit at the call site (and so a single conformance
 * vector pins the batch shape independently).
 */
export async function computeBatchBinding(
  domain: Uint8Array,
  r: Uint8Array,
  ops: readonly unknown[],
): Promise<Uint8Array> {
  return computeBinding(domain, r, ops);
}
