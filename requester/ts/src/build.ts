/**
 * Convenience builders for SUDP operations.
 *
 * Each helper fills in the act type and sets sensible defaults
 * (`iat = now`, `multiplicity = "one"`), so the Requester can produce
 * a well-formed `Operation` without writing the nested JSON by hand.
 *
 * No transport here — these functions just return a plain object the
 * Requester then POSTs / RPCs / etc. to the Custodian as it sees fit.
 */

import type {
  Act,
  ActType,
  Multiplicity,
  Operation,
  RecipientPk,
} from "./types.js";
import { validateBatchOperations } from "./validate.js";

/**
 * Options shared by every op builder. `target`, `redeemer`, and `iat`
 * cover most cases; the others are optional or per-op-type.
 */
export interface BuildOpOpts {
  /** Identifier of the protected object inside `M` (e.g. `"env.api_key"`). */
  target: string;
  /** Party entitled to redeem (typically the Custodian's id). */
  redeemer: string;
  /** Adapter-canonicalisable JSON. Defaults to `{}`. */
  scope?: unknown;
  /** Unix seconds. Defaults to current wall-clock time. */
  iat?: number;
  /** Unix seconds. Absent means "no explicit expiry". */
  exp?: number;
  /**
   * KEM recipient. **Required** for `type = "export"` and ignored for
   * other act types (sudp rejects `export` without a recipient at
   * redemption time).
   */
  recipient?: RecipientPk;
  /** Defaults to `"one"`. SUDP v0.1 only implements single-use. */
  multiplicity?: Multiplicity;
}

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

function makeAct(type: ActType, opts: BuildOpOpts): Act {
  const act: Act = {
    type,
    target: opts.target,
  };
  if (opts.scope !== undefined) {
    act.scope = opts.scope;
  } else {
    act.scope = {};
  }
  return act;
}

/**
 * Generic builder. The convenience wrappers below all delegate to this.
 */
export function buildOp(act_type: ActType, opts: BuildOpOpts): Operation {
  if (!opts.target) {
    throw new Error("buildOp: `target` is required");
  }
  if (!opts.redeemer) {
    throw new Error("buildOp: `redeemer` is required");
  }
  if (act_type === "export" && !opts.recipient) {
    throw new Error(
      "buildOp: `recipient` is required for `export` (sudp rejects export without bind.recipient at redemption)",
    );
  }

  const op: Operation = {
    act: makeAct(act_type, opts),
    bind: { redeemer: opts.redeemer },
    valid: {
      iat: opts.iat ?? nowSeconds(),
      multiplicity: opts.multiplicity ?? "one",
    },
  };
  if (opts.recipient) {
    op.bind.recipient = opts.recipient;
  }
  if (opts.exp !== undefined) {
    op.valid.exp = opts.exp;
  }
  return op;
}

/** Non-extracting consumption — spend the secret inside `T`. */
export const useOp = (opts: BuildOpOpts): Operation => buildOp("use", opts);

/** Recipient-protected extraction. `opts.recipient` is required. */
export const exportOp = (opts: BuildOpOpts): Operation => buildOp("export", opts);

/** Mutate the protected state at `target`. */
export const writeOp = (opts: BuildOpOpts): Operation => buildOp("write", opts);

/** Rotate the state-encryption key. */
export const rotateOp = (opts: BuildOpOpts): Operation => buildOp("rotate", opts);

/** Add a credential. */
export const enrollOp = (opts: BuildOpOpts): Operation => buildOp("enroll", opts);

/** Remove a credential. */
export const revokeOp = (opts: BuildOpOpts): Operation => buildOp("revoke", opts);

/**
 * Profile-defined dispatch type. The Custodian's deployment is responsible
 * for handling it; sudp's built-in `execute_use` / `execute_export` /
 * `execute_lifecycle` reject custom types with `ActTypeMismatch`.
 */
export const customOp = (actTypeName: string, opts: BuildOpOpts): Operation =>
  buildOp(actTypeName, opts);

/**
 * Assemble a batch from individual {@link Operation}s with a single-call
 * structural check (non-empty array, at most one rotation-class op).
 * Returns the same array — `BatchOperations` is a JSON array on the wire.
 *
 * Equivalent to validating with {@link validateBatchOperations}; this
 * helper just makes the construction site read intentionally.
 */
export function batchOps(ops: Operation[]): Operation[] {
  validateBatchOperations(ops);
  return ops;
}
