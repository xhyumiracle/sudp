/**
 * Structural validation of incoming Operation / Grant payloads.
 *
 * Catches missing or malformed fields BEFORE they reach the wire. This is
 * deliberately not a canonical-JSON check — that lives on the Authorizer
 * and Custodian sides (in `@sudp-protocol/authorizer` and `sudp` Rust respectively).
 */

import type { ActType, BatchGrant, BatchOperations, Grant, Operation } from "./types.js";

const BUILTIN_ACT_TYPES: ReadonlySet<string> = new Set([
  "use",
  "export",
  "write",
  "rotate",
  "enroll",
  "revoke",
]);

const ROTATION_CLASS_ACT_TYPES: ReadonlySet<string> = new Set([
  "write",
  "rotate",
  "enroll",
  "revoke",
]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function ensure(condition: boolean, where: string, message: string): asserts condition {
  if (!condition) {
    throw new Error(`validate ${where}: ${message}`);
  }
}

/**
 * Throw if `op` is missing required fields or has malformed shapes.
 * Returns the same value with a narrowed type on success.
 */
export function validateOperation(op: unknown): asserts op is Operation {
  ensure(isPlainObject(op), "Operation", "must be a plain object");

  ensure(isPlainObject(op.act), "Operation.act", "must be a plain object");
  const act = op.act;
  ensure(typeof act.type === "string" && act.type.length > 0, "Operation.act.type", "must be a non-empty string");
  ensure(typeof act.target === "string" && act.target.length > 0, "Operation.act.target", "must be a non-empty string");
  // scope may be undefined or any canonicalisable JSON; no shape check here.

  ensure(isPlainObject(op.bind), "Operation.bind", "must be a plain object");
  const bind = op.bind;
  ensure(typeof bind.redeemer === "string" && bind.redeemer.length > 0, "Operation.bind.redeemer", "must be a non-empty string");

  // Export requires recipient.
  if (act.type === "export") {
    ensure(
      isPlainObject(bind.recipient),
      "Operation.bind.recipient",
      "is required when act.type is 'export'",
    );
    const recipient = bind.recipient as Record<string, unknown>;
    ensure(typeof recipient.alg === "string" && recipient.alg.length > 0, "Operation.bind.recipient.alg", "must be a non-empty string");
    ensure(typeof recipient.bytes === "string" && recipient.bytes.length > 0, "Operation.bind.recipient.bytes", "must be a non-empty base64 string");
  } else if (bind.recipient !== undefined) {
    ensure(isPlainObject(bind.recipient), "Operation.bind.recipient", "if present, must be a plain object");
  }

  ensure(isPlainObject(op.valid), "Operation.valid", "must be a plain object");
  const valid = op.valid;
  ensure(Number.isInteger(valid.iat) && (valid.iat as number) >= 0, "Operation.valid.iat", "must be a non-negative integer (unix seconds)");
  if (valid.exp !== undefined) {
    ensure(Number.isInteger(valid.exp) && (valid.exp as number) >= 0, "Operation.valid.exp", "if present, must be a non-negative integer (unix seconds)");
  }
  if (valid.multiplicity !== undefined) {
    ensure(
      valid.multiplicity === "one" || valid.multiplicity === "unbounded",
      "Operation.valid.multiplicity",
      "if present, must be 'one' or 'unbounded'",
    );
  }
}

/**
 * Throw if `grant` is missing required fields. Does NOT verify any
 * cryptographic property — that's the Custodian's job at redemption.
 */
export function validateGrant(grant: unknown): asserts grant is Grant {
  ensure(isPlainObject(grant), "Grant", "must be a plain object");
  validateOperation((grant as Record<string, unknown>).o);
  ensure(typeof grant.r === "string" && grant.r.length > 0, "Grant.r", "must be a non-empty base64 string");
  ensure(typeof grant.credential_id === "string" && grant.credential_id.length > 0, "Grant.credential_id", "must be a non-empty base64 string");
  ensure(typeof grant.wrapping_key === "string" && grant.wrapping_key.length > 0, "Grant.wrapping_key", "must be a non-empty base64 string");
  ensure(grant.assertion !== undefined, "Grant.assertion", "must be present (authenticator-specific shape)");
  if (grant.opt !== undefined) {
    ensure(isPlainObject(grant.opt), "Grant.opt", "if present, must be a plain object");
  }
}

/**
 * True iff the act type is one of SUDP's built-in semantics. Custom
 * profile-defined types return false (sudp's built-in dispatchers reject
 * them with `ActTypeMismatch`).
 */
export function isBuiltinActType(t: ActType): boolean {
  return BUILTIN_ACT_TYPES.has(t);
}

/**
 * True iff the act type mutates sealed state (`write` / `rotate` /
 * `enroll` / `revoke`). Rotation-class ops drive `W*_next` and at most
 * one is allowed per batch — see {@link validateBatchOperations}.
 */
export function isRotationClassActType(t: ActType): boolean {
  return ROTATION_CLASS_ACT_TYPES.has(t);
}

/**
 * Throw if `ops` is not a well-formed batch:
 *  - must be a non-empty array
 *  - each element must pass {@link validateOperation}
 *  - at most one rotation-class op (sudp's `Error::BatchMultipleRotationOps`)
 */
export function validateBatchOperations(ops: unknown): asserts ops is BatchOperations {
  ensure(Array.isArray(ops), "BatchOperations", "must be an array");
  ensure(ops.length > 0, "BatchOperations", "must contain at least one operation");
  let rotationCount = 0;
  for (let i = 0; i < ops.length; i++) {
    try {
      validateOperation(ops[i]);
    } catch (e) {
      throw new Error(`validate BatchOperations[${i}]: ${(e as Error).message}`);
    }
    const op = ops[i] as Operation;
    if (isRotationClassActType(op.act.type)) {
      rotationCount++;
    }
  }
  ensure(
    rotationCount <= 1,
    "BatchOperations",
    "at most one rotation-class operation per batch (Write/Rotate/Enroll/Revoke); sudp rejects this with BatchMultipleRotationOps",
  );
}

/**
 * Throw if `grant` is not a well-formed {@link BatchGrant}.
 */
export function validateBatchGrant(grant: unknown): asserts grant is BatchGrant {
  ensure(isPlainObject(grant), "BatchGrant", "must be a plain object");
  validateBatchOperations((grant as Record<string, unknown>).ops);
  ensure(typeof grant.r === "string" && grant.r.length > 0, "BatchGrant.r", "must be a non-empty base64 string");
  ensure(typeof grant.credential_id === "string" && grant.credential_id.length > 0, "BatchGrant.credential_id", "must be a non-empty base64 string");
  ensure(typeof grant.wrapping_key === "string" && grant.wrapping_key.length > 0, "BatchGrant.wrapping_key", "must be a non-empty base64 string");
  ensure(grant.assertion !== undefined, "BatchGrant.assertion", "must be present (authenticator-specific shape)");
  if (grant.opt !== undefined) {
    ensure(isPlainObject(grant.opt), "BatchGrant.opt", "if present, must be a plain object");
  }
}
