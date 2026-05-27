/**
 * Wire-shape types for the SUDP Requester role.
 *
 * These types mirror the JSON shape the Authorizer and Custodian see on
 * the wire. They follow the Rust crate's serialization choices exactly
 * (e.g. `Act.kind` renames to `"type"` in JSON; missing optionals are
 * absent fields, not explicit nulls).
 *
 * Byte fields (`r`, `credential_id`, `wrapping_key`, etc.) travel as
 * base64 strings on the wire; this package keeps them as strings so the
 * package stays codec-free.
 */

/**
 * Built-in act-type names. SUDP also accepts arbitrary strings for
 * deployment-defined custom dispatch — see {@link ActType}.
 */
export type ActTypeBuiltin =
  | "use"
  | "export"
  | "write"
  | "rotate"
  | "enroll"
  | "revoke";

/**
 * Semantic class of an operation. Either a built-in or a profile-defined
 * custom string (sudp's `ActType::Custom(String)` on the Rust side).
 */
export type ActType = ActTypeBuiltin | (string & {});

/**
 * Recipient public key for KEM-protected delivery (`act.kind = "export"`).
 *
 * `bytes` is base64 of the raw public-key bytes; `alg` is an
 * implementation-defined identifier (e.g. `"hpke-p256-sha256-aes128gcm"`).
 * The Custodian's KEM realisation interprets both.
 */
export interface RecipientPk {
  alg: string;
  bytes: string;
}

/**
 * "What is approved." Maps to `sudp::Act` on the Custodian side.
 *
 * `scope` is canonicalisable JSON — integers, strings, booleans, nulls,
 * arrays, nested objects. Floats are rejected by the canonical encoder
 * because they have no byte-reproducible form across endpoints.
 */
export interface Act {
  type: ActType;
  target: string;
  scope?: unknown;
}

/**
 * Redemption binding. `recipient` is required when `act.type = "export"`
 * and forbidden (omitted) otherwise.
 */
export interface Bind {
  redeemer: string;
  recipient?: RecipientPk;
}

/**
 * Operation multiplicity. SUDP v0.1 only implements `"one"` (single use);
 * `"unbounded"` is recognised on the wire but rejected at redemption.
 */
export type Multiplicity = "one" | "unbounded";

/**
 * Validity constraints. `iat` is unix seconds; `exp` is optional.
 * `multiplicity` defaults to `"one"` when absent.
 */
export interface Valid {
  iat: number;
  exp?: number;
  multiplicity?: Multiplicity;
}

/**
 * Canonical SUDP operation: `o = (act, bind, valid)`.
 */
export interface Operation {
  act: Act;
  bind: Bind;
  valid: Valid;
}

/**
 * Optional grant payload — only populated for rotation-class operations
 * (`write` / `rotate` / `enroll` / `revoke`).
 *
 * `wrapping_key_next` is base64 of `W*_next`, the wrapping key for the
 * next epoch.
 */
export interface GrantOpt {
  wrapping_key_next?: string;
}

/**
 * One-shot authorization artifact. The Requester typically does NOT
 * construct this — it arrives from the Authorizer over the
 * `A → R → T` (or `A → T` direct) relay and is forwarded to T as-is.
 *
 * `assertion` is authenticator-specific (a WebAuthn assertion bundle,
 * an HSM signature blob, a mock-for-tests value). This package treats it
 * as opaque.
 */
export interface Grant<TAssertion = unknown> {
  o: Operation;
  r: string;
  credential_id: string;
  wrapping_key: string;
  assertion: TAssertion;
  opt?: GrantOpt;
}

/**
 * Batch of operations approved by a single signature.
 *
 * On the wire this is just a JSON array of {@link Operation}s — matches
 * the Rust crate's `serde(transparent)` `BatchOperations(Vec<Operation>)`.
 * β generalises to `H(DS_BIND ‖ r ‖ H(canonical(ops)))`.
 *
 * SUDP enforces at most **one rotation-class** operation per batch
 * (`write` / `rotate` / `enroll` / `revoke`), because a single
 * authenticator invocation produces a single `W*_next`. See
 * {@link validateBatchOperations} from this package and
 * `Error::BatchMultipleRotationOps` on the Custodian side.
 */
export type BatchOperations = Operation[];

/**
 * Batch counterpart of {@link Grant}: the operation field is a
 * {@link BatchOperations} array instead of a single {@link Operation}.
 * Otherwise identical (same `r`, `cid`, `W_c`, `σ`, optional rotation
 * key) — one signature covers the whole batch.
 */
export interface BatchGrant<TAssertion = unknown> {
  ops: BatchOperations;
  r: string;
  credential_id: string;
  wrapping_key: string;
  assertion: TAssertion;
  opt?: GrantOpt;
}
