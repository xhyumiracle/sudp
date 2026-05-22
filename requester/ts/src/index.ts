/**
 * `@sudp/requester` — wire-shape types and operation builders for the
 * SUDP Requester role.
 *
 * Intentionally thin: no crypto (the Authorizer signs β; see
 * `@sudp/authorizer`), no HTTP (transport is a deployment concern), no
 * framework adapters (each agent framework wires SUDP its own way).
 *
 * See `README.md` for the no-scope-creep contract.
 */

export type {
  Act,
  ActType,
  ActTypeBuiltin,
  Bind,
  Grant,
  GrantOpt,
  Multiplicity,
  Operation,
  RecipientPk,
  Valid,
} from "./types.js";

export {
  buildOp,
  customOp,
  enrollOp,
  exportOp,
  revokeOp,
  rotateOp,
  useOp,
  writeOp,
} from "./build.js";
export type { BuildOpOpts } from "./build.js";

export { isBuiltinActType, validateGrant, validateOperation } from "./validate.js";
