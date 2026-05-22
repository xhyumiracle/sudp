import { utf8 } from "./bytes.js";

/**
 * JCS-style canonical JSON encoder (RFC 8785 subset).
 *
 * Properties:
 *  - Object keys are sorted lexicographically by UTF-16 code unit.
 *  - Strings use `JSON.stringify` escaping.
 *  - Numbers must be finite. Floats are rejected — they have no
 *    byte-reproducible canonical form across endpoints and would be a
 *    substitution vector against `H(o)`. Use integers, strings, booleans,
 *    nulls, arrays, or nested objects.
 *  - `undefined` is treated as `null`.
 *
 * This MUST stay byte-for-byte aligned with the Rust crate's
 * `sudp::canonical::canonicalize_strict`. The `protocol/test_vectors/`
 * directory carries the conformance suite.
 */
export function canonicalize(value: unknown): Uint8Array {
  return utf8(canonicalizeStr(value));
}

function canonicalizeStr(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) {
      throw new Error("canonicalize: non-finite number is not allowed");
    }
    if (!Number.isInteger(v)) {
      throw new Error(
        "canonicalize: float values are rejected (no byte-reproducible canonical form)",
      );
    }
    return v.toString();
  }
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) {
    return "[" + v.map(canonicalizeStr).join(",") + "]";
  }
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return (
      "{" +
      keys
        .map((k) => JSON.stringify(k) + ":" + canonicalizeStr(obj[k]))
        .join(",") +
      "}"
    );
  }
  throw new Error(`canonicalize: unsupported value type: ${typeof v}`);
}
