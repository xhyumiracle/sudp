//! Deterministic canonical encoding for the operation hash.
//!
//! Both `U` and `T` must agree byte-for-byte on `canonical(o)` so that
//! `H(canonical(o))` recomputes identically at redemption time.
//!
//! This module implements an RFC 8785-style JSON Canonicalisation Scheme (JCS)
//! subset:
//!
//! - Object keys sorted by UTF-16 code unit order.
//! - No insignificant whitespace.
//! - Array order preserved.
//! - Strings re-serialised through `serde_json::to_string` (standard JSON
//!   escaping).
//! - Numbers re-serialised through `serde_json::Number::to_string`.
//!
//! Operations carry only integers, strings, booleans, nulls, and recursive
//! arrays/objects; floating-point edge cases do not arise.

use serde_json::Value;

use crate::Result;

/// Produce a canonical byte representation of a JSON value.
///
/// This is the function whose output is fed to [`Hash::hash`](crate::primitives::Hash)
/// to obtain `H(o)` for binding.
///
/// **Float behaviour**: this function silently round-trips floats through
/// `serde_json::Number::to_string()`. Floating-point representations are not
/// byte-reproducible across endpoints (NaN bit patterns, ±0, IEEE 754
/// rounding) — if the value reaches an operation hash, that's a substitution
/// vector. Use [`canonicalize_strict`] for any value that's about to enter
/// `H(o)` / `H(ops)` to fail loudly on floats instead.
pub fn canonicalize(value: &Value) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    encode_into(value, &mut buf, /*strict=*/ false).unwrap_or_else(|_| unreachable!());
    buf
}

/// Like [`canonicalize`] but **rejects float values** with
/// [`Error::CanonicalFloatRejected`](crate::Error::CanonicalFloatRejected).
///
/// All canonical paths that produce input for `H(o)` or `H(ops)` go through
/// this variant — see `Operation::canonical_bytes` and
/// `BatchOperations::canonical_bytes`. Use [`canonicalize`] only for
/// deployment-internal values where float-determinism doesn't matter.
pub fn canonicalize_strict(value: &Value) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(64);
    encode_into(value, &mut buf, /*strict=*/ true)?;
    Ok(buf)
}

fn encode_into(value: &Value, out: &mut Vec<u8>, strict: bool) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if strict && n.is_f64() {
                return Err(crate::Error::CanonicalFloatRejected);
            }
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => {
            let encoded = serde_json::to_string(s).unwrap_or_default();
            out.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_into(item, out, strict)?;
            }
            out.push(b']');
        }
        Value::Object(obj) => {
            out.push(b'{');
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort_by(|a, b| {
                let a16: Vec<u16> = a.encode_utf16().collect();
                let b16: Vec<u16> = b.encode_utf16().collect();
                a16.cmp(&b16)
            });
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let key = serde_json::to_string(k).unwrap_or_default();
                out.extend_from_slice(key.as_bytes());
                out.push(b':');
                encode_into(&obj[*k], out, strict)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys() {
        let v = json!({ "b": 1, "a": 2, "c": 3 });
        assert_eq!(
            std::str::from_utf8(&canonicalize(&v)).unwrap(),
            r#"{"a":2,"b":1,"c":3}"#
        );
    }

    #[test]
    fn preserves_array_order() {
        let v = json!([3, 1, 2]);
        assert_eq!(std::str::from_utf8(&canonicalize(&v)).unwrap(), "[3,1,2]");
    }

    #[test]
    fn nested_object_keys_sorted() {
        let v = json!({ "outer": { "z": 1, "a": 2 } });
        assert_eq!(
            std::str::from_utf8(&canonicalize(&v)).unwrap(),
            r#"{"outer":{"a":2,"z":1}}"#
        );
    }

    #[test]
    fn escapes_strings() {
        let v = json!({ "k": "hello \"world\"" });
        assert_eq!(
            std::str::from_utf8(&canonicalize(&v)).unwrap(),
            r#"{"k":"hello \"world\""}"#
        );
    }

    #[test]
    fn deterministic() {
        let a = json!({ "x": 1, "y": [2, 3] });
        let b = json!({ "y": [2, 3], "x": 1 });
        assert_eq!(canonicalize(&a), canonicalize(&b));
    }
}
