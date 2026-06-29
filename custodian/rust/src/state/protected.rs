//! Decrypted protected state `M`.
//!
//! `M` is what `T` transiently materialises inside its trusted boundary after
//! Phase III.0. It contains:
//!
//! - the authority-bearing service secrets `s_o := M[target]`,
//! - the in-state authenticator map `{cid_c → W_c}` for multi-credential
//!   recoverability (default recoverability policy),
//! - deployment-specific auxiliary data.

use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::grant::WrappingKey;
use crate::Result;

/// Authenticator map: `{cid_c → W_c}` (default recoverability policy).
///
/// `BTreeMap` keys are base64 strings (deterministic ordering on the wire).
/// The values are wrapping keys for credentials other than the acting one;
/// Phase III.3 uses them to rewrap the new `K'` under each authenticator
/// credential.
pub type AuthenticatorMap = BTreeMap<String, WrappingKey>;

/// `M`: the decrypted protected state, accessible only inside `T`'s trusted
/// boundary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtectedState {
    /// `M[target] = s_o`. Keys are target identifiers, values are raw secret
    /// bytes (e.g. an API key or signing key).
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretValue>,
    /// `{cid → W_c}`, used by Phase III.3 for multi-credential rewrap.
    #[serde(default)]
    pub authenticators: AuthenticatorMap,
    /// Deployment-specific auxiliary state (vault metadata, deployment hints,
    /// …). Out-of-scope of the protocol; the crate just preserves it.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub aux: serde_json::Value,
}

/// Authority-bearing service secret `s_o`. Held as a length-prefixed byte
/// vector inside `M` so the protocol layer can be opaque to the secret's
/// semantics (API key, OAuth token, signing key, …).
#[derive(Clone, Default, Serialize, Deserialize, Zeroize)]
#[serde(transparent)]
pub struct SecretValue(#[serde(with = "crate::wire::b64bytes")] pub Vec<u8>);

impl core::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretValue(<{} bytes redacted>)", self.0.len())
    }
}

impl SecretValue {
    /// Borrow the secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Construct from raw bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ProtectedState {
    /// New empty state. Used at Phase I.2 setup before any secrets are added.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up `s_o := M[target]`. Returns an error if the
    /// target is absent.
    pub fn secret(&self, name: &str) -> Result<&[u8]> {
        self.secrets
            .get(name)
            .map(|v| v.as_bytes())
            .ok_or_else(|| crate::Error::TargetNotFound(name.to_string()))
    }

    /// Insert or replace the secret for a target.
    pub fn put_secret(&mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) {
        self.secrets
            .insert(name.into(), SecretValue::from_bytes(value));
    }

    /// Remove the secret for a target.
    pub fn remove_secret(&mut self, name: &str) -> Option<SecretValue> {
        self.secrets.remove(name)
    }

    /// Serialise to canonical JCS-style JSON bytes for sealing under `K`.
    ///
    /// Returns a [`Zeroizing<Vec<u8>>`] so the canonical bytes (which contain
    /// base64-encoded secret plaintexts and authenticator wrapping keys) are
    /// wiped on drop. The encoder writes directly into the zeroizing buffer
    /// **without constructing an intermediate `serde_json::Value` tree** — this
    /// avoids the prior leak path where secret bytes' base64 form lived in a
    /// non-zeroizing `String` inside `Value`.
    ///
    /// The structurally fixed shape is
    /// `{"authenticators":{…},"aux":…?,"secrets":{…}}` (keys sorted
    /// lexicographically per JCS: `authenticators` < `aux` < `secrets`). The
    /// optional `aux` field goes through [`crate::canonical::canonicalize`]
    /// which still uses `serde_json::Value`; deployments that put sensitive
    /// data in `aux` trade some zeroize guarantees and should
    /// encrypt-before-stuffing.
    pub fn to_canonical(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::with_capacity(256));
        out.push(b'{');
        let mut wrote_field = false;

        // "authenticators": {cid → base64(W_c)} — sorted first lexicographically
        // (authenticators < aux < secrets).
        write_field_key(&mut out, "authenticators", &mut wrote_field);
        out.push(b'{');
        for (i, (cid_b64, w)) in self.authenticators.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            write_json_string(&mut out, cid_b64);
            out.push(b':');
            write_base64_string(&mut out, w.as_bytes());
        }
        out.push(b'}');

        // "aux"
        if !self.aux.is_null() {
            write_field_key(&mut out, "aux", &mut wrote_field);
            // best-effort: aux still routes through serde_json::Value. Caller
            // should treat aux as non-secret per the to_canonical doc.
            let aux_bytes = crate::canonical::canonicalize_strict(&self.aux)?;
            out.extend_from_slice(&aux_bytes);
        }

        // "secrets": {path → base64(s_o)}
        write_field_key(&mut out, "secrets", &mut wrote_field);
        out.push(b'{');
        for (i, (path, val)) in self.secrets.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            write_json_string(&mut out, path);
            out.push(b':');
            write_base64_string(&mut out, val.as_bytes());
        }
        out.push(b'}');

        out.push(b'}');
        Ok(out)
    }

    /// Parse from canonical bytes (after Phase III.0 decryption of `C`).
    ///
    /// Goes directly from bytes to `ProtectedState` via the serde visitor
    /// pattern (no intermediate `serde_json::Value`). Secret plaintexts and
    /// wrapping keys land in [`SecretValue`] / [`WrappingKey`] which both
    /// `Zeroize` on drop, so the deserialize path is already leak-free.
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|_| crate::Error::Encoding("ProtectedState canonical parse"))
    }
}

// ── canonical-encoding helpers (private) ────────────────────────────────

fn write_field_key(out: &mut Vec<u8>, key: &str, wrote_field: &mut bool) {
    if *wrote_field {
        out.push(b',');
    }
    *wrote_field = true;
    write_json_string(out, key);
    out.push(b':');
}

/// JSON-encode `s` as a quoted string, written directly to `out` with
/// minimal allocation. Standard JSON escaping for `\`, `"`, and control
/// chars; non-ASCII passes through (UTF-8).
fn write_json_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for byte in s.bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            c if c < 0x20 => {
                let s = format!("\\u{:04x}", c);
                out.extend_from_slice(s.as_bytes());
            }
            c => out.push(c),
        }
    }
    out.push(b'"');
}

/// base64-encode `bytes` into a quoted JSON string, with the intermediate
/// base64 buffer held in `Zeroizing<String>` so it's wiped on scope exit.
fn write_base64_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let b64 = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(bytes));
    out.push(b'"');
    out.extend_from_slice(b64.as_bytes());
    out.push(b'"');
}
