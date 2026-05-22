//! Decrypted protected state `M`.
//!
//! `M` is what `T` transiently materialises inside its trusted boundary after
//! Phase III.0. It contains:
//!
//! - the authority-bearing service secrets `s_o := M[target]`,
//! - the in-state peer map `Peer := {cid_c → W_c}` for multi-credential
//!   recoverability (default peer-map policy),
//! - deployment-specific auxiliary data.

use std::collections::BTreeMap;

use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::grant::WrappingKey;
use crate::Result;

/// Peer map: `{cid_c → W_c}` (default recoverability policy).
///
/// `BTreeMap` keys are base64 strings (deterministic ordering on the wire).
/// The values are wrapping keys for credentials other than the acting one;
/// Phase III.3 uses them to rewrap the new `K'` under each peer credential.
pub type PeerMap = BTreeMap<String, WrappingKey>;

/// `M`: the decrypted protected state, accessible only inside `T`'s trusted
/// boundary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtectedState {
    /// `M[target] = s_o`. Keys are target identifiers, values are raw secret
    /// bytes (e.g. an API key or signing key).
    #[serde(default)]
    pub targets: BTreeMap<String, TargetValue>,
    /// `Peer = {cid → W_c}`, used by Phase III.3 for multi-credential rewrap.
    #[serde(default)]
    pub peers: PeerMap,
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
pub struct TargetValue(#[serde(with = "crate::wire::b64bytes")] pub Vec<u8>);

impl core::fmt::Debug for TargetValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TargetValue(<{} bytes redacted>)", self.0.len())
    }
}

impl TargetValue {
    /// Borrow the secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Construct from raw bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

impl Drop for TargetValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ProtectedState {
    /// New empty state. Used at Phase I.2 setup before any targets are added.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up `s_o := M[target]`. Returns an error if the
    /// target is absent.
    pub fn target(&self, name: &str) -> Result<&[u8]> {
        self.targets
            .get(name)
            .map(|v| v.as_bytes())
            .ok_or_else(|| crate::Error::TargetNotFound(name.to_string()))
    }

    /// Insert or replace a target value.
    pub fn put_target(&mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) {
        self.targets
            .insert(name.into(), TargetValue::from_bytes(value));
    }

    /// Remove a target.
    pub fn remove_target(&mut self, name: &str) -> Option<TargetValue> {
        self.targets.remove(name)
    }

    /// Serialise to canonical JCS-style JSON bytes for sealing under `K`.
    ///
    /// Returns a [`Zeroizing<Vec<u8>>`] so the canonical bytes (which contain
    /// base64-encoded target plaintexts and peer wrapping keys) are wiped on
    /// drop. The encoder writes directly into the zeroizing buffer **without
    /// constructing an intermediate `serde_json::Value` tree** — this avoids
    /// the prior leak path where target bytes' base64 form lived in a
    /// non-zeroizing `String` inside `Value`.
    ///
    /// The structurally fixed shape is `{"aux":…?,"peers":{…},"targets":{…}}`
    /// (keys sorted lexicographically per JCS). The optional `aux` field
    /// goes through [`crate::canonical::canonicalize`] which still uses
    /// `serde_json::Value`; deployments that put sensitive data in `aux`
    /// trade some zeroize guarantees and should encrypt-before-stuffing.
    pub fn to_canonical(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::with_capacity(256));
        out.push(b'{');
        let mut wrote_field = false;

        // "aux" — sorted first lexicographically (a < p < t).
        if !self.aux.is_null() {
            write_field_key(&mut out, "aux", &mut wrote_field);
            // best-effort: aux still routes through serde_json::Value. Caller
            // should treat aux as non-secret per the to_canonical doc.
            let aux_bytes = crate::canonical::canonicalize_strict(&self.aux)?;
            out.extend_from_slice(&aux_bytes);
        }

        // "peers": {cid → base64(W_c)}
        write_field_key(&mut out, "peers", &mut wrote_field);
        out.push(b'{');
        for (i, (cid_b64, w)) in self.peers.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            write_json_string(&mut out, cid_b64);
            out.push(b':');
            write_base64_string(&mut out, w.as_bytes());
        }
        out.push(b'}');

        // "targets": {path → base64(s_o)}
        write_field_key(&mut out, "targets", &mut wrote_field);
        out.push(b'{');
        for (i, (path, val)) in self.targets.iter().enumerate() {
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
    /// pattern (no intermediate `serde_json::Value`). Target plaintexts and
    /// wrapping keys land in [`TargetValue`] / [`WrappingKey`] which both
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
