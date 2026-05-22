//! WebAuthn assertion verification ( standard profile).
//!
//! Checks (WebAuthn L3 §7.2 plus SUDP channel binding):
//! 1. Decode `authenticatorData`, `clientDataJSON`, `signature`.
//! 2. `clientDataJSON.type == "webauthn.get"` (or `"webauthn.create"` for enrollment).
//! 3. `clientDataJSON.origin == expected_origin`.
//! 4. `base64url_decode(clientDataJSON.challenge) == β` (channel binding).
//! 5. `authenticatorData.rpIdHash == SHA-256(rpId)`.
//! 6. User Present flag set (User Verified flag also, if `require_uv`).
//! 7. ECDSA-P-256 verify of `authenticatorData ‖ SHA-256(clientDataJSON)`.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::beta::constant_time_eq;
use crate::primitives::{Authenticator, AuthenticatorContext, EnrolledCredential};
use crate::{Error, Result};

/// WebAuthn assertion (`navigator.credentials.get` response).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebAuthnAssertion {
    /// Base64 of the credential id this assertion is for (optional embedded
    /// consistency check).
    #[serde(default, rename = "credentialId", alias = "credential_id")]
    pub credential_id: Option<String>,
    /// Base64 of `authenticatorData`.
    #[serde(rename = "authenticatorData", alias = "authenticator_data")]
    pub authenticator_data: String,
    /// Base64 of `clientDataJSON`.
    #[serde(rename = "clientDataJSON", alias = "client_data_json")]
    pub client_data_json: String,
    /// Base64 of the DER-encoded ECDSA signature.
    pub signature: String,
}

/// WebAuthn enrollment (`navigator.credentials.create` response).
///
/// Minimal form: the client supplies the credential id and the P-256 public
/// key coordinates directly. Concrete deployments may additionally verify the
/// attestation statement; this minimal profile trusts the client to deliver
/// `(cid, x, y)` honestly over the authenticated transport.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebAuthnEnrollment {
    /// Base64 of the credential id.
    pub credential_id: String,
    /// Base64 of the P-256 X coordinate (32 raw bytes).
    pub public_key_x: String,
    /// Base64 of the P-256 Y coordinate (32 raw bytes).
    pub public_key_y: String,
    /// Optional device label (e.g. "Chrome (MacOS)").
    #[serde(default, alias = "deviceName", rename = "device_name")]
    pub device_name: String,
}

/// Canonical public-key record kept inside `Reg`. Just the two coordinate
/// strings; reconstruction happens at verification time.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebAuthnPublicKey {
    /// Base64 of P-256 X.
    pub x: String,
    /// Base64 of P-256 Y.
    pub y: String,
    /// Optional device label.
    #[serde(default)]
    pub device_name: String,
}

/// WebAuthn implementation of [`Authenticator`].
pub struct WebAuthn;

impl Authenticator for WebAuthn {
    type Enrollment = WebAuthnEnrollment;
    type Assertion = WebAuthnAssertion;
    type PublicKey = WebAuthnPublicKey;
    type Context = AuthenticatorContext;

    fn verify_enrollment(
        enrollment: &Self::Enrollment,
        _context: &Self::Context,
    ) -> Result<EnrolledCredential<Self::PublicKey>> {
        let cid = STANDARD
            .decode(&enrollment.credential_id)
            .map_err(|_| Error::Malformed("WebAuthn enrollment: credential_id not base64"))?;
        // Reconstruct the public key once to validate length and the curve point.
        let x = STANDARD
            .decode(&enrollment.public_key_x)
            .map_err(|_| Error::Malformed("WebAuthn enrollment: x not base64"))?;
        let y = STANDARD
            .decode(&enrollment.public_key_y)
            .map_err(|_| Error::Malformed("WebAuthn enrollment: y not base64"))?;
        let _ = public_key_from_xy(&x, &y)?;
        Ok(EnrolledCredential {
            credential_id: cid,
            public_key: WebAuthnPublicKey {
                x: enrollment.public_key_x.clone(),
                y: enrollment.public_key_y.clone(),
                device_name: enrollment.device_name.clone(),
            },
        })
    }

    fn verify_assertion(
        public_key: &Self::PublicKey,
        beta: &[u8; 32],
        assertion: &Self::Assertion,
        context: &Self::Context,
    ) -> Result<()> {
        let auth_data = STANDARD
            .decode(&assertion.authenticator_data)
            .map_err(|_| Error::AuthorizationInvalid)?;
        let client_data_json = STANDARD
            .decode(&assertion.client_data_json)
            .map_err(|_| Error::AuthorizationInvalid)?;
        let sig_der = STANDARD
            .decode(&assertion.signature)
            .map_err(|_| Error::AuthorizationInvalid)?;

        let client_obj: serde_json::Value =
            serde_json::from_slice(&client_data_json).map_err(|_| Error::AuthorizationInvalid)?;

        let cd_type = client_obj
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or(Error::AuthorizationInvalid)?;
        if cd_type != "webauthn.get" {
            return Err(Error::AuthorizationInvalid);
        }

        let origin = client_obj
            .get("origin")
            .and_then(|v| v.as_str())
            .ok_or(Error::AuthorizationInvalid)?;
        if !constant_time_eq(origin.as_bytes(), context.origin.as_bytes()) {
            return Err(Error::AuthorizationInvalid);
        }

        let challenge_b64u = client_obj
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or(Error::AuthorizationInvalid)?;
        let challenge_bytes = URL_SAFE_NO_PAD
            .decode(challenge_b64u)
            .map_err(|_| Error::AuthorizationInvalid)?;
        if challenge_bytes.len() != 32 || !constant_time_eq(&challenge_bytes, beta) {
            return Err(Error::AuthorizationInvalid);
        }

        if auth_data.len() < 37 {
            return Err(Error::AuthorizationInvalid);
        }
        let expected_rp_id_hash = Sha256::digest(context.rp_id.as_bytes());
        if !constant_time_eq(&auth_data[..32], expected_rp_id_hash.as_slice()) {
            return Err(Error::AuthorizationInvalid);
        }
        let flags = auth_data[32];
        if flags & 0x01 == 0 {
            return Err(Error::AuthorizationInvalid);
        }
        if context.require_uv && flags & 0x04 == 0 {
            return Err(Error::AuthorizationInvalid);
        }

        let client_data_hash = Sha256::digest(&client_data_json);
        let mut signed = Vec::with_capacity(auth_data.len() + 32);
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(&client_data_hash);

        let x_bytes = STANDARD
            .decode(&public_key.x)
            .map_err(|_| Error::AuthorizationInvalid)?;
        let y_bytes = STANDARD
            .decode(&public_key.y)
            .map_err(|_| Error::AuthorizationInvalid)?;
        let pk = public_key_from_xy(&x_bytes, &y_bytes)?;
        let vk = VerifyingKey::from(&pk);

        let raw_sig = der_to_raw_rs(&sig_der)?;
        let sig =
            Signature::try_from(raw_sig.as_slice()).map_err(|_| Error::AuthorizationInvalid)?;

        vk.verify(&signed, &sig)
            .map_err(|_| Error::AuthorizationInvalid)
    }

    fn check_credential_binding(credential_id: &[u8], assertion: &Self::Assertion) -> Result<()> {
        if let Some(asserted) = assertion.credential_id.as_deref() {
            let asserted_bytes = STANDARD
                .decode(asserted)
                .map_err(|_| Error::AuthorizationInvalid)?;
            if !constant_time_eq(&asserted_bytes, credential_id) {
                return Err(Error::AuthorizationInvalid);
            }
        }
        Ok(())
    }
}

fn public_key_from_xy(x: &[u8], y: &[u8]) -> Result<PublicKey> {
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::Malformed("WebAuthn: x/y must be 32 bytes"));
    }
    let mut x_arr = [0u8; 32];
    x_arr.copy_from_slice(x);
    let mut y_arr = [0u8; 32];
    y_arr.copy_from_slice(y);
    let point = EncodedPoint::from_affine_coordinates(&x_arr.into(), &y_arr.into(), false);
    let pk_opt: Option<PublicKey> = PublicKey::from_encoded_point(&point).into();
    pk_opt.ok_or(Error::Malformed("WebAuthn: invalid P-256 point"))
}

fn der_to_raw_rs(der: &[u8]) -> Result<[u8; 64]> {
    if der.len() < 8 || der[0] != 0x30 {
        return Err(Error::AuthorizationInvalid);
    }
    let seq_len = der[1] as usize;
    if seq_len + 2 > der.len() {
        return Err(Error::AuthorizationInvalid);
    }
    let mut offset = 2usize;

    if der[offset] != 0x02 {
        return Err(Error::AuthorizationInvalid);
    }
    let r_len = der[offset + 1] as usize;
    if offset + 2 + r_len > der.len() {
        return Err(Error::AuthorizationInvalid);
    }
    let r = &der[offset + 2..offset + 2 + r_len];
    offset += 2 + r_len;

    if offset >= der.len() || der[offset] != 0x02 {
        return Err(Error::AuthorizationInvalid);
    }
    let s_len = der[offset + 1] as usize;
    if offset + 2 + s_len > der.len() {
        return Err(Error::AuthorizationInvalid);
    }
    let s = &der[offset + 2..offset + 2 + s_len];

    let mut out = [0u8; 64];
    let r_take = r.len().min(32);
    let r_src_start = r.len() - r_take;
    let r_dst_start = 32 - r_take;
    out[r_dst_start..32].copy_from_slice(&r[r_src_start..]);

    let s_take = s.len().min(32);
    let s_src_start = s.len() - s_take;
    let s_dst_start = 32 + (32 - s_take);
    out[s_dst_start..64].copy_from_slice(&s[s_src_start..]);

    Ok(out)
}
