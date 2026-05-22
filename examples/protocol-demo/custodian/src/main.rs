//! Demo Custodian — a thin HTTP server wrapping `sudp::Custodian` to make
//! the SUDP protocol observable end-to-end.
//!
//! This binary is **not for production**. It uses a mock authenticator
//! (SHA-256 over a shared secret) instead of WebAuthn, holds sealed
//! state in memory keyed by a server-issued id, and prints chatty logs
//! to stderr so the protocol's data flow is visible from the outside.
//!
//! Endpoints (sudp-aware shape — the same skeleton a real deployment
//! like safeclaw uses, just simplified for a single-binary demo):
//!
//!     POST /sudp/v1/setup                 — Phase I (enroll a credential)
//!     POST /sudp/v1/use                   — Phase II.1 (R proposes op, T issues r)
//!     POST /sudp/v1/use/{id}/redeem       — Phase II.3 + III.1 (R submits grant)
//!     GET  /health                         — liveness for the runner

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use sudp::beta::DS_BIND;
use sudp::primitives::{Authenticator, EnrolledCredential, StdPrimitives};
use sudp::{
    Act, ActType, Bind, Custodian, Error, Grant, GrantOpt, Operation, ProtectedState, RecipientPk,
    Result, Valid, WrappingKey,
};

// ─── Mock authenticator (shared with the TS runner) ──────────────────────
//
// Signature = SHA-256(secret ‖ β). The TS runner reproduces this exactly
// when it "signs" β at A. This intentionally has no cryptographic value;
// it exists so the demo can run without a real WebAuthn ceremony.

#[derive(Clone, Serialize, Deserialize)]
struct MockEnrollment {
    credential_id: Vec<u8>,
    secret: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MockPublicKey {
    secret: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MockAssertion {
    credential_id: Vec<u8>,
    tag: Vec<u8>,
}

struct MockAuthenticator;

impl Authenticator for MockAuthenticator {
    type Enrollment = MockEnrollment;
    type Assertion = MockAssertion;
    type PublicKey = MockPublicKey;
    type Context = ();

    fn verify_enrollment(
        e: &Self::Enrollment,
        _: &Self::Context,
    ) -> Result<EnrolledCredential<Self::PublicKey>> {
        Ok(EnrolledCredential {
            credential_id: e.credential_id.clone(),
            public_key: MockPublicKey {
                secret: e.secret.clone(),
            },
        })
    }

    fn verify_assertion(
        pk: &Self::PublicKey,
        beta: &[u8; 32],
        assertion: &Self::Assertion,
        _: &Self::Context,
    ) -> Result<()> {
        let mut h = Sha256::new();
        h.update(&pk.secret);
        h.update(beta);
        if h.finalize().as_slice() == assertion.tag.as_slice() {
            Ok(())
        } else {
            Err(Error::AuthorizationInvalid)
        }
    }

    fn check_credential_binding(cid: &[u8], a: &Self::Assertion) -> Result<()> {
        if a.credential_id == cid {
            Ok(())
        } else {
            Err(Error::AuthorizationInvalid)
        }
    }
}

// ─── Server state ────────────────────────────────────────────────────────

struct AppState {
    custodian: Custodian<StdPrimitives, MockAuthenticator>,
    /// Sealed state per setup. Keyed by `sealed_state_id` (uuid).
    states: HashMap<String, sudp::SealedState>,
    /// Pending freshness tokens per request id. Single-use.
    pending: HashMap<String, Vec<u8>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            custodian: Custodian::new("demo-custodian"),
            states: HashMap::new(),
            pending: HashMap::new(),
        }
    }
}

// ─── HTTP wiring ─────────────────────────────────────────────────────────

fn main() {
    let bind_addr = std::env::var("SUDP_DEMO_BIND").unwrap_or_else(|_| "127.0.0.1:28789".into());
    let server = tiny_http::Server::http(&bind_addr).expect("bind");

    eprintln!("[T] sudp-demo-custodian listening on http://{}", bind_addr);
    let state = Mutex::new(AppState::new());

    for mut req in server.incoming_requests() {
        let path = req.url().to_string();
        let method = req.method().to_string();
        eprintln!("[T] <- {} {}", method, path);

        let mut body = String::new();
        let _ = req.as_reader().read_to_string(&mut body);

        let result: std::result::Result<Value, String> = match (method.as_str(), path.as_str()) {
            ("GET", "/health") => Ok(json!({"status":"ok"})),
            ("POST", "/sudp/v1/setup") => handle_setup(&state, &body),
            ("POST", "/sudp/v1/use") => handle_freshness(&state, &body),
            (method, path) if method == "POST" && path.starts_with("/sudp/v1/use/") && path.ends_with("/redeem") => {
                let id = path
                    .trim_start_matches("/sudp/v1/use/")
                    .trim_end_matches("/redeem");
                handle_use_redeem(&state, id, &body)
            }
            _ => Err(format!("not found: {} {}", method, path)),
        };

        let (status, payload) = match result {
            Ok(v) => (200u32, v.to_string()),
            Err(e) => (400u32, json!({"error": e}).to_string()),
        };
        eprintln!("[T] -> {} ({} bytes)", status, payload.len());

        let response = tiny_http::Response::from_string(payload).with_status_code(status);
        let response = response.with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
        let _ = req.respond(response);
    }
}

// ─── Endpoint handlers ───────────────────────────────────────────────────

fn handle_setup(state: &Mutex<AppState>, body: &str) -> std::result::Result<Value, String> {
    #[derive(Deserialize)]
    struct Req {
        credential_id_b64: String,
        secret_b64: String,
        prf_salt_b64: String,
        wrapping_key_b64: String,
        initial_targets: HashMap<String, String>,
    }

    let req: Req = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let credential_id = b64_decode(&req.credential_id_b64)?;
    let secret = b64_decode(&req.secret_b64)?;
    let prf_salt = b64_decode(&req.prf_salt_b64)?;
    let wrapping_key = WrappingKey::from_bytes(b64_decode(&req.wrapping_key_b64)?);

    let mut protected = ProtectedState::new();
    for (k, v_b64) in &req.initial_targets {
        let v = b64_decode(v_b64)?;
        protected.put_target(k, v);
    }

    let mut s = state.lock().map_err(|e| e.to_string())?;
    let sealed = s
        .custodian
        .setup(
            protected,
            MockEnrollment {
                credential_id: credential_id.clone(),
                secret,
            },
            prf_salt,
            wrapping_key,
            &(),
        )
        .map_err(|e| format!("{:?}", e))?;
    let n_creds = sealed.credentials.len();
    let n_bytes = sealed.ciphertext.len();
    let id = uuid::Uuid::new_v4().to_string();
    s.states.insert(id.clone(), sealed);

    eprintln!(
        "[T] Σ_0 persisted under sealed_state_id={} (creds={}, ciphertext={}B)",
        id, n_creds, n_bytes
    );
    Ok(json!({
        "sealed_state_id": id,
        "credentials": n_creds,
        "ciphertext_bytes": n_bytes,
    }))
}

fn handle_freshness(state: &Mutex<AppState>, body: &str) -> std::result::Result<Value, String> {
    #[derive(Deserialize)]
    struct Req {
        sealed_state_id: String,
        op: Operation,
    }

    let req: Req = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let mut s = state.lock().map_err(|e| e.to_string())?;
    if !s.states.contains_key(&req.sealed_state_id) {
        return Err(format!("unknown sealed_state_id: {}", req.sealed_state_id));
    }
    let r = s.custodian.issue_freshness();
    let request_id = uuid::Uuid::new_v4().to_string();
    s.pending
        .insert(request_id.clone(), r.to_vec());

    eprintln!(
        "[T] issued r ({} bytes) for op.act.type={:?} -> request_id={}",
        r.len(),
        req.op.act.kind,
        request_id
    );
    Ok(json!({
        "request_id": request_id,
        "r_b64": B64.encode(&r),
        "ds_bind": String::from_utf8_lossy(DS_BIND).to_string(),
        "op": req.op,
    }))
}

fn handle_use_redeem(
    state: &Mutex<AppState>,
    request_id: &str,
    body: &str,
) -> std::result::Result<Value, String> {
    #[derive(Deserialize)]
    struct Req {
        sealed_state_id: String,
        op: Operation,
        credential_id_b64: String,
        wrapping_key_b64: String,
        assertion: MockAssertion,
    }

    let req: Req = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let mut s = state.lock().map_err(|e| e.to_string())?;
    let r = s
        .pending
        .remove(request_id)
        .ok_or_else(|| format!("unknown or already-consumed request_id: {}", request_id))?;
    let sealed = s
        .states
        .get(&req.sealed_state_id)
        .ok_or_else(|| format!("unknown sealed_state_id: {}", req.sealed_state_id))?
        .clone();

    let grant = Grant::<MockAuthenticator> {
        o: req.op,
        r,
        credential_id: b64_decode(&req.credential_id_b64)?,
        wrapping_key: WrappingKey::from_bytes(b64_decode(&req.wrapping_key_b64)?),
        assertion: req.assertion,
        opt: GrantOpt::default(),
    };

    let redeemed = s
        .custodian
        .redeem_grant(grant, &(), &sealed, now())
        .map_err(|e| format!("{:?}", e))?;
    eprintln!(
        "[T] σ verified, K unwrapped, M opened. target={}",
        redeemed.o.act.target
    );

    // Phase III.1: run the closure on s_o. Demo "uses" the secret by
    // echoing its length back to R, so R can verify "T saw bytes" without
    // ever seeing s_o itself.
    let status: u32 = s
        .custodian
        .execute_use(redeemed, &sealed, |target, s_o| {
            eprintln!(
                "[T] execute_use closure: target={} s_o.len()={}",
                target,
                s_o.len()
            );
            Ok(200u32)
        })
        .map_err(|e| format!("{:?}", e))?;

    Ok(json!({
        "status": status,
        "note": "R received only this response (ρ); s_o never crossed the wire.",
    }))
}

// ─── Helpers ─────────────────────────────────────────────────────────────

fn b64_decode(s: &str) -> std::result::Result<Vec<u8>, String> {
    B64.decode(s).map_err(|e| format!("base64: {}", e))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// Silence unused warnings for items used only by serde derives below.
#[allow(dead_code)]
fn _phantom(_: &Act, _: &ActType, _: &Bind, _: &Valid, _: &RecipientPk) {}
