//! End-to-end SUDP flow with a mock authenticator and the standard primitive
//! suite.
//!
//! Run with:
//!
//! ```bash
//! cargo run --example end_to_end
//! ```
//!
//! Walks through Phase I (setup) → Phase II.1 (issue freshness) → Phase II.2
//! (sign β at "A") → Phase II.3 (redeem at "T") → Phase III.1 (use the
//! secret inside T's boundary).
//!
//! The mock authenticator is **not cryptographic** — it hashes (secret, β)
//! with SHA-256 — so this example demonstrates the *protocol shape* only.
//! Real deployments plug in `sudp::passkey::WebAuthn`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use sudp::beta::{compute_beta_for_op, DS_BIND};
use sudp::primitives::{Authenticator, EnrolledCredential, Sha256 as SudpSha256, StdPrimitives};
use sudp::{
    Act, ActType, Bind, Custodian, Error, Grant, GrantOpt, Operation, ProtectedState, Result,
    Valid, WrappingKey,
};

// ── mock authenticator ────────────────────────────────────────────────────

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

fn sign(secret: &[u8], credential_id: &[u8], beta: &[u8; 32]) -> MockAssertion {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(beta);
    MockAssertion {
        credential_id: credential_id.to_vec(),
        tag: h.finalize().to_vec(),
    }
}

// ── flow ──────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    println!("== Phase I — Setup ==");
    let credential_id = b"demo-cred".to_vec();
    let auth_secret = b"would-be-WebAuthn-PRF-output".to_vec();
    let wrapping_key = WrappingKey::from_bytes(vec![0xAAu8; 32]);
    let prf_salt = vec![0xBBu8; 32];

    let mut protected = ProtectedState::new();
    protected.put_secret("env.api_key", b"sk_live_top_secret".to_vec());

    let mut custodian: Custodian<StdPrimitives, MockAuthenticator> =
        Custodian::new("demo-custodian");

    let sealed = custodian.setup(
        protected,
        MockEnrollment {
            credential_id: credential_id.clone(),
            secret: auth_secret.clone(),
        },
        prf_salt,
        wrapping_key.clone(),
        &(),
    )?;
    println!(
        "  Σ_0 built: {} credential, {} bytes of sealed M",
        sealed.credentials.len(),
        sealed.ciphertext.len()
    );

    println!("\n== Phase II.1 — Issue freshness r ==");
    let r = custodian.issue_freshness();
    println!("  r = {} bytes (single-use)", r.len());

    println!("\n== Phase II.2 — Authorizer authorizes at A ==");
    let o = Operation {
        act: Act {
            kind: ActType::Use,
            target: "env.api_key".into(),
            scope: serde_json::json!({ "endpoint": "GET /repos/me" }),
        },
        bind: Bind {
            redeemer: "demo-custodian".into(),
            recipient: None,
        },
        valid: Valid::single_use(now(), Some(now() + 600)),
    };
    let beta = compute_beta_for_op::<SudpSha256>(DS_BIND, &r, &o)?;
    let assertion = sign(&auth_secret, &credential_id, &beta);
    println!("  β = SHA-256(DS_bind ‖ r ‖ H(o))");
    println!("  σ* = mock-sign over β");

    let grant = Grant::<MockAuthenticator> {
        o: o.clone(),
        r: r.to_vec(),
        credential_id: credential_id.clone(),
        wrapping_key: wrapping_key.clone(),
        assertion,
        opt: GrantOpt::default(),
    };

    println!("\n== Phase II.3 — Redeem at T ==");
    let redeemed = custodian.redeem_grant(grant, &(), &sealed, now())?;
    println!("  ρ accepted: target = {}", redeemed.o.act.target);

    println!("\n== Phase III.1 — Use s_o inside T's boundary ==");
    let response_status: u16 = custodian.execute_use(redeemed, &sealed, |target, s_o| {
        println!(
            "  T sees target {} = {} bytes of secret material",
            target,
            s_o.len()
        );
        println!("  (T would now call the environment with s_o ... E returns 200 OK)");
        Ok(200u16)
    })?;
    println!(
        "  R receives only ρ_out (status code {}); never sees s_o.",
        response_status
    );

    println!("\n✓ End-to-end SUDP flow complete.");
    Ok(())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
