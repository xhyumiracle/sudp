//! Mock authenticator for protocol-level tests.
//!
//! The mock is *not* a real cryptographic signature scheme; it returns a
//! HMAC-SHA256 of β under a per-credential symmetric key. That's plenty for
//! exercising Phase II.3's flow — we just need a verifier that succeeds on
//! the right β and fails on a tampered one.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use sudp::primitives::{Authenticator, EnrolledCredential};
use sudp::{Error, Result};

#[derive(Clone, Serialize, Deserialize)]
pub struct MockEnrollment {
    pub credential_id: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MockPublicKey {
    pub secret: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MockAssertion {
    pub credential_id: Vec<u8>,
    pub tag: Vec<u8>,
}

pub struct MockAuthenticator;

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
        let expected = h.finalize();
        if expected.as_slice() == assertion.tag.as_slice() {
            Ok(())
        } else {
            Err(Error::AuthorizationInvalid)
        }
    }

    fn check_credential_binding(credential_id: &[u8], assertion: &Self::Assertion) -> Result<()> {
        if assertion.credential_id == credential_id {
            Ok(())
        } else {
            Err(Error::AuthorizationInvalid)
        }
    }
}

pub fn sign(secret: &[u8], credential_id: &[u8], beta: &[u8; 32]) -> MockAssertion {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(beta);
    MockAssertion {
        credential_id: credential_id.to_vec(),
        tag: h.finalize().to_vec(),
    }
}
