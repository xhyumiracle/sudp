//! End-to-end protocol tests using the mock authenticator and the standard
//! primitive suite.

mod mock_authenticator;

use mock_authenticator::{sign, MockAuthenticator, MockEnrollment};
use sudp::beta::compute_beta_for_op;
use sudp::primitives::{Hash, Sha256, StdPrimitives};
use sudp::{
    Act, ActType, Bind, Custodian, Grant, GrantOpt, Operation, ProtectedState, Valid, WrappingKey,
};

fn fresh_secret() -> Vec<u8> {
    use rand::RngCore;
    let mut s = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut s);
    s
}

fn op_use(target: &str, redeemer: &str) -> Operation {
    Operation {
        act: Act {
            kind: ActType::Use,
            target: target.into(),
            scope: serde_json::json!({}),
        },
        bind: Bind {
            redeemer: redeemer.into(),
            recipient: None,
        },
        valid: Valid {
            iat: 1_000_000,
            exp: Some(1_000_000 + 600),
        },
    }
}

fn op_write(target: &str, redeemer: &str) -> Operation {
    Operation {
        act: Act {
            kind: ActType::Write,
            target: target.into(),
            scope: serde_json::json!({ "new_value": "secret-v2" }),
        },
        bind: Bind {
            redeemer: redeemer.into(),
            recipient: None,
        },
        valid: Valid {
            iat: 1_000_000,
            exp: Some(1_000_000 + 600),
        },
    }
}

fn op_rotate(redeemer: &str) -> Operation {
    Operation {
        act: Act {
            kind: ActType::Rotate,
            target: "vault".into(),
            scope: serde_json::json!({}),
        },
        bind: Bind {
            redeemer: redeemer.into(),
            recipient: None,
        },
        valid: Valid {
            iat: 1_000_000,
            exp: Some(1_000_000 + 600),
        },
    }
}

fn op_enroll(redeemer: &str, new_cid_b64: &str) -> Operation {
    Operation {
        act: Act {
            kind: ActType::Enroll,
            target: "registry".into(),
            scope: serde_json::json!({ "new_credential_id_b64": new_cid_b64 }),
        },
        bind: Bind {
            redeemer: redeemer.into(),
            recipient: None,
        },
        valid: Valid {
            iat: 1_000_000,
            exp: Some(1_000_000 + 600),
        },
    }
}

fn op_revoke(redeemer: &str, revoked_cid_b64: &str) -> Operation {
    Operation {
        act: Act {
            kind: ActType::Revoke,
            target: "registry".into(),
            scope: serde_json::json!({ "revoked_credential_id_b64": revoked_cid_b64 }),
        },
        bind: Bind {
            redeemer: redeemer.into(),
            recipient: None,
        },
        valid: Valid {
            iat: 1_000_000,
            exp: Some(1_000_000 + 600),
        },
    }
}

#[test]
fn phase1_setup_then_phase23_use() {
    let credential_id = b"cred-001".to_vec();
    let auth_secret = fresh_secret();
    let mut protected = ProtectedState::new();
    protected.put_target("env.api_key", b"sk_live_top_secret".to_vec());

    let wrapping_key = WrappingKey::from_bytes(vec![0x11u8; 32]);
    let prf_salt = vec![0x22u8; 32];

    let mut custodian: Custodian<StdPrimitives, MockAuthenticator> = Custodian::new("custodian-A");

    // Phase I.
    let sealed = custodian
        .setup(
            protected,
            MockEnrollment {
                credential_id: credential_id.clone(),
                secret: auth_secret.clone(),
            },
            prf_salt,
            wrapping_key.clone(),
            &(),
        )
        .unwrap();
    assert_eq!(sealed.credentials.len(), 1);
    assert_eq!(sealed.registry.len(), 1);

    // Phase II.1: issue r.
    let r = custodian.issue_freshness();

    // Build op and grant.
    let o = op_use("env.api_key", "custodian-A");
    let beta = compute_beta_for_op::<Sha256>(&r, &o).unwrap();
    let assertion = sign(&auth_secret, &credential_id, &beta);
    let grant = Grant::<MockAuthenticator> {
        o: o.clone(),
        r: r.to_vec(),
        credential_id: credential_id.clone(),
        wrapping_key: wrapping_key.clone(),
        assertion,
        opt: GrantOpt::default(),
    };

    // Phase II.3.
    let redeemed = custodian
        .redeem_grant(grant, &(), &sealed, 1_000_100)
        .unwrap();
    assert_eq!(redeemed.o.act.target, "env.api_key");

    // Phase III.1.
    let observed: Vec<u8> = custodian
        .execute_use(&redeemed, &sealed, |target, s_o| {
            assert_eq!(target, "env.api_key");
            Ok(s_o.to_vec())
        })
        .unwrap();
    assert_eq!(observed, b"sk_live_top_secret");
}

#[test]
fn double_redemption_is_rejected_by_freshness() {
    let credential_id = b"cred-002".to_vec();
    let auth_secret = fresh_secret();
    let wrapping_key = WrappingKey::from_bytes(vec![0x33u8; 32]);
    let prf_salt = vec![0x44u8; 32];

    let mut custodian: Custodian<StdPrimitives, MockAuthenticator> = Custodian::new("custodian-B");
    let sealed = custodian
        .setup(
            ProtectedState::new(),
            MockEnrollment {
                credential_id: credential_id.clone(),
                secret: auth_secret.clone(),
            },
            prf_salt,
            wrapping_key.clone(),
            &(),
        )
        .unwrap();

    let r = custodian.issue_freshness();
    let o = op_use("env.x", "custodian-B");
    let beta = compute_beta_for_op::<Sha256>(&r, &o).unwrap();
    let assertion = sign(&auth_secret, &credential_id, &beta);
    let grant = Grant::<MockAuthenticator> {
        o: o.clone(),
        r: r.to_vec(),
        credential_id: credential_id.clone(),
        wrapping_key: wrapping_key.clone(),
        assertion: assertion.clone(),
        opt: GrantOpt::default(),
    };
    let _ = custodian.redeem_grant(grant.clone(), &(), &sealed, 1_000_100);

    // Second redemption with the same r must fail.
    let res = custodian.redeem_grant(grant, &(), &sealed, 1_000_100);
    assert!(matches!(res, Err(sudp::Error::FreshnessRejected)));
}

#[test]
fn tampered_operation_fails_signature_check() {
    let credential_id = b"cred-003".to_vec();
    let auth_secret = fresh_secret();
    let wrapping_key = WrappingKey::from_bytes(vec![0x55u8; 32]);
    let prf_salt = vec![0x66u8; 32];

    let mut custodian: Custodian<StdPrimitives, MockAuthenticator> = Custodian::new("custodian-C");
    let sealed = custodian
        .setup(
            ProtectedState::new(),
            MockEnrollment {
                credential_id: credential_id.clone(),
                secret: auth_secret.clone(),
            },
            prf_salt,
            wrapping_key.clone(),
            &(),
        )
        .unwrap();

    let r = custodian.issue_freshness();
    let o = op_use("env.x", "custodian-C");
    // Sign over the *original* op...
    let beta_orig = compute_beta_for_op::<Sha256>(&r, &o).unwrap();
    let assertion = sign(&auth_secret, &credential_id, &beta_orig);

    // ...but submit a different op.
    let mut tampered = o.clone();
    tampered.act.target = "env.evil".into();
    let grant = Grant::<MockAuthenticator> {
        o: tampered,
        r: r.to_vec(),
        credential_id,
        wrapping_key,
        assertion,
        opt: GrantOpt::default(),
    };
    let res = custodian.redeem_grant(grant, &(), &sealed, 1_000_100);
    assert!(matches!(res, Err(sudp::Error::AuthorizationInvalid)));
}

#[test]
fn redeemer_mismatch_rejected() {
    let credential_id = b"cred-004".to_vec();
    let auth_secret = fresh_secret();
    let wrapping_key = WrappingKey::from_bytes(vec![0x77u8; 32]);
    let prf_salt = vec![0x88u8; 32];

    let mut custodian: Custodian<StdPrimitives, MockAuthenticator> = Custodian::new("custodian-D");
    let sealed = custodian
        .setup(
            ProtectedState::new(),
            MockEnrollment {
                credential_id: credential_id.clone(),
                secret: auth_secret.clone(),
            },
            prf_salt,
            wrapping_key.clone(),
            &(),
        )
        .unwrap();

    let r = custodian.issue_freshness();
    let o = op_use("env.x", "custodian-Z"); // wrong redeemer
    let beta = compute_beta_for_op::<Sha256>(&r, &o).unwrap();
    let assertion = sign(&auth_secret, &credential_id, &beta);
    let grant = Grant::<MockAuthenticator> {
        o,
        r: r.to_vec(),
        credential_id,
        wrapping_key,
        assertion,
        opt: GrantOpt::default(),
    };
    let res = custodian.redeem_grant(grant, &(), &sealed, 1_000_100);
    assert!(matches!(res, Err(sudp::Error::RedeemerMismatch)));
}

#[test]
fn lifecycle_write_rotates_keys_and_updates_target() {
    let credential_id = b"cred-005".to_vec();
    let auth_secret = fresh_secret();
    let wrapping_key = WrappingKey::from_bytes(vec![0xAAu8; 32]);
    let next_wrapping_key = WrappingKey::from_bytes(vec![0xBBu8; 32]);
    let prf_salt = vec![0xC0u8; 32];
    let next_prf_salt = vec![0xC1u8; 32];

    let mut protected = ProtectedState::new();
    protected.put_target("env.api_key", b"v1".to_vec());

    let mut custodian: Custodian<StdPrimitives, MockAuthenticator> = Custodian::new("custodian-E");
    let sealed_v1 = custodian
        .setup(
            protected,
            MockEnrollment {
                credential_id: credential_id.clone(),
                secret: auth_secret.clone(),
            },
            prf_salt,
            wrapping_key.clone(),
            &(),
        )
        .unwrap();
    let key_v1 = sealed_v1.credentials[0].wrapped_key.clone();

    let r = custodian.issue_freshness();
    let o = op_write("env.api_key", "custodian-E");
    let beta = compute_beta_for_op::<Sha256>(&r, &o).unwrap();
    let assertion = sign(&auth_secret, &credential_id, &beta);
    let grant = Grant::<MockAuthenticator> {
        o,
        r: r.to_vec(),
        credential_id: credential_id.clone(),
        wrapping_key: wrapping_key.clone(),
        assertion,
        opt: GrantOpt {
            wrapping_key_next: Some(next_wrapping_key.clone()),
        },
    };
    let redeemed = custodian
        .redeem_grant(grant, &(), &sealed_v1, 1_000_100)
        .unwrap();

    let sealed_v2 = custodian
        .execute_lifecycle(
            &redeemed,
            &sealed_v1,
            &next_prf_salt,
            Box::new(|m: &mut ProtectedState| {
                m.put_target("env.api_key", b"v2".to_vec());
                Ok(())
            }),
        )
        .unwrap();

    // Wrapped key rotated.
    assert_ne!(sealed_v2.credentials[0].wrapped_key, key_v1);
    // Salt advanced.
    assert_eq!(sealed_v2.credentials[0].prf_salt, next_prf_salt);
    // The new wrapping-key value can open the new state.
    let r2 = custodian.issue_freshness();
    let o2 = op_use("env.api_key", "custodian-E");
    let beta2 = compute_beta_for_op::<Sha256>(&r2, &o2).unwrap();
    let assertion2 = sign(&auth_secret, &credential_id, &beta2);
    let grant2 = Grant::<MockAuthenticator> {
        o: o2,
        r: r2.to_vec(),
        credential_id: credential_id.clone(),
        wrapping_key: next_wrapping_key.clone(),
        assertion: assertion2,
        opt: GrantOpt::default(),
    };
    let redeemed2 = custodian
        .redeem_grant(grant2, &(), &sealed_v2, 1_000_200)
        .unwrap();
    let observed: Vec<u8> = custodian
        .execute_use(&redeemed2, &sealed_v2, |_, s| Ok(s.to_vec()))
        .unwrap();
    assert_eq!(observed, b"v2");

    // The old wrapping key can no longer open the new state.
    let r3 = custodian.issue_freshness();
    let o3 = op_use("env.api_key", "custodian-E");
    let beta3 = compute_beta_for_op::<Sha256>(&r3, &o3).unwrap();
    let assertion3 = sign(&auth_secret, &credential_id, &beta3);
    let grant3 = Grant::<MockAuthenticator> {
        o: o3,
        r: r3.to_vec(),
        credential_id: credential_id.clone(),
        wrapping_key: wrapping_key.clone(),
        assertion: assertion3,
        opt: GrantOpt::default(),
    };
    let redeemed3 = custodian
        .redeem_grant(grant3, &(), &sealed_v2, 1_000_300)
        .unwrap();
    let res = custodian.execute_use(&redeemed3, &sealed_v2, |_, _| Ok(()));
    assert!(matches!(res, Err(sudp::Error::SealDecryptionFailed)));
}

#[test]
fn batch_grant_validates_all_ops_under_one_signature() {
    use sudp::batch::{redeem_batch, BatchGrant, BatchOperations, RedeemBatchInputs};
    use sudp::phases::grant::RedeemerPolicy;

    let credential_id = b"cred-006".to_vec();
    let auth_secret = fresh_secret();
    let wrapping_key = WrappingKey::from_bytes(vec![0xD0u8; 32]);
    let prf_salt = vec![0xD1u8; 32];

    let mut protected = ProtectedState::new();
    protected.put_target("env.a", b"alpha".to_vec());
    protected.put_target("env.b", b"bravo".to_vec());

    let mut custodian: Custodian<StdPrimitives, MockAuthenticator> = Custodian::new("custodian-F");
    let sealed = custodian
        .setup(
            protected,
            MockEnrollment {
                credential_id: credential_id.clone(),
                secret: auth_secret.clone(),
            },
            prf_salt,
            wrapping_key.clone(),
            &(),
        )
        .unwrap();

    let r = custodian.issue_freshness();
    let ops = BatchOperations::new(vec![
        op_use("env.a", "custodian-F"),
        op_use("env.b", "custodian-F"),
    ]);
    let ops_canonical = ops.canonical_bytes().unwrap();
    let ops_hash = Sha256::hash(&ops_canonical);
    let beta = sudp::beta::compute_beta::<Sha256>(&r, &ops_hash);
    let assertion = sign(&auth_secret, &credential_id, &beta);
    let grant = BatchGrant::<MockAuthenticator> {
        ops,
        r: r.to_vec(),
        credential_id: credential_id.clone(),
        wrapping_key: wrapping_key.clone(),
        assertion,
        opt: GrantOpt::default(),
    };
    let redeemed = redeem_batch::<StdPrimitives, MockAuthenticator, _>(
        RedeemBatchInputs {
            grant,
            auth_context: &(),
            redeemer: RedeemerPolicy::Equals("custodian-F"),
            iat_skew_secs: 300,
            now_unix: 1_000_100,
        },
        &mut custodian.freshness,
        &sealed,
    )
    .unwrap();
    assert_eq!(redeemed.ops.len(), 2);

    for per_op in redeemed.per_op() {
        let val: Vec<u8> = custodian
            .execute_use(&per_op, &sealed, |_, s| Ok(s.to_vec()))
            .unwrap();
        assert!(val == b"alpha" || val == b"bravo");
    }
}

#[test]
fn enroll_adds_credential_and_it_can_redeem() {
    // Setup with cred A, enroll cred B via lifecycle, then redeem under B.
    let cred_a = b"cred-A".to_vec();
    let cred_b = b"cred-B".to_vec();
    let secret_a = fresh_secret();
    let secret_b = fresh_secret();
    let w_a = WrappingKey::from_bytes(vec![0x10u8; 32]);
    let w_a_next = WrappingKey::from_bytes(vec![0x11u8; 32]);
    let w_b = WrappingKey::from_bytes(vec![0x20u8; 32]);
    let salt_a = vec![0x12u8; 32];
    let salt_a_next = vec![0x13u8; 32];
    let salt_b = vec![0x21u8; 32];

    let mut protected = ProtectedState::new();
    protected.put_target("env.api_key", b"secret-v1".to_vec());

    let mut custodian: Custodian<StdPrimitives, MockAuthenticator> = Custodian::new("custodian-G");
    let sealed = custodian
        .setup(
            protected,
            MockEnrollment {
                credential_id: cred_a.clone(),
                secret: secret_a.clone(),
            },
            salt_a,
            w_a.clone(),
            &(),
        )
        .unwrap();
    assert_eq!(sealed.credentials.len(), 1);

    // Enroll cred B (A acts).
    use base64::Engine;
    let cred_b_b64 = base64::engine::general_purpose::STANDARD.encode(&cred_b);
    let r = custodian.issue_freshness();
    let o = op_enroll("custodian-G", &cred_b_b64);
    let beta = compute_beta_for_op::<Sha256>(&r, &o).unwrap();
    let assertion = sign(&secret_a, &cred_a, &beta);
    let grant = Grant::<MockAuthenticator> {
        o,
        r: r.to_vec(),
        credential_id: cred_a.clone(),
        wrapping_key: w_a.clone(),
        assertion,
        opt: GrantOpt {
            wrapping_key_next: Some(w_a_next.clone()),
        },
    };
    let redeemed = custodian
        .redeem_grant(grant, &(), &sealed, 1_000_100)
        .unwrap();

    let sealed_v2 = custodian
        .execute_enroll(
            &redeemed,
            &sealed,
            &salt_a_next,
            MockEnrollment {
                credential_id: cred_b.clone(),
                secret: secret_b.clone(),
            },
            salt_b.clone(),
            w_b.clone(),
            &(),
        )
        .unwrap();
    assert_eq!(sealed_v2.credentials.len(), 2);
    assert_eq!(sealed_v2.registry.len(), 2);

    // Now redeem under cred B and read the target.
    let r2 = custodian.issue_freshness();
    let o2 = op_use("env.api_key", "custodian-G");
    let beta2 = compute_beta_for_op::<Sha256>(&r2, &o2).unwrap();
    let assertion2 = sign(&secret_b, &cred_b, &beta2);
    let grant2 = Grant::<MockAuthenticator> {
        o: o2,
        r: r2.to_vec(),
        credential_id: cred_b.clone(),
        wrapping_key: w_b.clone(),
        assertion: assertion2,
        opt: GrantOpt::default(),
    };
    let redeemed2 = custodian
        .redeem_grant(grant2, &(), &sealed_v2, 1_000_200)
        .unwrap();
    let observed: Vec<u8> = custodian
        .execute_use(&redeemed2, &sealed_v2, |_, s| Ok(s.to_vec()))
        .unwrap();
    assert_eq!(observed, b"secret-v1");
}

#[test]
fn revoke_actually_removes_credential() {
    // Setup A → enroll B → revoke B → confirm B is gone from registry and
    // credentials list, and a grant signed by B is rejected as UnknownCredential.
    let cred_a = b"cred-A".to_vec();
    let cred_b = b"cred-B".to_vec();
    let secret_a = fresh_secret();
    let secret_b = fresh_secret();
    let w_a = WrappingKey::from_bytes(vec![0x30u8; 32]);
    let w_a_next1 = WrappingKey::from_bytes(vec![0x31u8; 32]);
    let w_a_next2 = WrappingKey::from_bytes(vec![0x32u8; 32]);
    let w_b = WrappingKey::from_bytes(vec![0x40u8; 32]);
    let salt_a = vec![0x33u8; 32];
    let salt_a_next1 = vec![0x34u8; 32];
    let salt_a_next2 = vec![0x35u8; 32];
    let salt_b = vec![0x41u8; 32];

    let mut custodian: Custodian<StdPrimitives, MockAuthenticator> = Custodian::new("custodian-H");
    let sealed = custodian
        .setup(
            ProtectedState::new(),
            MockEnrollment {
                credential_id: cred_a.clone(),
                secret: secret_a.clone(),
            },
            salt_a,
            w_a.clone(),
            &(),
        )
        .unwrap();

    use base64::Engine;
    let cred_b_b64 = base64::engine::general_purpose::STANDARD.encode(&cred_b);

    // Enroll B.
    let r1 = custodian.issue_freshness();
    let o1 = op_enroll("custodian-H", &cred_b_b64);
    let beta1 = compute_beta_for_op::<Sha256>(&r1, &o1).unwrap();
    let grant1 = Grant::<MockAuthenticator> {
        o: o1,
        r: r1.to_vec(),
        credential_id: cred_a.clone(),
        wrapping_key: w_a.clone(),
        assertion: sign(&secret_a, &cred_a, &beta1),
        opt: GrantOpt {
            wrapping_key_next: Some(w_a_next1.clone()),
        },
    };
    let redeemed1 = custodian
        .redeem_grant(grant1, &(), &sealed, 1_000_100)
        .unwrap();
    let sealed_v2 = custodian
        .execute_enroll(
            &redeemed1,
            &sealed,
            &salt_a_next1,
            MockEnrollment {
                credential_id: cred_b.clone(),
                secret: secret_b.clone(),
            },
            salt_b,
            w_b.clone(),
            &(),
        )
        .unwrap();
    assert_eq!(sealed_v2.credentials.len(), 2);
    assert_eq!(sealed_v2.registry.len(), 2);

    // Revoke B (A acts, now with the post-enroll W*_next1 as its current W*).
    let r2 = custodian.issue_freshness();
    let o2 = op_revoke("custodian-H", &cred_b_b64);
    let beta2 = compute_beta_for_op::<Sha256>(&r2, &o2).unwrap();
    let grant2 = Grant::<MockAuthenticator> {
        o: o2,
        r: r2.to_vec(),
        credential_id: cred_a.clone(),
        wrapping_key: w_a_next1.clone(),
        assertion: sign(&secret_a, &cred_a, &beta2),
        opt: GrantOpt {
            wrapping_key_next: Some(w_a_next2.clone()),
        },
    };
    let redeemed2 = custodian
        .redeem_grant(grant2, &(), &sealed_v2, 1_000_200)
        .unwrap();
    let sealed_v3 = custodian
        .execute_revoke(&redeemed2, &sealed_v2, &salt_a_next2, cred_b.clone())
        .unwrap();

    // B must be gone from credentials list and registry.
    assert_eq!(sealed_v3.credentials.len(), 1);
    assert_eq!(sealed_v3.registry.len(), 1);
    assert!(sealed_v3.find_credential(&cred_b).is_none());

    // A grant signed by B must now fail with UnknownCredential.
    let r3 = custodian.issue_freshness();
    let o3 = op_use("env.x", "custodian-H");
    let beta3 = compute_beta_for_op::<Sha256>(&r3, &o3).unwrap();
    let grant3 = Grant::<MockAuthenticator> {
        o: o3,
        r: r3.to_vec(),
        credential_id: cred_b.clone(),
        wrapping_key: w_b.clone(),
        assertion: sign(&secret_b, &cred_b, &beta3),
        opt: GrantOpt::default(),
    };
    let res = custodian.redeem_grant(grant3, &(), &sealed_v3, 1_000_300);
    assert!(matches!(res, Err(sudp::Error::UnknownCredential)));
}

#[test]
fn rotate_preserves_targets_but_rewraps_state_key() {
    // Pure K-rotation: M' = M, but every target should still be readable
    // under the new wrapping key, and the *old* wrapping key must no longer
    // open the new state.
    let credential_id = b"cred-rot".to_vec();
    let auth_secret = fresh_secret();
    let wrapping_key = WrappingKey::from_bytes(vec![0xE0u8; 32]);
    let next_wrapping_key = WrappingKey::from_bytes(vec![0xE1u8; 32]);
    let prf_salt = vec![0xE2u8; 32];
    let next_prf_salt = vec![0xE3u8; 32];

    let mut protected = ProtectedState::new();
    protected.put_target("env.api_key", b"unchanged-secret".to_vec());
    protected.put_target("env.other", b"other-secret".to_vec());

    let mut custodian: Custodian<StdPrimitives, MockAuthenticator> = Custodian::new("custodian-R");
    let sealed_v1 = custodian
        .setup(
            protected,
            MockEnrollment {
                credential_id: credential_id.clone(),
                secret: auth_secret.clone(),
            },
            prf_salt,
            wrapping_key.clone(),
            &(),
        )
        .unwrap();
    let key_v1 = sealed_v1.credentials[0].wrapped_key.clone();

    // Issue a rotate op (no target mutation).
    let r = custodian.issue_freshness();
    let o = op_rotate("custodian-R");
    let beta = compute_beta_for_op::<Sha256>(&r, &o).unwrap();
    let assertion = sign(&auth_secret, &credential_id, &beta);
    let grant = Grant::<MockAuthenticator> {
        o,
        r: r.to_vec(),
        credential_id: credential_id.clone(),
        wrapping_key: wrapping_key.clone(),
        assertion,
        opt: GrantOpt {
            wrapping_key_next: Some(next_wrapping_key.clone()),
        },
    };
    let redeemed = custodian
        .redeem_grant(grant, &(), &sealed_v1, 1_000_100)
        .unwrap();

    let sealed_v2 = custodian
        .execute_lifecycle(
            &redeemed,
            &sealed_v1,
            &next_prf_salt,
            Box::new(|_m: &mut ProtectedState| Ok(())), // identity mutation
        )
        .unwrap();

    // Wrapped key changed; salt advanced; ciphertext changed (fresh K').
    assert_ne!(sealed_v2.credentials[0].wrapped_key, key_v1);
    assert_eq!(sealed_v2.credentials[0].prf_salt, next_prf_salt);
    assert_ne!(sealed_v2.ciphertext, sealed_v1.ciphertext);

    // Both targets still readable under the new W*_next.
    for (path, expected) in [
        ("env.api_key", &b"unchanged-secret"[..]),
        ("env.other", &b"other-secret"[..]),
    ] {
        let r2 = custodian.issue_freshness();
        let o2 = op_use(path, "custodian-R");
        let beta2 = compute_beta_for_op::<Sha256>(&r2, &o2).unwrap();
        let assertion2 = sign(&auth_secret, &credential_id, &beta2);
        let grant2 = Grant::<MockAuthenticator> {
            o: o2,
            r: r2.to_vec(),
            credential_id: credential_id.clone(),
            wrapping_key: next_wrapping_key.clone(),
            assertion: assertion2,
            opt: GrantOpt::default(),
        };
        let redeemed2 = custodian
            .redeem_grant(grant2, &(), &sealed_v2, 1_000_200)
            .unwrap();
        let observed: Vec<u8> = custodian
            .execute_use(&redeemed2, &sealed_v2, |_, s| Ok(s.to_vec()))
            .unwrap();
        assert_eq!(observed.as_slice(), expected, "target {} mismatch", path);
    }

    // Old wrapping key must no longer open new state.
    let r3 = custodian.issue_freshness();
    let o3 = op_use("env.api_key", "custodian-R");
    let beta3 = compute_beta_for_op::<Sha256>(&r3, &o3).unwrap();
    let assertion3 = sign(&auth_secret, &credential_id, &beta3);
    let grant3 = Grant::<MockAuthenticator> {
        o: o3,
        r: r3.to_vec(),
        credential_id: credential_id.clone(),
        wrapping_key: wrapping_key.clone(),
        assertion: assertion3,
        opt: GrantOpt::default(),
    };
    let redeemed3 = custodian
        .redeem_grant(grant3, &(), &sealed_v2, 1_000_300)
        .unwrap();
    let res = custodian.execute_use(&redeemed3, &sealed_v2, |_, _| Ok(()));
    assert!(matches!(res, Err(sudp::Error::SealDecryptionFailed)));
}

#[test]
fn custom_act_type_passes_redemption_and_caller_dispatches() {
    // A profile defines a "co-sign" act type. SUDP's Phase II.3 should accept
    // it (β/σ verification is type-agnostic), but execute_use must reject it
    // with ActTypeMismatch — the deployment handles dispatch via `open`.
    let credential_id = b"cred-cust".to_vec();
    let auth_secret = fresh_secret();
    let wrapping_key = WrappingKey::from_bytes(vec![0xF0u8; 32]);
    let prf_salt = vec![0xF1u8; 32];

    let mut protected = ProtectedState::new();
    protected.put_target("env.signing_key", b"raw-private-key-bytes".to_vec());

    let mut custodian: Custodian<StdPrimitives, MockAuthenticator> = Custodian::new("custodian-X");
    let sealed = custodian
        .setup(
            protected,
            MockEnrollment {
                credential_id: credential_id.clone(),
                secret: auth_secret.clone(),
            },
            prf_salt,
            wrapping_key.clone(),
            &(),
        )
        .unwrap();

    let r = custodian.issue_freshness();
    let o = Operation {
        act: Act {
            kind: ActType::Custom("co-sign".into()),
            target: "env.signing_key".into(),
            scope: serde_json::json!({ "digest_to_sign": "deadbeef" }),
        },
        bind: Bind {
            redeemer: "custodian-X".into(),
            recipient: None,
        },
        valid: Valid {
            iat: 1_000_000,
            exp: Some(1_000_000 + 600),
        },
    };
    let beta = compute_beta_for_op::<Sha256>(&r, &o).unwrap();
    let assertion = sign(&auth_secret, &credential_id, &beta);
    let grant = Grant::<MockAuthenticator> {
        o,
        r: r.to_vec(),
        credential_id: credential_id.clone(),
        wrapping_key: wrapping_key.clone(),
        assertion,
        opt: GrantOpt::default(),
    };

    // Phase II.3 accepts Custom act type — β/σ check is type-agnostic.
    let redeemed = custodian
        .redeem_grant(grant, &(), &sealed, 1_000_100)
        .unwrap();
    assert!(matches!(&redeemed.o.act.kind, ActType::Custom(s) if s == "co-sign"));

    // execute_use rejects — wrong dispatch path.
    let res = custodian.execute_use(&redeemed, &sealed, |_, _| Ok(()));
    assert!(matches!(res, Err(sudp::Error::ActTypeMismatch(_))));

    // Caller can open the state manually and pull s_o themselves.
    let opened = custodian.open(&redeemed, &sealed).unwrap();
    let s_o = opened.m.target("env.signing_key").unwrap();
    assert_eq!(s_o, b"raw-private-key-bytes");
    // (Deployment would now use s_o to compute its custom co-sign output.)
}

#[cfg(feature = "hpke")]
mod export_hpke_test {
    use super::*;
    use sudp::phases::consumption::{open_export, seal_export, ExportArtifact};
    use sudp::primitives::{gen_keypair, DhKemP256HkdfSha256};
    use sudp::RecipientPk;

    fn op_export(target: &str, redeemer: &str, recipient_alg: &str) -> Operation {
        Operation {
            act: Act {
                kind: ActType::Export,
                target: target.into(),
                scope: serde_json::json!({}),
            },
            bind: Bind {
                redeemer: redeemer.into(),
                recipient: Some(RecipientPk {
                    alg: recipient_alg.into(),
                    bytes: "ignored-by-this-test".into(),
                }),
            },
            valid: Valid {
                iat: 1_000_000,
                exp: Some(1_000_000 + 600),
            },
        }
    }

    #[test]
    fn export_hpke_p256_roundtrip() {
        // Recipient: fresh DhP256 keypair (lives outside T and outside R).
        let (recipient_sk, recipient_pk) = gen_keypair::<hpke::kem::DhP256HkdfSha256>();

        // Setup the custodian and seed a secret target.
        let credential_id = b"cred-exp".to_vec();
        let auth_secret = fresh_secret();
        let wrapping_key = WrappingKey::from_bytes(vec![0x90u8; 32]);
        let prf_salt = vec![0x91u8; 32];

        let mut protected = ProtectedState::new();
        protected.put_target("env.api_key", b"sk_live_exported".to_vec());

        let mut custodian: Custodian<StdPrimitives, MockAuthenticator> =
            Custodian::new("custodian-EXP");
        let sealed = custodian
            .setup(
                protected,
                MockEnrollment {
                    credential_id: credential_id.clone(),
                    secret: auth_secret.clone(),
                },
                prf_salt,
                wrapping_key.clone(),
                &(),
            )
            .unwrap();

        // Issue an export op.
        let r = custodian.issue_freshness();
        let o = op_export("env.api_key", "custodian-EXP", "hpke-p256-sha256-chacha20");
        let beta = compute_beta_for_op::<Sha256>(&r, &o).unwrap();
        let assertion = sign(&auth_secret, &credential_id, &beta);
        let grant = Grant::<MockAuthenticator> {
            o,
            r: r.to_vec(),
            credential_id: credential_id.clone(),
            wrapping_key: wrapping_key.clone(),
            assertion,
            opt: GrantOpt::default(),
        };
        let redeemed = custodian
            .redeem_grant(grant, &(), &sealed, 1_000_100)
            .unwrap();

        // T executes export with paper §5.6 III.2 standard stitching.
        let artifact: ExportArtifact = custodian
            .execute_export(&redeemed, &sealed, |op_hash, s_o| {
                seal_export::<StdPrimitives, DhKemP256HkdfSha256>(&recipient_pk, op_hash, s_o)
            })
            .unwrap();

        // Recipient opens the artifact.
        let op_canonical = redeemed.o.canonical_bytes().unwrap();
        let op_hash = Sha256::hash(&op_canonical);
        let recovered =
            open_export::<StdPrimitives, DhKemP256HkdfSha256>(&recipient_sk, &op_hash, &artifact)
                .unwrap();
        assert_eq!(recovered, b"sk_live_exported");

        // Tamper test: substituting a different op_hash must fail AEAD auth.
        let mut bogus = op_hash;
        bogus[0] ^= 0xFF;
        let res =
            open_export::<StdPrimitives, DhKemP256HkdfSha256>(&recipient_sk, &bogus, &artifact);
        assert!(res.is_err());
    }
}

#[test]
fn xdevice_envelope_round_trips_grant() {
    // Simulate U and T not sharing TLS. Caller does ECDH with p256::ecdh,
    // passes the shared secret + r + both pk bytes to sudp::xdevice, gets a
    // sealed grant blob, T opens it.
    use p256::ecdh::EphemeralSecret;
    use p256::PublicKey;
    use rand::rngs::OsRng;
    use sudp::xdevice;

    // Generate ephemeral key pairs for U and T (paper §7.2 assumes pk_T
    // arrives authenticated by some out-of-band channel — we skip that part
    // and just verify the envelope crypto).
    let sk_u = EphemeralSecret::random(&mut OsRng);
    let pk_u = sk_u.public_key();
    let sk_t = EphemeralSecret::random(&mut OsRng);
    let pk_t = sk_t.public_key();
    let pk_u_bytes = pk_u.to_sec1_bytes().to_vec();
    let pk_t_bytes = pk_t.to_sec1_bytes().to_vec();

    // Both sides derive the same ss via ECDH.
    let pk_t_for_u = PublicKey::from_sec1_bytes(&pk_t_bytes).unwrap();
    let ss_u = sk_u.diffie_hellman(&pk_t_for_u);
    let pk_u_for_t = PublicKey::from_sec1_bytes(&pk_u_bytes).unwrap();
    let ss_t = sk_t.diffie_hellman(&pk_u_for_t);
    assert_eq!(ss_u.raw_secret_bytes(), ss_t.raw_secret_bytes());

    // Build a setup-side custodian and a real grant to seal.
    let credential_id = b"cred-xd".to_vec();
    let auth_secret = fresh_secret();
    let wrapping_key = WrappingKey::from_bytes(vec![0x70u8; 32]);
    let prf_salt = vec![0x71u8; 32];

    let mut protected = ProtectedState::new();
    protected.put_target("env.api_key", b"xd-secret".to_vec());

    let mut custodian: Custodian<StdPrimitives, MockAuthenticator> = Custodian::new("custodian-XD");
    let sealed = custodian
        .setup(
            protected,
            MockEnrollment {
                credential_id: credential_id.clone(),
                secret: auth_secret.clone(),
            },
            prf_salt,
            wrapping_key.clone(),
            &(),
        )
        .unwrap();

    let r = custodian.issue_freshness();
    let o = op_use("env.api_key", "custodian-XD");
    let beta = compute_beta_for_op::<Sha256>(&r, &o).unwrap();
    let assertion = sign(&auth_secret, &credential_id, &beta);
    let grant = Grant::<MockAuthenticator> {
        o,
        r: r.to_vec(),
        credential_id: credential_id.clone(),
        wrapping_key: wrapping_key.clone(),
        assertion,
        opt: GrantOpt::default(),
    };

    // U-side: derive k_xd, seal grant.
    let k_xd_u = xdevice::derive_session_key::<StdPrimitives>(
        ss_u.raw_secret_bytes().as_slice(),
        &r,
        &pk_u_bytes,
        &pk_t_bytes,
    )
    .unwrap();
    let ct_g = xdevice::seal_grant::<StdPrimitives, MockAuthenticator>(
        &grant,
        &k_xd_u,
        &pk_u_bytes,
        &pk_t_bytes,
        &r,
    )
    .unwrap();

    // T-side: derive same k_xd, open the blob, run normal redemption.
    let k_xd_t = xdevice::derive_session_key::<StdPrimitives>(
        ss_t.raw_secret_bytes().as_slice(),
        &r,
        &pk_u_bytes,
        &pk_t_bytes,
    )
    .unwrap();
    assert_eq!(k_xd_u, k_xd_t);

    let recovered: Grant<MockAuthenticator> =
        xdevice::open_grant::<StdPrimitives, MockAuthenticator>(
            &ct_g,
            &k_xd_t,
            &pk_u_bytes,
            &pk_t_bytes,
            &r,
        )
        .unwrap();

    // The recovered grant must redeem and use successfully.
    let redeemed = custodian
        .redeem_grant(recovered, &(), &sealed, 1_000_100)
        .unwrap();
    let observed: Vec<u8> = custodian
        .execute_use(&redeemed, &sealed, |_, s| Ok(s.to_vec()))
        .unwrap();
    assert_eq!(observed, b"xd-secret");
}

#[test]
fn xdevice_envelope_rejects_tampered_pk() {
    // An MITM that substitutes pk_U or pk_T must break AEAD authentication.
    use sudp::xdevice;

    let ss = vec![0x55u8; 32]; // pretend ECDH output
    let r = vec![0x66u8; 32];
    let pk_u_a = b"pk-U-original".to_vec();
    let pk_t_a = b"pk-T-original".to_vec();
    let pk_u_b = b"pk-U-tampered".to_vec();

    let k_xd = xdevice::derive_session_key::<StdPrimitives>(&ss, &r, &pk_u_a, &pk_t_a).unwrap();

    // Build any small grant for the sealing — content doesn't matter.
    let grant = Grant::<MockAuthenticator> {
        o: op_use("env.x", "custodian-MITM"),
        r: r.clone(),
        credential_id: b"x".to_vec(),
        wrapping_key: WrappingKey::from_bytes(vec![0; 32]),
        assertion: sign(&[0u8; 32], b"x", &[0u8; 32]),
        opt: GrantOpt::default(),
    };
    let sealed = xdevice::seal_grant::<StdPrimitives, MockAuthenticator>(
        &grant, &k_xd, &pk_u_a, &pk_t_a, &r,
    )
    .unwrap();

    // Open with tampered pk_U — AD changes → AEAD auth fails.
    let res = xdevice::open_grant::<StdPrimitives, MockAuthenticator>(
        &sealed, &k_xd, &pk_u_b, &pk_t_a, &r,
    );
    assert!(res.is_err());
}
