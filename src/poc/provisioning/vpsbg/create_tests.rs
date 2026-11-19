use super::*;

fn ack() -> Value {
    json!({"id":51,"hostname":"tau-web-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","billing_cycle":1,
        "plan":{"id":7,"key":"fake-plan","price_with_vat":"39.01"},"status":"processing",
        "created_at":"2026-01-01T00:00:00Z","expiry_at":"2026-02-01T02:00:00+02:00",
        "ip_addresses":[],"server_image":null})
}
fn decoded(method: &str, path: &str, status: u16, value: Value) -> Result<Value, String> {
    reduce_response(
        method,
        path,
        status,
        &serde_json::to_vec(&value).unwrap(),
        |_| Ok(()),
        |_| true,
    )
}

#[test]
fn vpsbg_create_route_reductions_and_observed_detail() {
    let value = ack();
    let reply: CreateReply = serde_json::from_value(
        decoded("POST", "/v1/servers", 201, json!({"data":[value.clone()]})).unwrap(),
    )
    .unwrap();
    let CreateReply::Accepted(server) = reply else {
        panic!("expected create acknowledgment");
    };
    assert_eq!(
        server.expiry_at,
        vpsbg_timestamp("2026-02-01T00:00:00Z").unwrap()
    );
    for (field, invalid) in [
        ("billing_cycle", json!(3)),
        ("status", json!("invented")),
        ("created_at", json!("2026-01-40T00:00:00Z")),
        ("expiry_at", json!("not-a-date")),
    ] {
        let mut wrong = value.clone();
        wrong[field] = invalid;
        assert!(decoded("POST", "/v1/servers", 200, json!({"data":[wrong]})).is_err());
    }
    for rows in [json!([]), json!([value.clone(), value.clone()])] {
        assert!(decoded("POST", "/v1/servers", 200, json!({"data":rows})).is_err());
    }
    for assigned in ["2026-01-01T00:00:01Z", "2026-01-01 00:00:01", "ignored"] {
        let mut detail = value.clone();
        detail["ip_addresses"] =
            json!([{"version":4,"main":true,"ip_address":"8.8.8.8","assigned_on":assigned}]);
        detail["state"] = json!({"running":true,"cloud_init_installing":true,"suspended":false,"cpu":{"discarded":3}});
        let fact: ServerFact = serde_json::from_value(
            decoded("GET", "/v1/servers/51", 200, json!({"data":detail})).unwrap(),
        )
        .unwrap();
        let ServerFact::Live(detail) = fact else {
            panic!("expected live detail");
        };
        assert_eq!(detail.public_ipv4.unwrap().to_string(), "8.8.8.8");
        let state = detail.state.unwrap();
        assert_eq!(state.running, Some(true));
        assert_eq!(state.cloud_init_installing, Some(true));
        assert_eq!(state.cloud_init_failed, None);
    }
    let mut wrong = value;
    wrong["state"] = json!({"cloud_init_failed":"false"});
    assert!(decoded("GET", "/v1/servers/51", 200, json!({"data":wrong})).is_err());
    for path in [
        "/v1/servers/51/startup-script",
        "/v1/servers/51/refund-quote",
        "/v1/servers/01",
    ] {
        assert!(!request_method_allowed(
            ORIGIN,
            "GET",
            &format!("{ORIGIN}{path}")
        ));
    }
    assert!(!request_method_allowed(
        ORIGIN,
        "DELETE",
        &format!("{ORIGIN}/v1/servers/51")
    ));
}

#[test]
fn vpsbg_login_error_shape_and_order_precedence() {
    let good = json!({"message":"Fake login validation","errors":{"ssh_keys":["Required without login"],"password":["Required without keys"]}});
    assert_eq!(
        decoded("POST", "/v1/servers", 422, good.clone()).unwrap(),
        json!(CreateReply::MissingLogin)
    );
    let mut order = good.clone();
    order["order_id"] = json!(71);
    assert_eq!(
        decoded("POST", "/v1/servers", 400, order.clone()).unwrap(),
        json!(CreateReply::Unpaid { order: 71 })
    );
    assert_eq!(
        decoded("POST", "/v1/servers", 422, order).unwrap(),
        json!(CreateReply::Unpaid { order: 71 })
    );
    for invalid in [
        json!({"message":"Fake validation","errors":{"per_page":["Too large"]}}),
        json!({"errors":{"ssh_keys":["Missing"],"per_page":["Wrong"]}}),
        json!({"errors":{}}),
        json!({"message":"Missing login"}),
        json!({"errors":{"ssh_keys":[]}}),
        json!({"errors":{"ssh_keys":[null]}}),
        json!({"errors":{"password":"Missing"}}),
    ] {
        assert!(decoded("POST", "/v1/servers", 422, invalid).is_err());
    }
    for id in [Value::Null, json!(0), json!("71"), json!(-1)] {
        let mut invalid = good.clone();
        invalid["order_id"] = id;
        assert!(decoded("POST", "/v1/servers", 422, invalid).is_err());
    }
    for (method, path) in [
        ("POST", "/v1/ssh-keys"),
        ("POST", "/v1/orders/pay"),
        ("GET", "/v1/servers"),
    ] {
        assert!(decoded(method, path, 422, good.clone()).is_err());
    }
}

#[test]
fn vpsbg_vendor_ssh_fingerprint_is_bounded_md5_text() {
    let private = ssh_key::PrivateKey::new(
        ssh_key::private::KeypairData::Ed25519(ssh_key::private::Ed25519Keypair::from_seed(
            &[47; 32],
        )),
        "",
    )
    .unwrap();
    let public = private.public_key().to_openssh().unwrap();
    let row = json!({"id":81,"name":"fake-key","key":public,
        "fingerprint":"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"});
    let fact: SshKeyFact = serde_json::from_value(
        decoded("POST", "/v1/ssh-keys", 200, json!({"data":row.clone()})).unwrap(),
    )
    .unwrap();
    assert_eq!(fact.key, public);
    assert_eq!(fact.fingerprint, row["fingerprint"].as_str().unwrap());
    let keys = decoded(
        "GET",
        "/v1/ssh-keys?page=1",
        200,
        json!({"data":[row.clone()],"meta":{"current_page":1,"last_page":1,"total":1,"per_page":10}}),
    )
    .unwrap();
    assert_eq!(keys["data"][0], json!(fact));
    for invalid in [
        "00:11",
        "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:fg",
        "00-11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff",
        "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00",
        "SHA256:fake-vendor-fingerprint",
    ] {
        let mut bad = row.clone();
        bad["fingerprint"] = json!(invalid);
        assert!(decoded("POST", "/v1/ssh-keys", 200, json!({"data":bad})).is_err());
    }
}

#[test]
fn vpsbg_user_data_composes_exact_hook() {
    use sha2::{Digest, Sha256};
    use ssh_key::{
        PrivateKey,
        private::{Ed25519Keypair, KeypairData},
    };
    let private = PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&[43; 32])),
        "",
    )
    .unwrap();
    let mut intro = crate::store::attest::AttestIntroduction {
        ca_private_openssh: private.to_openssh(ssh_key::LineEnding::LF).unwrap(),
        ca_public_openssh: private.public_key().to_openssh().unwrap(),
        principal: crate::store::attest::attest_principal(private.public_key()).unwrap(),
        deadline_unix: 1_767_227_400,
    };
    let client = private.public_key().to_openssh().unwrap();
    let composed = compose_user_data(&intro, &client).unwrap();
    let expected = Zeroizing::new(format!(
        "#!/bin/sh\n# tau-web CHN-R5a first-boot hook. Composed by harness code; no model supplies any of it.\nP='{}'\nDEADLINE='20260101003000'\nDEADLINE_EPOCH='1767227400'\nCLIENT='{client}'\numask 077\nmkdir -p /run/tau-attest\ncat > /run/tau-attest/ca <<'CAKEY'\n{}CAKEY\n{HOOK_BODY}",
        intro.principal,
        intro.ca_private_openssh.as_str()
    ));
    assert!(composed.as_str() == expected.as_str()); // Never print private bytes on assertion failure.
    assert!(composed.len() <= 65_536);
    assert_eq!(
        hex::encode(Sha256::digest(HOOK_BODY.as_bytes())),
        "cd835ce3ee4e27436e5a97edeef7cb9bdf7e3bc8271a7c30d237008fbeeca086"
    );
    for suffix in ["\n", "'", "\nCAKEY\n", "\""] {
        let original = intro.principal.clone();
        intro.principal.push_str(suffix);
        assert!(compose_user_data(&intro, &client).is_err());
        intro.principal = original;
        assert!(compose_user_data(&intro, &format!("{client}{suffix}")).is_err());
    }
    intro.ca_private_openssh.push_str("CAKEY\n");
    assert!(compose_user_data(&intro, &client).is_err());
    intro.ca_private_openssh = Zeroizing::new("x".repeat(65_537));
    assert!(compose_user_data(&intro, &client).is_err());
    assert!(budget_fits(1000, 1901));
    assert!(!budget_fits(1000, 1900));
    assert!(!budget_fits(u64::MAX, u64::MAX));
}
