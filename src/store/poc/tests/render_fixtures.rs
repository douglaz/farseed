//! Full worker messages assembled from native store reports and fixed fake worker custody.
use super::*;

/// The existing thread-local seam fixes the seed and every generated public identifier.
pub(in crate::store) fn fixed<T>(run: impl FnOnce() -> T) -> T {
    let _identifiers = FixedIdentifiers::new();
    run()
}

/// Mirror `src/harness/inference.rs:199-285` for a running, sessionless provider report.
/// The wasm-only holders have no native seam: inference has a public configuration but no
/// key (as after test_poc_configuration); provider ACCOUNT custody follows the installed account.
pub(in crate::store) fn report<K: Kdf>(
    store: Store<MemoryStorage>,
    kdf: K,
    error: Option<&str>,
    catalogue: Option<Value>,
) -> Value {
    let mut local = Local::new(store.storage.clone(), kdf);
    local.state = State::Unlocked(Box::new(store));
    let mut value = local.report(error);
    // src/store.rs:2995: the served build has neither cfg(test) nor feature="tracer".
    value["setup_offer"] = Value::Null;
    // src/store.rs:3000-3004: this report member exists only with feature="tracer".
    value.as_object_mut().unwrap().remove("fixture_admission");
    if let Some(catalogue) = catalogue {
        value["provider_catalogue"] = catalogue;
    }
    // src/harness/inference.rs:201-203; provider requests use the machine step
    // (www/worker.js: presentationReport / reportStore).
    if value.get("error").is_some() {
        value["page_error_step"] = "machine".into();
    }
    // src/store.rs:3053-3061: native Local::report omits these wasm worker fields.
    assert!(value.get("lifecycle_state").is_none(), "protection failed");
    value["lifecycle_generation"] = "1".into();
    value["lifecycle_state"] = "running".into();
    let store = local.store().expect("fixture store is unlocked");
    assert!(store.inference.account.is_none());
    // browser.rs:42-50 restores ACCOUNT from provider_account; VPSBG_TOKEN is separate.
    // Unlock (store.rs:2775) and provider actions (browser.rs:382) both restore it.
    let provider_key_set = store.provider_account().is_some();
    let configuration = crate::poc::inference::Configuration::new(
        "https://fake-inference.invalid/chat/completions".into(),
        "fake-render-model".into(),
    )
    .unwrap();
    // src/harness/inference.rs:209-218. test_poc_configuration itself is wasm-only;
    // its Configuration::new value is the same public object available in native tests.
    value["poc_configuration"] = store
        .protect_publication(&json!({"key_set":false,"configuration":configuration}), &[])
        .expect("fake inference configuration must survive protection");
    // src/harness/inference.rs:219-243. Never substitute key_set:false for real custody.
    value["provider_configuration"] = store
        .protect_publication(
            &json!({
                "key_set":provider_key_set,
                "origin":store.procurement_origin(),
                "account":store.provider_account().map(|a| a.public()),
                "recorded":store.provider_account().is_some(),
                "entered":store.provider_account_entered(),
                "relay_deployed":store.deployment_relay_present(),
            }),
            &[],
        )
        .expect("fake provider configuration must survive protection");
    // src/harness/inference.rs:244-260 calls browser::readiness_report, which is
    // wasm-only and reads js_sys::Date::now without a fixed-clock seam. Omit those
    // states rather than publish an incomplete or invented readiness overlay.
    assert!(
        value["procurement"]["payment"]["is_paid"] != true
            || !value["procurement"]["target"].is_null(),
        "paid-without-target needs the wasm-only readiness report; see handoff"
    );
    let encoded = local.encode_report(value);
    let mut report: Value =
        serde_json::from_str(&encoded).expect("full report must survive protection");
    assert_eq!(report["state"], "unlocked");
    for field in ["setup", "sessions", "goal_templates", "procurement"] {
        assert!(report.get(field).is_some(), "full report lost {field}");
    }
    assert_eq!(report["lifecycle_state"], "running");
    assert_eq!(report["lifecycle_generation"], "1");
    assert!(report["setup_offer"].is_null());
    assert!(report.get("fixture_admission").is_none());
    assert_eq!(
        report["provider_configuration"]["key_set"],
        provider_key_set
    );
    assert!(report["poc_configuration"]["configuration"].is_object());
    // src/harness/inference.rs:269-277, then the sole-member envelope at :282.
    let object = report.as_object_mut().unwrap();
    for (from, to) in [
        ("state", "store_state"),
        ("error", "store_error"),
        ("reason", "store_reason"),
    ] {
        if let Some(value) = object.remove(from) {
            object.insert(to.into(), value);
        }
    }
    let message = json!({"store":report});
    store_message(&message);
    message
}

/// Assert the exact envelope accepted by render-net's messagesOf and lastState.
fn store_message(message: &Value) {
    let object = message.as_object().expect("worker message object");
    assert_eq!(object.len(), 1, "a report must be the only message member");
    let store = &message["store"];
    assert_eq!(store["store_state"], "unlocked");
    assert_eq!(store["lifecycle_state"], "running");
    assert_eq!(store["lifecycle_generation"], "1");
    for field in ["state", "error", "reason"] {
        assert!(store.get(field).is_none(), "unrenamed worker field {field}");
    }
}

/// Keep ordering explicit even when serde_json is built with preserve_order.
fn sorted(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries: Vec<_> = object.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sorted).collect()),
        scalar => scalar,
    }
}

pub(in crate::store) fn dump(vendor: &str, state: &str, report: Value) {
    store_message(&report);
    assert!(matches!(vendor, "vpsbg" | "lnvps"));
    assert!(!state.is_empty());
    assert!(state.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{vendor}-render"))
        .join(format!("{state}.json"));
    let mut bytes = serde_json::to_vec_pretty(&sorted(report)).unwrap();
    bytes.push(b'\n');
    if std::env::var("TAU_WRITE_RENDER_FIXTURES").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
    } else {
        let expected = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}; generate with TAU_WRITE_RENDER_FIXTURES=1",
                path.display()
            )
        });
        assert_eq!(
            bytes,
            expected,
            "render fixture differs: {}",
            path.display()
        );
    }
}
