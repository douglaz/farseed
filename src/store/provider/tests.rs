use super::*;
use crate::store::inference::tests::Fixed;

const KEY: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"provider custody fixture passphrase".to_vec())
}
fn ready() -> Store<MemoryStorage> {
    let mut store = block_on(create(MemoryStorage::default(), &Fixed, pass())).unwrap();
    block_on(store.seed_backup(allocation::Completion::Skipped)).unwrap();
    store
}
fn install(store: &mut Store<MemoryStorage>) -> Result<(), String> {
    let account = Account::parse(KEY.to_uppercase().as_bytes()).unwrap();
    block_on(store.procurement_configure(
        &account,
        KEY.to_uppercase().as_bytes(),
        "https://Fixture.INVALID:443/",
    ))
}
fn reopen(store: &Store<MemoryStorage>) -> Result<Store<MemoryStorage>, String> {
    block_on(unlock(
        MemoryStorage::with_files(store.storage.files()),
        &Fixed,
        pass(),
    ))
}
// Construct valid encryption and chaining independently of the production append guard.
fn append(store: &mut Store<MemoryStorage>, event: Value) {
    let plaintext = Zeroizing::new(serde_json::to_vec(&journal(event)).unwrap());
    append_plaintext(store, &plaintext);
}
fn append_plaintext(store: &mut Store<MemoryStorage>, plaintext: &[u8]) {
    let number = store.next;
    let previous = hex::encode(store.previous.0);
    let nonce = random::<12>().unwrap();
    let ciphertext = cipher(&store.key.0)
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad: record_aad(&store.id, EVENT, number, &previous).as_bytes(),
            },
        )
        .unwrap();
    let bytes = serde_json::to_vec(&RecordJson {
        id: store.id.clone(),
        kind: EVENT.into(),
        number,
        previous,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
    .unwrap();
    block_on(store.storage.write(STAGING, &bytes)).unwrap();
    block_on(store.storage.rename(STAGING, &number.to_string())).unwrap();
    store.next += 1;
    store.previous = Address(Sha256::digest(&bytes).into());
}

#[test]
fn provider_custody_commits_then_protects_and_replays_canonical_account() {
    let mut store = ready();
    assert!(store.provider_account().is_none());
    assert!(store.provider_filters.is_empty());
    let before = store.next;
    install(&mut store).unwrap();
    assert_eq!(store.next, before + 1);
    let public = store.provider_account().unwrap().public();
    for mut current in [reopen(&store).unwrap(), store] {
        assert_eq!(current.provider_account().unwrap().public(), public);
        assert_eq!(current.procurement_origin(), "https://fixture.invalid");
        assert_eq!(
            install(&mut current).unwrap_err(),
            "Provider account already recorded"
        );
        for text in [
            KEY.to_string(),
            KEY.to_uppercase(),
            hex::encode(hex::decode(KEY).unwrap()),
        ] {
            assert!(
                block_on(current.commit(&Event::Command {
                    machine: "fixture".into(),
                    command: text.clone()
                }))
                .is_err()
            );
            assert_ne!(current.protect_output(&json!(text)).unwrap(), json!(text));
            assert!(!crate::poc::inference::safe(&current, &json!(text), &[]));
        }
        let account = Account::parse(&[b'3'; 64]).unwrap();
        assert_eq!(
            block_on(current.commit(&Event::PocProviderAccount(
                account.record(AccountSource::Entered, "https://fixture.invalid".into())
            )))
            .unwrap_err(),
            "Provider account already recorded"
        );
    }
}

#[test]
fn provider_custody_failed_append_installs_nothing() {
    for fault in [
        Fault::Fail(1),
        Fault::Fail(2),
        Fault::Fail(3),
        Fault::LandThenFail(3),
    ] {
        let mut store = ready();
        store.deployment_origin = Some("https://fixture.invalid".into());
        store.storage.fault(fault);
        assert!(block_on(store.provider_generate()).is_err());
        assert!(store.provider_account().is_none());
        assert!(store.provider_filters.is_empty());
        assert!(store.failed.is_some());
        if matches!(fault, Fault::LandThenFail(_)) {
            assert!(reopen(&store).unwrap().provider_account().is_some());
        }
    }
}

#[test]
fn provider_custody_later_encrypted_occurrence_refuses_unlock() {
    for event in [
        json!({"command":{"machine":"fixture","command":KEY}}),
        json!({"poc_credit_account":{"credit_id":KEY,"default_key":"synthetic-other-account-482700"}}),
    ] {
        let mut store = ready();
        install(&mut store).unwrap();
        append(&mut store, event);
        assert!(
            reopen(&store)
                .err()
                .unwrap()
                .contains("protected provider material")
        );
    }
}

#[test]
fn provider_custody_second_record_refuses_replay() {
    let mut store = ready();
    install(&mut store).unwrap();
    append(
        &mut store,
        json!({"poc_provider_account":{"key":"12".repeat(32),"source":"generated","origin":"https://fixture.invalid"}}),
    );
    assert!(
        reopen(&store)
            .err()
            .unwrap()
            .contains("Provider account already recorded")
    );
}

#[test]
fn provider_custody_malformed_shape_scalar_and_origin_refuse_open() {
    let valid = json!({"key":KEY,"source":"entered","origin":"https://fixture.invalid"});
    let mut bodies = Vec::new();
    for key in [
        "0".repeat(64),
        "f".repeat(64),
        KEY.to_uppercase(),
        "12".repeat(31),
        "g".repeat(64),
    ] {
        let mut v = valid.clone();
        v["key"] = key.into();
        bodies.push(v);
    }
    let mut v = valid.clone();
    v["extra"] = true.into();
    bodies.push(v);
    let mut v = valid.clone();
    v["origin"] = "https://Fixture.invalid/".into();
    bodies.push(v);
    let mut v = valid.clone();
    v["source"] = "other".into();
    bodies.push(v);
    // A singleton sequence can deserialize as a struct; the round-trip shape guard must refuse it.
    bodies.push(json!([KEY, "entered", "https://fixture.invalid"]));
    let mut v = valid;
    v["origin"] = format!("https://{KEY}.invalid").into();
    bodies.push(v);
    for body in bodies {
        let mut store = ready();
        append(&mut store, json!({"poc_provider_account":body}));
        let why = reopen(&store)
            .err()
            .expect("malformed custody refuses Unlock");
        assert!(!why.contains(KEY));
    }
}

#[test]
fn provider_generation_requires_deployment_origin_and_retains_it() {
    let mut store = ready();
    let before = store.storage.files();
    assert!(
        block_on(store.provider_generate())
            .unwrap_err()
            .contains("valid deployment defaults")
    );
    assert_eq!(store.storage.files(), before);
    assert!(store.provider_account().is_none());
    store.deployment_origin = Some(provider_origin("https://Deployment.INVALID:443/").unwrap());
    block_on(store.provider_generate()).unwrap();
    assert_eq!(store.procurement_origin(), "https://deployment.invalid");
    assert_ne!(store.procurement_origin(), crate::poc::provisioning::ORIGIN);
    let public = store.provider_account().unwrap().public();
    block_on(store.provider_generate()).unwrap();
    assert_eq!(
        reopen(&store).unwrap().provider_account().unwrap().public(),
        public
    );
    assert_eq!(
        reopen(&store).unwrap().procurement_origin(),
        "https://deployment.invalid"
    );
}

fn relay_forms(key: &str) -> Vec<String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    let raw = hex::decode(key).unwrap();
    let mut forms = vec![key.to_string(), key.to_uppercase()];
    for bytes in [
        raw.as_slice(),
        key.as_bytes(),
        key.to_uppercase().as_bytes(),
    ] {
        forms.extend([
            hex::encode(bytes),
            hex::encode_upper(bytes),
            STANDARD.encode(bytes),
            STANDARD_NO_PAD.encode(bytes),
            URL_SAFE_NO_PAD.encode(bytes),
        ]);
    }
    forms.sort();
    forms.dedup();
    forms
}

#[test]
fn deployment_defaults_refuse_relay_overlap_before_configuration() {
    let fields = json!({"provider_origin":"https://fixture.invalid","relay_url":"wss://relay.invalid/","chat_endpoint":"https://inference.invalid/v1","model":"fixture-a","topup_sat":1200});
    for form in relay_forms(KEY) {
        for (field, text) in [
            ("model", form.clone()),
            ("chat_endpoint", format!("https://inference.invalid/{form}")),
            ("relay_url", format!("wss://relay.invalid/{form}/")),
            ("provider_origin", format!("https://{form}.invalid")),
        ] {
            let mut local = Local::new(MemoryStorage::default(), Fixed);
            let mut public = fields.clone();
            public[field] = text.into();
            assert!(
                !local
                    .deployment_configure(
                        Some("https://fixture.invalid".into()),
                        KEY.as_bytes(),
                        &public.to_string()
                    )
                    .unwrap()
            );
            assert!(local.deployment_origin.is_none());
            assert!(local.deployment_relay.is_none());
        }
    }
    let mut local = Local::new(MemoryStorage::default(), Fixed);
    assert!(
        !local
            .deployment_configure(Some(format!("https://{KEY}.invalid")), KEY.as_bytes(), "{}")
            .unwrap()
    );
    assert!(local.deployment_origin.is_none());
    for key in [KEY, "", "not-a-scalar"] {
        let mut local = Local::new(MemoryStorage::default(), Fixed);
        assert!(
            local
                .deployment_configure(
                    Some("https://fixture.invalid".into()),
                    key.as_bytes(),
                    &fields.to_string()
                )
                .unwrap()
        );
        assert_eq!(
            local.deployment_origin.as_deref(),
            Some("https://fixture.invalid")
        );
        assert_eq!(local.deployment_relay.is_some(), key == KEY);
    }
}

#[test]
fn deployment_relay_scalar_validation_gating_and_held_redaction() {
    use crate::credential::RelayKey;
    for input in [
        "0".repeat(64),
        "f".repeat(64),
        KEY.to_uppercase(),
        "12".repeat(31),
        "g".repeat(64),
    ] {
        assert!(RelayKey::from_deployment(input.as_bytes()).is_none());
    }
    let mut store = ready();
    store.deployment_relay = RelayKey::from_deployment(KEY.as_bytes());
    assert!(
        store.relay_key().is_none(),
        "override retains allocation gating"
    );
    // Raw and hexadecimal protection must come from held custody, even without a pass.
    let raw = hex::decode(KEY).unwrap();
    let safe = crate::redaction::Redacted::decoded(&store, &raw).unwrap();
    assert_ne!(safe.as_bytes(), raw.as_slice());
    for text in relay_forms(KEY)
        .into_iter()
        .chain([format!("before {KEY} after")])
    {
        assert_ne!(store.protect_output(&json!(text)).unwrap(), json!(text));
        assert!(
            block_on(store.commit(&Event::Command {
                machine: "fixture".into(),
                command: text
            }))
            .is_err()
        );
    }
    let identity = block_on(store.allocate(Family::Passes)).unwrap();
    let key = store.relay_key().unwrap();
    assert_eq!(
        key.public_key(),
        store.deployment_relay.as_ref().unwrap().public_key()
    );
    let seed_key = store
        .seed()
        .unwrap()
        .relay_key(identity.derivation_version, identity.index)
        .unwrap();
    assert_ne!(seed_key.public_key(), key.public_key());
    assert_ne!(
        crate::redaction::Redacted::decoded(&store, &seed_key.0)
            .unwrap()
            .as_bytes(),
        seed_key.0
    );
    assert!(
        reopen(&store).unwrap().deployment_relay.is_none(),
        "a reopened store requires deployment material to be delivered again"
    );
    let mut reader = Store::new(
        store.storage.clone(),
        DataKey(store.key.0),
        store.id.clone(),
    );
    let mut records = 0;
    for number in 0..store.next {
        let bytes = block_on(store.storage.read(&number.to_string())).unwrap();
        let (_, plaintext) = reader.open_record(number, &bytes).unwrap();
        for form in relay_forms(KEY) {
            assert!(
                !plaintext
                    .windows(form.len())
                    .any(|bytes| bytes == form.as_bytes()),
                "authenticated journal content excludes deployment material in every field"
            );
        }
        assert!(
            !plaintext
                .windows(raw.len())
                .any(|bytes| bytes == raw.as_slice())
        );
        reader.previous = Address(Sha256::digest(&bytes).into());
        records += 1;
    }
    assert_eq!(records, store.next);
    assert!(records > 0);
    store.deployment_relay = None;
    assert_eq!(
        store.relay_key().unwrap().public_key(),
        seed_key.public_key()
    );
}

#[test]
fn provider_entry_invalid_origin_is_atomic_before_custody() {
    let mut store = ready();
    let account = Account::parse(KEY.as_bytes()).unwrap();
    let before = store.storage.files();
    for origin in [
        "",
        "http://fixture.invalid",
        "https://@fixture.invalid",
        "https://fixture.invalid?",
        "https://fixture.invalid/path",
        "https://fixture.invalid:65536",
        "https://127.1",
        " https://fixture.invalid",
    ] {
        assert!(block_on(store.procurement_configure(&account, KEY.as_bytes(), origin)).is_err());
        assert!(store.provider_account().is_none());
        assert!(store.provider_filters.is_empty());
        assert_eq!(store.storage.files(), before);
        assert_eq!(store.provider_origin, crate::poc::provisioning::ORIGIN);
    }
}

#[test]
fn provider_custody_replay_checks_original_plaintext_before_numeric_normalization() {
    let mut store = ready();
    let key = "12".repeat(32);
    let account = Account::parse(key.as_bytes()).unwrap();
    block_on(store.procurement_configure(&account, key.as_bytes(), "https://fixture.invalid"))
        .unwrap();
    let text = [
        "{\"journal_version\":2,\"event\":{\"procurement\":{\"observation\":{\"amount\":",
        key.as_str(),
        "}}}}",
    ]
    .concat();
    let number = store.next;
    let previous = store.previous.0;
    append_plaintext(&mut store, text.as_bytes());
    let mut reader = Store::new(
        store.storage.clone(),
        DataKey(store.key.0),
        store.id.clone(),
    );
    reader.previous = Address(previous);
    let (event, plaintext) = reader
        .open_record(
            number,
            &block_on(store.storage.read(&number.to_string())).unwrap(),
        )
        .unwrap();
    assert!(std::str::from_utf8(&plaintext).unwrap().contains(&key));
    assert!(
        !serde_json::to_string(&event).unwrap().contains(&key),
        "fixture actually changes spelling when parsed"
    );
    assert!(
        reopen(&store)
            .err()
            .unwrap()
            .contains("protected provider material")
    );
}

#[test]
fn provider_custody_malformed_record_metadata_never_echoes_the_key() {
    for mutation in ["kind", "member", "number"] {
        let mut store = ready();
        install(&mut store).unwrap();
        block_on(store.commit(&Event::Command {
            machine: "fixture".into(),
            command: "true".into(),
        }))
        .unwrap();
        let name = (store.next - 1).to_string();
        let mut files = store.storage.files();
        let bytes = if mutation == "kind" {
            let mut record: RecordJson = serde_json::from_slice(&files[&name]).unwrap();
            record.kind = KEY.into();
            serde_json::to_vec(&record).unwrap()
        } else {
            let mut record: Value = serde_json::from_slice(&files[&name]).unwrap();
            if mutation == "member" {
                record[KEY] = true.into();
            } else {
                record["number"] = KEY.into();
            }
            serde_json::to_vec(&record).unwrap()
        };
        files.insert(name, bytes);
        let why = block_on(unlock(MemoryStorage::with_files(files), &Fixed, pass()))
            .err()
            .unwrap();
        assert!(
            !why.contains(KEY),
            "malformed record diagnostic must not quote private material"
        );
    }
}

#[test]
fn provider_custody_out_of_range_filename_never_echoes_the_key() {
    let mut store = ready();
    let key = "12".repeat(32);
    let account = Account::parse(key.as_bytes()).unwrap();
    block_on(store.procurement_configure(&account, key.as_bytes(), "https://fixture.invalid"))
        .unwrap();
    let mut files = store.storage.files();
    files.insert(key.clone(), vec![]);
    let why = block_on(unlock(MemoryStorage::with_files(files), &Fixed, pass()))
        .err()
        .unwrap();
    assert!(
        !why.contains(&key),
        "invalid record number must not quote private material"
    );
}

#[test]
fn deployment_relay_malformed_unlock_envelope_never_echoes_the_key() {
    for field in ["member", "purpose", "kdf", "version"] {
        let store = ready();
        let mut files = store.storage.files();
        let mut envelope: Value = serde_json::from_slice(&files[ENVELOPE]).unwrap();
        if field == "member" {
            envelope[KEY] = true.into();
        } else {
            envelope[field] = KEY.into();
        }
        files.insert(ENVELOPE.into(), serde_json::to_vec(&envelope).unwrap());
        let mut local = Local::new(MemoryStorage::with_files(files), Fixed);
        local
            .deployment_configure(None, KEY.as_bytes(), "{}")
            .unwrap();
        block_on(local.open());
        let report = block_on(local.unlock(pass()));
        assert_eq!(report["state"], "refused");
        assert!(
            !report.to_string().contains(KEY),
            "locked diagnostic must not quote deployment material"
        );
    }
}
