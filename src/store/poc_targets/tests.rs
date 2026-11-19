use super::*;
use crate::harness::PinSource;
use crate::jobs::Elevation;
use crate::poc::targets::StoredPins;

struct Fixed;
impl Kdf for Fixed {
    async fn derive(&self, _: LocalPassphrase, _: &Salt) -> Result<WrappingKey, String> {
        Ok(WrappingKey([9; 32]))
    }
}
fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"local target test passphrase".to_vec())
}
fn fresh() -> Store<MemoryStorage> {
    block_on(create(MemoryStorage::default(), &Fixed, pass())).unwrap()
}
fn ready() -> Store<MemoryStorage> {
    let mut store = fresh();
    block_on(store.seed_backup(allocation::Completion::Skipped)).unwrap();
    store
}
fn reopen(store: &Store<MemoryStorage>) -> Result<Store<MemoryStorage>, String> {
    block_on(unlock(
        MemoryStorage::with_files(store.storage.files()),
        &Fixed,
        pass(),
    ))
}
fn enrollment() -> Enrollment {
    Enrollment {
        target: TargetRecord {
            machine: "machine-a".into(),
            relay: "wss://relay.invalid/".into(),
            profile: "v1".into(),
            host: "192.0.2.1".into(),
            port: 22,
            user: "arch".into(),
            elevation: Elevation::None,
            pin: format!(
                "SHA256:{}",
                base64::engine::general_purpose::STANDARD_NO_PAD.encode([3; 32])
            ),
        },
        approve_existing: true,
        class_answer: ClassAnswer::No,
        approve_maintained_access: true,
    }
}
fn enroll(store: &mut Store<MemoryStorage>) {
    block_on(store.poc_enroll(enrollment())).unwrap();
}

#[test]
fn poc_targets_atomic_encrypted_enrollment_replay_and_public_identity() {
    let mut store = ready();
    enroll(&mut store);
    let files = store.storage.files();
    for bytes in files.values() {
        let text = String::from_utf8_lossy(bytes);
        for protected in ["machine-a", "192.0.2.1", "relay.invalid"] {
            assert!(!text.contains(protected));
        }
    }
    assert_eq!(store.allocation().next_unused().machines, 1);
    assert_eq!(store.allocation().next_unused().passes, 1);
    let keys = store.poc_public_keys("machine-a").unwrap();
    let line = keys["authorized_keys"].as_str().unwrap();
    let encoded = line.strip_prefix("ssh-ed25519 ").unwrap();
    let wire = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    assert_eq!(&wire[..19], b"\0\0\0\x0bssh-ed25519\0\0\0\x20");
    let identity = &store.dispatch.approved_entries["machine-a"]
        .approved
        .identity;
    let key = store
        .seed()
        .unwrap()
        .ssh_client_key(identity.derivation_version, identity.index)
        .unwrap();
    assert_eq!(&wire[19..], &key.public_key());
    assert_eq!(
        keys["relay_pubkey"],
        hex::encode(store.relay_key().unwrap().public_key())
    );
    assert_eq!(keys["relay_pubkey"].as_str().unwrap().len(), 64);
    let mut reopened = reopen(&store).unwrap();
    assert_eq!(reopened.poc_public_keys("machine-a").unwrap(), keys);
    assert_eq!(
        reopened.poc_target("machine-a"),
        store.poc_target("machine-a")
    );
    let pins = StoredPins::from_record(reopened.poc_target("machine-a").unwrap()).unwrap();
    assert_eq!(pins.pin("machine-a").unwrap().0, enrollment().target.pin);
    assert!(pins.pin("missing").is_none());
    assert!(reopened.poc_target("missing").is_none());
    assert_eq!(reopened.storage.files(), files);
    let first = block_on(reopened.poc_bind("machine-a")).unwrap();
    let bound_records = reopened.records().end;
    assert_eq!(block_on(reopened.poc_bind("machine-a")).unwrap(), first);
    assert_eq!(reopened.records().end, bound_records);
    assert!(
        reopened
            .dispatch
            .check_installation("machine-a")
            .unwrap_err()
            .contains("declaration missing")
    );
}

#[test]
fn poc_targets_idempotent_immutable_and_replayed_rebinding() {
    let mut store = ready();
    enroll(&mut store);
    let before = store.storage.files();
    enroll(&mut store);
    assert_eq!(store.storage.files(), before);
    for field in [
        "host",
        "relay",
        "profile",
        "port",
        "user",
        "pin",
        "elevation",
        "class",
    ] {
        let mut changed = enrollment();
        match field {
            "host" => changed.target.host = "192.0.2.2".into(),
            "relay" => changed.target.relay = "wss://other.invalid/".into(),
            "profile" => changed.target.profile = "v2".into(),
            "port" => changed.target.port = 2222,
            "user" => changed.target.user = "root".into(),
            "pin" => {
                changed.target.pin = format!(
                    "SHA256:{}",
                    base64::engine::general_purpose::STANDARD_NO_PAD.encode([4; 32])
                )
            }
            "elevation" => changed.target.elevation = Elevation::SudoNoninteractive,
            _ => changed.class_answer = ClassAnswer::Yes,
        }
        assert!(block_on(store.poc_enroll(changed)).is_err(), "{field}");
        assert_eq!(store.storage.files(), before);
    }
    let first = block_on(store.poc_bind("machine-a")).unwrap();
    let mut successor = reopen(&store).unwrap();
    enroll(&mut successor);
    let next = block_on(successor.poc_bind("machine-a")).unwrap();
    assert_eq!(first, next);
    assert_eq!(successor.allocation().next_unused().machines, 1);
    assert_eq!(successor.allocation().next_unused().passes, 1);
}

#[test]
fn poc_targets_prerequisites_collision_and_pass_reuse() {
    let mut unbacked = fresh();
    assert!(block_on(unbacked.poc_enroll(enrollment())).is_err());
    let mut store = ready();
    for existing in [false, true] {
        let mut request = enrollment();
        if existing {
            request.approve_existing = false;
        } else {
            request.approve_maintained_access = false;
        }
        assert!(block_on(store.poc_enroll(request)).is_err());
    }
    let pass = block_on(store.allocate(Family::Passes)).unwrap();
    enroll(&mut store);
    assert_eq!(store.poc_targets["machine-a"].relay_identity, pass);
    assert_eq!(store.allocation().next_unused().passes, 1);
    let mut fixture = ready();
    block_on(fixture.approve_setup(crate::dispatch::fixture_setup())).unwrap();
    let before = fixture.storage.files();
    assert!(
        block_on(fixture.poc_enroll(enrollment()))
            .unwrap_err()
            .contains("another setup approval")
    );
    assert_eq!(fixture.storage.files(), before);
    let mut history = ready();
    let intent = Intent {
        call: history.next,
        machine: "machine-a".into(),
        command: hex::encode(b"true"),
        approval: Some(Approval::LegacyCommand),
        job: None,
        provenance: None,
    };
    let n = block_on(history.commit(&Event::Intent(intent.clone()))).unwrap();
    history.apply_intent(n, intent).unwrap();
    assert!(
        block_on(history.poc_enroll(enrollment()))
            .unwrap_err()
            .contains("unrelated command history")
    );
}

#[test]
fn poc_targets_append_failure_and_interrupted_enrollment_recover_without_reallocation() {
    for fault in [
        Fault::Fail(1),
        Fault::Fail(2),
        Fault::Fail(3),
        Fault::LandThenFail(3),
    ] {
        let mut store = ready();
        store.storage.fault(fault);
        assert!(block_on(store.poc_enroll(enrollment())).is_err());
        assert!(store.poc_target("machine-a").is_none());
        assert!(
            block_on(store.poc_enroll(enrollment())).is_err(),
            "failed append latches"
        );
        let mut successor = reopen(&store).unwrap();
        enroll(&mut successor);
        assert_eq!(successor.allocation().next_unused().machines, 1);
        assert_eq!(successor.allocation().next_unused().passes, 1);
        block_on(successor.poc_bind("machine-a")).unwrap();
    }
}

#[test]
fn poc_targets_old_journal_replay_and_conflicting_authenticated_record_fail_closed() {
    let old = ready();
    let bytes = old.storage.files();
    let replayed = reopen(&old).unwrap();
    assert_eq!(replayed.storage.files(), bytes);
    assert!(replayed.poc_targets.is_empty());
    let mut store = ready();
    enroll(&mut store);
    let mut conflict = store.poc_targets["machine-a"].clone();
    conflict.target.elevation = Elevation::SudoNoninteractive;
    let n = store.records().end;
    block_on(store.commit(&Event::PocTarget(conflict))).unwrap();
    let reason = reopen(&store).err().unwrap();
    assert!(reason.contains(&format!("record {n}")));
    assert!(reason.contains("immutable"));
}

#[test]
fn poc_targets_operator_messages_and_suspension_are_admitted_explicitly() {
    let mut local = Local::new(MemoryStorage::default(), Fixed);
    assert_eq!(block_on(local.poc_enroll("{}"))["error"], "locked");
    block_on(local.open());
    let created = block_on(local.create(pass()));
    assert_eq!(created["state"], "unlocked");
    assert_eq!(block_on(local.poc_enroll("{}"))["error"], "seed_backup");
    local.seed_backup_answer();
    block_on(local.seed_backup_complete(None));
    let value = json!({"target":enrollment().target,"approve_existing":true,"class_answer":"no","approve_maintained_access":true});
    let mut extra = value.clone();
    extra["unexpected"] = json!(true);
    assert_eq!(
        block_on(local.poc_enroll(&extra.to_string()))["error"],
        "invalid existing-machine enrollment"
    );
    assert!(
        block_on(local.poc_enroll(&value.to_string()))
            .get("error")
            .is_none()
    );
    assert_eq!(
        local.poc_public_keys("unknown")["refused"],
        "machine has no stored target or pin"
    );
    let store = local.store().unwrap();
    store.authority.suspend();
    assert!(block_on(store.poc_enroll(enrollment())).is_err());
    assert!(block_on(store.poc_bind("machine-a")).is_err());
    assert!(store.poc_public_keys("machine-a").is_err());
    store.authority.revalidated().unwrap();
    assert!(store.poc_public_keys("machine-a").is_ok());
}

#[test]
fn poc_targets_positional_enrollment_and_target_messages_create_no_authority() {
    let storage = MemoryStorage::default();
    let mut local = Local::new(storage.clone(), Fixed);
    block_on(local.open());
    block_on(local.create(pass()));
    local.seed_backup_answer();
    block_on(local.seed_backup_complete(None));
    let target = enrollment().target;
    let positional_target = json!([
        target.machine,
        target.relay,
        target.profile,
        target.host,
        target.port,
        target.user,
        target.elevation,
        target.pin
    ]);
    let positional_enrollment = json!([enrollment().target, true, "no", true]);
    let nested_positional = json!({
        "target": positional_target,
        "approve_existing": true,
        "class_answer": "no",
        "approve_maintained_access": true
    });
    let both_positional = json!([positional_target, true, "no", true]);
    let before = storage.files();
    let allocation = local.store().unwrap().allocation().clone();
    for malformed in [positional_enrollment, nested_positional, both_positional] {
        assert_eq!(
            block_on(local.poc_enroll(&malformed.to_string()))["error"],
            "invalid existing-machine enrollment"
        );
        assert_eq!(storage.files(), before);
        let store = local.store().unwrap();
        assert_eq!(store.allocation(), &allocation);
        assert!(store.poc_target("machine-a").is_none());
        assert!(store.dispatch.approved_entries.is_empty());
        assert!(store.relay_key().is_none());
    }
}

fn assert_poc_echoes_absent(value: &Value, keys: &[&[u8]]) {
    let serialized = value.to_string();
    for key in keys {
        let key_text = std::str::from_utf8(key).unwrap();
        let embedded =
            base64::engine::general_purpose::STANDARD.encode([b"x".as_slice(), key].concat());
        assert!(
            !serialized.contains(key_text),
            "raw credential escaped protection"
        );
        assert!(
            !serialized.contains(&hex::encode(key)),
            "hex credential escaped protection"
        );
        assert!(
            !serialized.contains(&embedded),
            "embedded container escaped protection"
        );
    }
    match value {
        Value::String(text) => {
            if let Ok(decoded) = hex::decode(text) {
                let decoded = String::from_utf8_lossy(&decoded);
                for key in keys {
                    let key_text = std::str::from_utf8(key).unwrap();
                    let embedded = base64::engine::general_purpose::STANDARD
                        .encode([b"x".as_slice(), key].concat());
                    assert!(
                        !decoded.contains(key_text),
                        "journal evidence retained a raw credential"
                    );
                    assert!(
                        !decoded.contains(&embedded),
                        "journal evidence retained an encoded container"
                    );
                }
                if let Ok(nested) = serde_json::from_str::<Value>(&decoded) {
                    assert_poc_echoes_absent(&nested, keys);
                }
            }
            if let Ok(nested) = serde_json::from_str::<Value>(text) {
                assert_poc_echoes_absent(&nested, keys);
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_poc_echoes_absent(value, keys);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                assert_poc_echoes_absent(&Value::String(key.clone()), keys);
                assert_poc_echoes_absent(value, keys);
            }
        }
        _ => {}
    }
}

fn assert_poc_decrypted_journal_private_counts(
    store: &Store<MemoryStorage>,
    keys: &[&[u8]],
    expected_observations: usize,
) {
    let files = store.storage.files();
    let mut reader = Store::new(
        store.storage.clone(),
        DataKey(store.key.0),
        store.id.clone(),
    );
    let mut observations = 0;
    let mut terminals = 0;
    for number in store.records() {
        let bytes = &files[&number.to_string()];
        let event = reader.open(number, bytes).unwrap();
        if matches!(&event, Event::JobObservation(_)) {
            observations += 1;
        }
        if matches!(&event, Event::JobTerminal(_)) {
            terminals += 1;
        }
        assert_poc_echoes_absent(&serde_json::to_value(&event).unwrap(), keys);
        reader.previous = Address(Sha256::digest(bytes).into());
    }
    assert_eq!(observations, expected_observations);
    assert_eq!(terminals, 1);
}

#[test]
fn poc_targets_access_snapshot_revision_is_preserved_and_conflicts_refuse() {
    let mut store = ready();
    let access = Access {
        model: crate::dispatch::AccessModel::Maintained,
        profile: "ad-hoc".into(),
        revision: Access::ad_hoc().revision.checked_add(7).unwrap(),
    };
    // An authenticated enrollment made under a different compiled profile revision.
    let record = Record {
        target: enrollment().target,
        machine_identity: store.allocation().issue(Family::Machines).unwrap(),
        relay_identity: store.allocation().issue(Family::Passes).unwrap(),
        class_answer: ClassAnswer::No,
        application_inference_keys: Vec::new(),
        key_card_class: None,
        access: access.clone(),
    };
    block_on(store.commit(&Event::PocTarget(record.clone()))).unwrap();
    let mut recovered = reopen(&store).unwrap();
    assert_eq!(
        recovered.dispatch.approved_entries["machine-a"]
            .approved
            .access,
        Some(access.clone())
    );
    assert_eq!(recovered.poc_targets["machine-a"].access, access);
    let before = recovered.storage.files();
    enroll(&mut recovered);
    assert_eq!(recovered.storage.files(), before);
    let mut conflict = record;
    conflict.access.revision += 1;
    let number = recovered.records().end;
    block_on(recovered.commit(&Event::PocTarget(conflict))).unwrap();
    let reason = reopen(&recovered).err().unwrap();
    assert!(reason.contains(&format!("record {number}")));
    assert!(reason.contains("immutable"));
}

#[test]
fn poc_targets_access_snapshot_rejects_unapproved_model_or_profile() {
    for invalid_model in [true, false] {
        let mut store = ready();
        let mut access = Access::ad_hoc();
        if invalid_model {
            access.model = crate::dispatch::AccessModel::Sealed;
        } else {
            access.profile = "other-profile".into();
        }
        let record = Record {
            target: enrollment().target,
            machine_identity: store.allocation().issue(Family::Machines).unwrap(),
            relay_identity: store.allocation().issue(Family::Passes).unwrap(),
            class_answer: ClassAnswer::No,
            application_inference_keys: Vec::new(),
            key_card_class: None,
            access,
        };
        let before = store.storage.files();
        assert!(store.poc_projections(&record).is_err());
        assert_eq!(store.storage.files(), before);
        let number = store.records().end;
        block_on(store.commit(&Event::PocTarget(record))).unwrap();
        let reason = reopen(&store).err().unwrap();
        assert!(reason.contains(&format!("record {number}")));
        assert!(reason.contains("unsupported ad-hoc access"));
    }
}

#[test]
fn poc_operator_declaration_approval_admits_production_commands_and_replays() {
    use crate::goals::Tool;
    let mut store = ready();
    enroll(&mut store);
    let session = block_on(store.poc_bind("machine-a")).unwrap();
    let proposal = json!({"kind":"declaration","machine":"machine-a","declaration":crate::declaration::ad_hoc_minimum()});
    assert!(block_on(store.check("machine-a")).is_err());
    let files = store.storage.files();
    assert!(
        store.poc_propose_requirements(&session, &proposal).is_err(),
        "missing goal"
    );
    block_on(store.enter_goal(&session, "Install a small service".into(), None)).unwrap();
    assert!(
        store.poc_propose_requirements(&session, &proposal).is_err(),
        "missing acting acceptance"
    );
    block_on(store.accept_mode(&session, crate::modes::Mode::NoBrief)).unwrap();
    let before = store.storage.files();
    let mut malformed = proposal.clone();
    malformed["declaration"]["version"] = 1.into();
    assert!(
        store
            .poc_propose_requirements(&session, &malformed)
            .is_err()
    );
    let mut wrong = proposal.clone();
    wrong["machine"] = "wrong-machine".into();
    assert!(store.poc_propose_requirements(&session, &wrong).is_err());
    assert!(
        store
            .poc_propose_requirements("wrong-session", &proposal)
            .is_err()
    );
    assert_eq!(before, store.storage.files());
    store.poc_propose_requirements(&session, &proposal).unwrap();
    let candidate = store.pending_requirements[&session].candidate;
    assert!(block_on(store.approve_requirements("wrong-session", "machine-a", candidate)).is_err());
    assert!(block_on(store.approve_requirements(&session, "wrong-machine", candidate)).is_err());
    assert!(block_on(store.approve_requirements(&session, "machine-a", candidate + 1)).is_err());
    store
        .reject_requirements(&session, "machine-a", candidate)
        .unwrap();
    store.poc_propose_requirements(&session, &proposal).unwrap();
    let replacement = store.pending_requirements[&session].candidate;
    assert_ne!(replacement, candidate);
    assert!(block_on(store.approve_requirements(&session, "machine-a", candidate)).is_err());
    assert!(
        store
            .check_tool(
                &session,
                &Tool::Exec {
                    machine: "machine-a".into(),
                    command: "true".into()
                }
            )
            .is_err()
    );
    let approval_number = store.records().end;
    block_on(store.approve_requirements(&session, "machine-a", replacement)).unwrap();
    block_on(store.check("machine-a")).unwrap();
    let mut reader = Store::new(
        store.storage.clone(),
        DataKey(store.key.0),
        store.id.clone(),
    );
    reader.previous =
        Address(Sha256::digest(&store.storage.files()[&(approval_number - 1).to_string()]).into());
    let event = reader
        .open(
            approval_number,
            &store.storage.files()[&approval_number.to_string()],
        )
        .unwrap();
    let value = serde_json::to_value(event).unwrap();
    assert_eq!(value["setup"]["requirements"]["proposal"], proposal);
    assert_eq!(value["setup"]["requirements"]["session"], session);
    let replayed = reopen(&store).unwrap();
    block_on(replayed.check("machine-a")).unwrap();
    assert_ne!(files, store.storage.files());
}

fn poc_pending_job(store: &mut Store<MemoryStorage>, output: &[u8]) -> crate::jobs::Evidence {
    poc_pending_command(store, output, b"true")
}

fn poc_pending_command(
    store: &mut Store<MemoryStorage>,
    output: &[u8],
    command: &[u8],
) -> crate::jobs::Evidence {
    enroll(store);
    let session = block_on(store.poc_bind("machine-a")).unwrap();
    block_on(store.enter_goal(&session, "Inspect a small service".into(), None)).unwrap();
    block_on(store.accept_mode(&session, crate::modes::Mode::NoBrief)).unwrap();
    store.poc_propose_requirements(&session, &json!({"kind":"declaration","machine":"machine-a","declaration":crate::declaration::ad_hoc_minimum()})).unwrap();
    let candidate = store.pending_requirements[&session].candidate;
    block_on(store.approve_requirements(&session, "machine-a", candidate)).unwrap();
    let entry = Entry {
        machine: "machine-a".into(),
        command: command.to_vec(),
        provenance: None,
    };
    let call = block_on(store.append(
        &entry,
        &Approval::HarnessPin {
            machine: entry.machine.clone(),
            fingerprint: enrollment().target.pin,
        },
    ))
    .unwrap();
    let intent = &store.dispatch.calls[&call].intent;
    crate::jobs::Evidence {
        call,
        job: intent.job.clone().unwrap(),
        record: crate::jobs::Record::Present {
            machine: hex::encode("machine-a"),
            command: intent.command.clone(),
            boot: "boot-a".into(),
            current_boot: "boot-a".into(),
            pid: 42,
            alive: false,
            exit_status: Some(7),
            stdout: hex::encode(output),
            stderr: String::new(),
        },
    }
}

fn poc_package_output(size: usize) -> Vec<u8> {
    b"Package abc012345 xyz789 installed successfully.\n"
        .iter()
        .copied()
        .cycle()
        .take(size)
        .collect()
}

#[test]
fn poc_comparison_collision_replays_the_committed_projection() {
    let mut store = ready();
    let evidence = poc_pending_job(&mut store, b"ordinary package output");
    let command = store.dispatch.calls[&evidence.call].intent.command.clone();
    store.hold_test_credential(b"true");
    assert_eq!(
        store.protect_output(&json!("true")).unwrap(),
        json!(crate::redaction::MARKER)
    );
    assert_eq!(
        store.protect_output(&json!(command)).unwrap(),
        json!(command)
    );
    let report = block_on(store.job_evidence(&evidence)).unwrap();
    let recovered = reopen(&store).unwrap();
    assert_eq!(store.dispatch.jobs, recovered.dispatch.jobs);
    assert_eq!(store.dispatch.calls, recovered.dispatch.calls);
    assert_eq!(store.dispatch.calls[&evidence.call].intent.command, command);
    assert_eq!(command, hex::encode("true"));
    assert!(matches!(
        report.comparison,
        crate::jobs::Comparison::AdvisoryMatch
    ));
    assert_eq!(block_on(store.collectable("machine-a")).unwrap().len(), 0);
    assert_eq!(
        block_on(recovered.collectable("machine-a")).unwrap().len(),
        0
    );
    let mut recovered = recovered;
    recovered.hold_test_credential(b"true");
    let live = block_on(crate::harness::BoundJournal::release(
        &store,
        serde_json::to_value(&report).unwrap(),
    ))
    .unwrap();
    let replayed = block_on(crate::harness::BoundJournal::release(
        &recovered,
        serde_json::to_value(recovered.dispatch.jobs.last()).unwrap(),
    ))
    .unwrap();
    assert_eq!(live, replayed);
    assert_eq!(live["agreement"], "advisory_match");
    assert!(live.get("journal").is_none());
    assert_eq!(live["record"]["command"], command);
    for current in [&store, &recovered] {
        let released = block_on(crate::harness::BoundJournal::release(
            current,
            json!({"journal":"true","encoded":command}),
        ))
        .unwrap();
        assert_eq!(released["journal"], crate::redaction::MARKER);
        assert_eq!(released["encoded"], command);
        assert!(!released.to_string().contains("true"));
    }
    let files = store.storage.files();
    assert!(block_on(store.job_evidence(&evidence)).is_err());
    assert_eq!(store.storage.files(), files);
    assert_eq!(store.dispatch.calls.len(), 1);
}

#[test]
fn poc_comparison_collision_failed_append_keeps_projection_and_hold() {
    let mut store = ready();
    let evidence = poc_pending_job(&mut store, b"ordinary package output");
    store.hold_test_credential(b"true");
    let files = store.storage.files();
    let calls = store.dispatch.calls.clone();
    store.storage.fault(Fault::Fail(1));
    assert!(
        block_on(store.job_evidence(&evidence))
            .unwrap_err()
            .contains("fail")
    );
    assert_eq!(store.storage.files(), files);
    assert_eq!(store.dispatch.calls, calls);
    assert!(store.dispatch.jobs.is_empty());
    assert!(store.dispatch.terminals.is_empty());
    assert_eq!(block_on(store.collectable("machine-a")).unwrap().len(), 1);
    let recovered = reopen(&store).unwrap();
    assert_eq!(recovered.dispatch.calls, calls);
    assert!(block_on(recovered.check("machine-a")).is_err());
}

fn poc_served_job(store: &Store<MemoryStorage>, report: &crate::jobs::Report) -> Value {
    let intent = &store.dispatch.calls[&report.evidence.call].intent;
    let command = hex::decode(&intent.command).unwrap();
    let elevation = store.poc_target(&intent.machine).unwrap().elevation;
    let done = crate::harness::Done {
        seq: intent.call,
        sent: crate::jobs::launch_with_elevation(
            intent.job.as_deref().unwrap(),
            &intent.machine,
            &command,
            elevation,
        )
        .into_bytes(),
        recorded: Entry {
            machine: intent.machine.clone(),
            command,
            provenance: intent.provenance.clone(),
        },
        stdout: report.stdout.as_bytes().to_vec(),
        stderr: report.stderr.as_bytes().to_vec(),
        exit_status: report.exit_status.unwrap(),
        terminal: report.number.unwrap(),
        host_key: store.poc_target(&intent.machine).unwrap().pin.clone(),
        evidence: report.clone(),
    };
    crate::harness::response(done.report())
}

fn poc_assert_release_invariant(size: usize, long: bool) {
    let mut store = ready();
    let output = if long {
        String::from_utf8(poc_package_output(327680)).unwrap()
    } else {
        hex::encode(poc_package_output(size))
    };
    let command = if long {
        "#".repeat(8192)
    } else {
        "true".into()
    };
    let mut evidence = poc_pending_command(&mut store, output.as_bytes(), command.as_bytes());
    if long {
        store.hold_test_credential(b"previous-normal-key-482700");
        if let crate::jobs::Record::Present { stderr, .. } = &mut evidence.record {
            *stderr = hex::encode(poc_package_output(24576));
        }
    }
    store.hold_test_credential(b"normal-synthetic-key-482700");
    let files = store.storage.files();
    let calls = store.dispatch.calls.clone();
    match block_on(store.job_evidence(&evidence)) {
        Ok(report) => {
            assert_eq!(store.dispatch.terminals.len(), 1);
            let value = poc_served_job(&store, &report);
            let released = store
                .protect_command_results(&value)
                .expect("a committed terminal must survive the complete served release");
            assert_eq!(released["outcome"]["stdout"], output);
            assert_eq!(
                released["outcome"]["job_record"]["record"]["stdout"],
                hex::encode(&output)
            );
            assert_eq!(reopen(&store).unwrap().dispatch.jobs, store.dispatch.jobs);
            assert!(block_on(store.collectable("machine-a")).unwrap().is_empty());
            block_on(store.check("machine-a")).unwrap();
            let settled = store.storage.files();
            assert!(block_on(store.job_evidence(&evidence)).is_err());
            assert_eq!(store.storage.files(), settled);
        }
        Err(why) => {
            assert!(why.contains("bound"), "{why}");
            assert_eq!(store.storage.files(), files);
            assert_eq!(store.dispatch.calls, calls);
            assert!(store.dispatch.terminals.is_empty());
            assert!(store.dispatch.jobs.is_empty());
            assert_eq!(block_on(store.collectable("machine-a")).unwrap().len(), 1);
            assert!(block_on(store.check("machine-a")).is_err());
            let recovered = reopen(&store).unwrap();
            assert_eq!(recovered.dispatch.calls, store.dispatch.calls);
            assert_eq!(recovered.dispatch.jobs, store.dispatch.jobs);
            assert_eq!(store.dispatch.calls.len(), 1);
        }
    }
}

#[test]
fn poc_served_release_181890_never_withholds_after_terminal_commit() {
    poc_assert_release_invariant(181890, false);
}
#[test]
fn poc_served_release_183300_never_withholds_after_terminal_commit() {
    poc_assert_release_invariant(183300, false);
}
#[test]
fn poc_served_release_long_command_never_withholds_after_terminal_commit() {
    poc_assert_release_invariant(327680, true);
}
#[test]
fn poc_release_bound_never_withholds_after_terminal_commit() {
    poc_assert_release_invariant(185344, false);
}

fn assert_normal_job_settlement(
    size: usize,
    stderr_size: usize,
    key: bool,
    rotated: bool,
    textual_hex: bool,
) {
    eprintln!(
        "ordinary settlement: stdout={size}, stderr={stderr_size}, key={key}, rotated={rotated}, textual_hex={textual_hex}"
    );
    let started = std::time::Instant::now();
    let mut store = ready();
    let output = if textual_hex {
        hex::encode(poc_package_output(size / 2)).into_bytes()
    } else {
        poc_package_output(size)
    };
    let stderr = poc_package_output(stderr_size);
    let mut evidence = poc_pending_job(&mut store, &output);
    if let crate::jobs::Record::Present { stderr: field, .. } = &mut evidence.record {
        *field = hex::encode(&stderr);
    }
    if rotated {
        store.hold_test_credential(b"previous-normal-key-482700");
    }
    if key {
        store.hold_test_credential(b"normal-synthetic-key-482700");
    }
    assert_eq!(block_on(store.collectable("machine-a")).unwrap().len(), 1);
    assert!(block_on(store.check("machine-a")).is_err());
    // A nonterminal observation remains collectable; only the truthful finish clears it.
    let mut observation = evidence.clone();
    if let crate::jobs::Record::Present {
        exit_status, pid, ..
    } = &mut observation.record
    {
        *exit_status = None;
        *pid = 0;
    }
    for _ in 0..2 {
        assert_eq!(
            block_on(store.job_evidence(&observation)).unwrap().state,
            crate::jobs::State::Incomplete
        );
    }
    let uncommitted = block_on(crate::harness::BoundJournal::uncommitted(
        &store,
        &evidence,
        "machine-a",
        &store.dispatch.calls[&evidence.call].intent.command,
    ))
    .unwrap();
    assert_eq!(uncommitted.number, None);
    assert_eq!(uncommitted.stdout.as_bytes(), output);
    assert_eq!(uncommitted.stderr.as_bytes(), stderr);
    let report = block_on(store.job_evidence(&evidence)).unwrap();
    assert_eq!(report.state, crate::jobs::State::Finished);
    assert_eq!(report.exit_status, Some(7));
    assert_eq!(report.stdout.as_bytes(), output);
    assert_eq!(report.stderr.as_bytes(), stderr);
    assert_eq!(report.evidence, evidence);
    let released = block_on(crate::harness::BoundJournal::release(
        &store,
        serde_json::to_value(&report).unwrap(),
    ))
    .unwrap();
    assert_eq!(released["stdout"].as_str().unwrap().as_bytes(), output);
    assert_eq!(released["stderr"].as_str().unwrap().as_bytes(), stderr);
    assert_eq!(released["record"]["stdout"], hex::encode(&output));
    assert_eq!(released["record"]["stderr"], hex::encode(&stderr));
    assert_eq!(released["exit_status"], 7);
    assert_poc_decrypted_journal_private_counts(
        &store,
        &[
            b"normal-synthetic-key-482700",
            b"previous-normal-key-482700",
        ],
        2,
    );

    assert!(matches!(
        store.dispatch.calls[&evidence.call].state,
        crate::dispatch::CallState::Finished { exit_status: 7, .. }
    ));
    assert!(block_on(store.collectable("machine-a")).unwrap().is_empty());
    block_on(store.check("machine-a")).unwrap();
    let files = store.storage.files();
    assert!(block_on(store.job_evidence(&evidence)).is_err());
    assert_eq!(files, store.storage.files());
    let recovered = reopen(&store).unwrap();
    assert_eq!(recovered.dispatch.jobs.last().unwrap(), &report);
    assert_eq!(
        recovered.dispatch.calls.len(),
        1,
        "collection/replay never creates another intent"
    );
    assert_eq!(recovered.dispatch.terminals.len(), 1);
    assert!(
        block_on(recovered.collectable("machine-a"))
            .unwrap()
            .is_empty()
    );
    block_on(recovered.check("machine-a")).unwrap();
    let replay_release = block_on(crate::harness::BoundJournal::release(
        &recovered,
        serde_json::to_value(&report).unwrap(),
    ))
    .unwrap();
    assert_eq!(replay_release, released);
    assert_eq!(recovered.storage.files(), files);
    eprintln!(
        "ordinary settlement/release/replay passed in {:?}",
        started.elapsed()
    );
}

#[test]
fn poc_normal_job_settlement_preserves_full_output_and_replay_without_relaunch_row_1() {
    assert_normal_job_settlement(65536, 0, true, false, false);
}

#[test]
fn poc_normal_job_settlement_preserves_full_output_and_replay_without_relaunch_row_2() {
    assert_normal_job_settlement(262144, 0, true, false, false);
}

#[test]
fn poc_normal_job_settlement_preserves_full_output_and_replay_without_relaunch_row_3() {
    assert_normal_job_settlement(393216, 0, false, false, false);
}

#[test]
fn poc_normal_job_settlement_preserves_full_output_and_replay_without_relaunch_row_4() {
    assert_normal_job_settlement(262144, 16384, true, false, false);
}

#[test]
fn poc_normal_job_settlement_preserves_full_output_and_replay_without_relaunch_row_5() {
    assert_normal_job_settlement(262144, 0, true, true, false);
}

#[test]
fn poc_normal_job_settlement_preserves_full_output_and_replay_without_relaunch_row_6() {
    assert_normal_job_settlement(262144, 0, true, false, true);
}

#[test]
fn poc_normal_job_settlement_preserves_full_output_and_replay_without_relaunch_row_7() {
    assert_normal_job_settlement(262144, 16384, true, true, false);
}

#[test]
fn poc_normal_job_settlement_preserves_full_output_and_replay_without_relaunch_row_8() {
    assert_normal_job_settlement(327680, 24576, true, true, false);
}

#[test]
fn poc_page_single_acceptance_keeps_goal_and_waits_for_model_declaration() {
    let mut local = Local::new(MemoryStorage::default(), Fixed);
    block_on(local.open());
    assert_eq!(block_on(local.create(pass()))["state"], "unlocked");
    local.seed_backup_answer();
    block_on(local.seed_backup_complete(None));
    let store = local.store().unwrap();
    enroll(store);
    let session = block_on(store.poc_bind("machine-a")).unwrap();
    block_on(store.enter_goal(&session, "Inspect a service".into(), None)).unwrap();
    let request = json!({"session":session}).to_string();
    assert!(block_on(local.poc_accept(&request)).get("error").is_none());
    let task = block_on(local.store().unwrap().poc_page_start(&session)).unwrap();
    assert_eq!(task.requests, 0);
    assert!(task.checks.is_empty());
    assert_eq!(task.status, crate::store::poc::Status::Running);
    assert!(
        local
            .store()
            .unwrap()
            .pending_requirements_view(&session)
            .is_null()
    );
    assert!(
        block_on(local.poc_accept(&json!({"session":session,"checks":["false"]}).to_string()))
            .get("error")
            .is_some()
    );
    let same = block_on(local.store().unwrap().poc_start(&session)).unwrap();
    assert_eq!(same.id, task.id);
    assert_eq!(
        local
            .store()
            .unwrap()
            .conduct_acceptances
            .iter()
            .filter(|acceptance| acceptance.session == session)
            .count(),
        1
    );
}

#[test]
fn completion_target_proposal_approval_rejection_and_goal_only_start() {
    use crate::goals::Tool;
    use crate::store::poc::{Change, Status};
    let mut store = ready();
    enroll(&mut store);
    let session = block_on(store.poc_bind("machine-a")).unwrap();
    block_on(store.enter_goal(&session, "Run a local queue service".into(), None)).unwrap();
    let mut task = block_on(store.poc_start(&session)).unwrap();
    let configuration = crate::poc::inference::Configuration::new(
        "https://127.0.0.1/completion".into(),
        "fixture".into(),
    )
    .unwrap();
    let body = crate::poc::inference::request(
        &store,
        &configuration,
        &task.goal,
        &task.machine,
        &task.completed,
        &[],
    )
    .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["tools"].as_array().unwrap().len(), 1);
    assert_eq!(body["tools"][0]["function"]["name"], "propose_declaration");
    for attempt in 0..2 {
        task = block_on(store.poc_change(&task.id, task.revision, Change::Request)).unwrap();
        task = block_on(store.poc_propose(
            &task,
            &session,
            format!("declaration-{attempt}"),
            Tool::ProposeDeclaration {
                machine: "machine-a".into(),
                declaration: json!(crate::declaration::ad_hoc_minimum()),
            },
            None,
        ))
        .unwrap();
        let why = store.poc_prepare_execution(&task, &session).unwrap_err();
        task = block_on(store.poc_change(&task.id, task.revision, Change::Pause(why))).unwrap();
        let pending = store.pending_requirements_view(&session);
        assert_eq!(pending["proposal"]["kind"], "declaration");
        assert!(store.dispatch.calls.is_empty());
        let candidate = pending["candidate"].as_u64().unwrap();
        if attempt == 0 {
            block_on(store.poc_reject_requirements(&session, "machine-a", candidate)).unwrap();
            task = store.poc_task(&task.id).unwrap();
            assert_eq!(task.status, Status::Paused);
            assert!(task.proposal.is_none());
            assert!(task.completed[0].2["content"].get("rejected").is_some());
            let replay = block_on(unlock(
                MemoryStorage::with_files(store.storage.files()),
                &Fixed,
                pass(),
            ))
            .unwrap();
            assert_eq!(replay.poc_task(&task.id).unwrap(), task);
            let context = crate::poc::inference::request(
                &store,
                &configuration,
                &task.goal,
                &task.machine,
                &task.completed,
                &[],
            )
            .unwrap();
            assert!(String::from_utf8_lossy(&context).contains("rejected"));
            assert!(
                store.dispatch.approved_entries["machine-a"]
                    .declaration
                    .is_none()
            );
        } else {
            block_on(store.approve_requirements(&session, "machine-a", candidate)).unwrap();
            task = store.poc_task(&task.id).unwrap();
            assert_eq!(task.status, Status::Running);
            assert!(task.proposal.is_none());
            assert_eq!(task.completed[1].2["content"]["approved"], true);
        }
    }
    let body = crate::poc::inference::request(
        &store,
        &configuration,
        &task.goal,
        &task.machine,
        &task.completed,
        &[],
    )
    .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["tools"].as_array().unwrap().len(), 5);
    assert_eq!(
        body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["function"]["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "exec",
            "done",
            "request_ai_key",
            "offer_file",
            "ask_operator"
        ]
    );
    assert!(
        body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["function"]["name"] != "propose_declaration")
    );
}
