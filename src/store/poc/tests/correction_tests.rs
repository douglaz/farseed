use super::*;
use crate::poc::completion::{Observation as ReadObservation, Read};
use crate::poc::inference::{self, ReplyError};

fn malformed() -> ReplyError {
    ReplyError::Malformed {
        reason: "arguments: malformed JSON".into(),
        cut_off: false,
    }
}
fn body(store: &Store<MemoryStorage>, task: &Task) -> String {
    let config = inference::Configuration::new(
        "https://example.invalid/completion".into(),
        "example".into(),
    )
    .unwrap();
    String::from_utf8(
        inference::request_for_task(store, &config, task, &[])
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

#[test]
fn correction_three_consecutive_replies_pause_durably_and_resume_resets() {
    let (mut runtime, original, session) = Fixture::new();
    let mut model = Script {
        calls: VecDeque::from([Err(malformed()), Err(malformed()), Err(malformed())]),
        ..Default::default()
    };
    let paused = block_on(run::drive(&mut runtime, &mut model, &original.id, &session)).unwrap();
    assert_eq!(paused.requests, 3);
    assert_eq!(paused.steps, 0);
    assert!(paused.completed.is_empty() && paused.proposal.is_none());
    assert!(runtime.remote.borrow().sends.is_empty());
    assert_eq!(paused.status, Status::Paused);
    assert_eq!(
        paused.pause_reason.as_deref(),
        Some(
            "3 malformed replies in a row; last reason: arguments: malformed JSON. Resume asks the model again."
        )
    );
    assert_eq!(paused.malformed.as_ref().unwrap().count, 3);
    assert_eq!(
        reopen(&runtime.store.borrow())
            .poc_task(&paused.id)
            .unwrap(),
        paused
    );
    let text = body(&runtime.store.borrow(), &paused);
    assert!(text.contains("Your last reply could not be used: arguments: malformed JSON. Reply with exactly one call to an offered tool."));
    runtime.reload();
    assert_eq!(runtime.task(&paused.id).malformed, paused.malformed);
    model.calls.push_back(Err(malformed()));
    let first = block_on(run::resume(&mut runtime, &mut model, &paused.id, &session)).unwrap();
    assert_eq!(first.status, Status::Running);
    assert_eq!(first.requests, 4);
    assert_eq!(first.malformed.as_ref().unwrap().count, 1);
    model.calls.push_back(Ok(("done".into(), done())));
    let usable = block_on(run::resume(&mut runtime, &mut model, &paused.id, &session)).unwrap();
    assert!(usable.malformed.is_none());
}

#[test]
fn correction_first_two_continue_limits_apply_and_refused_proposal_resets() {
    let (mut runtime, original, session) = Fixture::new();
    let mut model = Script {
        calls: VecDeque::from([
            Err(malformed()),
            Err(malformed()),
            Ok(("usable".into(), done())),
        ]),
        ..Default::default()
    };
    let result = block_on(run::drive(&mut runtime, &mut model, &original.id, &session)).unwrap();
    assert_eq!(result.requests, 3);
    assert_eq!(result.status, Status::Complete);
    assert!(result.malformed.is_none());
    assert_eq!(model.seen.len(), 3);
    let mut store = ready_without_requirements();
    let original = create_task(&mut store);
    let task = change(&mut store, &original, Change::Request);
    let task = change(
        &mut store,
        &task,
        Change::Malformed {
            reason: "arguments.command: expected string".into(),
            cut_off: true,
        },
    );
    assert_eq!(task.malformed.as_ref().unwrap().count, 1);
    assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
    let text = body(&store, &task);
    assert!(text.contains("If your reply was cut off, make it shorter."));
    let task = completion_tests::finish_request(
        &mut store,
        &task,
        Tool::ProposeDeclaration {
            machine: "fixture".into(),
            declaration: json!({}),
        },
    );
    assert!(task.malformed.is_none());
    assert!(
        task.completed.last().unwrap().2["content"]["refused"]
            .as_str()
            .unwrap()
            .contains("declaration.version")
    );
    let (mut runtime, original, session) = Fixture::with_limits(Limits {
        requests: 1,
        steps: 2,
    });
    let mut model = Script {
        calls: VecDeque::from([Err(malformed())]),
        ..Default::default()
    };
    let paused = block_on(run::drive(&mut runtime, &mut model, &original.id, &session)).unwrap();
    assert_eq!(paused.requests, 1);
    assert_eq!(paused.malformed.as_ref().unwrap().count, 1);
    assert_eq!(
        paused.pause_reason.as_deref(),
        Some("request limit reached; raise limits and Resume")
    );
}

#[test]
fn correction_fact_append_is_atomic_bounded_and_protected() {
    let mut store = ready();
    let task = create_task(&mut store);
    let task = change(&mut store, &task, Change::Request);
    for reason in ["".into(), "界".repeat(172)] {
        let files = store.storage.files();
        assert!(
            block_on(store.poc_change(
                &task.id,
                task.revision,
                Change::Malformed {
                    reason,
                    cut_off: false
                }
            ))
            .is_err()
        );
        assert_eq!(store.storage.files(), files);
        assert_eq!(store.poc_task(&task.id).unwrap(), task);
    }
    store.remember_poc_credential(b"protected-correction-token");
    assert!(
        block_on(store.poc_change(
            &task.id,
            task.revision,
            Change::Malformed {
                reason: "protected-correction-token".into(),
                cut_off: false
            }
        ))
        .is_err()
    );
    store.storage.fault(Fault::Fail(1));
    assert!(
        block_on(store.poc_change(
            &task.id,
            task.revision,
            Change::Malformed {
                reason: "arguments: expected object".into(),
                cut_off: false
            }
        ))
        .is_err()
    );
    assert_eq!(store.poc_task(&task.id).unwrap(), task);
}

fn before(store: &mut Store<MemoryStorage>) -> Task {
    let task = create_task(store);
    block_on(store.poc_prepare_next(&task, &task.start_session)).unwrap()
}
#[test]
fn before_setup_read_uses_exact_pinned_command_once_with_durable_identity() {
    let mut store = ready_without_requirements();
    let task = before(&mut store);
    assert!(task.preparing_read());
    assert_eq!(task.steps, 1);
    assert_eq!(task.requests, 0);
    assert_eq!(
        task.proposal.as_ref().unwrap().tool,
        exec("ss -H -n -l -t -u")
    );
    assert_eq!(Read::Listeners.command(), "ss -H -n -l -t -u");
    assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
    assert!(store.dispatch.calls.is_empty());
    append(&mut store, &task, &task.start_session);
    let pending = store.poc_task(&task.id).unwrap();
    assert!(pending.pending.is_some());
    assert_eq!(pending.requests, 0);
    assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), pending);
    assert!(
        block_on(store.poc_prepare_next(&pending, &pending.start_session))
            .unwrap()
            .pending
            .is_some()
    );
    assert!(block_on(store.poc_change(&pending.id, pending.revision, Change::Request)).is_err());
    let output = "tcp LISTEN 0 128 0.0.0.0:22 *:*\ntcp LISTEN 0 128 127.0.0.53%lo:53 *:*\nudp UNCONN 0 0 0.0.0.0:5353 *:*\n";
    evidence(&mut store, &pending, record(&pending, Some(0), output));
    let task = change(&mut store, &pending, Change::Settle);
    assert!(matches!(
        task.before_setup.as_ref().unwrap().observation,
        Some(ReadObservation::Sockets(_))
    ));
    assert!(task.before_setup.as_ref().unwrap().settled);
    assert!(task.completed[0].0.starts_with('$'));
    assert!(inference::model_steps(&task).is_empty());
    let text = body(&store, &task);
    assert!(text.contains("listening before setup, observed by the harness"));
    assert!(
        text.contains("127.0.0.53")
            && !text.contains("%lo")
            && !text.contains("5353")
            && !text.contains("LISTEN")
    );
    assert!(!text.contains("$before:"));
    assert_eq!(
        block_on(store.poc_prepare_next(&task, &task.start_session)).unwrap(),
        task
    );
    assert_eq!(store.dispatch.calls.len(), 1);
    let next = completion_tests::finish_request(
        &mut store,
        &task,
        Tool::ProposeDeclaration {
            machine: "fixture".into(),
            declaration: serde_json::to_value(crate::declaration::ad_hoc_minimum()).unwrap(),
        },
    );
    let rejected = change(&mut store, &next, Change::RejectDeclaration);
    assert_eq!(
        block_on(store.poc_prepare_next(&rejected, &rejected.start_session)).unwrap(),
        rejected
    );
    assert_eq!(reopen(&store).poc_task(&rejected.id).unwrap(), rejected);
    assert_eq!(store.dispatch.calls.len(), 1);
}

#[test]
fn before_setup_read_failures_and_unknown_disposition_never_repeat() {
    for (exit, output) in [(1, ""), (0, "not a socket row")] {
        let mut store = ready_without_requirements();
        let task = before(&mut store);
        append(&mut store, &task, &task.start_session);
        let task = store.poc_task(&task.id).unwrap();
        evidence(&mut store, &task, record(&task, Some(exit), output));
        let task = change(&mut store, &task, Change::Settle);
        assert!(body(&store, &task).contains("listening before setup: not read"));
        assert_eq!(
            block_on(store.poc_prepare_next(&task, &task.start_session)).unwrap(),
            task
        );
        assert_eq!(store.dispatch.calls.len(), 1);
    }
    let mut store = ready_without_requirements();
    let task = before(&mut store);
    let task = change(
        &mut store,
        &task,
        Change::SkipRead("command refused".into()),
    );
    assert!(body(&store, &task).contains("listening before setup: not read"));
    assert_eq!(
        block_on(store.poc_prepare_next(&task, &task.start_session)).unwrap(),
        task
    );
    assert!(store.dispatch.calls.is_empty());
    let mut store = ready_without_requirements();
    let task = before(&mut store);
    append(&mut store, &task, &task.start_session);
    let task = store.poc_task(&task.id).unwrap();
    evidence(&mut store, &task, crate::jobs::Record::Missing);
    let task = change(
        &mut store,
        &task,
        Change::Pause("pending listeners read".into()),
    );
    let mut restored = reopen(&store);
    fresh(&mut restored);
    assert_eq!(restored.poc_task(&task.id).unwrap(), task);
    let offer = store
        .poc_disposition_offer(&task.id, &task.start_session)
        .unwrap();
    let settled =
        block_on(store.poc_dispose(&offer, crate::dispatch::Continuation::AsIfNotDone)).unwrap();
    assert!(settled.pending.is_none());
    assert!(settled.before_setup.as_ref().unwrap().settled);
    assert!(body(&store, &settled).contains("listening before setup: not read"));
    let request = change(&mut store, &settled, Change::Request);
    assert!(
        store
            .check_inference_request(&request, &request.start_session)
            .is_ok()
    );
    assert_eq!(store.dispatch.calls.len(), 1);
}

#[test]
fn before_setup_runner_reads_before_proposal_and_never_runs_unapproved_commands() {
    let (mut runtime, _, _) = Fixture::new();
    let mut store = ready_without_requirements();
    let task = create_task(&mut store);
    let session = task.start_session.clone();
    *runtime.store.borrow_mut() = store;
    let mut model = Script::one("unapproved-command", exec("install-example-service"));
    let task = block_on(run::drive(&mut runtime, &mut model, &task.id, &session)).unwrap();
    assert_eq!(runtime.remote.borrow().sends.len(), 1);
    assert_eq!(task.steps, 2);
    assert!(task.before_setup.as_ref().unwrap().settled);
    assert_eq!(task.completed[0].1, exec("ss -H -n -l -t -u"));
    assert!(
        task.completed[1].2["content"]["refused"]
            .as_str()
            .unwrap()
            .contains("before commands")
    );
    assert_eq!(model.seen.len(), 2);
    assert!(task.proposal.is_none());
    assert_eq!(
        reopen(&runtime.store.borrow()).poc_task(&task.id).unwrap(),
        task
    );
}

#[test]
fn before_setup_stock_socket_remains_a_delivery_finding_and_protection_is_preserved() {
    let mut store = ready_without_requirements();
    let task = before(&mut store);
    let task = change(&mut store, &task, Change::SkipRead("unavailable".into()));
    store.remember_poc_credential(b"protected-proposal-field");
    let requested = change(&mut store, &task, Change::Request);
    let mut declaration = crate::poc::proposal::example();
    declaration["services"][0]["protected-proposal-field"] = json!("neutral");
    let files = store.storage.files();
    assert!(
        block_on(store.poc_propose(
            &requested,
            &requested.start_session,
            "unsafe".into(),
            Tool::ProposeDeclaration {
                machine: "fixture".into(),
                declaration
            }
        ))
        .is_err()
    );
    assert_eq!(store.storage.files(), files);
    assert!(store.dispatch.calls.is_empty());
    let d = crate::declaration::ad_hoc_minimum();
    let plan = crate::poc::completion::reads(&d).unwrap();
    let observed = Read::Listeners.observe(
        0,
        "tcp LISTEN 0 128 127.0.0.53:53 *:*\ntcp LISTEN 0 128 0.0.0.0:5355 *:*\n",
    );
    let result = crate::poc::completion::judge(&d, &plan, &[Some(observed)], &[]);
    assert!(!result.delivered);
    assert!(result.findings.iter().any(
        |f| f.detail == "Something answers on tcp port 5355 that the declaration does not list"
    ));
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.detail
                == "Something answers on tcp port 53 that the declaration does not list")
    );
}

#[test]
fn correction_request_facts_belong_to_the_exact_task() {
    let mut store = ready_without_requirements();
    let task = before(&mut store);
    let task = change(&mut store, &task, Change::SkipRead("unavailable".into()));
    let task = change(&mut store, &task, Change::Request);
    let task = change(
        &mut store,
        &task,
        Change::Malformed {
            reason: "current-task-reason".into(),
            cut_off: false,
        },
    );
    let mut other = task.clone();
    other.id = "000-other-task".into();
    other.malformed.as_mut().unwrap().reason = "other-task-reason".into();
    other.before_setup.as_mut().unwrap().observation = Some(ReadObservation::Sockets(vec![
        crate::poc::completion::Socket {
            proto: crate::declaration::Protocol::Tcp,
            port: 9876,
            address: "127.0.0.1".into(),
        },
    ]));
    store.poc.insert(other.id.clone(), other);
    let request = body(&store, &task);
    assert!(request.contains("current-task-reason"));
    assert!(request.contains("listening before setup: not read"));
    assert!(!request.contains("other-task-reason") && !request.contains("9876"));
    let value: Value = serde_json::from_str(&request).unwrap();
    let facts = value["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["content"].as_str())
        .filter_map(|s| serde_json::from_str::<Value>(s).ok())
        .find(|v| v.get("requests_consumed").is_some())
        .unwrap();
    assert_eq!(facts["task"], task.id);
    assert_eq!(facts["requests_consumed"], task.requests);
}

#[test]
fn before_setup_crash_windows_retain_the_read_without_requesting_a_proposal() {
    for window in [Window::BeforeSend, Window::AfterSend, Window::AfterEvidence] {
        let (mut runtime, _, _) = Fixture::new();
        let mut store = ready_without_requirements();
        let task = create_task(&mut store);
        let session = task.start_session.clone();
        *runtime.store.borrow_mut() = store;
        runtime.window = window;
        let mut model = Script::default();
        {
            let mut work =
                std::pin::pin!(run::resume(&mut runtime, &mut model, &task.id, &session));
            assert!(matches!(
                work.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ));
        }
        let pending = runtime.task(&task.id);
        assert_eq!(pending.requests, 0);
        assert!(pending.preparing_read());
        let session = runtime.reload();
        assert_eq!(runtime.task(&task.id), pending);
        let resumed = block_on(run::resume(&mut runtime, &mut model, &task.id, &session)).unwrap();
        assert_eq!(model.seen.len(), 0);
        assert_eq!(resumed.requests, 0);
        if matches!(window, Window::BeforeSend) {
            assert_eq!(resumed.pending, pending.pending);
            assert_eq!(resumed.status, Status::Paused);
            assert!(runtime.remote.borrow().sends.is_empty());
            assert!(
                block_on(
                    runtime
                        .store
                        .borrow_mut()
                        .poc_prepare_next(&resumed, &session)
                )
                .unwrap()
                .pending
                .is_some()
            );
            assert!(
                runtime
                    .store
                    .borrow()
                    .check_inference_request(&resumed, &session)
                    .is_err()
            );
        } else {
            assert!(resumed.pending.is_none());
            assert!(resumed.before_setup.as_ref().unwrap().settled);
            assert!(runtime.remote.borrow().sends.values().all(|n| *n == 1));
            assert!(inference::model_steps(&resumed).is_empty());
        }
        assert_eq!(runtime.store.borrow().dispatch.calls.len(), 1);
    }
}

#[test]
fn correction_exhausted_pause_is_bounded_and_keeps_the_complete_last_fact() {
    let mut store = ready();
    let mut task = create_task(&mut store);
    let reason = "界".repeat(170);
    for _ in 0..3 {
        task = change(&mut store, &task, Change::Request);
        task = change(
            &mut store,
            &task,
            Change::Malformed {
                reason: reason.clone(),
                cut_off: false,
            },
        );
    }
    let why = task.pause_reason.as_ref().unwrap();
    assert!(why.len() <= 512 && why.contains('…'));
    assert!(
        why.starts_with("3 malformed replies in a row;")
            && why.ends_with("Resume asks the model again.")
    );
    assert_eq!(task.malformed.as_ref().unwrap().reason, reason);
    assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
}

#[test]
fn before_setup_exception_keeps_other_holds_and_installation_prerequisites() {
    let mut store = ready_without_requirements();
    let task = before(&mut store);
    let b = binding(&task, &task.start_session);
    assert!(block_on(store.poc_check_command(&b, &task.machine)).is_ok());
    assert!(
        block_on(store.check(&task.machine)).is_err(),
        "ordinary jobs still need the installation declaration"
    );
    append(&mut store, &task, &task.start_session);
    let task = store.poc_task(&task.id).unwrap();
    evidence(&mut store, &task, crate::jobs::Record::Missing);
    let task = change(
        &mut store,
        &task,
        Change::Pause("listeners outcome unavailable".into()),
    );
    let offer = store
        .poc_disposition_offer(&task.id, &task.start_session)
        .unwrap();
    assert!(
        block_on(store.poc_dispose(&offer, crate::dispatch::Continuation::DestructiveReinstall))
            .is_err()
    );
    assert_eq!(store.poc_task(&task.id).unwrap().pending, task.pending);
    let task =
        block_on(store.poc_dispose(&offer, crate::dispatch::Continuation::AsIfNotDone)).unwrap();
    assert!(body(&store, &task).contains("listening before setup: not read"));
    assert!(
        block_on(store.check(&task.machine)).is_err(),
        "settlement does not grant installation approval"
    );
    assert!(
        block_on(store.poc_prepare_next(&task, &task.start_session))
            .unwrap()
            .proposal
            .is_none()
    );
    assert_eq!(store.dispatch.calls.len(), 1);
}
