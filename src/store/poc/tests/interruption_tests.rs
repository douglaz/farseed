use super::*;
use crate::dispatch::LaunchAttempt;
use crate::poc::inference::{ReplyError, TRANSPORT_INTERRUPTED};

fn prepared() -> (Store<MemoryStorage>, Task, LaunchAttempt) {
    let mut store = ready();
    let task = create_task(&mut store);
    let task = proposal(&mut store, &task);
    let call = append(&mut store, &task, &task.start_session);
    let task = store.poc_task(&task.id).unwrap();
    let pending = task.pending.as_ref().unwrap();
    assert_eq!(pending.call, call);
    let attempt = LaunchAttempt {
        call,
        job: pending.job.clone(),
    };
    let fence = &store.dispatch.launches[&call];
    let command = hex::decode(&store.dispatch.calls[&call].intent.command).unwrap();
    let elevation = store.poc_target(&task.machine).unwrap().elevation;
    let wrapper =
        crate::jobs::launch_with_elevation(&attempt.job, &task.machine, &command, elevation);
    assert_eq!(fence.prepared.call, call);
    assert_eq!(fence.prepared.job, attempt.job);
    assert_eq!(fence.prepared.elevation, elevation);
    assert_eq!(
        fence.prepared.wrapper_sha256,
        hex::encode(Sha256::digest(wrapper.as_bytes()))
    );
    assert!(!fence.attempted && !fence.resent);
    (store, task, attempt)
}

fn reserve(store: &mut Store<MemoryStorage>, attempt: &LaunchAttempt, resend: bool) {
    let mut dispatch = store.dispatch.clone();
    dispatch.launch_attempt(attempt, resend).unwrap();
    let event = if resend {
        Event::Resend(attempt.clone())
    } else {
        Event::LaunchTransmission(attempt.clone())
    };
    block_on(store.commit(&event)).unwrap();
    store.dispatch = dispatch;
}

fn refused(store: &mut Store<MemoryStorage>, attempt: &LaunchAttempt, reason: &str) {
    let files = store.storage.files();
    let next = store.next;
    let calls = store.dispatch.calls.clone();
    assert_eq!(
        store.dispatch.launch_attempt(attempt, true),
        Err(reason.into())
    );
    assert_eq!(store.storage.files(), files);
    assert_eq!(store.next, next);
    assert_eq!(store.dispatch.calls, calls);
}

fn refused_on_replay(store: &Store<MemoryStorage>, event: Event, reason: &str) {
    let mut invalid = reopen(store);
    block_on(invalid.commit(&event)).unwrap();
    let why = block_on(unlock(
        MemoryStorage::with_files(invalid.storage.files()),
        &Fixed,
        pass(),
    ))
    .err()
    .expect("invalid reservation must refuse replay");
    assert!(why.contains("replay stopped"), "{why}");
    assert!(why.contains(reason), "{why}");
}

#[test]
fn poc_transmission_reservation_survives_missing_and_reopen_without_resend() {
    let (mut store, task, attempt) = prepared();
    let preparation = store.dispatch.launches[&attempt.call].prepared.clone();
    let original = store.dispatch.calls.clone();
    reserve(&mut store, &attempt, false);
    evidence(&mut store, &task, crate::jobs::Record::Missing);
    assert!(
        store
            .poc_committed(task.pending.as_ref().unwrap())
            .unwrap()
            .number
            .is_some()
    );
    refused(&mut store, &attempt, "launch transmission already reserved");
    refused_on_replay(
        &store,
        Event::Resend(attempt.clone()),
        "launch transmission already reserved",
    );
    let mut replay = reopen(&store);
    let fence = &replay.dispatch.launches[&attempt.call];
    assert_eq!(fence.prepared, preparation);
    assert!(fence.attempted && !fence.resent);
    assert_eq!(replay.dispatch.calls, original);
    assert_eq!(replay.poc_task(&task.id).unwrap().pending, task.pending);
    refused(
        &mut replay,
        &attempt,
        "launch transmission already reserved",
    );
    assert_eq!(replay.dispatch.calls.len(), 1);
}

#[test]
fn poc_prepared_missing_reserves_one_resend_after_reopen() {
    let (mut store, task, attempt) = prepared();
    let preparation = store.dispatch.launches[&attempt.call].prepared.clone();
    evidence(&mut store, &task, crate::jobs::Record::Missing);
    let mut store = reopen(&store);
    let before = store.next;
    reserve(&mut store, &attempt, true);
    assert_eq!(store.next, before + 1);
    refused(&mut store, &attempt, "launch transmission already reserved");
    refused_on_replay(
        &store,
        Event::Resend(attempt.clone()),
        "launch transmission already reserved",
    );
    let mut replay = reopen(&store);
    let fence = &replay.dispatch.launches[&attempt.call];
    assert_eq!(fence.prepared, preparation);
    assert!(fence.attempted && fence.resent);
    assert_eq!(replay.poc_task(&task.id).unwrap(), task);
    assert_eq!(replay.dispatch.calls, store.dispatch.calls);
    assert_eq!(replay.dispatch.calls.len(), 1);
    refused(
        &mut replay,
        &attempt,
        "launch transmission already reserved",
    );
}

#[test]
fn poc_resend_requires_committed_missing_and_no_other_evidence() {
    let (mut store, task, attempt) = prepared();
    refused(
        &mut store,
        &attempt,
        "resend requires committed missing evidence only",
    );
    refused_on_replay(
        &store,
        Event::Resend(attempt.clone()),
        "resend requires committed missing evidence only",
    );
    evidence(&mut store, &task, crate::jobs::Record::Missing);
    let mut projection = store.dispatch.clone();
    projection.jobs.last_mut().unwrap().number = None;
    assert_eq!(
        projection.launch_attempt(&attempt, true),
        Err("resend requires committed missing evidence only".into())
    );
    assert!(!projection.launches[&attempt.call].attempted);
    for case in 0..7 {
        let (mut store, task, attempt) = prepared();
        let mut observed = record(&task, if case == 0 { Some(0) } else { None }, "seen");
        if let crate::jobs::Record::Present { machine, alive, .. } = &mut observed {
            if case == 2 || case == 6 {
                *alive = false;
            }
            if case == 3 {
                *machine = hex::encode("another-machine");
            }
        }
        if case == 4 {
            observed = crate::jobs::Record::Incomplete {
                machine: None,
                command: None,
            };
        }
        if case == 5 {
            observed = crate::jobs::Record::Background {
                machine: hex::encode(&task.machine),
                command: store.dispatch.calls[&attempt.call].intent.command.clone(),
                boot: "boot-one".into(),
                current_boot: "boot-one".into(),
                pid: 123,
                alive: true,
                stdout: String::new(),
                stderr: String::new(),
            };
        }
        let state = observed.classify(&task.machine);
        assert_ne!(state, crate::jobs::State::Missing);
        if state == crate::jobs::State::Running {
            let why = block_on(store.job_evidence(&crate::jobs::Evidence {
                call: attempt.call,
                job: attempt.job.clone(),
                record: observed,
            }))
            .unwrap_err();
            assert_eq!(
                why,
                "job evidence kind differs from what the record establishes"
            );
            assert!(store.dispatch.jobs.is_empty());
        } else {
            evidence(&mut store, &task, observed);
        }
        if case == 6 {
            evidence(&mut store, &task, crate::jobs::Record::Missing);
        }
        let reason = if matches!(
            state,
            crate::jobs::State::Finished | crate::jobs::State::Background
        ) {
            "launch call is terminal or job differs"
        } else {
            "resend requires committed missing evidence only"
        };
        refused(&mut store, &attempt, reason);
        refused_on_replay(&store, Event::Resend(attempt.clone()), reason);
        let replay = reopen(&store);
        assert!(!replay.dispatch.launches[&attempt.call].attempted);
        assert_eq!(replay.dispatch.calls.len(), 1);
    }
}

#[test]
fn poc_historical_command_without_preparation_is_never_eligible_for_resend() {
    let mut store = ready();
    let task = create_task(&mut store);
    let task = proposal(&mut store, &task);
    let mut historical = reopen(&store);
    let call = append(&mut store, &task, &task.start_session);
    let intent = store.dispatch.calls[&call].intent.clone();
    let attempt = LaunchAttempt {
        call,
        job: intent.job.clone().unwrap(),
    };
    let record = Record::Command {
        binding: binding(&task, &task.start_session),
        intent,
        launch: None,
    };
    let number = block_on(historical.commit(&Event::Poc(record.clone()))).unwrap();
    historical.apply_poc(number, &record).unwrap();
    let task = historical.poc_task(&task.id).unwrap();
    evidence(&mut historical, &task, crate::jobs::Record::Missing);
    assert!(historical.dispatch.launches.is_empty());
    refused(&mut historical, &attempt, "launch is not prepared");
    refused_on_replay(
        &historical,
        Event::Resend(attempt.clone()),
        "launch is not prepared",
    );
    let mut replay = reopen(&historical);
    assert!(replay.dispatch.launches.is_empty());
    assert_eq!(replay.dispatch.calls.len(), 1);
    assert_eq!(replay.poc_task(&task.id).unwrap(), task);
    refused(&mut replay, &attempt, "launch is not prepared");
}

fn interrupted() -> Script {
    Script {
        calls: VecDeque::from([Err(ReplyError::Pause(TRANSPORT_INTERRUPTED.into()))]),
        ..Default::default()
    }
}

fn recovery_records(store: &Store<MemoryStorage>) -> usize {
    let mut reader = Store::new(
        store.storage.clone(),
        DataKey(store.key.0),
        store.id.clone(),
    );
    let files = store.storage.files();
    store
        .records()
        .filter(|number| {
            let bytes = &files[&number.to_string()];
            let event = reader.open(*number, bytes).unwrap();
            reader.previous = Address(Sha256::digest(bytes).into());
            matches!(
                event,
                Event::Poc(Record::Change {
                    change: Change::RecoverRequest,
                    ..
                })
            )
        })
        .count()
}

#[test]
fn poc_interrupted_requests_remain_counted_and_recover_five_times_across_reopen() {
    let (mut runtime, original, session) = Fixture::new();
    for count in 1..=6 {
        let mut script = interrupted();
        let task = block_on(run::resume(
            &mut runtime,
            &mut script,
            &original.id,
            &session,
        ))
        .unwrap();
        assert_eq!(script.seen.len(), 1);
        assert_eq!(task.requests, count);
        assert_eq!(task.request_recoveries, count.min(5));
        assert!(!task.requesting && task.pending.is_none() && task.proposal.is_none());
        assert!(task.completed.is_empty());
        assert_eq!(task.steps, 0);
        assert!(runtime.remote.borrow().sends.is_empty());
        assert!(runtime.store.borrow().dispatch.calls.is_empty());
        assert_eq!(recovery_records(&runtime.store.borrow()), count as usize);
        if count <= 5 {
            assert_eq!(task.status, Status::Running);
            assert!(task.pause_reason.is_none());
        } else {
            assert_eq!(task.status, Status::Paused);
            assert_eq!(
                task.pause_reason.as_deref(),
                Some(
                    "The AI connection was interrupted repeatedly. Check the connection, then Resume to try again."
                )
            );
        }
        assert_eq!(
            reopen(&runtime.store.borrow())
                .poc_task(&original.id)
                .unwrap(),
            task
        );
        assert_eq!(runtime.reload(), session);
        assert_eq!(runtime.task(&original.id), task);
    }
    let mut held = Script {
        hold: true,
        ..Default::default()
    };
    {
        let mut resume =
            std::pin::pin!(run::resume(&mut runtime, &mut held, &original.id, &session));
        assert!(
            resume
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    let requested = runtime.task(&original.id);
    assert_eq!(requested.request_recoveries, 0);
    assert_eq!(requested.requests, 7);
    assert!(requested.requesting);
    assert_eq!(requested.status, Status::Running);
    assert!(requested.pending.is_none() && requested.proposal.is_none());
    assert!(runtime.remote.borrow().sends.is_empty());
    assert_eq!(
        reopen(&runtime.store.borrow())
            .poc_task(&original.id)
            .unwrap(),
        requested
    );
}

#[test]
fn poc_committed_and_malformed_replies_reset_request_recoveries() {
    for malformed in [false, true] {
        let (mut runtime, original, session) = Fixture::new();
        for count in 1..=2 {
            let task = block_on(run::resume(
                &mut runtime,
                &mut interrupted(),
                &original.id,
                &session,
            ))
            .unwrap();
            assert_eq!(task.request_recoveries, count);
        }
        let reply = if malformed {
            Err(ReplyError::Malformed {
                reason: "arguments: malformed JSON".into(),
                cut_off: false,
            })
        } else {
            Ok((
                "report".into(),
                Tool::OfferFile {
                    machine: "fixture".into(),
                    path: "/tmp/report.txt".into(),
                    label: "report".into(),
                    why: "requested report".into(),
                },
            ))
        };
        let mut script = Script {
            calls: VecDeque::from([reply]),
            ..Default::default()
        };
        let task = block_on(run::resume(
            &mut runtime,
            &mut script,
            &original.id,
            &session,
        ))
        .unwrap();
        assert_eq!(task.requests, 3);
        assert_eq!(task.request_recoveries, 0);
        assert!(!task.requesting && task.pending.is_none() && task.proposal.is_none());
        if malformed {
            assert_eq!(task.malformed.as_ref().unwrap().count, 1);
            assert!(task.completed.is_empty());
        } else {
            assert!(task.malformed.is_none());
            assert_eq!(task.completed.len(), 1);
            assert_eq!(task.completed[0].0, "report");
        }
        assert!(runtime.remote.borrow().sends.is_empty());
        assert!(runtime.store.borrow().dispatch.calls.is_empty());
        assert_eq!(
            reopen(&runtime.store.borrow())
                .poc_task(&original.id)
                .unwrap(),
            task
        );
    }
}
