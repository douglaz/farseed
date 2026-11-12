use super::*;
use crate::dispatch::{CallState, Continuation};
use crate::store::poc::disposition::{CRASH, Confirmation};

fn pending() -> (Store<MemoryStorage>, Task, Confirmation) {
    let mut store = ready();
    let task = create_task(&mut store);
    let task = proposal(&mut store, &task);
    append(&mut store, &task, &task.start_session);
    let task = store.poc_task(&task.id).unwrap();
    evidence(&mut store, &task, crate::jobs::Record::Missing);
    let task = change(
        &mut store,
        &task,
        Change::Pause("record is missing; outcome unresolved".into()),
    );
    let offer = store
        .poc_disposition_offer(&task.id, &task.start_session)
        .unwrap();
    (store, task, offer)
}
fn accept(
    store: &mut Store<MemoryStorage>,
    offer: &Confirmation,
    continuation: Continuation,
) -> Task {
    block_on(store.poc_dispose(offer, continuation)).unwrap()
}
fn assert_result(task: &Task, offer: &Confirmation, number: u64, continuation: Continuation) {
    assert!(task.pending.is_none());
    assert!(task.proposal.is_none());
    assert_eq!(task.revision, offer.revision + 1);
    assert_eq!(task.completed.len(), 1);
    let result = &task.completed[0].2;
    assert_eq!(result["source"], "tool_output");
    assert_eq!(result["type"], "untrusted");
    let out = &result["content"];
    assert_eq!(out["call"], offer.pending.call);
    assert_eq!(out["job"], offer.pending.job);
    assert_eq!(out["machine"], offer.machine);
    assert_eq!(out["outcome"], "unknown");
    assert_eq!(out["disposition"], number);
    assert_eq!(
        out["continuation"],
        serde_json::to_value(continuation).unwrap()
    );
    assert_eq!(out["collection_read"]["record"], offer.observation);
    assert_eq!(out["collection_read"]["state"], "missing");
    assert!(!result.to_string().contains("exit_status"));
}

#[test]
fn poc_disposition_both_assumptions_live_equal_replay_and_late_evidence() {
    for continuation in [Continuation::AsIfDone, Continuation::AsIfNotDone] {
        let (mut store, before, offer) = pending();
        let number = store.next;
        let task = accept(&mut store, &offer, continuation);
        assert_result(&task, &offer, number, continuation);
        assert_eq!(
            serde_json::to_vec(&task).unwrap(),
            serde_json::to_vec(&reopen(&store).poc_task(&task.id).unwrap()).unwrap()
        );
        assert_eq!(store.dispatch.dispositions.len(), 1);
        assert!(store.dispatch.collectable(&task.machine).is_empty());
        let files = store.storage.files();
        assert!(block_on(store.poc_dispose(&offer, continuation)).is_err());
        assert_eq!(files, store.storage.files());
        evidence(
            &mut store,
            &before,
            record(&before, Some(0), "late command"),
        );
        assert_eq!(store.poc_task(&task.id).unwrap(), task);
        assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
        assert!(store.poc_configuration_ready().is_ok());
        assert!(matches!(
            store.dispatch.calls[&offer.pending.call].state,
            CallState::Disposed { .. }
        ));
        assert!(block_on(store.poc_change(&task.id, task.revision, Change::Settle)).is_err());
        let next = change(&mut store, &task, Change::Request);
        assert!(next.requesting && next.pending.is_none() && next.proposal.is_none());
        assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), next);
        assert_eq!(
            store.commands.len(),
            1,
            "only a new proposal may arm another command"
        );
    }
}

#[test]
fn poc_disposition_exact_crash_points_complete_without_another_record() {
    for point in [1, 2] {
        let (mut store, _, offer) = pending();
        let number = store.next;
        CRASH.set(point);
        {
            let mut future = std::pin::pin!(store.poc_dispose(&offer, Continuation::AsIfNotDone));
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
        }
        CRASH.set(0);
        assert!(
            store.poc_task(&offer.task).unwrap().pending.is_some(),
            "projection not applied at cut"
        );
        assert_eq!(store.dispatch.dispositions.len(), usize::from(point == 2));
        let replay = reopen(&store);
        let task = replay.poc_task(&offer.task).unwrap();
        assert_result(&task, &offer, number, Continuation::AsIfNotDone);
        assert_eq!(replay.dispatch.dispositions.len(), 1);
        assert_eq!(replay.commands.len(), 1);
        assert_eq!(replay.next, number + 1, "recovery appends nothing");
        assert_eq!(reopen(&replay).poc_task(&offer.task).unwrap(), task);
    }
}

#[test]
fn poc_disposition_unlanded_and_landed_append_failures() {
    for fault in [
        Fault::Fail(1),
        Fault::Fail(2),
        Fault::Fail(3),
        Fault::LandThenFail(3),
    ] {
        let (mut store, before, offer) = pending();
        let number = store.next;
        store.storage.fault(fault);
        assert!(block_on(store.poc_dispose(&offer, Continuation::AsIfDone)).is_err());
        assert_eq!(store.poc_task(&before.id).unwrap(), before);
        assert!(store.failed.is_some());
        assert!(
            store
                .poc_disposition_offer(&before.id, &before.start_session)
                .is_err()
        );
        let mut replay = reopen(&store);
        fresh(&mut replay);
        if matches!(fault, Fault::LandThenFail(_)) {
            assert_result(
                &replay.poc_task(&before.id).unwrap(),
                &offer,
                number,
                Continuation::AsIfDone,
            );
        } else {
            assert_eq!(replay.poc_task(&before.id).unwrap(), before);
            assert!(
                replay
                    .poc_disposition_offer(&before.id, &before.start_session)
                    .is_ok()
            );
            assert!(replay.dispatch.dispositions.is_empty());
        }
    }
}

#[test]
fn poc_disposition_stale_confirmation_and_writer_refusals_append_nothing() {
    for case in 0..18 {
        let (mut store, before, mut offer) = pending();
        match case {
            0 => offer.revision += 1,
            1 => offer.pending.call += 1,
            2 => offer.pending.job = "f".repeat(48),
            3 => offer.machine = "another".into(),
            4 => offer.session = "another".into(),
            5 => {
                evidence(&mut store, &before, crate::jobs::Record::Missing);
            }
            6 => {
                change(&mut store, &before, Change::Inspect);
            }
            7 => {
                change(&mut store, &before, Change::Abandon);
            }
            8 => {
                evidence(&mut store, &before, record(&before, Some(0), "done"));
            }
            9 => {
                store.sessions[0].ended.set(true);
            }
            10 => {
                store.dispatch.jobs.clear();
            }
            11 => {
                store.dispatch.jobs.last_mut().unwrap().state = crate::jobs::State::Running;
            }
            12 => {
                store.dispatch.jobs.last_mut().unwrap().number = None;
            }
            13 => {
                evidence(
                    &mut store,
                    &before,
                    crate::jobs::Record::Incomplete {
                        machine: Some(hex::encode("foreign")),
                        command: None,
                    },
                );
            }
            14 => {
                evidence(
                    &mut store,
                    &before,
                    crate::jobs::Record::Incomplete {
                        machine: None,
                        command: Some(hex::encode("wrong")),
                    },
                );
            }
            15 => {
                store.dispatch.jobs.last_mut().unwrap().state = crate::jobs::State::OtherMachine;
            }
            16 => {
                let t = change(&mut store, &before, Change::Inspect);
                change(
                    &mut store,
                    &t,
                    Change::Wait {
                        why: "failed read".into(),
                        running: false,
                    },
                );
            }
            17 => {
                store
                    .dispatch
                    .calls
                    .get_mut(&offer.pending.call)
                    .unwrap()
                    .state = CallState::Cancelled;
            }
            _ => unreachable!(),
        }
        let files = store.storage.files();
        let task = store.poc_task(&before.id).unwrap();
        // Check current admission separately: rejecting the old confirmation below
        // can otherwise mask a missing evidence guard with snapshot inequality.
        let refusal = match case {
            11 | 15 => Some("latest committed read is not missing, incomplete or ended"),
            13 | 14 => Some("committed read names a foreign machine or mismatched command"),
            16 => {
                assert_eq!(task.revision, before.revision + 2);
                assert!(
                    store
                        .poc_committed(task.pending.as_ref().unwrap())
                        .unwrap()
                        .number
                        .unwrap()
                        <= task.inspection_record.unwrap()
                );
                Some("latest inspection has no eligible committed read")
            }
            _ => None,
        };
        if let Some(reason) = refusal {
            assert_eq!(
                store
                    .poc_disposition_offer(&task.id, &task.start_session)
                    .unwrap_err(),
                reason,
                "fresh offer in case {case}"
            );
        }
        assert!(
            block_on(store.poc_dispose(&offer, Continuation::AsIfDone)).is_err(),
            "case {case}"
        );
        assert_eq!(store.storage.files(), files, "case {case}");
        assert_eq!(store.poc_task(&before.id).unwrap(), task, "case {case}");
        assert_eq!(store.commands.len(), 1);
    }
}

#[test]
fn poc_disposition_verification_unknown_requires_explicit_retry() {
    for continuation in [Continuation::AsIfDone, Continuation::AsIfNotDone] {
        let mut store = ready();
        let task = create_task(&mut store);
        let task = change(&mut store, &task, Change::Request);
        let task = change(
            &mut store,
            &task,
            Change::Propose {
                call_id: "done".into(),
                tool: done(),
            },
        );
        let task = change(&mut store, &task, Change::PrepareCheck);
        append(&mut store, &task, &task.start_session);
        let pending = store.poc_task(&task.id).unwrap();
        assert!(
            block_on(store.poc_change(&task.id, pending.revision, Change::RetryChecks)).is_err()
        );
        evidence(&mut store, &pending, crate::jobs::Record::Missing);
        let task = change(&mut store, &pending, Change::Pause("missing check".into()));
        let offer = store
            .poc_disposition_offer(&task.id, &task.start_session)
            .unwrap();
        let disposed = accept(&mut store, &offer, continuation);
        let job = offer.pending.job.clone();
        assert_eq!(disposed.verification[0].exit_status, None);
        assert!(disposed.disposed_check(&disposed.verification[0]));
        let paused = change(&mut store, &disposed, Change::PrepareCheck);
        assert_eq!(paused.status, Status::Paused);
        assert_eq!(store.commands.len(), 1);
        evidence(
            &mut store,
            &pending,
            record(&pending, Some(0), "late check"),
        );
        assert_eq!(store.poc_task(&task.id).unwrap(), paused);
        assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), paused);
        let retry = change(&mut store, &paused, Change::RetryChecks);
        assert_eq!(retry.completed, paused.completed);
        let retry = change(&mut store, &retry, Change::PrepareCheck);
        append(&mut store, &retry, &retry.start_session);
        let next = store.poc_task(&task.id).unwrap();
        assert_ne!(next.pending.as_ref().unwrap().job, job);
        assert_ne!(next.pending.as_ref().unwrap().call, offer.pending.call);
        assert_eq!(next.completed, disposed.completed);
    }
}

fn historical_call(store: &mut Store<MemoryStorage>, job: char) -> u64 {
    let number = store.next;
    let intent = Intent {
        call: number,
        machine: "fixture".into(),
        command: hex::encode("earlier-command"),
        approval: Some(approval()),
        job: Some(job.to_string().repeat(48)),
        provenance: None,
    };
    block_on(store.commit(&Event::Intent(intent.clone()))).unwrap();
    store.apply_intent(number, intent).unwrap();
    number
}

#[test]
fn poc_disposition_remaining_hold_and_standing_replacement_are_snapshot_bound() {
    for continuation in [Continuation::AsIfDone, Continuation::AsIfNotDone] {
        let (mut store, task, old_offer) = pending();
        // Historical records can contain multiple unresolved commands. Admission stays unchanged.
        let dropped = historical_call(&mut store, 'a');
        let remaining = historical_call(&mut store, 'b');
        let standing_number = store.next;
        block_on(store.dispose(Disposition {
            machine: "fixture".into(),
            calls: vec![dropped],
            continuation: Continuation::AsIfNotDone,
            uncertainty: "owner accepted unknown outcome".into(),
        }))
        .unwrap();
        let before = store.storage.files();
        assert!(block_on(store.poc_dispose(&old_offer, continuation)).is_err());
        assert_eq!(before, store.storage.files());
        let offer = store
            .poc_disposition_offer(&task.id, &task.start_session)
            .unwrap();
        assert_eq!(offer.remaining, [remaining]);
        assert_eq!(offer.standing.as_ref().unwrap().calls, [dropped]);
        assert_eq!(offer.standing.as_ref().unwrap().number, standing_number);
        let accepted = accept(&mut store, &offer, continuation);
        let result = &accepted.completed[0].2["content"];
        assert_eq!(result["remaining_unresolved"], json!([remaining]));
        assert_eq!(result["machine_held"], true);
        assert!(matches!(
            store.dispatch.calls[&remaining].state,
            CallState::Unresolved
        ));
        assert!(
            matches!(store.dispatch.calls[&dropped].state, CallState::Disposed {disposition, ..} if disposition == standing_number)
        );
        assert_eq!(
            store.dispatch.standing["fixture"].disposition.calls,
            [offer.pending.call]
        );
        assert!(matches!(
            block_on(store.check("fixture")),
            Err(AppendRefusal::Policy(
                crate::dispatch::DispatchRefusal::Held(_)
            ))
        ));
        assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), accepted);
    }
}

#[test]
fn poc_disposition_destructive_standing_and_ended_tasks_never_continue() {
    for continuation in [
        Continuation::Abandonment,
        Continuation::DestructiveReinstall,
    ] {
        let (mut store, task, offer) = pending();
        let other = historical_call(&mut store, 'a');
        let n = store.next;
        block_on(store.dispose(Disposition {
            machine: "fixture".into(),
            calls: vec![other],
            continuation,
            uncertainty: "unknown".into(),
        }))
        .unwrap();
        let before = store.storage.files();
        let why = block_on(store.poc_dispose(&offer, Continuation::AsIfDone)).unwrap_err();
        assert!(why.contains(&n.to_string()) && why.contains(&format!("{continuation:?}")));
        assert_eq!(store.storage.files(), before);
        assert_eq!(store.poc_task(&task.id).unwrap(), task);
    }
    let (mut store, task, offer) = pending();
    let ended = change(&mut store, &task, Change::Abandon);
    block_on(store.dispose(Disposition {
        machine: task.machine.clone(),
        calls: vec![offer.pending.call],
        continuation: Continuation::AsIfDone,
        uncertainty: "unknown".into(),
    }))
    .unwrap();
    assert_eq!(store.poc_task(&task.id).unwrap(), ended);
    assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), ended);
}

#[test]
fn poc_disposition_preflight_revision_proposal_and_output_protection() {
    for case in 0..4 {
        let (mut store, task, _) = pending();
        match case {
            0 => store.poc.get_mut(&task.id).unwrap().revision = u64::MAX,
            1 => store.poc.get_mut(&task.id).unwrap().proposal = None,
            2 => {
                store
                    .poc
                    .get_mut(&task.id)
                    .unwrap()
                    .proposal
                    .as_mut()
                    .unwrap()
                    .tool = exec("different")
            }
            3 => store.remember_poc_credential(b"The owner accepted an unknown outcome"),
            _ => unreachable!(),
        }
        let offer = store
            .poc_disposition_offer(&task.id, &task.start_session)
            .unwrap();
        let before = store.storage.files();
        let task = store.poc_task(&task.id).unwrap();
        assert!(
            block_on(store.poc_dispose(&offer, Continuation::AsIfDone)).is_err(),
            "case {case}"
        );
        assert_eq!(store.storage.files(), before);
        assert_eq!(store.poc_task(&task.id).unwrap(), task);
        assert!(store.failed.is_none());
    }
}

#[test]
fn poc_disposition_active_inspection_refuses_even_with_eligible_history() {
    let (store, task, offer) = pending();
    let (mut fixture, _, _) = Fixture::new();
    *fixture.store.borrow_mut() = store;
    fixture.hold_observe = true;
    let control = fixture.store.clone();
    let mut model = Script::default();
    {
        let mut future = std::pin::pin!(run::drive(
            &mut fixture,
            &mut model,
            &task.id,
            &task.start_session
        ));
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let mut store = control.borrow_mut();
        let files = store.storage.files();
        assert!(
            block_on(store.poc_dispose(&offer, Continuation::AsIfDone))
                .unwrap_err()
                .contains("active")
        );
        assert_eq!(store.storage.files(), files);
    }
    assert!(fixture.remote.borrow().sends.is_empty());
}

#[test]
fn poc_disposition_next_resume_requests_a_fresh_decision_without_resending() {
    let (mut store, task, offer) = pending();
    let disposed = accept(&mut store, &offer, Continuation::AsIfNotDone);
    let (mut fixture, _, _) = Fixture::new();
    *fixture.store.borrow_mut() = store;
    let mut model = Script::one("fresh-decision", done());
    let result = block_on(run::resume(
        &mut fixture,
        &mut model,
        &task.id,
        &task.start_session,
    ))
    .unwrap();
    assert_eq!(model.seen, [disposed.completed]);
    assert!(fixture.remote.borrow().sends.is_empty());
    assert_eq!(fixture.store.borrow().commands.len(), 1);
    assert_eq!(result.requests, task.requests + 1);
    assert!(result.verifying && result.pending.is_none());
}

#[test]
fn poc_disposition_incomplete_and_ended_reads_preserve_unknown_outcomes() {
    for ended in [true, false] {
        let (mut store, task, _) = pending();
        let record = if ended {
            let mut r = record(&task, None, "partial");
            if let crate::jobs::Record::Present { alive, .. } = &mut r {
                *alive = false;
            }
            r
        } else {
            crate::jobs::Record::Incomplete {
                machine: Some(hex::encode(&task.machine)),
                command: Some(hex::encode("install-example-service")),
            }
        };
        evidence(&mut store, &task, record);
        let offer = store
            .poc_disposition_offer(&task.id, &task.start_session)
            .unwrap();
        let result = accept(&mut store, &offer, Continuation::AsIfDone);
        assert_eq!(
            result.completed[0].2["content"]["collection_read"]["state"],
            if ended { "ended" } else { "incomplete" }
        );
        assert!(!result.completed[0].2.to_string().contains("exit_status"));
        assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), result);
    }
}

#[test]
fn poc_disposition_refused_historical_record_does_not_complete_pending_task() {
    let (mut store, task, offer) = pending();
    let disposition = Disposition {
        machine: task.machine.clone(),
        calls: vec![offer.pending.call, u64::MAX],
        continuation: Continuation::AsIfDone,
        uncertainty: "unknown".into(),
    };
    assert!(matches!(
        store.dispatch.check_disposition(store.next, &disposition),
        DispositionReport::Refused { .. }
    ));
    block_on(store.commit(&Event::Disposition(disposition))).unwrap();
    assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
}
