use super::*;
use crate::declaration::{Declaration, Field, Lifecycle, Scope, Service};
use crate::poc::completion::{self, Observation as ReadObservation, Read};

fn declaration(enabled: bool) -> Declaration {
    let mut d = crate::declaration::ad_hoc_minimum();
    d.services = Field::Value(vec![Service {
        name: "example".into(),
        scope: Scope::System,
        lifecycle: if enabled {
            Lifecycle::EnabledSurvivesReboot
        } else {
            Lifecycle::RunningAtDelivery
        },
    }]);
    d
}
fn declared(d: Declaration) -> Store<MemoryStorage> {
    let mut store = ready_without_requirements();
    let session = store.sessions[0].identity.clone();
    store
        .propose_requirements(
            &session,
            42,
            crate::declaration::Proposal::Declaration {
                machine: "fixture".into(),
                declaration: d,
            },
            &done(),
        )
        .unwrap();
    block_on(store.approve_requirements(&session, "fixture", 42)).unwrap();
    store
}
pub(super) fn finish_request(store: &mut Store<MemoryStorage>, task: &Task, tool: Tool) -> Task {
    let task = change(store, task, Change::Request);
    change(
        store,
        &task,
        Change::Propose {
            call_id: format!("request-{}", task.requests),
            tool,
        },
    )
}
fn begin(store: &mut Store<MemoryStorage>, checks: Vec<String>) -> Task {
    let task = create_task(store);
    finish_request(
        store,
        &task,
        Tool::Done {
            machine: "fixture".into(),
            checks,
        },
    )
}
fn settle(store: &mut Store<MemoryStorage>, task: &Task, exit: u32, output: &str) -> Task {
    append(store, task, &task.start_session);
    let task = store.poc_task(&task.id).unwrap();
    evidence(store, &task, record(&task, Some(exit), output));
    change(store, &task, Change::Settle)
}
fn measure(
    store: &mut Store<MemoryStorage>,
    mut task: Task,
    running: &str,
    enabled: &str,
    sockets: &str,
) -> Task {
    for _ in 0..16 {
        if task.status == Status::Complete || task.status == Status::Paused {
            return task;
        }
        task = change(store, &task, Change::PrepareCheck);
        if let Some(proposal) = &task.proposal {
            let (exit, output) = if let Some(index) = proposal.check {
                match task.read_plan[index] {
                    Read::Running { .. } => (3, running),
                    Read::Enabled { .. } => (1, enabled),
                    Read::Listeners => (0, sockets),
                }
            } else {
                (1, "functional report")
            };
            task = settle(store, &task, exit, output);
        }
    }
    panic!("bounded read plan did not finish")
}

#[test]
fn completion_proposal_admission_returns_each_refusal_without_commands() {
    let good = serde_json::to_value(declaration(true)).unwrap();
    let mut variants = vec![];
    for (pointer, value, reason) in [
        (
            "/required",
            json!([{"check":"true"}]),
            "expected empty array",
        ),
        (
            "/drift_checks",
            json!([{"command":"true"}]),
            "expected empty array",
        ),
        ("/listeners/inbound", json!([]), "preserve"),
        (
            "/services/0/scope",
            json!({"kind":"user","account":"worker"}),
            "user-scope",
        ),
        ("/services", json!("unspecified"), "services: not stated"),
        (
            "/listeners/outbound",
            json!("unspecified"),
            "listeners.outbound: not stated",
        ),
        ("/version", json!(1), "declaration version"),
        (
            "/services/0/name",
            json!("sh -c 'touch /tmp/marker'"),
            "declaration.services[0].name",
        ),
        (
            "/listeners/inbound/0/port",
            json!(0),
            "declaration.listeners.inbound[0].port",
        ),
    ] {
        let mut candidate = good.clone();
        *candidate.pointer_mut(pointer).unwrap() = value;
        variants.push((candidate, reason));
    }
    variants.push((
        json!({"version":2}),
        "declaration.listeners: missing required field",
    ));
    for (candidate, reason) in variants {
        let mut store = ready_without_requirements();
        let task = create_task(&mut store);
        let task = finish_request(
            &mut store,
            &task,
            Tool::ProposeDeclaration {
                machine: "fixture".into(),
                declaration: candidate,
            },
        );
        assert!(
            task.completed[0].2["content"]["refused"]
                .as_str()
                .unwrap()
                .contains(reason)
        );
        assert_eq!(task.steps, 1);
        assert!(task.proposal.is_none());
        assert!(store.dispatch.calls.is_empty());
    }
    let mut store = ready_without_requirements();
    let task = create_task(&mut store);
    let task = finish_request(
        &mut store,
        &task,
        Tool::ProposeDeclaration {
            machine: "fixture".into(),
            declaration: good,
        },
    );
    // Fixture target is not enrolled; the existing proposal path still validates authority.
    assert!(task.proposal.is_some());
    assert!(store.dispatch.calls.is_empty());
    let mut other = ready_without_requirements();
    let fresh = create_task(&mut other);
    let refused = finish_request(&mut other, &fresh, exec("true"));
    assert!(refused.proposal.is_none());
}

#[test]
fn completion_pinned_reads_and_lifecycle_statuses() {
    for enabled in [false, true] {
        let d = declaration(enabled);
        let plan = completion::reads(&d).unwrap();
        assert_eq!(
            plan[0].command(),
            "systemctl is-active -- 'example'.service"
        );
        if enabled {
            assert_eq!(
                plan[1].command(),
                "systemctl is-enabled -- 'example'.service"
            );
        }
        assert_eq!(plan.last().unwrap().command(), "ss -H -n -l -t -u");
        for (running, enablement, delivered) in [
            ("active", "enabled", true),
            ("reloading", "enabled", true),
            ("inactive", "enabled", false),
            ("active", "disabled", !enabled),
        ] {
            let mut store = declared(d.clone());
            let task = begin(&mut store, vec![]);
            let task = measure(&mut store, task, running, enablement, "");
            assert_eq!(
                task.status == Status::Complete,
                delivered,
                "{running}/{enablement}/{enabled}"
            );
            assert_eq!(
                task.verdict.as_deref(),
                Some(if delivered {
                    completion::DELIVERED
                } else {
                    completion::FINDINGS
                })
            );
            if delivered && enabled {
                assert_eq!(task.notes[0].text, "enabled, restart not demonstrated");
            }
            assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
        }
    }
    assert_eq!(
        completion::reads(&crate::declaration::ad_hoc_minimum()).unwrap(),
        [Read::Listeners]
    );
}

fn duplicate_services_complete_with_every_read_recorded(enabled: bool) {
    let mut d = declaration(enabled);
    if let Field::Value(services) = &mut d.services {
        services.push(services[0].clone());
    }
    assert_eq!(completion::proposal(&json!(d)).unwrap(), d);
    let plan = completion::reads(&d).unwrap();
    assert_eq!(plan.len(), if enabled { 5 } else { 3 });
    let mut store = declared(d.clone());
    let task = begin(&mut store, vec![]);
    assert_eq!(task.read_plan, plan);
    let steps = task.steps;
    let task = measure(&mut store, task, "active", "enabled", "");
    assert_eq!(task.status, Status::Complete);
    assert_eq!(task.verdict.as_deref(), Some(completion::DELIVERED));
    assert!(task.findings.is_empty());
    assert_eq!(task.steps, steps + plan.len() as u32);
    assert_eq!(task.verification.len(), plan.len());
    for (index, read) in plan.iter().enumerate() {
        assert_eq!(task.verification[index].command, read.command());
        assert!(!task.verification[index].job.is_empty());
        assert!(task.verification[index].observation.is_some());
        assert!(task.completed.iter().any(|step| {
            step.0 == format!("$verify:{index}:{}", steps + index as u32 + 1)
                && step.1 == exec(&read.command())
        }));
    }
    if enabled {
        assert_eq!(task.notes.len(), 2);
        assert!(
            task.notes
                .iter()
                .all(|note| { note.text == "enabled, restart not demonstrated" })
        );
    } else {
        assert!(task.notes.is_empty());
    }
    assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
}

#[test]
fn completion_duplicate_services_running_complete_with_every_read_recorded() {
    duplicate_services_complete_with_every_read_recorded(false);
}

#[test]
fn completion_duplicate_services_enabled_complete_with_every_read_recorded() {
    duplicate_services_complete_with_every_read_recorded(true);
}

#[test]
fn completion_duplicate_services_require_every_lifecycle_read_to_settle_good() {
    for enabled in [false, true] {
        let mut d = declaration(enabled);
        if let Field::Value(services) = &mut d.services {
            services.push(services[0].clone());
        }
        let plan = completion::reads(&d).unwrap();
        let good: Vec<_> = plan
            .iter()
            .map(|read| {
                Some(read.observe(
                    0,
                    match read {
                        Read::Running { .. } => "active",
                        Read::Enabled { .. } => "enabled",
                        Read::Listeners => "",
                    },
                ))
            })
            .collect();
        assert!(completion::judge(&d, &plan, &good, &[]).delivered);
        for index in 0..plan.len() - 1 {
            for (exit, output) in [(0, "inactive"), (1, "disabled"), (127, ""), (5, "active")] {
                let mut changed = good.clone();
                changed[index] = Some(plan[index].observe(exit, output));
                let result = completion::judge(&d, &plan, &changed, &[]);
                assert!(
                    result.complete && !result.delivered && !result.findings.is_empty(),
                    "{enabled}/{index}/{exit}/{output}"
                );
                // An earlier good duplicate must not replace a missing or refused later read.
                changed[index] = None;
                let unknown = completion::judge(&d, &plan, &changed, &result.findings);
                assert!(!unknown.complete && !unknown.delivered && unknown.findings_unknown);
                assert_eq!(unknown.findings, result.findings);
            }
        }
        let missing = completion::judge(&d, &plan, &good[..good.len() - 1], &[]);
        assert!(!missing.complete && !missing.delivered && missing.findings_unknown);

        // The second duplicate's refusal also stays unknown through the ordinary task path.
        let mut store = declared(d);
        let mut task = begin(&mut store, vec![]);
        for read in plan.iter().take(if enabled { 2 } else { 1 }) {
            task = change(&mut store, &task, Change::PrepareCheck);
            task = settle(
                &mut store,
                &task,
                0,
                match read {
                    Read::Running { .. } => "active",
                    Read::Enabled { .. } => "enabled",
                    Read::Listeners => unreachable!(),
                },
            );
        }
        task = change(&mut store, &task, Change::PrepareCheck);
        let task = change(
            &mut store,
            &task,
            Change::Pause("read refused before dispatch".into()),
        );
        assert_eq!(task.status, Status::Paused);
        assert!(task.verdict.is_none());
        assert!(
            task.pause_reason
                .as_deref()
                .unwrap()
                .starts_with(completion::UNKNOWN)
        );
        assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
        let task = change(&mut store, &task, Change::RetryChecks);
        let task = measure(&mut store, task, "active", "enabled", "");
        assert_eq!(task.status, Status::Complete);
        assert_eq!(task.verdict.as_deref(), Some(completion::DELIVERED));
    }
}

#[test]
fn completion_duplicate_services_preserve_failures_while_other_reads_unsettled() {
    for enabled in [false, true] {
        let mut d = declaration(enabled);
        if let Field::Value(services) = &mut d.services {
            services.push(services[0].clone());
        }
        let plan = completion::reads(&d).unwrap();
        let good: Vec<_> = plan
            .iter()
            .map(|read| {
                Some(read.observe(
                    0,
                    match read {
                        Read::Running { .. } => "active",
                        Read::Enabled { .. } => "enabled",
                        Read::Listeners => "",
                    },
                ))
            })
            .collect();
        for failed in 0..plan.len() - 1 {
            for missing in 0..plan.len() {
                if failed == missing {
                    continue;
                }
                for exit in [0, 127] {
                    let mut observations = good.clone();
                    observations[failed] = Some(plan[failed].observe(exit, "inactive"));
                    observations[missing] = None;
                    let result = completion::judge(&d, &plan, &observations, &[]);
                    assert!(!result.complete && !result.delivered && result.findings_unknown);
                    assert!(result.findings.iter().any(|finding| {
                        finding.field == crate::delivery::FieldId::Services
                            && finding.detail == "Service example (System) differs from its declared lifecycle"
                    }), "{enabled}/{failed}/{missing}/{exit}");
                }
            }
        }
        let mut store = declared(d);
        let mut task = begin(&mut store, vec![]);
        task = change(&mut store, &task, Change::PrepareCheck);
        task = settle(&mut store, &task, 127, "");
        if enabled {
            task = change(&mut store, &task, Change::PrepareCheck);
            task = settle(&mut store, &task, 0, "enabled");
        }
        task = change(&mut store, &task, Change::PrepareCheck);
        append(&mut store, &task, &task.start_session);
        let task = store.poc_task(&task.id).unwrap();
        evidence(&mut store, &task, crate::jobs::Record::Missing);
        let task = change(
            &mut store,
            &task,
            Change::Wait {
                why: "read outcome not established".into(),
                running: false,
            },
        );
        let offer = store
            .poc_disposition_offer(&task.id, &task.start_session)
            .unwrap();
        let task = block_on(store.poc_dispose(&offer, crate::dispatch::Continuation::AsIfNotDone))
            .unwrap();
        let task = measure(&mut store, task, "active", "enabled", "");
        assert_eq!(task.status, Status::Paused);
        assert!(task.verdict.is_none());
        assert!(!task.findings.is_empty());
        assert!(
            task.pause_reason
                .as_deref()
                .unwrap()
                .starts_with(completion::UNKNOWN)
        );
        assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
    }
}

#[test]
fn completion_tcp_permissions_judge_loopback_and_record_udp() {
    let mut d = crate::declaration::ad_hoc_minimum();
    let plan = completion::reads(&d).unwrap();
    let judge = |d: &Declaration, text: &str| {
        completion::judge(d, &plan, &[Some(plan[0].observe(0, text))], &[])
    };
    for address in ["0.0.0.0", "127.0.0.1", "[::1]"] {
        let result = judge(&d, &format!("tcp LISTEN 0 128 {address}:8888 *:*\n"));
        assert_eq!(
            result.findings[0].detail,
            "Something answers on tcp port 8888 that the declaration does not list"
        );
    }
    assert!(judge(&d, "tcp LISTEN 0 128 0.0.0.0:22 *:*\n").delivered);
    assert!(judge(&d, "udp UNCONN 0 0 0.0.0.0:9999 *:*\n").delivered);
    assert!(judge(&d, "").delivered);
    if let Field::Value(allowed) = &mut d.listeners.inbound {
        allowed.push(crate::declaration::Inbound {
            proto: crate::declaration::Protocol::Tcp,
            port: 8888,
            from: crate::declaration::From::None,
        });
    }
    assert!(judge(&d, "tcp LISTEN 0 128 127.2.3.4:8888 *:*\n").delivered);
    assert!(judge(&d, "tcp LISTEN 0 128 [::1%lo]:8888 *:*\n").delivered);
    assert_eq!(
        judge(&d, "tcp LISTEN 0 128 0.0.0.0:8888 *:*\n").findings[0].detail,
        "tcp port 8888 is declared local-only but listens on 0.0.0.0"
    );
}

#[test]
fn completion_recheck_retires_queued_and_proposed_reports_without_dispatch() {
    for proposed in [false, true] {
        let mut store = declared(declaration(true));
        let task = begin(
            &mut store,
            vec!["printf first".into(), "printf second".into()],
        );
        let task = if proposed {
            change(&mut store, &task, Change::PrepareCheck)
        } else {
            task
        };
        let mut store = reopen(&store);
        let task = change(&mut store, &task, Change::Pause("seed_backup".into()));
        let task = change(&mut store, &task, Change::RetryChecks);
        assert!(task.proposal.is_none());
        for report in &task.reports {
            assert_eq!(report.status, "not run");
            assert_eq!(
                report.excerpt,
                "Complete re-check schedules only harness reads"
            );
            assert!(report.job.is_none() && report.exit_status.is_none());
        }
        assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
        let task = change(&mut store, &task, Change::PrepareCheck);
        let proposal = task.proposal.as_ref().unwrap();
        assert_eq!(proposal.check, Some(0));
        assert_eq!(proposal.report, None);
        assert_eq!(
            proposal.tool,
            exec("systemctl is-active -- 'example'.service")
        );
        let task = settle(&mut store, &task, 0, "active");
        let task = measure(&mut store, task, "active", "enabled", "");
        assert_eq!(task.status, Status::Complete);
        assert!(
            !task
                .completed
                .iter()
                .any(|step| step.0.starts_with("$report:"))
        );
    }

    // A re-check cannot discard a report's pending job or its later unknown outcome.
    let mut store = declared(declaration(true));
    let task = begin(
        &mut store,
        vec!["printf first".into(), "printf second".into()],
    );
    let task = change(&mut store, &task, Change::PrepareCheck);
    append(&mut store, &task, &task.start_session);
    let task = store.poc_task(&task.id).unwrap();
    let task = change(
        &mut store,
        &task,
        Change::Pause("collection interrupted".into()),
    );
    assert!(block_on(store.poc_change(&task.id, task.revision, Change::RetryChecks)).is_err());
    assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
    evidence(&mut store, &task, crate::jobs::Record::Missing);
    let offer = store
        .poc_disposition_offer(&task.id, &task.start_session)
        .unwrap();
    let task =
        block_on(store.poc_dispose(&offer, crate::dispatch::Continuation::AsIfNotDone)).unwrap();
    let task = change(
        &mut store,
        &task,
        Change::Pause("complete re-check requested".into()),
    );
    let history = task.reports[0].clone();
    let completed = task.completed.clone();
    let task = change(&mut store, &task, Change::RetryChecks);
    assert_eq!(task.reports[0], history);
    assert_eq!(task.reports[0].status, "outcome unknown");
    assert_eq!(task.reports[1].status, "not run");
    assert_eq!(task.completed, completed);
    assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
}

#[test]
fn completion_scoped_ipv6_records_udp_and_matches_local_tcp() {
    use crate::declaration::{Inbound, Protocol};
    let mut d = crate::declaration::ad_hoc_minimum();
    let read = Read::Listeners;
    for address in [
        "[fe80::5054:ff:fe12:3456]%eth0",
        "[fe80::5054:ff:fe12:3456%eth0]",
    ] {
        let observation = read.observe(0, &format!("udp UNCONN 0 0 {address}:546 *:*\n"));
        let ReadObservation::Sockets(sockets) = &observation else {
            panic!("scoped UDP must be recorded: {observation:?}")
        };
        assert_eq!(sockets.len(), 1);
        assert_eq!(
            sockets[0],
            completion::Socket {
                proto: Protocol::Udp,
                port: 546,
                address: "fe80::5054:ff:fe12:3456".into()
            }
        );
        assert!(
            completion::judge(&d, std::slice::from_ref(&read), &[Some(observation)], &[]).delivered
        );
    }
    if let Field::Value(allowed) = &mut d.listeners.inbound {
        allowed.push(Inbound {
            proto: Protocol::Tcp,
            port: 8888,
            from: crate::declaration::From::None,
        });
    }
    for address in ["[::1]%lo", "[::1%lo]"] {
        let observation = read.observe(0, &format!("tcp LISTEN 0 128 {address}:8888 *:*\n"));
        let ReadObservation::Sockets(sockets) = &observation else {
            panic!("scoped TCP must be recorded: {observation:?}")
        };
        assert_eq!(sockets[0].address, "::1");
        assert!(
            completion::judge(&d, std::slice::from_ref(&read), &[Some(observation)], &[]).delivered
        );
    }
    for row in [
        "tcp LISTEN 0 128 [invalid]%lo:8888 *:*",
        "udp UNCONN 0 0 [fe80::1]%eth0:bad *:*",
        "tcp LISTEN 0 128 [fe80::1]%eth0:8888 *:*",
    ] {
        let observation = read.observe(0, row);
        assert!(
            !completion::judge(&d, std::slice::from_ref(&read), &[Some(observation)], &[])
                .delivered
        );
    }
}

#[test]
fn completion_optional_reports_never_judge_and_recheck_never_repeats_them() {
    for running in ["active", "inactive"] {
        let mut store = declared(declaration(true));
        let task = begin(&mut store, vec!["printf success; exit 0".into()]);
        let task = change(&mut store, &task, Change::PrepareCheck);
        assert!(task.proposal.as_ref().unwrap().report.is_some());
        let task = settle(
            &mut store,
            &task,
            if running == "active" { 1 } else { 0 },
            "success",
        );
        let task = measure(&mut store, task, running, "enabled", "");
        assert_eq!(task.status == Status::Complete, running == "active");
        assert_eq!(task.reports[0].status, "recorded");
        if running != "active" {
            let task = change(&mut store, &task, Change::RetryChecks);
            let task = measure(&mut store, task, "active", "enabled", "");
            assert_eq!(task.status, Status::Complete);
            assert_eq!(
                task.completed
                    .iter()
                    .filter(|s| s.0.starts_with("$report:"))
                    .count(),
                1
            );
        }
    }
    let mut store = declared(declaration(false));
    let mut task = begin(&mut store, vec!["systemctl stop example".into()]);
    // Reserve exactly the remaining read steps: the optional command must never dispatch.
    let limit = task.steps + task.read_plan.len() as u32;
    store.poc.get_mut(&task.id).unwrap().limits.steps = limit;
    task.limits.steps = limit;
    let task = measure(&mut store, task, "active", "", "");
    assert_eq!(task.status, Status::Complete);
    assert_eq!(task.reports[0].status, "not run");
    assert!(!task.completed.iter().any(|s| s.0.starts_with("$report:")));
}

#[test]
fn completion_unknown_reads_never_clear_findings_and_full_retry_can() {
    let d = declaration(true);
    let plan = completion::reads(&d).unwrap();
    let negative = vec![
        Some(ReadObservation::Running(false)),
        Some(ReadObservation::Enabled(true)),
        Some(ReadObservation::Sockets(vec![])),
    ];
    let old = completion::judge(&d, &plan, &negative, &[]).findings;
    let partial = completion::judge(
        &d,
        &plan,
        &[
            Some(ReadObservation::Running(true)),
            None,
            Some(ReadObservation::Sockets(vec![])),
        ],
        &old,
    );
    assert!(!partial.complete && !partial.delivered && partial.findings_unknown);
    assert_eq!(partial.findings, old);
    let mut store = declared(d);
    let task = begin(&mut store, vec![]);
    let task = change(&mut store, &task, Change::PrepareCheck);
    append(&mut store, &task, &task.start_session);
    let task = store.poc_task(&task.id).unwrap();
    evidence(&mut store, &task, record(&task, Some(0), "active"));
    assert_ne!(
        reopen(&store).poc_task(&task.id).unwrap().status,
        Status::Complete
    );
    let task = change(&mut store, &task, Change::Settle);
    let task = change(&mut store, &task, Change::PrepareCheck);
    let task = change(
        &mut store,
        &task,
        Change::Pause("read refused before dispatch".into()),
    );
    assert_ne!(task.status, Status::Complete);
    assert!(task.verdict.is_none());
    assert!(
        task.pause_reason
            .as_ref()
            .unwrap()
            .starts_with(completion::UNKNOWN)
    );
    let task = change(&mut store, &task, Change::RetryChecks);
    let task = measure(&mut store, task, "active", "enabled", "");
    assert_eq!(task.status, Status::Complete);
    for pointer in ["/services", "/listeners/outbound"] {
        let mut value = serde_json::to_value(declaration(true)).unwrap();
        *value.pointer_mut(pointer).unwrap() = json!("unspecified");
        let unstated = Declaration::parse(&value).unwrap();
        let plan = completion::reads(&unstated).unwrap();
        let good: Vec<_> = plan
            .iter()
            .map(|read| {
                Some(match read {
                    Read::Running { .. } => ReadObservation::Running(true),
                    Read::Enabled { .. } => ReadObservation::Enabled(true),
                    Read::Listeners => ReadObservation::Sockets(vec![]),
                })
            })
            .collect();
        let result = completion::judge(&unstated, &plan, &good, &[]);
        assert!(!result.complete && !result.delivered && result.findings_unknown);
        assert_eq!(
            completion::unstated(&unstated),
            Some(&pointer[1..].replace('/', ".")[..])
        );
        let mut store = declared(unstated);
        let task = begin(&mut store, vec![]);
        let task = change(&mut store, &task, Change::PrepareCheck);
        assert!(task.verdict.is_none());
        assert_eq!(task.status, Status::Paused);
        assert!(task.pause_reason.unwrap().contains("not stated"));
    }
    for exit in [127, 5] {
        let plan = completion::reads(&crate::declaration::ad_hoc_minimum()).unwrap();
        let result = completion::judge(
            &crate::declaration::ad_hoc_minimum(),
            &plan,
            &[Some(plan[0].observe(exit, ""))],
            &[],
        );
        assert!(result.complete && !result.delivered && !result.findings.is_empty());
    }
}

#[test]
fn completion_pending_disposed_read_stays_unknown_until_full_recheck() {
    for state in [
        crate::jobs::Record::Missing,
        crate::jobs::Record::Incomplete {
            machine: None,
            command: None,
        },
    ] {
        let mut store = declared(declaration(false));
        let task = begin(&mut store, vec![]);
        let task = change(&mut store, &task, Change::PrepareCheck);
        append(&mut store, &task, &task.start_session);
        let task = store.poc_task(&task.id).unwrap();
        assert!(block_on(store.poc_change(&task.id, task.revision, Change::Settle)).is_err());
        assert_ne!(
            reopen(&store).poc_task(&task.id).unwrap().status,
            Status::Complete
        );
        evidence(&mut store, &task, state);
        let task = change(
            &mut store,
            &task,
            Change::Wait {
                why: "read outcome not established".into(),
                running: false,
            },
        );
        let offer = store
            .poc_disposition_offer(&task.id, &task.start_session)
            .unwrap();
        let task = block_on(store.poc_dispose(&offer, crate::dispatch::Continuation::AsIfNotDone))
            .unwrap();
        let task = change(&mut store, &task, Change::PrepareCheck);
        assert_eq!(task.status, Status::Paused);
        assert_eq!(task.pause_reason.as_deref(), Some(completion::UNKNOWN));
        assert!(task.verdict.is_none());
        assert_eq!(reopen(&store).poc_task(&task.id).unwrap(), task);
        let task = change(&mut store, &task, Change::RetryChecks);
        let task = measure(&mut store, task, "active", "", "");
        assert_eq!(task.status, Status::Complete);
    }
}
