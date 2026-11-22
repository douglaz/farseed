use super::*;
use crate::poc::credit::{Mint, SecretText};
use crate::store::ai_keys::Record as KeyRecord;

fn starting_session() -> (Store<MemoryStorage>, Task, Task) {
    renewal_session(true)
}
fn renewal_session(approve: bool) -> (Store<MemoryStorage>, Task, Task) {
    let mut store = ready();
    block_on(store.credit_install(&crate::poc::credit::AccountRecord::from_response(
        201, &json!({"success":true,"credit_id":"synthetic-credit-account","api_key":"synthetic-default-key"}),
    ).unwrap())).unwrap();
    let setup = ai_key_proposal(&mut store);
    let setup = change(
        &mut store,
        &setup,
        Change::AiKeyDecision {
            create: true,
            approved_cap: None,
        },
    );
    block_on(store.ai_key_commit(KeyRecord::Request {
        task: setup.id.clone(),
        call: setup.proposal.as_ref().unwrap().call_id.clone(),
        path: crate::store::ai_keys::path(&setup),
        mint: Mint::ai_key(&setup, "k0123456789abcdef01234567".into(), 1_794_355_200),
        configuration: None,
    }))
    .unwrap();
    block_on(store.ai_key_commit(KeyRecord::Held {
        machine: setup.machine.clone(),
        name: "k0123456789abcdef01234567".into(),
        issuer_id: "setup-key".into(),
        expires: "2026-11-11T00:00:00Z".into(),
        key: SecretText(Zeroizing::new("synthetic-setup-application-key".into())),
    }))
    .unwrap();
    block_on(store.end_session(&setup.start_session)).unwrap();
    let session = block_on(store.admit_fixture("fixture")).unwrap();
    store.synthetic_confirm_limits(100).unwrap();
    block_on(store.enter_goal(
        &session,
        "Do nothing on the machine; reply done.".into(),
        None,
    ))
    .unwrap();
    let goal = block_on(store.poc_start(&session)).unwrap();
    assert!(goal.proposal.is_none());
    let renewal = block_on(store.poc_renew_ai_key("fixture", &session, &"a".repeat(48))).unwrap();
    let renewal = if approve {
        change(
            &mut store,
            &renewal,
            Change::AiKeyDecision {
                create: true,
                approved_cap: None,
            },
        )
    } else {
        renewal
    };
    (store, goal, renewal)
}

#[test]
fn poc_ai_key_renewal_pause_hides_remote_bytes_without_inventing_step_failure() {
    let (mut store, _, renewal) = starting_session();
    let paused = change(
        &mut store,
        &renewal,
        Change::Pause("remote diagnostic <untrusted>".into()),
    );
    let why = paused.pause_reason.unwrap();
    assert!(!why.contains("remote diagnostic"), "{why}");
    assert!(!why.contains("failed"), "{why}");
    assert!(why.contains("Resume"), "{why}");
}

#[test]
fn poc_ai_key_renewal_only_an_executed_step_can_report_failure() {
    let (mut store, _, renewal) = starting_session();
    for reason in [
        crate::poc::key_renewal::failed(crate::poc::key_renewal::KEY),
        "Credit operation interrupted.".into(),
        crate::poc::wait::PIN_REQUIRED.into(),
        "no inference credit account is available".into(),
        format!(
            "original accepted session authority for the task machine is required: {}",
            crate::poc::wait::ACCEPTANCE
        ),
    ] {
        let current = store.poc_task(&renewal.id).unwrap();
        let paused = change(&mut store, &current, Change::Pause(reason));
        let why = paused.pause_reason.as_deref().unwrap();
        assert!(!why.contains("failed"), "{why}");
        assert!(why.contains("Resume"), "{why}");
        assert!(paused.proposal.is_some());
    }
    let current = store.poc_task(&renewal.id).unwrap();
    let failed = change(
        &mut store,
        &current,
        Change::AiKeyFailed("the credit service refused the key request".into()),
    );
    let reason = crate::poc::key_renewal::next(&store, &failed).unwrap_err();
    let failed = change(&mut store, &failed, Change::Pause(reason));
    assert_eq!(failed.status, Status::Paused);
    assert_eq!(
        failed.pause_reason.as_deref(),
        Some("AI key renewal stopped: Create key failed.")
    );
    assert_eq!(failed.completed[0].2["content"]["status"], "failed");
}

#[test]
fn poc_ai_key_renewal_starting_goal_requirements_approval_then_resume_creates() {
    let (mut store, goal, renewal) = renewal_session(false);
    assert!(renewal.completed.is_empty());
    store
        .propose_requirements(
            &goal.start_session,
            42,
            crate::declaration::Proposal::Declaration {
                machine: "fixture".into(),
                declaration: crate::declaration::ad_hoc_minimum(),
            },
            &done(),
        )
        .unwrap();
    store
        .poc_key_decision_authority(&renewal, &renewal.start_session)
        .unwrap();
    let renewal = change(
        &mut store,
        &renewal,
        Change::AiKeyDecision {
            create: true,
            approved_cap: None,
        },
    );
    assert!(
        store
            .poc_authority(&renewal.id, &renewal.start_session)
            .is_err()
    );
    let mut runtime = MintRuntime::new(store);
    let paused = block_on(run::resume(
        &mut runtime,
        &mut run::Unconfigured,
        &renewal.id,
        &renewal.start_session,
    ))
    .unwrap();
    assert_eq!(
        paused.pause_reason.as_deref(),
        Some(
            "AI key renewal is waiting for requirements approval. Approve or reject the open requirements card, then Resume."
        )
    );
    let candidate = runtime.store.pending_requirements_view(&goal.start_session)["candidate"]
        .as_u64()
        .unwrap();
    block_on(
        runtime
            .store
            .approve_requirements(&goal.start_session, "fixture", candidate),
    )
    .unwrap();
    let waiting = runtime.store.poc_task(&renewal.id).unwrap();
    assert_eq!(
        waiting, paused,
        "approval must not change renewal state or revision"
    );
    assert!(waiting.ai_key_approved);
    assert_eq!(waiting.proposal, renewal.proposal);
    assert!(
        !runtime
            .store
            .eligible_tasks()
            .iter()
            .any(|task| task.id == renewal.id)
    );
    assert_eq!(
        reopen(&runtime.store).poc_task(&renewal.id).unwrap(),
        waiting
    );
    let created = block_on(run::resume(
        &mut runtime,
        &mut run::Unconfigured,
        &renewal.id,
        &renewal.start_session,
    ))
    .unwrap();
    assert_eq!(created.completed[0].2["content"]["status"], "created");
    assert_eq!(runtime.service.requests, 1);
}

/// No network: this service applies the account-scoped name constraint and response shape
/// that the permissive earlier mint fixtures omitted.
#[derive(Default)]
struct CreditService {
    names: BTreeMap<String, std::collections::BTreeSet<String>>,
    requests: usize,
}

#[test]
fn poc_ai_key_renewal_rejected_requirements_keep_state_until_resume() {
    let (mut store, goal, task) = starting_session();
    store
        .propose_requirements(
            &goal.start_session,
            42,
            crate::declaration::Proposal::Declaration {
                machine: "fixture".into(),
                declaration: crate::declaration::ad_hoc_minimum(),
            },
            &done(),
        )
        .unwrap();
    let mut runtime = MintRuntime::new(store);
    let paused = block_on(run::resume(
        &mut runtime,
        &mut run::Unconfigured,
        &task.id,
        &task.start_session,
    ))
    .unwrap();
    assert_eq!(
        paused.pause_reason.as_deref(),
        Some(crate::poc::key_renewal::APPROVAL)
    );
    block_on(
        runtime
            .store
            .poc_reject_requirements(&task.start_session, &task.machine, 42),
    )
    .unwrap();
    let waiting = runtime.store.poc_task(&task.id).unwrap();
    assert_eq!(
        waiting, paused,
        "rejection must preserve the renewal revision"
    );
    assert_eq!(
        paused.pause_reason.as_deref(),
        Some(crate::poc::key_renewal::APPROVAL)
    );
    assert!(
        runtime
            .store
            .pending_requirements_view(&task.start_session)
            .is_null()
    );
    let created = block_on(run::resume(
        &mut runtime,
        &mut run::Unconfigured,
        &task.id,
        &task.start_session,
    ))
    .unwrap();
    assert_eq!(created.completed[0].2["content"]["status"], "created");
    assert_eq!(runtime.service.requests, 1);
}
impl CreditService {
    fn create(&mut self, account: &str, body: &Value) -> (u16, Value) {
        self.requests += 1;
        let name = body["name"].as_str().unwrap();
        if !self
            .names
            .entry(account.into())
            .or_default()
            .insert(name.into())
        {
            return (409, json!({"status":"error","error":"duplicate name"}));
        }
        (
            201,
            json!({"status":"success","data":{
                "_id":format!("key-{}", self.requests), "api_key":format!("synthetic-application-key-{}", self.requests),
                "name":name,"usage_limit_usd":body["usage_limit_usd"],"reset_period":null,"expire_at":body["expire_at"]
            }}),
        )
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Interruption {
    None,
    BeforeRequest,
    AfterRecord,
    AfterResponse,
    AfterHeld,
}

struct MintRuntime {
    store: Store<MemoryStorage>,
    service: CreditService,
    revision: Cell<u64>,
    continuation: crate::lifecycle::Continuation,
    interruption: Interruption,
    queued_configuration_change: bool,
    writes: usize,
    journal_checkpoints: Vec<(&'static str, u64, BTreeMap<String, Task>)>,
}
impl MintRuntime {
    fn new(store: Store<MemoryStorage>) -> Self {
        Self {
            store,
            service: CreditService::default(),
            revision: Cell::new(0),
            continuation: Rc::new(crate::lifecycle::Authority::default())
                .continuation()
                .unwrap(),
            interruption: Interruption::None,
            queued_configuration_change: false,
            writes: 0,
            journal_checkpoints: Vec::new(),
        }
    }
    fn checkpoint(&mut self, label: &'static str) {
        self.journal_checkpoints
            .push((label, self.store.next, self.store.poc.clone()));
    }
    fn interrupt(&self, point: Interruption) {
        if self.interruption == point {
            self.revision.set(self.revision.get() + 1);
        }
    }
}
impl Runtime for MintRuntime {
    async fn load(&mut self, id: &str) -> Result<Task, String> {
        self.store.poc_task(id)
    }
    async fn authority(&mut self, id: &str, session: &str) -> Result<(), String> {
        self.store.poc_authority(id, session).map(|_| ())
    }
    async fn change(&mut self, task: &Task, change: Change) -> Result<Task, String> {
        let task = self
            .store
            .poc_change(&task.id, task.revision, change)
            .await?;
        self.checkpoint("change");
        Ok(task)
    }
    async fn prepare(&mut self, task: &Task, session: &str) -> Result<Task, String> {
        self.store.poc_prepare_next(task, session).await
    }
    async fn propose(
        &mut self,
        task: &Task,
        session: &str,
        call: String,
        tool: Tool,
        origin: Option<BlockOrigin>,
    ) -> Result<Task, String> {
        self.store
            .poc_propose(task, session, call, tool, origin)
            .await
    }
    async fn execute(&mut self, binding: Binding, task: &Task) -> Result<(), String> {
        use crate::poc::credit::{OperationFence, ai_key_request, returned_mint};
        use crate::store::ai_keys::Preparation;
        self.store.poc_prepare_execution(task, &binding.session)?;
        let (fence, ()) = OperationFence::after_wait(
            &self.continuation,
            async {
                if self.queued_configuration_change {
                    self.revision.set(self.revision.get() + 1);
                }
            },
            || self.revision.get(),
        )
        .await?;
        self.interrupt(Interruption::BeforeRequest);
        fence.check(self.revision.get())?;
        let call = task.proposal.as_ref().unwrap().call_id.clone();
        match self.store.ai_key_preparation(task)? {
            Preparation::Unknown => return Err(crate::poc::key_renewal::UNKNOWN_KEY.into()),
            Preparation::AccountRequired => return Err(crate::poc::key_renewal::CREDIT.into()),
            Preparation::Held => {}
            Preparation::Mint => {
                let expiry = "2026-11-11T00:00:00Z";
                let mint = Mint::ai_key(
                    task,
                    crate::poc::credit::mint_name()?,
                    crate::poc::provisioning::timestamp(expiry)?,
                );
                self.store
                    .ai_key_commit(KeyRecord::Request {
                        task: task.id.clone(),
                        call: call.clone(),
                        path: crate::store::ai_keys::path(task),
                        mint: mint.clone(),
                        configuration: None,
                    })
                    .await?;
                self.checkpoint("mint request");
                self.interrupt(Interruption::AfterRecord);
                fence.check(self.revision.get())?;
                let (status, value) = self
                    .service
                    .create("operator", &ai_key_request(&mint, expiry));
                self.interrupt(Interruption::AfterResponse);
                fence.check(self.revision.get())?;
                assert_eq!(status, 201);
                let (issuer_id, expires) = returned_mint(&value, &mint)?;
                self.store
                    .ai_key_commit(KeyRecord::Held {
                        machine: task.machine.clone(),
                        name: mint.name,
                        issuer_id,
                        expires,
                        key: SecretText(Zeroizing::new(
                            value["data"]["api_key"].as_str().unwrap().into(),
                        )),
                    })
                    .await?;
                self.checkpoint("Held");
                self.interrupt(Interruption::AfterHeld);
                fence.check(self.revision.get())?;
            }
        }
        let held = self.store.ai_key(&task.id, &call).unwrap();
        let command =
            crate::store::ai_keys::command(&held.path, held.key.as_ref().unwrap().0.len());
        let mut entry = Entry {
            machine: task.machine.clone(),
            command: command.as_bytes().to_vec(),
            provenance: None,
        };
        entry.provenance = Some(crate::dispatch::CommandProvenance {
            target: crate::dispatch::Target::Entry(task.machine.clone()),
            session: Some(task.start_session.clone()),
            requester: crate::dispatch::Requester::Session,
        });
        self.store
            .poc_append(&binding, &entry, &approval())
            .await
            .map_err(|why| why.to_string())?;
        self.checkpoint("machine write");
        self.writes += 1;
        let pending = self.store.poc_task(&task.id)?;
        evidence(
            &mut self.store,
            &pending,
            crate::jobs::Record::Present {
                machine: hex::encode(&task.machine),
                command: hex::encode(command),
                boot: "boot-one".into(),
                current_boot: "boot-one".into(),
                pid: 123,
                alive: false,
                exit_status: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        self.checkpoint("terminal evidence");
        Ok(())
    }
    async fn observe(&mut self, task: &Task, _: &str) -> Result<Observation, String> {
        assert!(
            self.store
                .poc_committed(task.pending.as_ref().unwrap())
                .is_some()
        );
        Ok(Observation::Committed)
    }
}

#[test]
fn poc_ai_key_renewal_credit_fence_resume_never_mints_a_recorded_request_twice() {
    for interruption in [
        Interruption::BeforeRequest,
        Interruption::AfterRecord,
        Interruption::AfterResponse,
        Interruption::AfterHeld,
    ] {
        let (store, _, task) = starting_session();
        let mut runtime = MintRuntime::new(store);
        runtime.interruption = interruption;
        let paused = block_on(run::resume(
            &mut runtime,
            &mut run::Unconfigured,
            &task.id,
            &task.start_session,
        ))
        .unwrap();
        assert_eq!(paused.status, Status::Paused);
        assert!(paused.completed.is_empty());
        assert!(!paused.pause_reason.as_deref().unwrap().contains("failed"));
        let count = runtime.service.requests;
        // Replay has no current authority until explicitly restored, just as Unlock requires.
        runtime.store = reopen(&runtime.store);
        fresh(&mut runtime.store);
        runtime.interruption = Interruption::None;
        let resumed = block_on(run::resume(
            &mut runtime,
            &mut run::Unconfigured,
            &task.id,
            &task.start_session,
        ))
        .unwrap();
        if matches!(
            interruption,
            Interruption::BeforeRequest | Interruption::AfterHeld
        ) {
            assert_eq!(resumed.completed.len(), 1);
            assert_eq!(resumed.completed[0].2["content"]["status"], "created");
            assert_eq!(runtime.service.requests, 1);
            assert_eq!(runtime.writes, 1);
        } else {
            assert_eq!(resumed.status, Status::Paused);
            assert_eq!(
                resumed.pause_reason.as_deref(),
                Some(crate::poc::key_renewal::UNKNOWN_KEY)
            );
            assert_eq!(runtime.service.requests, count);
            assert_eq!(runtime.writes, 0);
        }
    }
}

#[test]
fn poc_ai_key_renewal_credit_queue_waits_for_start_and_uses_real_api_shape() {
    let (store, goal, task) = starting_session();
    assert!(goal.proposal.is_none());
    let mut runtime = MintRuntime::new(store);
    runtime.queued_configuration_change = true;
    let mut response = None;
    // Start already admitted the live session but has not entered mint_inner yet.
    // This is the same reservation and mint gate used by the worker.
    run::reserve_execution_response(&task, &mut response);
    crate::poc::credit::session_mint_ready().expect("renewal must let Start mint the session key");
    // A Start mint and a renewal mint share one account, and must use distinct names.
    let start = json!({"name":crate::poc::credit::mint_name().unwrap(),"usage_limit_usd":1.0,"expire_at":"2026-11-11T00:00:00Z"});
    assert_eq!(runtime.service.create("operator", &start).0, 201);
    assert_eq!(runtime.service.create("operator", &start).0, 409);
    assert_eq!(runtime.service.create("another-account", &start).0, 201);
    let completed = block_on(run::resume(
        &mut runtime,
        &mut run::Unconfigured,
        &task.id,
        &task.start_session,
    ))
    .unwrap();
    assert_eq!(completed.completed[0].2["content"]["status"], "created");
    assert_eq!(completed.completed[0].2["content"]["limit_usd"], 5.0);
    assert_eq!(runtime.service.names["operator"].len(), 2);
    assert_eq!(runtime.writes, 1);
    run::reserve_execution_response(&goal, &mut response);
    assert!(
        crate::poc::credit::session_mint_ready().is_err(),
        "machine responses still protect configuration"
    );
    drop(response);
    crate::poc::credit::session_mint_ready().unwrap();
}

/// This uses unlock/replay, not a second compiled historical reader. The replay path
/// (including apply_requirements_task, apply_poc, project_poc, project_poc_task,
/// apply_poc_key_class, validate_ai_key and replay_ai_key) is unchanged from b3f6e11.
/// Comparing every Task compares status, revision, proposal and completed outcomes too.
/// The fake service/transport does not establish browser scheduling or remote effects.
#[test]
fn poc_ai_key_renewal_whole_journal_replays_with_unchanged_projection() {
    for approve in [true, false] {
        let (mut store, goal, task) = renewal_session(false);
        store
            .propose_requirements(
                &goal.start_session,
                42,
                crate::declaration::Proposal::Declaration {
                    machine: task.machine.clone(),
                    declaration: crate::declaration::ad_hoc_minimum(),
                },
                &done(),
            )
            .unwrap();
        let task = change(
            &mut store,
            &task,
            Change::AiKeyDecision {
                create: true,
                approved_cap: None,
            },
        );
        let mut runtime = MintRuntime::new(store);
        runtime.checkpoint("Create key approval");
        let paused = block_on(run::resume(
            &mut runtime,
            &mut run::Unconfigured,
            &task.id,
            &task.start_session,
        ))
        .unwrap();
        assert_eq!(paused.status, Status::Paused);
        assert_eq!(
            paused.pause_reason.as_deref(),
            Some(crate::poc::key_renewal::APPROVAL)
        );
        assert_eq!(runtime.service.requests, 0);
        if approve {
            block_on(
                runtime
                    .store
                    .approve_requirements(&goal.start_session, &task.machine, 42),
            )
            .unwrap();
        } else {
            block_on(
                runtime
                    .store
                    .poc_reject_requirements(&goal.start_session, &task.machine, 42),
            )
            .unwrap();
        }
        assert_eq!(runtime.store.poc_task(&task.id).unwrap(), paused);
        runtime.checkpoint("requirements decision");
        let settled = block_on(run::resume(
            &mut runtime,
            &mut run::Unconfigured,
            &task.id,
            &task.start_session,
        ))
        .unwrap();
        assert_eq!(settled.status, Status::Running);
        assert!(settled.pending.is_none());
        assert!(settled.proposal.is_none());
        assert_eq!(settled.completed.len(), 1);
        assert_eq!(settled.completed[0].2["content"]["status"], "created");
        assert_eq!(runtime.service.requests, 1);
        assert_eq!(runtime.writes, 1);
        assert_eq!(
            runtime
                .journal_checkpoints
                .iter()
                .filter_map(|(label, _, _)| {
                    matches!(
                        *label,
                        "mint request" | "Held" | "machine write" | "terminal evidence"
                    )
                    .then_some(*label)
                })
                .collect::<Vec<_>>(),
            ["mint request", "Held", "machine write", "terminal evidence"]
        );
        // Finish the deterministic renewal too, using synthetic machine results.
        // This covers the revisions of every following command through verification.
        let mut completed = settled;
        while !completed.ended() {
            let (call, tool, origin) =
                crate::poc::key_renewal::next(&runtime.store, &completed).unwrap();
            let stdout = if call.starts_with(crate::poc::key_renewal::WAIT) {
                "REBUILD OK synthetic-build"
            } else if call == crate::poc::key_renewal::CHECK {
                "CHECKS hermes PASS"
            } else {
                ""
            };
            let requesting = block_on(runtime.change(&completed, Change::Request)).unwrap();
            let proposal =
                block_on(runtime.propose(&requesting, &task.start_session, call, tool, origin))
                    .unwrap();
            runtime.checkpoint("renewal proposal");
            append(&mut runtime.store, &proposal, &task.start_session);
            runtime.checkpoint("renewal command");
            let pending = runtime.store.poc_task(&task.id).unwrap();
            evidence(
                &mut runtime.store,
                &pending,
                record(&pending, Some(0), stdout),
            );
            runtime.checkpoint("renewal evidence");
            completed = block_on(run::resume(
                &mut runtime,
                &mut run::Unconfigured,
                &task.id,
                &task.start_session,
            ))
            .unwrap();
        }
        assert_eq!(completed.status, Status::Complete);
        assert_eq!(completed.completed.len(), 6);
        assert_eq!(runtime.service.requests, 1);
        assert_eq!(runtime.writes, 1);
        // Each prefix comes from the final encrypted journal; replay re-runs the
        // unchanged validators and projectors without calling admission/poc_change.
        let files = runtime.store.storage.files();
        for (label, next, expected_tasks) in &runtime.journal_checkpoints {
            let prefix = files
                .iter()
                .filter(|(name, _)| !is_record_name(name) || name.parse::<u64>().unwrap() < *next)
                .map(|(name, bytes)| (name.clone(), bytes.clone()))
                .collect();
            let replayed = block_on(unlock(MemoryStorage::with_files(prefix), &Fixed, pass()))
                .unwrap_or_else(|why| panic!("{label} (approve={approve}): {why}"));
            assert_eq!(&replayed.poc, expected_tasks, "{label} (approve={approve})");
        }
        assert_eq!(reopen(&runtime.store).poc, runtime.store.poc);
    }
}
