use super::*;
use crate::poc::credit::{Mint, SecretText};
use crate::store::ai_keys::Record as KeyRecord;

fn starting_session() -> (Store<MemoryStorage>, Task, Task) {
    renewal_session(true)
}
fn renewal_session(approve: bool) -> (Store<MemoryStorage>, Task, Task) {
    renewal_session_mode(approve, false)
}
fn renewal_session_mode(approve: bool, legacy: bool) -> (Store<MemoryStorage>, Task, Task) {
    let mut store = ready();
    block_on(store.credit_install(&crate::poc::credit::AccountRecord::from_response(
        201, &json!({"success":true,"credit_id":"synthetic-credit-account","api_key":"synthetic-default-key"}),
    ).unwrap())).unwrap();
    let setup = ai_key_proposal(&mut store);
    // The replacement starts with a previously installed finite key.
    let setup = apply_recorded_ai_key_decision(
        &mut store,
        &setup,
        Change::AiKeyDecision {
            create: true,
            approved_cap: Some(5.0),
            approved_policy: None,
        },
    );
    let expiry = "2026-11-11T00:00:00Z";
    block_on(store.ai_key_commit(KeyRecord::Request {
        task: setup.id.clone(),
        call: setup.proposal.as_ref().unwrap().call_id.clone(),
        path: crate::store::ai_keys::path(&setup),
        mint: finite_ai_key_mint(&setup, "k0123456789abcdef01234567", 5.0, expiry),
        configuration: None,
    }))
    .unwrap();
    block_on(store.ai_key_commit(KeyRecord::Held {
        machine: setup.machine.clone(),
        name: "k0123456789abcdef01234567".into(),
        issuer_id: "setup-key".into(),
        expires: Some(expiry.into()),
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
    let renewal = if legacy {
        let record = Record::RenewAiKey {
            id: "a".repeat(48),
            session: session.clone(),
            limits: Limits::default(),
            replacement: None,
        };
        let number = block_on(store.commit(&Event::Poc(record.clone()))).unwrap();
        store.apply_poc(number, &record).unwrap();
        store.poc_task(&"a".repeat(48)).unwrap()
    } else {
        block_on(store.poc_renew_ai_key("fixture", &session, &"a".repeat(48))).unwrap()
    };
    let renewal = if approve {
        change(
            &mut store,
            &renewal,
            Change::AiKeyDecision {
                create: true,
                approved_cap: None,
                approved_policy: None,
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
            approved_policy: None,
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
    keys: BTreeMap<String, (String, String, bool)>,
    deletes: Vec<String>,
    events: Vec<String>,
    delete_failure: bool,
    delete_lost: bool,
    list_failure: bool,
    omit_deleted_at: bool,
    hide_old_from_list: bool,
    unrelated_delete_404: Option<&'static [u8]>,
    list_responses: std::collections::VecDeque<Value>,
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
        self.keys.insert(
            format!("key-{}", self.requests),
            (account.into(), name.into(), false),
        );
        (
            201,
            json!({"status":"success","data":{
                "_id":format!("key-{}", self.requests), "api_key":format!("synthetic-application-key-{}", self.requests),
                "name":name,"usage_limit_usd":body["usage_limit_usd"],"reset_period":body["reset_period"],"expire_at":body["expire_at"]
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
        let mut service = CreditService::default();
        for key in store
            .poc_targets
            .values()
            .flat_map(|target| &target.application_inference_keys)
        {
            service.keys.insert(
                key.record_id.clone(),
                ("operator".into(), key.name.clone(), false),
            );
        }
        Self {
            store,
            service,
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

const LEGACY_REPLACEMENT_NAME: &str = "historical-renewal-key-v1";
const LEGACY_REPLACEMENT_EXPIRY: &str = "2026-11-11T00:00:00Z";

fn legacy_renewal() -> (MintRuntime, Task) {
    use crate::poc::credit::{AI_KEY_APPROVAL_REQUIRED, returned_mint};

    let (mut store, _, task) = renewal_session_mode(false, true);
    let task = apply_recorded_ai_key_decision(
        &mut store,
        &task,
        Change::AiKeyDecision {
            create: true,
            approved_cap: Some(5.0),
            approved_policy: None,
        },
    );
    assert_eq!(
        store.ai_key_preparation(&task).unwrap_err(),
        AI_KEY_APPROVAL_REQUIRED
    );

    // Recreate the historical request and custody before the current runtime resumes.
    let mut runtime = MintRuntime::new(store);
    let mint = finite_ai_key_mint(
        &task,
        LEGACY_REPLACEMENT_NAME,
        5.0,
        LEGACY_REPLACEMENT_EXPIRY,
    );
    block_on(runtime.store.ai_key_commit(KeyRecord::Request {
        task: task.id.clone(),
        call: task.proposal.as_ref().unwrap().call_id.clone(),
        path: crate::store::ai_keys::path(&task),
        mint: mint.clone(),
        configuration: None,
    }))
    .unwrap();
    let (status, value) = runtime.service.create(
        "operator",
        &json!({
            "name": mint.name,
            "usage_limit_usd": mint.requested_cap,
            "expire_at": LEGACY_REPLACEMENT_EXPIRY,
        }),
    );
    assert_eq!(status, 201);
    let (issuer_id, expires) = returned_mint(&value, &mint).unwrap();
    block_on(runtime.store.ai_key_commit(KeyRecord::Held {
        machine: task.machine.clone(),
        name: mint.name,
        issuer_id,
        expires,
        key: SecretText(Zeroizing::new(
            value["data"]["api_key"].as_str().unwrap().into(),
        )),
    }))
    .unwrap();
    (runtime, task)
}

fn assert_legacy_replacement(store: &Store<MemoryStorage>, task: &Task) {
    let entry = store
        .ai_key(&task.id, crate::poc::key_renewal::KEY)
        .unwrap();
    assert_eq!(entry.mint.name, LEGACY_REPLACEMENT_NAME);
    assert_eq!(entry.mint.requested_cap, 5.0);
    assert_eq!(
        entry.mint.requested_expiry,
        Some(crate::poc::provisioning::timestamp(LEGACY_REPLACEMENT_EXPIRY).unwrap())
    );
    assert_eq!(entry.mint.requested_reset_period, None);
    assert!(entry.key.is_some());
    let held = store.poc_targets[&task.machine]
        .application_inference_keys
        .iter()
        .find(|key| key.name == entry.mint.name && key.path == entry.path)
        .unwrap();
    assert_eq!(held.record_id, "key-1");
    assert_eq!(held.expires.as_deref(), Some(LEGACY_REPLACEMENT_EXPIRY));
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
                let mint = Mint::ai_key(task, crate::poc::credit::mint_name()?)?;
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
                let (status, value) = self.service.create("operator", &ai_key_request(&mint));
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
    let outcome = &completed.completed[0].2["content"];
    assert_eq!(outcome["status"], "created");
    assert_eq!(outcome["limit_usd"], 5.0);
    assert_eq!(outcome["reset_period"], "monthly");
    assert_eq!(outcome.get("expires"), Some(&Value::Null));
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

/// This compares the live projection against unlock/replay in the current reader.
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
                approved_policy: None,
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
            if completed
                .completed
                .last()
                .is_some_and(|(call, _, _)| call == crate::poc::key_renewal::CHECK)
            {
                assert!(
                    !completed.ended(),
                    "Hermes passing must still retire the replaced key"
                );
                assert!(completed.verdict.is_none());
                block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
                    runtime: &mut runtime,
                    task: completed.clone(),
                    account: "operator",
                }))
                .unwrap();
                runtime.checkpoint("old key revoked");
            }
        }
        assert_eq!(completed.status, Status::Complete);
        assert_eq!(completed.completed.len(), 7);
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

struct RetireRuntime<'a> {
    runtime: &'a mut MintRuntime,
    task: Task,
    account: &'a str,
}
impl crate::poc::key_renewal::RetirementRuntime for RetireRuntime<'_> {
    async fn retirement(&mut self) -> Result<crate::store::ai_keys::Retirement, String> {
        self.runtime.store.check_key_retirement(&self.task)?;
        self.runtime
            .store
            .ai_key_retirements_for(&self.task)
            .cloned()
            .ok_or("retirement missing".into())
    }
    async fn record(
        &mut self,
        state: crate::store::ai_keys::RetirementState,
    ) -> Result<(), String> {
        let issuer_id = self
            .runtime
            .store
            .ai_key_retirements_for(&self.task)
            .unwrap()
            .key
            .record_id
            .clone();
        self.runtime
            .store
            .ai_key_commit(KeyRecord::Retirement {
                task: self.task.id.clone(),
                issuer_id,
                state,
            })
            .await
    }
    async fn list(&mut self) -> Result<(u16, Value), String> {
        let service = &mut self.runtime.service;
        service.events.push("GET".into());
        if service.list_failure {
            return Err("lost GET".into());
        }
        if let Some(value) = service.list_responses.pop_front() {
            return Ok((200, value));
        }
        Ok((
            200,
            json!({"status":"success","data":service.keys.iter()
            .filter(|(id, (account, _, _))| account == self.account && !(service.hide_old_from_list && *id == "setup-key"))
            .map(|(id, (_, name, deleted))| {
                let mut key = json!({"_id":id,"name":name});
                if !service.omit_deleted_at {
                    key["deleted_at"] = json!(deleted.then_some("2026-11-22T00:00:00Z"));
                }
                key
            })
            .collect::<Vec<_>>()}),
        ))
    }
    async fn delete(&mut self, id: &str) -> Result<u16, String> {
        self.runtime.store.check_key_retirement(&self.task)?;
        let retirement = self
            .runtime
            .store
            .ai_key_retirements_for(&self.task)
            .unwrap();
        if retirement.key.record_id != id
            || retirement.state != crate::store::ai_keys::RetirementState::Pending
        {
            return Err("retirement identity or state changed".into());
        }
        let service = &mut self.runtime.service;
        service.events.push(format!("DELETE {id}"));
        service.deletes.push(id.into());
        let Some((owner, _, deleted)) = service.keys.get_mut(id) else {
            return Ok(404);
        };
        if owner != self.account {
            return Ok(403);
        }
        if service.delete_failure {
            return Ok(503);
        }
        if let Some(body) = service.unrelated_delete_404 {
            // Match the browser transport: these statuses need no JSON body.
            if crate::poc::key_renewal::delete_status_without_body(404) {
                return Ok(404);
            }
            crate::poc::credit::decode(body)?;
            return Ok(404);
        }
        *deleted = true;
        if service.delete_lost {
            return Err("lost DELETE response".into());
        }
        Ok(200)
    }
}

/// Drive all real proposals/settlements through CHECK, with fake machine output only.
fn checked_renewal(pass: bool) -> (MintRuntime, Task) {
    let (store, _, task) = starting_session();
    complete_renewal_check(MintRuntime::new(store), &task, pass)
}
fn complete_renewal_check(
    mut runtime: MintRuntime,
    task: &Task,
    pass: bool,
) -> (MintRuntime, Task) {
    let mut task = block_on(run::resume(
        &mut runtime,
        &mut run::Unconfigured,
        &task.id,
        &task.start_session,
    ))
    .unwrap();
    loop {
        let (call, tool, origin) = crate::poc::key_renewal::next(&runtime.store, &task).unwrap();
        let checking = call == crate::poc::key_renewal::CHECK;
        let stdout = if call.starts_with(crate::poc::key_renewal::WAIT) {
            "REBUILD OK fixture"
        } else if checking && pass {
            "CHECKS hermes PASS"
        } else {
            ""
        };
        let requesting = block_on(runtime.change(&task, Change::Request)).unwrap();
        let proposal =
            block_on(runtime.propose(&requesting, &task.start_session, call, tool, origin))
                .unwrap();
        append(&mut runtime.store, &proposal, &task.start_session);
        let pending = runtime.store.poc_task(&task.id).unwrap();
        evidence(
            &mut runtime.store,
            &pending,
            record(
                &pending,
                Some(if checking && !pass { 1 } else { 0 }),
                stdout,
            ),
        );
        task = block_on(run::resume(
            &mut runtime,
            &mut run::Unconfigured,
            &task.id,
            &task.start_session,
        ))
        .unwrap();
        if checking {
            return (runtime, task);
        }
    }
}

#[test]
fn poc_ai_key_renewal_retirement_only_after_check_and_never_new_key() {
    use crate::poc::key_renewal::retire;
    let (store, _, task) = starting_session();
    let mut runtime = MintRuntime::new(store);
    let created = block_on(run::resume(
        &mut runtime,
        &mut run::Unconfigured,
        &task.id,
        &task.start_session,
    ))
    .unwrap();
    assert!(
        block_on(retire(&mut RetireRuntime {
            runtime: &mut runtime,
            task: created,
            account: "operator"
        }))
        .is_err()
    );
    assert!(
        runtime.service.events.is_empty(),
        "no credit requests before the Hermes check"
    );
    let (mut runtime, task) = checked_renewal(false);
    assert!(
        block_on(retire(&mut RetireRuntime {
            runtime: &mut runtime,
            task,
            account: "operator"
        }))
        .is_err()
    );
    assert!(runtime.service.deletes.is_empty());
    let (mut runtime, task) = checked_renewal(true);
    assert!(!task.ended());
    let retirement = runtime.store.ai_key_retirements_for(&task).unwrap().clone();
    assert_eq!(retirement.key.record_id, "setup-key");
    assert_eq!(
        retirement.key.expires.as_deref(),
        Some("2026-11-11T00:00:00Z")
    );
    let new = runtime.store.poc_targets[&task.machine]
        .application_inference_keys
        .last()
        .unwrap()
        .record_id
        .clone();
    block_on(retire(&mut RetireRuntime {
        runtime: &mut runtime,
        task: task.clone(),
        account: "operator",
    }))
    .unwrap();
    assert_eq!(runtime.service.deletes, ["setup-key"]);
    assert!(!runtime.service.keys[&new].2);
    let (call, tool, _) = crate::poc::key_renewal::next(&runtime.store, &task).unwrap();
    assert!(call.starts_with(crate::poc::key_renewal::REMOVE));
    assert!(
        matches!(tool, Tool::Exec {command, ..} if command == crate::poc::key_renewal::remove_command(&retirement.key))
    );
}

#[test]
fn poc_ai_key_renewal_retirement_failure_and_lost_response_resume_without_blind_delete() {
    use crate::poc::key_renewal::{RETIRE_FAILED, retire};
    use crate::store::ai_keys::RetirementState;
    for lost in [false, true] {
        let (mut runtime, task) = checked_renewal(true);
        runtime.service.delete_failure = !lost;
        runtime.service.delete_lost = lost;
        let error = block_on(retire(&mut RetireRuntime {
            runtime: &mut runtime,
            task: task.clone(),
            account: "operator",
        }))
        .unwrap_err();
        assert_eq!(error, RETIRE_FAILED);
        assert_eq!(
            runtime.store.ai_key_retirements_for(&task).unwrap().state,
            RetirementState::Failed
        );
        let paused = change(&mut runtime.store, &task, Change::Pause(error));
        assert_eq!(paused.view()["pause_reason"], RETIRE_FAILED);
        assert!(paused.verdict.is_none());
        runtime.store = reopen(&runtime.store);
        fresh(&mut runtime.store);
        runtime.service.list_failure = true;
        assert!(
            block_on(retire(&mut RetireRuntime {
                runtime: &mut runtime,
                task: paused.clone(),
                account: "operator"
            }))
            .is_err()
        );
        assert_eq!(
            runtime.service.deletes.len(),
            1,
            "failed read never authorizes a retry"
        );
        runtime.service.list_failure = false;
        runtime.service.delete_failure = false;
        runtime.service.delete_lost = false;
        block_on(retire(&mut RetireRuntime {
            runtime: &mut runtime,
            task: paused,
            account: "operator",
        }))
        .unwrap();
        assert_eq!(runtime.service.deletes.len(), if lost { 1 } else { 2 });
        for (index, event) in runtime.service.events.iter().enumerate() {
            if event.starts_with("DELETE") {
                assert_eq!(runtime.service.events[index - 1], "GET");
            }
        }
    }
}

#[test]
fn poc_ai_key_renewal_reload_mid_revoke_reconciles_pending() {
    use crate::poc::key_renewal::{RetirementRuntime, retire};
    use crate::store::ai_keys::RetirementState;
    for sent in [false, true] {
        let (mut runtime, task) = checked_renewal(true);
        let mut adapter = RetireRuntime {
            runtime: &mut runtime,
            task: task.clone(),
            account: "operator",
        };
        block_on(adapter.record(RetirementState::Pending)).unwrap();
        if sent {
            block_on(adapter.list()).unwrap();
            assert_eq!(block_on(adapter.delete("setup-key")).unwrap(), 200);
        }
        runtime.store = reopen(&runtime.store);
        assert_eq!(
            runtime.store.ai_key_retirements_for(&task).unwrap().state,
            RetirementState::Pending
        );
        fresh(&mut runtime.store);
        block_on(retire(&mut RetireRuntime {
            runtime: &mut runtime,
            task: task.clone(),
            account: "operator",
        }))
        .unwrap();
        assert_eq!(runtime.service.deletes, ["setup-key"]);
        let calls = runtime.service.events.len();
        block_on(retire(&mut RetireRuntime {
            runtime: &mut runtime,
            task,
            account: "operator",
        }))
        .unwrap();
        assert_eq!(
            runtime.service.events.len(),
            calls,
            "revoked record avoids another request"
        );
    }
}

#[test]
fn poc_ai_key_renewal_r3_unrelated_404_stays_failed_and_retries_fresh() {
    use crate::poc::key_renewal::{RETIRE_FAILED, next, retire};
    use crate::store::ai_keys::RetirementState;
    for omit_deleted_at in [false, true] {
        let (mut runtime, mut task) = checked_renewal(true);
        runtime.service.omit_deleted_at = omit_deleted_at;
        let completed = task.completed.clone();
        let old = runtime
            .store
            .ai_key_retirements_for(&task)
            .unwrap()
            .key
            .clone();
        for body in [
            b"".as_slice(),
            b"<html>Cannot DELETE /keys/setup-key</html>".as_slice(),
        ] {
            runtime.service.unrelated_delete_404 = Some(body);
            let error = block_on(retire(&mut RetireRuntime {
                runtime: &mut runtime,
                task: task.clone(),
                account: "operator",
            }))
            .unwrap_err();
            assert_eq!(error, RETIRE_FAILED);
            assert!(error.contains("old key's revocation is not confirmed"));
            assert_eq!(
                runtime.store.ai_key_retirements_for(&task).unwrap().state,
                RetirementState::Failed
            );
            assert!(
                !runtime.service.keys["setup-key"].2,
                "the issuer still holds the live key"
            );
            assert!(
                next(&runtime.store, &task).is_err(),
                "no old-file removal is dispatched"
            );
            task = change(&mut runtime.store, &task, Change::Pause(error));
            assert_eq!(task.completed, completed, "no removal outcome is recorded");
            assert!(task.pending.is_none());
            assert!(task.verdict.is_none());
            assert_eq!(
                runtime.store.ai_key_retirements_for(&task).unwrap().key,
                old
            );
            runtime.store = reopen(&runtime.store);
            fresh(&mut runtime.store);
        }
        assert_eq!(
            runtime.service.events,
            [
                "GET",
                "DELETE setup-key",
                "GET",
                "GET",
                "DELETE setup-key",
                "GET"
            ]
        );
        runtime.service.unrelated_delete_404 = None;
        block_on(retire(&mut RetireRuntime {
            runtime: &mut runtime,
            task: task.clone(),
            account: "operator",
        }))
        .unwrap();
        assert_eq!(&runtime.service.events[6..], ["GET", "DELETE setup-key"]);
        assert_eq!(
            runtime.store.ai_key_retirements_for(&task).unwrap().state,
            RetirementState::Revoked
        );
    }
}

#[test]
fn poc_ai_key_renewal_r3_complete_absence_and_delete_404_is_revoked() {
    let (mut runtime, task) = checked_renewal(true);
    runtime.service.keys.remove("setup-key");
    block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
        runtime: &mut runtime,
        task: task.clone(),
        account: "operator",
    }))
    .unwrap();
    assert_eq!(runtime.service.events, ["GET", "DELETE setup-key"]);
    assert_eq!(
        runtime.store.ai_key_retirements_for(&task).unwrap().state,
        crate::store::ai_keys::RetirementState::Revoked
    );
}

#[test]
fn poc_ai_key_renewal_r3_incomplete_absence_404_needs_confirmation() {
    use crate::store::ai_keys::RetirementState;
    for paginated in [false, true] {
        for confirmation in ["revoked", "live", "absent", "incomplete", "malformed"] {
            let (mut runtime, task) = checked_renewal(true);
            runtime.service.unrelated_delete_404 = Some(b"");
            let keys = (0..if paginated { 1 } else { 129 })
                .map(|i| json!({"_id":format!("extra-{i}"), "name":format!("extra-name-{i}")}))
                .collect::<Vec<_>>();
            let mut listing = json!({"status":"success", "data": keys});
            if paginated {
                listing["has_more"] = json!(true);
            }
            runtime.service.list_responses.push_back(listing.clone());
            let confirmed = match confirmation {
                "revoked" | "live" => {
                    listing["data"].as_array_mut().unwrap().push(json!({"_id":"setup-key", "name":runtime.service.keys["setup-key"].1, "deleted_at": if confirmation == "revoked" { json!("2026-11-22T00:00:00Z") } else { Value::Null }}));
                    listing
                }
                "absent" => json!({"status":"success", "data":[]}),
                "incomplete" => listing,
                _ => json!({"status":"success", "data":null}),
            };
            runtime.service.list_responses.push_back(confirmed);
            let result = block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
                runtime: &mut runtime,
                task: task.clone(),
                account: "operator",
            }));
            let revoked = matches!(confirmation, "revoked" | "absent");
            assert_eq!(
                result.is_ok(),
                revoked,
                "paginated={paginated}, confirmation={confirmation}"
            );
            assert_eq!(runtime.service.events, ["GET", "DELETE setup-key", "GET"]);
            assert_eq!(
                runtime.store.ai_key_retirements_for(&task).unwrap().state,
                if revoked {
                    RetirementState::Revoked
                } else {
                    RetirementState::Failed
                }
            );
            assert!(task.verdict.is_none());
        }
    }
}

#[test]
fn poc_ai_key_renewal_r3_delete_200_is_revoked() {
    let (mut runtime, task) = checked_renewal(true);
    block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
        runtime: &mut runtime,
        task: task.clone(),
        account: "operator",
    }))
    .unwrap();
    assert_eq!(runtime.service.events, ["GET", "DELETE setup-key"]);
    assert_eq!(
        runtime.store.ai_key_retirements_for(&task).unwrap().state,
        crate::store::ai_keys::RetirementState::Revoked
    );
}

#[test]
fn poc_ai_key_renewal_r2_missing_deleted_at_sends_delete() {
    let (mut runtime, task) = checked_renewal(true);
    runtime.service.omit_deleted_at = true;
    block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
        runtime: &mut runtime,
        task: task.clone(),
        account: "operator",
    }))
    .unwrap();
    assert_eq!(runtime.service.events, ["GET", "DELETE setup-key"]);
    assert_eq!(
        runtime.store.ai_key_retirements_for(&task).unwrap().state,
        crate::store::ai_keys::RetirementState::Revoked
    );
}

#[test]
fn poc_ai_key_renewal_r2_absent_id_sends_delete_for_200_and_404() {
    for absent_on_server in [false, true] {
        let (mut runtime, task) = checked_renewal(true);
        runtime.service.hide_old_from_list = true;
        if absent_on_server {
            runtime.service.keys.remove("setup-key");
        }
        block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
            runtime: &mut runtime,
            task: task.clone(),
            account: "operator",
        }))
        .unwrap();
        assert_eq!(runtime.service.events, ["GET", "DELETE setup-key"]);
        assert_eq!(
            runtime.store.ai_key_retirements_for(&task).unwrap().state,
            crate::store::ai_keys::RetirementState::Revoked
        );
    }
}

#[test]
fn poc_ai_key_renewal_r2_absent_id_failed_delete_remains_retryable() {
    let (mut runtime, task) = checked_renewal(true);
    runtime.service.hide_old_from_list = true;
    runtime.service.delete_failure = true;
    assert!(
        block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
            runtime: &mut runtime,
            task: task.clone(),
            account: "operator",
        }))
        .is_err()
    );
    assert_eq!(
        runtime.store.ai_key_retirements_for(&task).unwrap().state,
        crate::store::ai_keys::RetirementState::Failed
    );
    runtime.service.delete_failure = false;
    block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
        runtime: &mut runtime,
        task,
        account: "operator",
    }))
    .unwrap();
    assert_eq!(
        runtime.service.events,
        ["GET", "DELETE setup-key", "GET", "DELETE setup-key"]
    );
}

#[test]
fn poc_ai_key_renewal_r2_oversized_list_falls_back_to_delete() {
    let (mut runtime, task) = checked_renewal(true);
    for i in 0..129 {
        runtime.service.keys.insert(
            format!("extra-{i}"),
            ("operator".into(), format!("extra-name-{i}"), false),
        );
    }
    block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
        runtime: &mut runtime,
        task: task.clone(),
        account: "operator",
    }))
    .unwrap();
    assert_eq!(runtime.service.events, ["GET", "DELETE setup-key"]);
    assert_eq!(
        runtime.store.ai_key_retirements_for(&task).unwrap().state,
        crate::store::ai_keys::RetirementState::Revoked
    );
}

#[test]
fn poc_ai_key_renewal_r2_ended_session_recovers_same_task_and_retirement() {
    for pending_removal in [false, true] {
        let (mut runtime, mut task) = checked_renewal(true);
        if pending_removal {
            block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
                runtime: &mut runtime,
                task: task.clone(),
                account: "operator",
            }))
            .unwrap();
            let (call, tool, origin) =
                crate::poc::key_renewal::next(&runtime.store, &task).unwrap();
            let requesting = block_on(runtime.change(&task, Change::Request)).unwrap();
            let proposal =
                block_on(runtime.propose(&requesting, &task.start_session, call, tool, origin))
                    .unwrap();
            append(&mut runtime.store, &proposal, &task.start_session);
            task = runtime.store.poc_task(&task.id).unwrap();
        } else {
            runtime.service.delete_failure = true;
            assert!(
                block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
                    runtime: &mut runtime,
                    task: task.clone(),
                    account: "operator",
                }))
                .is_err()
            );
            runtime.service.delete_failure = false;
        }
        let retirement = runtime.store.ai_key_retirements_for(&task).unwrap().clone();
        let key_requests = runtime.service.requests;
        assert!(
            runtime
                .store
                .project_poc(
                    runtime.store.next,
                    &Record::TakeOverRenewal {
                        id: task.id.clone(),
                        expected: task.revision,
                        session: task.start_session.clone(),
                    }
                )
                .is_err(),
            "a live session's renewal cannot be taken over"
        );
        block_on(runtime.store.end_session(&task.start_session)).unwrap();
        runtime.store = reopen(&runtime.store);
        let session = fresh(&mut runtime.store);
        // A normal new session has its own goal and acceptance before Renew AI key.
        block_on(
            runtime
                .store
                .enter_goal(&session, "Keep Hermes working".into(), None),
        )
        .unwrap();
        assert!(
            runtime
                .store
                .project_poc(
                    runtime.store.next,
                    &Record::TakeOverRenewal {
                        id: task.id.clone(),
                        expected: task.revision + 1,
                        session: session.clone(),
                    }
                )
                .is_err(),
            "stale takeover must not change authority"
        );
        let recovered = block_on(runtime.store.poc_renew_ai_key(
            &task.machine,
            &session,
            &"b".repeat(48),
        ))
        .unwrap();
        assert_eq!(recovered.id, task.id);
        assert_eq!(
            recovered.start_session, session,
            "Renew must take over the ended session's task"
        );
        assert_eq!(recovered.revision, task.revision + 1);
        // The page's Renew handler continues the recovered task instead of
        // rejecting a second key-creation decision after the key was installed.
        assert_eq!(
            block_on(runtime.store.poc_renew_ai_key_decision(
                recovered.clone(),
                Change::AiKeyDecision {
                    create: true,
                    approved_cap: None,
                    approved_policy: None,
                }
            ))
            .unwrap(),
            recovered
        );
        assert_eq!(recovered.pending, task.pending);
        assert_eq!(recovered.proposal, task.proposal);
        assert_eq!(recovered.completed, task.completed);
        assert_eq!(
            runtime.store.ai_key_retirements_for(&recovered),
            Some(&retirement)
        );
        runtime
            .store
            .check_task_session(&recovered, &session)
            .unwrap();
        runtime
            .store
            .poc_authority(&recovered.id, &session)
            .unwrap();
        assert!(
            runtime
                .store
                .check_task_session(&task, &task.start_session)
                .is_err()
        );
        let duplicate = block_on(runtime.store.poc_renew_ai_key(
            &task.machine,
            &session,
            &"c".repeat(48),
        ))
        .unwrap();
        assert_eq!(duplicate, recovered, "never create a second live renewal");
        runtime.store = reopen(&runtime.store);
        fresh(&mut runtime.store);
        assert_eq!(runtime.store.poc_task(&task.id).unwrap(), recovered);
        let completed = if pending_removal {
            evidence(
                &mut runtime.store,
                &recovered,
                record(&recovered, Some(0), ""),
            );
            block_on(run::resume(
                &mut runtime,
                &mut run::Unconfigured,
                &recovered.id,
                &session,
            ))
            .unwrap()
        } else {
            finish_retirement(&mut runtime, &recovered)
        };
        assert_eq!(completed.status, Status::Complete);
        assert_eq!(
            runtime.service.requests, key_requests,
            "takeover must not mint again"
        );
        assert_eq!(
            runtime
                .service
                .deletes
                .iter()
                .filter(|id| *id == "setup-key")
                .count(),
            if pending_removal { 1 } else { 2 }
        );
        let next = block_on(runtime.store.poc_renew_ai_key(
            &task.machine,
            &session,
            &"d".repeat(48),
        ))
        .unwrap();
        assert_ne!(next.id, recovered.id, "future renewals are unblocked");
        assert_ne!(
            runtime
                .store
                .ai_key_retirements_for(&next)
                .unwrap()
                .key
                .record_id,
            retirement.key.record_id
        );
        assert_eq!(reopen(&runtime.store).poc, runtime.store.poc);
    }
}

#[test]
fn poc_ai_key_renewal_fixed_command_removes_only_old_file() {
    let (runtime, task) = checked_renewal(true);
    let mut key = runtime
        .store
        .ai_key_retirements_for(&task)
        .unwrap()
        .key
        .clone();
    let directory = std::env::current_dir()
        .unwrap()
        .join("target")
        .join(format!(
            "renewkey-files-{}",
            hex::encode(random::<8>().unwrap())
        ));
    std::fs::create_dir_all(&directory).unwrap();
    let old = directory.join("old-key");
    let new = directory.join("new-key");
    std::fs::write(&old, "synthetic old key").unwrap();
    std::fs::write(&new, "synthetic new key").unwrap();
    key.path = old.to_str().unwrap().into();
    let command = crate::poc::key_renewal::remove_command(&key);
    assert!(
        std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .status()
            .unwrap()
            .success()
    );
    assert!(!old.exists());
    assert!(new.exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn poc_ai_key_renewal_legacy_journal_keeps_check_completion_unchanged() {
    let (runtime, task) = legacy_renewal();
    let (runtime, task) = complete_renewal_check(runtime, &task, true);
    assert_eq!(
        task.template.as_deref(),
        Some(crate::poc::key_renewal::LEGACY_ID)
    );
    assert_eq!(task.status, Status::Complete);
    assert_eq!(
        task.verdict.as_deref(),
        Some("Hermes's AI key was renewed. The Hermes check passed.")
    );
    assert_eq!(task.completed.len(), 6);
    let replayed = reopen(&runtime.store);
    assert_legacy_replacement(&replayed, &task);
    assert_eq!(replayed.poc, runtime.store.poc);
    assert!(replayed.ai_key_retirements.is_empty());
    assert_eq!(
        replayed.poc_targets_view(),
        runtime.store.poc_targets_view()
    );
    assert_eq!(runtime.service.requests, 1);
}

#[test]
fn poc_ai_key_renewal_retirement_rejects_new_or_other_issuer_and_active_users() {
    use crate::store::ai_keys::RetirementState;
    let (mut runtime, task) = checked_renewal(true);
    let new = runtime.store.poc_targets[&task.machine]
        .application_inference_keys
        .last()
        .unwrap()
        .record_id
        .clone();
    for issuer_id in [new, "another-machines-key".into()] {
        assert!(
            block_on(runtime.store.ai_key_commit(KeyRecord::Retirement {
                task: task.id.clone(),
                issuer_id,
                state: RetirementState::Pending,
            }))
            .is_err()
        );
    }
    let old_path = runtime
        .store
        .ai_key_retirements_for(&task)
        .unwrap()
        .key
        .path
        .clone();
    let mut goal = runtime
        .store
        .poc
        .values()
        .find(|other| other.id != task.id && other.start_session == task.start_session)
        .unwrap()
        .clone();
    goal.proposal = Some(Proposal {
        call_id: "other-user".into(),
        tool: Tool::Exec {
            machine: task.machine.clone(),
            command: format!("cat '{old_path}'"),
        },
        check: None,
        report: None,
    });
    runtime.store.poc.insert(goal.id.clone(), goal.clone());
    assert!(
        block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
            runtime: &mut runtime,
            task: task.clone(),
            account: "operator"
        }))
        .is_err()
    );
    assert!(runtime.service.deletes.is_empty());
    runtime.store.poc.get_mut(&goal.id).unwrap().status = Status::Complete;
    // Stale work cannot revoke after Stop task or another task change.
    let _ = change(&mut runtime.store, &task, Change::Abandon);
    assert!(
        block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
            runtime: &mut runtime,
            task,
            account: "operator"
        }))
        .is_err()
    );
    assert!(runtime.service.deletes.is_empty());
}

#[test]
fn poc_ai_key_renewal_fake_credit_delete_enforces_account_scope() {
    use crate::poc::key_renewal::RetirementRuntime;
    let (mut runtime, task) = checked_renewal(true);
    let mut adapter = RetireRuntime {
        runtime: &mut runtime,
        task,
        account: "another-account",
    };
    block_on(adapter.record(crate::store::ai_keys::RetirementState::Pending)).unwrap();
    assert!(
        block_on(adapter.delete("key-1")).is_err(),
        "the adapter never accepts the new key's id"
    );
    assert_eq!(block_on(adapter.delete("setup-key")).unwrap(), 403);
    assert_eq!(runtime.service.deletes, ["setup-key"]);
    assert!(!runtime.service.keys["setup-key"].2);
}

#[test]
fn poc_ai_key_renewal_remove_failure_pauses_and_resume_retries_with_new_job() {
    use crate::poc::key_renewal::{REMOVE_FAILED, next, retire};
    let (mut runtime, task) = checked_renewal(true);
    block_on(retire(&mut RetireRuntime {
        runtime: &mut runtime,
        task: task.clone(),
        account: "operator",
    }))
    .unwrap();
    let (first, tool, origin) = next(&runtime.store, &task).unwrap();
    let requesting = block_on(runtime.change(&task, Change::Request)).unwrap();
    let proposal = block_on(runtime.propose(
        &requesting,
        &task.start_session,
        first.clone(),
        tool,
        origin,
    ))
    .unwrap();
    append(&mut runtime.store, &proposal, &task.start_session);
    let pending = runtime.store.poc_task(&task.id).unwrap();
    let identity = pending.pending.clone();
    // Reload with the recorded removal outstanding: collect, never relaunch.
    runtime.store = reopen(&runtime.store);
    fresh(&mut runtime.store);
    assert_eq!(runtime.store.poc_task(&task.id).unwrap().pending, identity);
    evidence(&mut runtime.store, &pending, record(&pending, Some(1), ""));
    let paused = block_on(run::resume(
        &mut runtime,
        &mut run::Unconfigured,
        &task.id,
        &task.start_session,
    ))
    .unwrap();
    assert_eq!(paused.status, Status::Paused);
    assert_eq!(paused.pause_reason.as_deref(), Some(REMOVE_FAILED));
    assert!(paused.verdict.is_none());
    let (retry, _, _) = next(&runtime.store, &paused).unwrap();
    assert_ne!(
        retry, first,
        "only a known terminal failure permits another removal job"
    );
    assert_eq!(runtime.service.deletes, ["setup-key"]);
}

fn finish_retirement(runtime: &mut MintRuntime, task: &Task) -> Task {
    block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
        runtime,
        task: task.clone(),
        account: "operator",
    }))
    .unwrap();
    let (call, tool, origin) = crate::poc::key_renewal::next(&runtime.store, task).unwrap();
    let requesting = block_on(runtime.change(task, Change::Request)).unwrap();
    let proposal =
        block_on(runtime.propose(&requesting, &task.start_session, call, tool, origin)).unwrap();
    append(&mut runtime.store, &proposal, &task.start_session);
    let pending = runtime.store.poc_task(&task.id).unwrap();
    evidence(&mut runtime.store, &pending, record(&pending, Some(0), ""));
    block_on(run::resume(
        runtime,
        &mut run::Unconfigured,
        &task.id,
        &task.start_session,
    ))
    .unwrap()
}

#[test]
fn poc_ai_key_renewal_next_renewal_replaces_newest_installed_key() {
    let (mut runtime, task) = checked_renewal(true);
    let new = runtime
        .store
        .installed_hermes_key(&task.machine)
        .unwrap()
        .clone();
    assert_ne!(new.record_id, "setup-key");
    let completed = finish_retirement(&mut runtime, &task);
    assert_eq!(completed.status, Status::Complete);
    let next = block_on(runtime.store.poc_renew_ai_key(
        &task.machine,
        &task.start_session,
        &"b".repeat(48),
    ))
    .unwrap();
    assert_eq!(
        runtime.store.ai_key_retirements_for(&next).unwrap().key,
        new
    );
    let replayed = reopen(&runtime.store);
    assert_eq!(
        replayed.ai_key_retirements,
        runtime.store.ai_key_retirements
    );
}

#[test]
fn poc_ai_key_renewal_card_shows_failure_retry_progress_and_success_offline() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let (mut runtime, task) = checked_renewal(true);
    runtime.service.unrelated_delete_404 = Some(b"<html>Cannot DELETE</html>");
    let error = block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
        runtime: &mut runtime,
        task: task.clone(),
        account: "operator",
    }))
    .unwrap_err();
    let paused = change(&mut runtime.store, &task, Change::Pause(error));
    let check_page = |store: &Store<MemoryStorage>, task: &Task, sentence: &str| {
        let payload = json!({"state":"unlocked", "seed_backup_stage":"inactive", "renewalProbe":true,
            "expectedSentence":sentence, "setup":store.dispatch.setup_view(), "sessions":store.sessions(),
            "tasks":[store.poc_task_view(task)]});
        let mut probe = Command::new("node")
            .args([
                "--experimental-vm-modules",
                "-e",
                include_str!("../page-probe.cjs"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        probe
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        let output = probe.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    check_page(
        &runtime.store,
        &paused,
        crate::poc::key_renewal::RETIRE_FAILED,
    );
    runtime.service.unrelated_delete_404 = None;
    block_on(crate::poc::key_renewal::retire(&mut RetireRuntime {
        runtime: &mut runtime,
        task: paused.clone(),
        account: "operator",
    }))
    .unwrap();
    check_page(
        &runtime.store,
        &paused,
        "The old key was revoked. Its file still needs removal. Resume collects any recorded removal job before continuing.",
    );
    let complete = finish_retirement(&mut runtime, &paused);
    assert_eq!(complete.status, Status::Complete);
    check_page(&runtime.store, &complete, crate::poc::key_renewal::SUCCESS);
}

#[test]
fn poc_ai_key_renewal_legacy_resume_records_upgrade_without_losing_pending_job() {
    let (mut runtime, task) = legacy_renewal();
    let created = block_on(run::resume(
        &mut runtime,
        &mut run::Unconfigured,
        &task.id,
        &task.start_session,
    ))
    .unwrap();
    let (call, tool, origin) = crate::poc::key_renewal::next(&runtime.store, &created).unwrap();
    let requesting = block_on(runtime.change(&created, Change::Request)).unwrap();
    let proposed =
        block_on(runtime.propose(&requesting, &task.start_session, call, tool, origin)).unwrap();
    append(&mut runtime.store, &proposed, &task.start_session);
    let before = runtime.store.poc_task(&task.id).unwrap();
    runtime.store = reopen(&runtime.store);
    assert_legacy_replacement(&runtime.store, &task);
    assert_eq!(
        runtime.store.poc_task(&task.id).unwrap(),
        before,
        "opening a historical journal never upgrades it"
    );
    fresh(&mut runtime.store);
    let upgraded = block_on(runtime.store.prepare_key_retirement(&before)).unwrap();
    assert_eq!(
        upgraded.template.as_deref(),
        Some(crate::poc::key_renewal::ID)
    );
    assert_eq!(upgraded.revision, before.revision + 1);
    assert_eq!(upgraded.completed, before.completed);
    assert_eq!(upgraded.pending, before.pending);
    assert_eq!(upgraded.proposal, before.proposal);
    assert_eq!(
        runtime
            .store
            .ai_key_retirements_for(&upgraded)
            .unwrap()
            .key
            .record_id,
        "setup-key"
    );
    let replayed = reopen(&runtime.store);
    assert_legacy_replacement(&replayed, &task);
    assert_eq!(replayed.poc_task(&task.id).unwrap(), upgraded);
    assert_eq!(
        replayed.ai_key_retirements,
        runtime.store.ai_key_retirements
    );
    evidence(
        &mut runtime.store,
        &upgraded,
        record(&upgraded, Some(0), ""),
    );
    let collected = block_on(run::resume(
        &mut runtime,
        &mut run::Unconfigured,
        &task.id,
        &task.start_session,
    ))
    .unwrap();
    assert!(collected.pending.is_none());
    assert_eq!(collected.completed.len(), 2);
    assert_eq!(
        &collected.completed[..before.completed.len()],
        before.completed.as_slice()
    );
    assert_eq!(
        collected.completed[1].0,
        before.proposal.as_ref().unwrap().call_id
    );
    assert!(
        runtime.service.deletes.is_empty(),
        "upgrading does not revoke before CHECK"
    );
    let mut current = collected;
    loop {
        let (call, tool, origin) = crate::poc::key_renewal::next(&runtime.store, &current).unwrap();
        let checking = call == crate::poc::key_renewal::CHECK;
        let stdout = if checking {
            "CHECKS hermes PASS"
        } else if call.starts_with(crate::poc::key_renewal::WAIT) {
            "REBUILD OK fixture"
        } else {
            ""
        };
        let requesting = block_on(runtime.change(&current, Change::Request)).unwrap();
        let proposal =
            block_on(runtime.propose(&requesting, &task.start_session, call, tool, origin))
                .unwrap();
        append(&mut runtime.store, &proposal, &task.start_session);
        let pending = runtime.store.poc_task(&task.id).unwrap();
        evidence(
            &mut runtime.store,
            &pending,
            record(&pending, Some(0), stdout),
        );
        current = block_on(run::resume(
            &mut runtime,
            &mut run::Unconfigured,
            &task.id,
            &task.start_session,
        ))
        .unwrap();
        if checking {
            break;
        }
    }
    assert!(
        !current.ended(),
        "an upgraded legacy task cannot finish at CHECK"
    );
    let complete = finish_retirement(&mut runtime, &current);
    assert_eq!(
        complete.verdict.as_deref(),
        Some(crate::poc::key_renewal::SUCCESS)
    );
    assert_eq!(runtime.service.deletes, ["setup-key"]);
    assert_eq!(runtime.service.requests, 1);
}
