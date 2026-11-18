//! Durable browser execution through configured inference and stored connection authority.
use super::run::{self, Observation, Runtime};
use crate::binding::Session;
use crate::dispatch::{Approval, Intent, Terminal};
use crate::harness::{AppendRefusal, BoundJournal, Entry, Journal, PinSource, Target};
use crate::store::poc::{Binding, Change, Status, Task};
use crate::worker::{StoreJournal, local};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use wasm_bindgen::JsCast;
pub(crate) type Response = Rc<RefCell<Option<crate::poc::inference::CommandResponse>>>;

#[derive(PartialEq, Eq)]
struct Progress {
    generation: u64,
    session: String,
    revision: u64,
    status: Status,
    pending: bool,
    proposal: bool,
    requesting: bool,
}

thread_local! {
    static WAKING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static WAKE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LAST_PROGRESS: RefCell<BTreeMap<String, Progress>> = const { RefCell::new(BTreeMap::new()) };
}

#[wasm_bindgen::prelude::wasm_bindgen]
pub fn wake_tasks() {
    wake();
}

pub(crate) fn wake_task(id: &str) {
    let id = id.to_owned();
    wasm_bindgen_futures::spawn_local(async move {
        let candidate = {
            let local = local();
            let mut writer = local.lock().await;
            if writer.dispatch_refusal().is_some() || crate::lifecycle::owner().ordinary().is_err()
            {
                None
            } else {
                writer.store().and_then(|store| {
                    store
                        .eligible_tasks()
                        .into_iter()
                        .find(|task| task.id == id)
                })
            }
        };
        if let Some(task) = candidate {
            if run::defer_if_active(&task.id) {
                return;
            }
            let generation = crate::harness::inference::publication_generation();
            let response = Response::default();
            let report = request_with_mode(
                serde_json::json!({"action":"resume","id":task.id,"session":task.start_session})
                    .to_string(),
                response.clone(),
                true,
            )
            .await;
            let _response = response.borrow_mut().take();
            crate::harness::inference::publish_report(generation, task.start_session, report).await;
        }
    });
}

pub(crate) fn wake() {
    WAKE.set(true);
    if WAKING.replace(true) {
        return;
    }
    wasm_bindgen_futures::spawn_local(async {
        while WAKE.replace(false) {
            let candidates = {
                let local = local();
                let mut writer = local.lock().await;
                if writer.dispatch_refusal().is_some()
                    || crate::lifecycle::owner().ordinary().is_err()
                {
                    Vec::new()
                } else if let Some(store) = writer.store() {
                    store.eligible_tasks()
                } else {
                    Vec::new()
                }
            };
            for task in candidates {
                if run::defer_if_active(&task.id) {
                    continue;
                }
                let generation = crate::harness::inference::publication_generation();
                let session = task.start_session.clone();
                let response = Response::default();
                let report = request_with_mode(
                    serde_json::json!({"action":"resume","id":task.id,"session":session})
                        .to_string(),
                    response.clone(),
                    true,
                )
                .await;
                let _response = response.borrow_mut().take();
                crate::harness::inference::publish_report(generation, session, report).await;
            }
        }
        WAKING.set(false);
    });
}

pub(crate) async fn publish_progress(session: &str) {
    publish_cycle_progress(session, None).await;
}

async fn publish_cycle_progress(session: &str, cycle: Option<u64>) {
    let _timing = super::timings::Timer::new(cycle, super::timings::Mark::Progress);
    let generation = crate::harness::inference::publication_generation();
    #[cfg(feature = "tracer")]
    crate::testonly::session_point("poc_progress_publication").await;
    crate::harness::inference::publish_report_timed(generation, session.into(), "{}".into(), cycle)
        .await;
}

pub(crate) async fn resume_with(
    task: &Task,
    session: &str,
    target: &Target,
    pins: &impl PinSource,
    model: &mut impl run::Model,
    response: Response,
    continuation: crate::lifecycle::Continuation,
) -> Result<Task, String> {
    {
        let local = local();
        let mut writer = local.lock().await;
        continuation.check()?;
        writer
            .store()
            .ok_or(crate::poc::wait::LOCKED)?
            .check_task_session(task, session)?;
    }
    let mut runtime = Web {
        target,
        pins,
        response,
        session,
        continuation,
    };
    run::drive(&mut runtime, model, &task.id, session).await
}

struct Web<'a, P> {
    response: Response,
    target: &'a Target,
    pins: &'a P,
    session: &'a str,
    continuation: crate::lifecycle::Continuation,
}
impl<P: PinSource> Runtime for Web<'_, P> {
    async fn progress(&mut self, task: &Task) {
        if self.continuation.check().is_err() {
            return;
        }
        if task.pending.is_some() {
            self.response
                .borrow_mut()
                .get_or_insert_with(crate::poc::inference::CommandResponse::reserve);
        }
        let progress = Progress {
            generation: crate::harness::inference::publication_generation(),
            session: self.session.into(),
            revision: task.revision,
            status: task.status,
            pending: task.pending.is_some(),
            proposal: task.proposal.is_some(),
            requesting: task.requesting,
        };
        if LAST_PROGRESS.with_borrow(|last| last.get(&task.id) == Some(&progress)) {
            return;
        }
        publish_cycle_progress(self.session, super::timings::recording(&task.id)).await;
        // Worker-local only; other publication paths never populate this memory.
        if self.continuation.check().is_ok() {
            LAST_PROGRESS.with_borrow_mut(|last| last.insert(task.id.clone(), progress));
        }
    }
    async fn load(&mut self, id: &str) -> Result<Task, String> {
        local()
            .lock()
            .await
            .store()
            .ok_or(crate::poc::wait::LOCKED)?
            .poc_task(id)
    }
    async fn authority(&mut self, id: &str, session: &str) -> Result<(), String> {
        let local = local();
        let mut writer = local.lock().await;
        self.continuation.check()?;
        if let Some(why) = writer.dispatch_refusal() {
            return Err(why.into());
        }
        writer
            .store()
            .ok_or(crate::poc::wait::LOCKED)?
            .poc_authority(id, session)
            .map(|_| ())
    }
    async fn change(&mut self, task: &Task, change: Change) -> Result<Task, String> {
        if task.pending.is_some() {
            super::timings::resume(task);
        }
        let local = local();
        let mut writer = local.lock().await;
        self.continuation.check()?;
        let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
        store.check_task_session(task, self.session)?;
        let changed = store.poc_change(&task.id, task.revision, change).await?;
        self.continuation.check()?;
        drop(writer);
        Ok(changed)
    }
    async fn prepare(&mut self, task: &Task, session: &str) -> Result<Task, String> {
        let local = local();
        let mut writer = local.lock().await;
        self.continuation.check()?;
        let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
        store.check_task_session(task, session)?;
        store.poc_prepare_next(task, session).await
    }
    async fn propose(
        &mut self,
        task: &Task,
        session: &str,
        call_id: String,
        tool: crate::goals::Tool,
    ) -> Result<Task, String> {
        let local = local();
        let mut writer = local.lock().await;
        self.continuation.check()?;
        let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
        let changed = store.poc_propose(task, session, call_id, tool).await?;
        drop(writer);
        Ok(changed)
    }

    async fn execute(&mut self, binding: Binding, task: &Task) -> Result<(), String> {
        super::timings::resume(task);
        self.response
            .borrow_mut()
            .get_or_insert_with(crate::poc::inference::CommandResponse::reserve);
        {
            let local = local();
            let mut writer = local.lock().await;
            self.continuation.check()?;
            writer
                .store()
                .ok_or(crate::poc::wait::LOCKED)?
                .poc_prepare_execution(task, &binding.session)?;
        }
        if self.target.machine != task.machine {
            return Err(crate::poc::wait::TARGET_DIFFERS.into());
        }
        if self.target.relay.is_empty()
            || self.target.host.is_empty()
            || self.target.user.is_empty()
        {
            return Err(crate::poc::wait::TARGET_REQUIRED.into());
        }
        if self.pins.pin(&task.machine).is_none() {
            return Err(crate::poc::wait::PIN_REQUIRED.into());
        }
        let origin = local()
            .lock()
            .await
            .store()
            .ok_or(crate::poc::wait::LOCKED)?
            .poc_authority(&task.id, &binding.session)?;
        let proposal = task.proposal.as_ref().ok_or("missing command proposal")?;
        let (command, input) = match &proposal.tool {
            crate::goals::Tool::Exec { command, .. } => (command.clone(), None),
            crate::goals::Tool::RequestAiKey { .. } => {
                if !crate::poc::credit::browser::prepare_ai_key(task).await? {
                    return Ok(());
                }
                let local = local();
                let mut writer = local.lock().await;
                self.continuation.check()?;
                let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
                store.check_task_session(task, &binding.session)?;
                let entry = store
                    .ai_key(&task.id, &proposal.call_id)
                    .ok_or("AI key custody missing")?;
                let key = entry.key.as_ref().ok_or("AI key custody missing")?;
                (
                    crate::store::ai_keys::command(&entry.path, key.0.len()),
                    Some(zeroize::Zeroizing::new(key.0.as_bytes().to_vec())),
                )
            }
            _ => return Err("command required".into()),
        };
        let mut journal = ScopedJournal {
            base: StoreJournal {
                local: local(),
                unavailable: false,
            },
            binding,
            origin: origin.clone(),
            collecting: false,
            continuation: self.continuation.clone(),
        };
        let result = crate::harness::run_command_input(
            self.pins,
            &mut journal,
            self.target,
            command.as_bytes(),
            input.as_deref().map(Vec::as_slice),
            Some(&origin),
            #[cfg(feature = "tracer")]
            false,
        )
        .await;
        #[cfg(feature = "tracer")]
        crate::testonly::session_point("poc_execution_return").await;
        match result {
            Ok(_) => Ok(()),
            Err(why) => Err(local()
                .lock()
                .await
                .store()
                .ok_or(crate::poc::wait::LOCKED)?
                .poc_refusal(&why.to_json())),
        }
    }
    async fn observe(&mut self, task: &Task, session: &str) -> Result<Observation, String> {
        self.response
            .borrow_mut()
            .get_or_insert_with(crate::poc::inference::CommandResponse::reserve);
        if let Some(observation) = committed(task, &self.continuation).await? {
            return Ok(observation);
        }
        if self.target.machine != task.machine {
            return Err(crate::poc::wait::TARGET_DIFFERS.into());
        }
        if self.target.relay.is_empty()
            || self.target.host.is_empty()
            || self.target.user.is_empty()
        {
            return Err(crate::poc::wait::TARGET_REQUIRED.into());
        }
        if self.pins.pin(&task.machine).is_none() {
            return Err(crate::poc::wait::PIN_REQUIRED.into());
        }
        let origin = local()
            .lock()
            .await
            .store()
            .ok_or(crate::poc::wait::LOCKED)?
            .poc_authority(&task.id, session)?;
        let mut journal = ScopedJournal {
            base: StoreJournal {
                local: local(),
                unavailable: false,
            },
            binding: Binding {
                task: task.id.clone(),
                revision: task.revision,
                session: session.into(),
            },
            origin,
            collecting: true,
            continuation: self.continuation.clone(),
        };
        publish_cycle_progress(session, super::timings::active(&task.id)).await;
        let collect_timing = super::timings::Timer::new(
            super::timings::active(&task.id),
            super::timings::Mark::Collect,
        );
        let result = crate::harness::collect_jobs(
            self.pins,
            &mut journal,
            self.target,
            #[cfg(feature = "tracer")]
            false,
        )
        .await;
        drop(collect_timing);
        if let Some(observation) = committed(task, &self.continuation).await? {
            return Ok(observation);
        }
        let local = local();
        let mut writer = local.lock().await;
        let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
        let pending = task
            .pending
            .as_ref()
            .ok_or(crate::poc::wait::MISSING_PENDING_JOB)?;
        let call = pending.call;
        match result {
            Ok(reports) => Ok(Observation::Unknown(
                store.poc_collection_reason(pending, &reports),
            )),
            Err(why) => Err(crate::poc::wait::COLLECTION_FAILED.render(
                call,
                "",
                &store.poc_refusal(&why.to_json()),
            )),
        }
    }
}
async fn committed(
    task: &Task,
    continuation: &crate::lifecycle::Continuation,
) -> Result<Option<Observation>, String> {
    let local = local();
    let mut writer = local.lock().await;
    let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
    let pending = task
        .pending
        .as_ref()
        .ok_or(crate::poc::wait::MISSING_PENDING_IDENTITY)?;
    let Some(report) = store.poc_committed(pending).cloned() else {
        return Ok(None);
    };
    let Some(observation) = run::committed_observation(&report) else {
        return Ok(None);
    };

    let mut value = serde_json::json!({"command_result":report});
    if task
        .proposal
        .as_ref()
        .is_some_and(|proposal| proposal.report.is_some())
    {
        value["command_result"]["optional_report"] = true.into();
    }
    let mut safe = store.protect_publication(&value, &[])?;
    if store.current_command_results(&mut safe) {
        safe = store.protect_publication(&safe, &[])?;
    }
    let worker: web_sys::DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    loop {
        if continuation.check().is_err() && safe["historical"] != true {
            crate::jobs::historical(&mut safe, "stale result after suspension");
            safe = store.protect_publication(&safe, &[])?;
        }
        let encoded = safe.to_string();
        store.check_output_bytes(encoded.as_bytes())?;
        let message =
            js_sys::JSON::parse(&encoded).map_err(|_| crate::poc::wait::RESULT_ENCODING)?;
        if store.current_command_results(&mut safe) {
            safe = store.protect_publication(&safe, &[])?;
            continue;
        }
        // The same writer and response reservation cover scanning, encoding and post.
        worker
            .post_message(&message)
            .map_err(|_| crate::poc::wait::RESULT_PUBLICATION)?;
        break;
    }
    Ok(Some(observation))
}

/// This isolated adapter owns one task/step binding; no ambient tag can leak across awaits.
struct ScopedJournal {
    base: StoreJournal,
    binding: Binding,
    origin: Rc<Session>,
    collecting: bool,
    continuation: crate::lifecycle::Continuation,
}
impl Journal for ScopedJournal {
    async fn check_signature(
        &mut self,
        machine: &str,
        command: &[u8],
    ) -> Result<(), AppendRefusal> {
        self.base.check_signature(machine, command).await
    }
    async fn check(&self, machine: &str) -> Result<(), AppendRefusal> {
        let local = local();
        let mut writer = local.lock().await;
        self.continuation.check().map_err(AppendRefusal::Storage)?;
        if let Some(why) = writer.dispatch_refusal() {
            return Err(AppendRefusal::Storage(why.into()));
        }
        writer
            .store()
            .ok_or_else(|| AppendRefusal::Storage(crate::poc::wait::LOCKED.into()))?
            .poc_check_command(&self.binding, machine)
            .await
    }
    async fn append(&mut self, _: &Entry, _: &Approval) -> Result<u64, AppendRefusal> {
        Err(AppendRefusal::Storage(
            "task commands require bound append".into(),
        ))
    }
    async fn terminal(&mut self, terminal: &Terminal) -> Result<u64, String> {
        self.base.terminal(terminal).await
    }
    async fn read(&self, seq: u64) -> Option<Entry> {
        self.base.read(seq).await
    }
    async fn intent(&self, call: u64) -> Option<Intent> {
        self.base.intent(call).await
    }
    async fn collectable(&self, machine: &str) -> Result<Vec<Intent>, String> {
        let pending = local()
            .lock()
            .await
            .store()
            .ok_or(crate::poc::wait::LOCKED)?
            .poc_task(&self.binding.task)?
            .pending
            .ok_or("no pending task job")?;
        Ok(self
            .base
            .collectable(machine)
            .await?
            .into_iter()
            .filter(|i| i.call == pending.call && i.job.as_ref() == Some(&pending.job))
            .collect())
    }
    async fn job_evidence(
        &mut self,
        evidence: &crate::jobs::Evidence,
    ) -> Result<crate::jobs::Report, String> {
        self.base.job_evidence(evidence).await
    }
    async fn job_evidence_unless_stopped(
        &mut self,
        evidence: &crate::jobs::Evidence,
        stop: &crate::harness::Stop,
    ) -> Option<Result<crate::jobs::Report, String>> {
        self.base.job_evidence_unless_stopped(evidence, stop).await
    }
}
impl BoundJournal for ScopedJournal {
    fn command_cycle(&self) -> Option<u64> {
        super::timings::active(&self.binding.task)
    }
    async fn append_bound(
        &mut self,
        session: &Session,
        entry: &Entry,
        approval: &Approval,
    ) -> Result<u64, AppendRefusal> {
        run::commit_command(
            async {
                let local = local();
                let mut writer = local.lock().await;
                self.continuation.check().map_err(AppendRefusal::Storage)?;
                if let Some(why) = writer.dispatch_refusal() {
                    return Err(AppendRefusal::Storage(why.into()));
                }
                let store = writer
                    .store()
                    .ok_or_else(|| AppendRefusal::Storage(crate::poc::wait::LOCKED.into()))?;
                store
                    .check_current_session(session)
                    .map_err(AppendRefusal::Storage)?;
                if self.collecting
                    || !std::ptr::eq(session, self.origin.as_ref())
                    || session.identity != self.binding.session
                {
                    return Err(AppendRefusal::Storage("stale task session".into()));
                }
                store.poc_append(&self.binding, entry, approval).await
            },
            publish_cycle_progress(&self.binding.session, self.command_cycle()),
        )
        .await
    }
    async fn current(&self, session: &Session) -> Result<(), String> {
        self.base.current(session).await?;
        if !std::ptr::eq(session, self.origin.as_ref()) {
            return Err("stale task session".into());
        }
        let local = local();
        let mut writer = local.lock().await;
        self.continuation.check()?;
        if let Some(why) = writer.dispatch_refusal() {
            return Err(why.into());
        }
        let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
        if self.collecting {
            store.poc_authority(&self.binding.task, &self.binding.session)?;
            if store.poc_task(&self.binding.task)?.revision != self.binding.revision {
                return Err("stale task collection".into());
            }
            Ok(())
        } else {
            store.poc_binding_current(&self.binding)
        }
    }
    async fn release(&self, value: Value) -> Result<Value, String> {
        self.base.release(value).await
    }
    async fn uncommitted(
        &self,
        evidence: &crate::jobs::Evidence,
        machine: &str,
        command: &str,
    ) -> Result<crate::jobs::Report, String> {
        self.base.uncommitted(evidence, machine, command).await
    }
    async fn connection_session(
        &mut self,
        machine: &str,
        _: Option<&Rc<Session>>,
    ) -> Result<Rc<Session>, crate::binding::AdmissionRefusal> {
        self.current(&self.origin)
            .await
            .map_err(crate::binding::AdmissionRefusal::Journal)?;
        self.base
            .connection_session(machine, Some(&self.origin))
            .await
    }
    async fn relay_key(&self) -> Option<crate::credential::RelayKey> {
        self.base.relay_key().await
    }
}

pub(crate) async fn request(request: String) -> String {
    request_with(request, Response::default()).await
}
pub(crate) async fn request_with(request: String, response: Response) -> String {
    request_with_mode(request, response, false).await
}
async fn request_with_mode(request: String, response: Response, automatic: bool) -> String {
    let owner = crate::lifecycle::owner();
    let continuation = owner.continuation();
    // End shares the suspension-capable lifecycle fence; no issuer readiness is needed.
    let ending = owner.clock_continuation();
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        action: String,
        id: Option<String>,
        session: Option<String>,
        limits: Option<crate::store::poc::Limits>,
        confirmation: Option<crate::store::poc::disposition::Confirmation>,
        continuation: Option<crate::dispatch::Continuation>,
        call_id: Option<String>,
        revision: Option<u64>,
        machine_class_answer: Option<crate::store::poc_targets::KeyCardAnswer>,
        answer: Option<String>,
    }
    let result = async {
        let value: Value = serde_json::from_str(&request).map_err(|_| "task request")?;
        if !value.is_object() {
            return Err("task request".into());
        }
        let request: Request = serde_json::from_value(value).map_err(|_| "task request")?;
        if request.action == "end-session" {
            ending.as_ref().map_err(Clone::clone)?.check()?;
        } else {
            continuation.as_ref().map_err(Clone::clone)?.check()?;
        }
        if matches!(
            request.action.as_str(),
            "resume"
                | "dispose-pending"
                | "ai-key-create"
                | "ai-key-decline"
                | "ai-key-class"
                | "operator-answer"
        ) {
            let continuation = continuation.as_ref().map_err(Clone::clone)?;
            let id = request.id.as_deref().ok_or("task ID required")?;
            #[cfg(feature = "tracer")]
            if automatic {
                crate::testonly::session_point(&format!("poc_automatic_resume_{id}")).await;
            }
            let session = request
                .session
                .as_deref()
                .ok_or("original session required")?;
            #[cfg(feature = "tracer")]
            if request.action == "dispose-pending" {
                crate::testonly::session_point("pending_disposition_writer").await;
            }
            let task = {
                let local = local();
                let mut writer = local.lock().await;
                continuation.check()?;
                if request.action == "dispose-pending"
                    && let Some(why) = writer.dispatch_refusal()
                {
                    return Err(why.into());
                }
                let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
                let task = store.poc_task(id)?;
                store.check_task_session(&task, session)?;
                // A queued wake may have selected this task before recovery paused it.
                if automatic && !store.eligible_tasks().iter().any(|task| task.id == id) {
                    return Ok(());
                }
                if request.action == "dispose-pending" {
                    let confirmation = request
                        .confirmation
                        .as_ref()
                        .ok_or("confirmation required")?;
                    if confirmation.task != id || confirmation.session != session {
                        return Err("confirmation task or session differs".into());
                    }

                    continuation.check()?;
                    response
                        .borrow_mut()
                        .get_or_insert_with(crate::poc::inference::CommandResponse::reserve);
                    store
                        .poc_dispose(
                            confirmation,
                            request
                                .continuation
                                .ok_or("continuing assumption required")?,
                        )
                        .await?
                } else if request.action == "operator-answer" {
                    crate::poc::run::check_raise(id)?;
                    store.poc_authority(id, session)?;
                    if automatic || request.revision != Some(task.revision) {
                        return Err("The question is no longer available.".into());
                    }
                    store
                        .poc_change(
                            id,
                            task.revision,
                            Change::OperatorAnswer {
                                call_id: request
                                    .call_id
                                    .ok_or("The question is no longer available.")?,
                                answer: request
                                    .answer
                                    .ok_or("Choose an answer on the question card.")?,
                            },
                        )
                        .await?
                } else if matches!(
                    request.action.as_str(),
                    "ai-key-create" | "ai-key-decline" | "ai-key-class"
                ) {
                    crate::poc::run::check_raise(id)?;
                    store.poc_authority(id, session)?;
                    if automatic
                        || request.revision != Some(task.revision)
                        || request.call_id.as_deref()
                            != task
                                .proposal
                                .as_ref()
                                .map(|proposal| proposal.call_id.as_str())
                    {
                        return Err("AI key decision is no longer available".into());
                    }
                    let decision = match (request.action.as_str(), request.machine_class_answer) {
                        (
                            "ai-key-create",
                            Some(crate::store::poc_targets::KeyCardAnswer::OnlyMe),
                        )
                        | (
                            "ai-key-class",
                            Some(
                                crate::store::poc_targets::KeyCardAnswer::OthersToo
                                | crate::store::poc_targets::KeyCardAnswer::NotSure,
                            ),
                        ) => Change::AiKeyClassDecision {
                            answer: request.machine_class_answer.expect("matched answer"),
                            at: (js_sys::Date::now() / 1000.0) as u64,
                        },
                        ("ai-key-create" | "ai-key-decline", None) => Change::AiKeyDecision {
                            create: request.action == "ai-key-create",
                        },
                        _ => return Err("AI key decision is no longer available".into()),
                    };
                    store.poc_change(id, task.revision, decision).await?
                } else {
                    task
                }
            };
            if !automatic {
                crate::poc::credit::browser::retry_mint(session);
            }
            let resolved = {
                let local = local();
                let mut writer = local.lock().await;
                continuation.check()?;
                let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
                store.check_task_session(&task, session)?;
                match crate::poc::targets::resolve(store, &task.machine) {
                    Ok(resolved) => Ok(resolved),
                    Err(reason) => {
                        let reason = if let Some(profile) =
                            reason.strip_prefix("unsupported relay profile: ")
                        {
                            let safe = store.protect_output(&serde_json::json!(profile))?;
                            format!(
                                "unsupported relay profile: {}",
                                safe.as_str().ok_or("profile protection")?
                            )
                        } else {
                            reason
                        };
                        let safe = store.protect_output(&serde_json::json!(reason))?;
                        Err(safe.as_str().ok_or("resolver protection")?.to_string())
                    }
                }
            };
            match resolved {
                Ok((target, pins)) => {
                    resume_with(
                        &task,
                        session,
                        &target,
                        &pins,
                        &mut Configured {
                            response: response.clone(),
                            automatic,
                            continuation: continuation.clone(),
                        },
                        response.clone(),
                        continuation.clone(),
                    )
                    .await?;
                }
                Err(reason) => return Err(reason),
            }
        } else {
            let local = local();
            #[cfg(feature = "tracer")]
            if request.action == "end-session" {
                crate::testonly::session_point("poc_end_writer").await;
            }
            let mut writer = local.lock().await;
            if request.action == "end-session" {
                ending.as_ref().map_err(Clone::clone)?.check()?;
            } else {
                continuation.as_ref().map_err(Clone::clone)?.check()?;
            }
            let store = writer.store().ok_or(crate::poc::wait::LOCKED)?;
            match request.action.as_str() {
                "start" => {
                    store
                        .poc_start(request.session.as_deref().ok_or("session required")?)
                        .await?;
                }
                "end-session" => {
                    store
                        .end_session(request.session.as_deref().ok_or("session required")?)
                        .await?;
                }
                "retry-checks" => {
                    let id = request.id.as_deref().ok_or("task ID required")?;
                    crate::poc::run::check_raise(id)?;
                    store
                        .poc_authority(id, request.session.as_deref().ok_or("session required")?)?;
                    let task = store.poc_task(id)?;
                    store
                        .poc_change(id, task.revision, Change::RetryChecks)
                        .await?;
                }
                "abandon" => {
                    let id = request.id.as_deref().ok_or("task ID required")?;
                    let task = store.poc_task(id)?;
                    store.poc_change(id, task.revision, Change::Abandon).await?;
                    crate::poc::inference::stop_task(id);
                }
                "raise" => {
                    let id = request.id.as_deref().ok_or("task ID required")?;
                    store
                        .poc_raise(id, request.limits.ok_or("limits required")?)
                        .await?;
                }
                _ => return Err("unknown task action".into()),
            }
        }
        Ok::<(), String>(())
    }
    .await;
    local()
        .lock()
        .await
        .report(result.as_ref().err().map(String::as_str))
        .to_string()
}

struct Configured {
    continuation: crate::lifecycle::Continuation,
    response: Response,
    automatic: bool,
}
impl run::Model for Configured {
    async fn ready(&mut self, task: &Task, session: &str) -> Result<(), String> {
        #[cfg(feature = "tracer")]
        if crate::testonly::poc_model_configured() {
            return Ok(());
        }
        self.continuation.check()?;
        let credit = {
            let local = local();
            let mut writer = local.lock().await;
            self.continuation.check()?;
            writer.store().ok_or("locked")?.credit_session(session)
        };
        if credit && (task.steps >= task.limits.steps || task.requests >= task.limits.requests) {
            // Let the runner record its budget pause without requesting another allowance.
            return Ok(());
        }
        if credit && !crate::poc::credit::browser::has_key(session) {
            self.response.borrow_mut().take();
        }
        crate::poc::credit::browser::ensure(session, &self.continuation).await?;
        if !crate::poc::inference::key_is_set() {
            return Err("waiting for the admitted inference key; no request consumed".into());
        }
        if self.automatic {
            let local = local();
            let mut writer = local.lock().await;
            let admitted = writer
                .store()
                .ok_or("locked")?
                .session_configuration(session)?;
            if crate::poc::inference::configuration().as_ref() != Some(&admitted) {
                return Err("automatic continuation waits for the admitted endpoint and model; restore them or explicitly Resume with the displayed configuration; no request consumed".into());
            }
        }
        Ok(())
    }
    async fn next(
        &mut self,
        task: &Task,
        session: &str,
    ) -> Result<(String, crate::goals::Tool), crate::poc::inference::ReplyError> {
        // Progress has released the preceding result. Configuration may change during
        // the next request, whose adapter detects changes and aborts honestly.
        self.response.borrow_mut().take();
        #[cfg(feature = "tracer")]
        if let Some(next) = crate::testonly::poc_model_next(
            &task.machine,
            local()
                .lock()
                .await
                .store()
                .ok_or("locked")?
                .poc_needs_declaration(&task.machine),
        ) {
            *self.response.borrow_mut() = Some(crate::poc::inference::CommandResponse::reserve());
            return Ok(next);
        }
        let next = crate::poc::inference::next(task, session).await;
        // A failed request has no new command result to release. In particular, let
        // the operator configure an endpoint/key while its pause is being recorded.
        if next.is_ok() {
            *self.response.borrow_mut() = Some(crate::poc::inference::CommandResponse::reserve());
        }
        #[cfg(feature = "tracer")]
        crate::testonly::session_point("poc_model_return").await;
        next
    }
}

/// Stored targets select the durable page route in fixture builds as well.
/// The legacy exercises have no enrolled target and keep their original route.
#[cfg(feature = "tracer")]
pub(crate) async fn page_uses_runner(session: &str) -> bool {
    #[cfg(not(feature = "tracer"))]
    {
        let _ = session;
        true
    }
    #[cfg(feature = "tracer")]
    {
        local()
            .lock()
            .await
            .store()
            .and_then(|store| {
                let live = store.live_goal_session(session).ok()?;
                live.bound_set
                    .first()
                    .and_then(|machine| store.poc_target(machine))
                    .map(|_| ())
            })
            .is_some()
    }
}

/// The page owns this scope through its actual final post. Each execution acquires a
/// reservation; requests release it while awaiting inference and reacquire on return.
#[wasm_bindgen::prelude::wasm_bindgen]
pub struct TaskPublication {
    response: Response,
}
#[wasm_bindgen::prelude::wasm_bindgen]
impl TaskPublication {
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            response: Response::default(),
        }
    }
    pub async fn request(&self, request: String) -> String {
        request_with(request, self.response.clone()).await
    }
    pub async fn continue_task(&self, id: String, session: String) -> String {
        {
            let local = local();
            let mut writer = local.lock().await;
            if !writer.store().is_some_and(|store| {
                store
                    .eligible_tasks()
                    .iter()
                    .any(|task| task.id == id && task.start_session == session)
            }) {
                return writer.report(None).to_string();
            }
        }
        request_with_mode(
            serde_json::json!({"action":"resume","id":id,"session":session}).to_string(),
            self.response.clone(),
            true,
        )
        .await
    }
    pub async fn run_goal(&self, session: String) -> String {
        crate::worker::run_page_goal_with(session, self.response.clone()).await
    }
    pub async fn publish(&self, generation: u64, session: String, report: String) {
        // Take ownership before awaiting the publisher: destruction covers every exit,
        // without a writer held during transport or an operator wait.
        let _response = self.response.borrow_mut().take();
        crate::harness::inference::publish_report(generation, session, report).await;
    }
}
impl Default for TaskPublication {
    fn default() -> Self {
        Self::new()
    }
}

/// Read one ended task under the report writer, without restoring any action authority.
#[wasm_bindgen::prelude::wasm_bindgen]
pub async fn publish_task_details(generation: u64, id: String, request: String) -> bool {
    let local = local();
    let mut writer = local.lock().await;
    let owner = crate::lifecycle::owner();
    if generation != owner.generation()
        || owner.state() == "reconciling"
        || crate::harness::inference::ending()
        || writer.dispatch_refusal().is_some()
    {
        return false;
    }
    let Some(store) = writer.store() else {
        return false;
    };
    let details = store.poc_task(&id).ok().filter(|task| task.ended());
    let protected = details.and_then(|task| {
        let value = serde_json::json!({"task_details":{"id":id,"request":request,
            "generation":generation.to_string(),"task":store.poc_task_view(&task)}});
        let protected = store.protect_page_publication(&value).ok()?;
        // A protected correlation field must still identify this exact request and task.
        (protected["task_details"]["id"] == id
            && protected["task_details"]["request"] == request
            && protected["task_details"]["generation"] == value["task_details"]["generation"]
            && protected["task_details"]["task"]["id"] == id)
            .then_some(protected)
    });
    let protected = if let Some(protected) = protected {
        protected
    } else {
        let refusal = serde_json::json!({"task_details_unavailable":request});
        let Ok(protected) = store.protect_publication(&refusal, &[]) else {
            return false;
        };
        // Even fixed framing and the page's token must survive protection unchanged.
        if protected != refusal {
            return false;
        }
        protected
    };
    let encoded = protected.to_string();
    if store.check_output_bytes(encoded.as_bytes()).is_err()
        || generation != owner.generation()
        || owner.state() == "reconciling"
        || crate::harness::inference::ending()
    {
        return false;
    }
    let Ok(message) = js_sys::JSON::parse(&encoded) else {
        return false;
    };
    let worker: web_sys::DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    worker.post_message(&message).is_ok()
}

/// The caller supplies an offer identity, never a path. This result is private binary data,
/// outside the report publisher; the worker transfers it only to the download handler.
#[wasm_bindgen::prelude::wasm_bindgen]
pub async fn poc_download(
    id: String,
    offer: String,
) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue> {
    let result = async {
        let continuation = crate::lifecycle::owner().continuation()?;
        let (file, target, pins) = {
            let local = local();
            let mut writer = local.lock().await;
            continuation.check()?;
            let store = writer
                .store()
                .ok_or("Unlock before downloading the file.")?;
            let task = store.poc_task(&id)?;
            let file = task
                .file_offers()
                .into_iter()
                .find(|file| file.id == offer)
                .ok_or("This file offer is no longer available.")?;
            if !crate::poc::files::allowed_path(&file.path) {
                return Err("This file path cannot be downloaded.".into());
            }
            let (target, pins) = crate::poc::targets::resolve(store, &file.machine)
                .map_err(|_| "The machine connection is unavailable. Try again.")?;
            (file, target, pins)
        };
        let mut journal = StoreJournal {
            local: local(),
            unavailable: false,
        };
        let bytes = crate::harness::download_file(&pins, &mut journal, &target, &file.path).await?;
        {
            let local = local();
            let mut writer = local.lock().await;
            continuation.check()?;
            let store = writer
                .store()
                .ok_or("Unlock before downloading the file.")?;
            if !store
                .poc_task(&id)?
                .file_offers()
                .iter()
                .any(|current| current.id == offer)
            {
                return Err("This file offer is no longer available.".into());
            }
        }
        let result = js_sys::Object::new();
        js_sys::Reflect::set(
            &result,
            &"filename".into(),
            &crate::poc::files::filename(&file.path).into(),
        )
        .map_err(|_| "The download could not be prepared. Try again.")?;
        let data = js_sys::Uint8Array::from(bytes.as_slice());
        js_sys::Reflect::set(&result, &"bytes".into(), &data)
            .map_err(|_| "The download could not be prepared. Try again.")?;
        Ok::<_, String>(result.into())
    }
    .await;
    result.map_err(Into::into)
}
