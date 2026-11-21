//! Durable local orchestration. A session supplies current authority, never continuation state.
use super::*;
use crate::goals::Tool;
use std::collections::BTreeMap;

pub type Step = (String, Tool, Value);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockOrigin {
    pub step: usize,
    pub block: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub requests: u32,
    pub steps: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            requests: 250,
            steps: 500,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Running,
    Waiting,
    Verifying,
    Paused,
    Complete,
    Abandoned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub call_id: String,
    pub tool: Tool,
    pub check: Option<usize>,
    pub report: Option<usize>,
}
impl Proposal {
    pub(crate) fn check_batch(&self) -> bool {
        self.check.is_some()
            && (self.call_id.starts_with("$verify-batch:")
                || self.call_id.starts_with("$verify-batch-to:"))
    }
    pub(crate) fn check_batch_end(&self, checks: usize) -> usize {
        // Historical batches cover every remaining read. New batches record their
        // exclusive end so dispatch, collection and replay use the same range.
        self.call_id
            .strip_prefix("$verify-batch-to:")
            .map(|suffix| {
                suffix
                    .split(':')
                    .next()
                    .expect("batch end")
                    .parse()
                    .expect("batch end index")
            })
            .unwrap_or(checks)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub call: u64,
    pub job: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub command: String,
    pub job: String,
    pub exit_status: Option<u32>,
    pub excerpt: String,
    pub observation: Option<crate::poc::completion::Observation>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionalReport {
    pub command: String,
    pub status: String,
    pub job: Option<String>,
    pub exit_status: Option<u32>,
    pub excerpt: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Malformed {
    pub count: u32,
    pub reason: String,
    pub cut_off: bool,
}
fn initial_completion_tokens() -> u32 {
    // Historical journal state only; requests use the fixed inference reply limit.
    4000
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeforeSetup {
    pub settled: bool,
    pub observation: Option<crate::poc::completion::Observation>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnmetCommand {
    pub created: u64,
    pub call: u64,
    pub machine: String,
    /// Exact UTF-8 command bytes, without normalization.
    pub command: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub id: String,
    pub start_session: String,
    pub goal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<crate::poc::template::Options>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<crate::poc::template::Inputs>,
    pub machine: String,
    pub approved_plan: Option<String>,
    pub completed: Vec<Step>,
    pub proposal: Option<Proposal>,
    pub ai_key_approved: bool,
    pub pending: Option<Pending>,
    pub status: Status,
    pub pause_reason: Option<String>,
    pub requests: u32,
    pub steps: u32,
    pub limits: Limits,
    pub checks: Vec<String>,
    pub verification: Vec<Verification>,
    pub read_plan: Vec<crate::poc::completion::Read>,
    pub previous_reads: Vec<Vec<Verification>>,
    pub reports: Vec<OptionalReport>,
    pub findings: Vec<crate::delivery::Finding>,
    pub notes: Vec<crate::delivery::Note>,
    pub verdict: Option<String>,
    pub verifying: bool,
    pub requesting: bool,
    /// Consecutive interrupted requests for this turn; survives worker loss.
    #[serde(default)]
    pub request_recoveries: u32,
    pub malformed: Option<Malformed>,
    #[serde(default = "initial_completion_tokens")]
    pub completion_tokens: u32,
    pub before_setup: Option<BeforeSetup>,
    /// Compare-and-append token: stale requests cannot publish or arm a command.
    pub revision: u64,
    pub inspection_record: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub block_origins: BTreeMap<String, BlockOrigin>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmet_commands: Vec<UnmetCommand>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands_recorded_as_run: Vec<UnmetCommand>,
}
impl Task {
    pub fn awaiting_operator(&self) -> bool {
        self.pending.is_none()
            && self
                .proposal
                .as_ref()
                .is_some_and(|proposal| matches!(proposal.tool, Tool::AskOperator { .. }))
    }
    pub fn awaiting_ai_key(&self) -> bool {
        !self.ai_key_approved
            && self.pending.is_none()
            && self
                .proposal
                .as_ref()
                .is_some_and(|proposal| matches!(proposal.tool, Tool::RequestAiKey { .. }))
    }
    pub fn preparing_read(&self) -> bool {
        self.before_setup.as_ref().is_some_and(|r| !r.settled)
            && self.proposal.as_ref().is_some_and(|p| {
                p.call_id.starts_with("$before:")
                    && p.check.is_none()
                    && p.report.is_none()
                    && p.tool
                        == (Tool::Exec {
                            machine: self.machine.clone(),
                            command: crate::poc::completion::Read::Listeners.command(),
                        })
            })
    }
    /// Keep complete text until the publication boundary protects it and bounds the card.
    pub(super) fn view(&self) -> Value {
        let mut value = serde_json::to_value(self).expect("task serializes");
        value["ai_key_renewal"] = json!(crate::poc::key_renewal::is_renewal(self));
        value["file_offers"] = serde_json::to_value(self.file_offers()).expect("offers serialize");
        value["pause_reason"] = self.publication_pause_reason();
        if crate::poc::key_renewal::is_renewal(self) {
            for step in value["completed"].as_array_mut().expect("completed steps") {
                if step[1]["name"] == "exec" {
                    step[2]["content"] = json!({"step":crate::poc::key_renewal::step_name(step[0].as_str().unwrap_or_default())});
                }
            }
        }
        if self.awaiting_ai_key() {
            value["ai_key_limit_usd"] = json!(crate::poc::credit::AI_KEY_CAP);
        }
        value
    }
    fn publication_pause_reason(&self) -> Value {
        if let Some(reason) = &self.pause_reason
            && let Some(malformed) = self.malformed.as_ref().filter(|m| m.count == 3)
            && let Some(prefix) = Self::malformed_pause_prefix(reason)
        {
            // Rebuild from the complete recorded diagnostic; append/replay keep their old cut.
            return format!("{prefix}{}. Resume asks the model again.", malformed.reason).into();
        }
        json!(self.pause_reason)
    }
    fn malformed_pause_prefix(reason: &str) -> Option<&'static str> {
        [
            "the AI's reply was cut off; 3 unusable replies in a row; last reason: ",
            "3 malformed replies in a row; last reason: ",
        ]
        .into_iter()
        .find(|prefix| {
            reason.starts_with(prefix) && reason.ends_with(". Resume asks the model again.")
        })
    }
    /// Only the card heading and the cross-card lookups; never serialize old outcomes here.
    pub(super) fn summary_view(&self) -> Value {
        let delivered_urls = self
            .completed
            .iter()
            .rev()
            .find_map(|(_, tool, outcome)| {
                let Tool::Done { urls, .. } = tool else {
                    return None;
                };
                if outcome["content"]["verification_required"] != true {
                    return None;
                }
                Some(
                    urls.iter()
                        .map(|entry| {
                            let mut value =
                                serde_json::to_value(entry).expect("address serializes");
                            if let Some(label) = outcome["content"]["unvisited_urls"]
                                .as_array()
                                .and_then(|skipped| {
                                    skipped.iter().find(|skipped| skipped["url"] == entry.url)
                                })
                                .and_then(|skipped| skipped.get("label"))
                            {
                                value["notVisited"] = label.clone();
                            }
                            value
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .unwrap_or_default();
        json!({"summary":true,"ai_key_renewal":crate::poc::key_renewal::is_renewal(self),"id":self.id,"revision":self.revision,"start_session":self.start_session,
            "machine":self.machine,"status":self.status,
            "goal":self.goal,
            "pause_reason":self.publication_pause_reason(),"verdict":self.verdict,
            "delivered_urls":delivered_urls})
    }
    pub(super) fn truncate_view(
        value: &mut Value,
        protect_cut: &impl Fn(&str) -> Result<String, String>,
    ) -> Result<(), String> {
        if let Some(steps) = value.get_mut("completed").and_then(Value::as_array_mut) {
            for step in steps {
                Self::truncate_step_view(step, protect_cut)?;
            }
        }
        if let Some(reason) = value["pause_reason"].as_str()
            && reason.len() > 512
            && Self::malformed_pause_prefix(reason).is_some()
        {
            const SUFFIX: &str = ". Resume asks the model again.";
            let mut end = 512 - SUFFIX.len() - "…".len();
            while !reason.is_char_boundary(end) {
                end -= 1;
            }
            // Recheck the newly exposed end before adding the pause framing.
            value["pause_reason"] = format!("{}…{SUFFIX}", protect_cut(&reason[..end])?).into();
        }
        Ok(())
    }
    fn truncate_step_view(
        step: &mut Value,
        protect_cut: &impl Fn(&str) -> Result<String, String>,
    ) -> Result<(), String> {
        let content = &mut step[2]["content"];
        for field in ["stdout", "stderr"] {
            if let Some(text) = content[field].as_str() {
                let excerpt: String = text.chars().take(1024).collect();
                if excerpt.len() < text.len() {
                    content[field] = protect_cut(&excerpt)?.into();
                    content[format!("{field}_truncated")] = true.into();
                }
            }
        }
        Ok(())
    }
    pub fn ended(&self) -> bool {
        matches!(self.status, Status::Complete | Status::Abandoned)
    }
    fn pause(&mut self, why: impl Into<String>) {
        self.status = Status::Paused;
        self.pause_reason = Some(why.into());
        self.requesting = false;
    }
    fn active(&mut self) {
        self.pause_reason = None;
        self.status =
            if self.pending.is_some() || self.awaiting_ai_key() || self.awaiting_operator() {
                Status::Waiting
            } else if self.verifying {
                Status::Verifying
            } else {
                Status::Running
            };
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub task: String,
    pub revision: u64,
    pub session: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Change {
    Request,
    RecoverRequest,
    PrepareRead,
    SkipRead(String),
    Malformed {
        reason: String,
        cut_off: bool,
    },
    CutOff {
        reason: String,
    },
    // New fixed-limit cutoffs always count a strike. Keep CutOff's replay meaning.
    CutOffAtLimit {
        reason: String,
    },
    Propose {
        call_id: String,
        tool: Tool,
    },
    // New done calls pin template hashes and add sign-in reads; keep Propose's read plan.
    ProposeDone {
        call_id: String,
        tool: Tool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        control_center_hashes: Option<[String; 2]>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unvisited_urls: Option<Vec<crate::goals::DeliveredUrl>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        missing_files: Option<Vec<String>>,
    },
    // Record admission once; URL parsing must never change a question during replay.
    ProposeOperator {
        call_id: String,
        tool: Tool,
        refusal: Option<String>,
    },
    ProposeBlock {
        call_id: String,
        tool: Tool,
        origin: BlockOrigin,
    },
    PrepareCheck,
    // New attempts batch harness reads; PrepareCheck keeps its historical replay meaning.
    PrepareCheckBatch,
    // Keep both historical preparation changes unchanged when replaying journals.
    PrepareCheckJobs,
    SkipCheckBatch(String),
    RetryChecks,
    CommandAlreadyRan {
        obligation: u64,
    },
    RepairFindings,
    SkipReport(String),
    RejectDeclaration,
    AiKeyFailed(String),
    AiKeyDecision {
        create: bool,
    },
    OperatorAnswer {
        call_id: String,
        answer: String,
    },
    AiKeyClassDecision {
        answer: super::poc_targets::KeyCardAnswer,
        at: u64,
    },
    Settle,
    Inspect,
    Wait {
        why: String,
        running: bool,
    },
    Pause(String),
    Raise(Limits),
    Abandon,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Record {
    Create {
        id: String,
        session: String,
        limits: Limits,
    },
    Start {
        id: String,
        session: String,
        limits: Limits,
    },
    // A separate maintenance task retains the setup task and all old key custody.
    RenewAiKey {
        id: String,
        session: String,
        limits: Limits,
    },
    Change {
        id: String,
        expected: u64,
        change: Change,
    },
    // The disposition and its single replacement proposal share one commit.
    // Its record number links the replacement to the unknown historical outcome.
    Rerun {
        confirmation: disposition::Confirmation,
        disposition: Disposition,
        // Absent in old journals: those replay without command obligations.
        #[serde(default)]
        track_command: bool,
    },
    Command {
        binding: Binding,
        intent: Intent,
        // Part of the existing page intent append, absent in historical journals.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        launch: Option<crate::dispatch::PreparedLaunch>,
    },
}

impl<S: Storage> Store<S> {
    #[cfg(all(target_arch = "wasm32", feature = "tracer"))]
    pub(crate) async fn test_approval_neighbor(&mut self) -> Result<String, String> {
        let mut paused = None;
        for machine in ["machine-b", "machine-c"] {
            let mut entry = self
                .dispatch
                .approved_entries
                .get("machine-a")
                .ok_or("fixture entry")?
                .clone();
            entry.approved.entry.machine = machine.into();
            entry.approved.identity = self
                .allocation()
                .issue(Family::Machines)
                .map_err(|e| e.to_string())?;
            self.record(allocation::Event::Reserve(entry.approved.identity.clone()))
                .await?;
            // Independent fixture sessions retain ordinary journaled task transitions.
            self.dispatch.approved_entries.insert(machine.into(), entry);
            let session = self.admit_fixture(machine).await?;
            self.enter_goal(&session, "retain an independent task".into(), None)
                .await?;
            let task = if machine == "machine-c" {
                // Run the eligible sentinel before the approved task in a broad wake.
                let record = Record::Start {
                    id: "0".repeat(48),
                    session: session.clone(),
                    limits: Limits::default(),
                };
                self.project_poc(self.next, &record)?;
                let number = self.commit(&Event::Poc(record.clone())).await?;
                self.apply_poc(number, &record)?;
                self.poc_task(&"0".repeat(48))?
            } else {
                self.poc_start(&session).await?
            };
            if machine == "machine-b" {
                self.poc_change(
                    &task.id,
                    task.revision,
                    Change::Pause("independent fixture pause".into()),
                )
                .await?;
                paused = Some(task.id);
            }
        }
        Ok(paused.expect("paused neighbour created"))
    }
    pub(super) fn apply_requirements_task(
        &mut self,
        number: u64,
        record: &crate::dispatch::SetupRecord,
    ) {
        if let crate::dispatch::SetupRecord::Requirements(approval) = record {
            for task in self.poc.values_mut() {
                if task.start_session == approval.session && task.machine == approval.proposal.machine()
                    && task.status == Status::Paused
                    && task.pause_reason.as_deref().is_some_and(|why| {
                        why == "propose and explicitly approve the installation declaration to continue"
                            || why == "installation facts: approved declaration missing; review the proposed requirements and approve explicitly to continue"
                            || why == crate::poc::wait::APPROVAL_PENDING
                    }) {
                    if let Some(proposal) = task.proposal.take() {
                        if matches!(proposal.tool, Tool::ProposeDeclaration { .. }) {
                            task.completed.push((proposal.call_id, proposal.tool, crate::goals::untrusted("tool_output", json!({"approved":true}))));
                        } else { task.proposal = Some(proposal); }
                    }
                    task.active();
                    task.revision = number;
                }
            }
        }
    }
    pub(crate) fn poc_machine_distribution(&self, machine: &str) -> Option<&str> {
        self.procurement
            .iter()
            .chain(&self.completed_purchases)
            .find(|p| p.machine == machine && p.target.is_some())
            .and_then(|p| p.selected.image["distribution"].as_str())
    }
    pub(crate) fn poc_inference_facts(&self, task: &Task) -> Option<Value> {
        let machine = task.machine.as_str();
        let exposure = self
            .exposure_ledger
            .iter()
            .find(|e| e.session == task.start_session)?;
        let approved = self.dispatch.approved_entries.get(machine)?;
        Some(json!({
            "session":task.start_session,
            "task":task.id,
            "distribution":self.poc_machine_distribution(machine),
            "user":self.poc_target(machine).map(|target| &target.user),
            "goal_source":self.goal(&task.start_session),
            "bound_set":exposure.bound_set.iter().map(|bound| &bound.machine).collect::<Vec<_>>(),
            "approved_entry":{"entry":approved.approved.entry,"access":approved.approved.access},
            "class":approved.class,
            "declaration_in_force":approved.declaration,
            "requirements":approved.requirements.iter().filter(|r| r.session == task.start_session).collect::<Vec<_>>(),
            "requests_consumed":task.requests,
            "steps_consumed":task.steps,
            "limits":task.limits,
            "uncertainty":"Earlier requests without a committed proposal may have lost their responses. Counts are not refunded and imply no machine outcome.",
            "unresolved_commands":self.dispatch.calls.values().filter(|c| c.intent.machine == machine && matches!(c.state, crate::dispatch::CallState::Unresolved)).map(|c| json!({"call":c.intent.call,"job":c.intent.job})).collect::<Vec<_>>()
        }))
    }
    /// Recovery retires uncertain requests; it grants no session or dispatch authority.
    /// Failed transitions remain requesting and are reported without blocking other tasks.
    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn poc_recover_interrupted_requests(&mut self) {
        self.poc_reconciliation_failures.clear();
        let interrupted: Vec<_> = self
            .poc
            .values()
            .filter(|task| {
                task.requesting
                    && !task.ended()
                    && !self.ended_sessions.contains(&task.start_session)
            })
            .map(|task| (task.id.clone(), task.revision))
            .collect();
        if interrupted.is_empty() {
            return;
        }
        for (id, revision) in interrupted {
            let result = self.poc_change(&id, revision, Change::RecoverRequest).await;
            if let Err(why) = result {
                self.poc_reconciliation_failures.insert(
                    id,
                    (revision, format!("Could not record recovery of the interrupted AI request: {why}. Work is paused so the request cannot be applied twice.")),
                );
            }
        }
    }
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn eligible_tasks(&self) -> Vec<Task> {
        self.poc
            .values()
            .filter(|t| {
                matches!(
                    t.status,
                    Status::Running | Status::Verifying | Status::Waiting
                ) && !t.requesting
                    && !self.ended_sessions.contains(&t.start_session)
                    && (t.status != Status::Waiting
                        || t.pending.is_some()
                            && (t.pause_reason.is_none()
                                || t.pause_reason.as_deref() == Some(crate::poc::wait::RUNNING)
                                || t.pause_reason.as_deref().is_some_and(|why| {
                                    why.starts_with("inspecting the recorded job")
                                })))
            })
            .cloned()
            .collect()
    }
    #[cfg(all(target_arch = "wasm32", feature = "tracer"))]
    pub(crate) async fn test_poc_inference_request(
        &mut self,
        machine: &str,
        goal: String,
        completed: Vec<Step>,
    ) -> Result<(Task, String), String> {
        let session = self
            .sessions
            .iter()
            .find(|s| !s.ended.get() && s.bound_set == [machine])
            .ok_or("no admitted fixture session")?
            .identity
            .clone();
        if self.goal(&session).is_none() {
            self.enter_goal(&session, goal.clone(), None).await?;
        }
        let task = match self.poc_session_task(&session) {
            Some(task) => task.clone(),
            None => self.poc_start(&session).await?,
        };
        let task = self
            .poc_change(
                &task.id,
                task.revision,
                Change::Raise(Limits {
                    requests: 1000,
                    steps: 2000,
                }),
            )
            .await?;
        let mut task = self
            .poc_change(&task.id, task.revision, Change::Request)
            .await?;
        task.goal = goal;
        task.completed = completed;
        Ok((task, session))
    }

    fn poc_safe(&self, value: &impl Serialize) -> Result<(), String> {
        let value = serde_json::to_value(value).map_err(|_| crate::poc::wait::TASK_ENCODING)?;
        if !crate::redaction::Redacted::inference_value_is_safe(self, &value, &[]) {
            return Err(crate::poc::wait::TASK_BOUNDARY.into());
        }
        Ok(())
    }
    fn poc_record_safe(&self, record: &Record) -> Result<(), String> {
        let timing = super::unlock_marks::Timer::new(super::unlock_marks::Mark::RecordCheck);
        timing.count(super::unlock_marks::Counter::RecordChecks, 1);
        let event = Event::Poc(record.clone());
        self.poc_safe(&event)?;
        let encoded = Zeroizing::new(
            serde_json::to_vec(&journal(&event)).map_err(|_| crate::poc::wait::TASK_ENCODING)?,
        );
        if crate::redaction::Redacted::for_store(self, &encoded, &[])
            .is_ok_and(|safe| safe.as_bytes() == encoded.as_slice())
        {
            Ok(())
        } else {
            Err(crate::poc::wait::TASK_BOUNDARY.into())
        }
    }
    pub(super) fn measured_dispatch_copy(&self) -> crate::dispatch::Dispatch {
        let timing = super::unlock_marks::Timer::new(super::unlock_marks::Mark::DispatchCopy);
        timing.count(super::unlock_marks::Counter::DispatchCopies, 1);
        timing.count(
            super::unlock_marks::Counter::DispatchCopyEntries,
            (self.dispatch.calls.len() + self.dispatch.jobs.len()) as u64,
        );
        self.dispatch.clone()
    }
    pub fn poc_task(&self, id: &str) -> Result<Task, String> {
        let task = self.poc.get(id).ok_or(crate::poc::wait::UNKNOWN_TASK)?;
        // Internal orchestration reads durable metadata without releasing the transcript.
        // Reports and inference independently scan their payloads against current custody.
        Ok(task.clone())
    }
    pub(crate) fn check_task_session(&self, task: &Task, session: &str) -> Result<(), String> {
        let current = self
            .poc
            .get(&task.id)
            .ok_or(crate::poc::wait::UNKNOWN_TASK)?;
        if current.revision != task.revision || current.start_session != session || current.ended()
        {
            return Err("stale task session or revision".into());
        }
        let live = self.live_goal_session(session)?;
        if live.bound_set != [task.machine.as_str()] {
            return Err("task binding differs".into());
        }
        Ok(())
    }

    pub fn check_inference_request(&self, task: &Task, session: &str) -> Result<(), String> {
        self.check_task_session(task, session)?;
        self.poc_authority(&task.id, session)?;
        if !task.requesting || task.pending.is_some() || task.proposal.is_some() {
            return Err("no current task request".into());
        }
        if self.poc_needs_declaration(&task.machine) {
            if !task.before_setup.as_ref().is_some_and(|r| r.settled) {
                return Err("listeners observation has not settled".into());
            }
            self.dispatch
                .check_command(&task.machine)
                .map_err(|why| format!("{why:?}"))?;
        }
        Ok(())
    }
    pub fn poc_authority(&self, id: &str, session: &str) -> Result<Rc<Session>, String> {
        let task = self.poc.get(id).ok_or(crate::poc::wait::UNKNOWN_TASK)?;
        if task.ended() {
            return Err(crate::poc::wait::TASK_ENDED.into());
        }
        if task.start_session != session {
            return Err("task requires its original session".into());
        }
        let live = self.live_goal_session(session)?;
        if !crate::poc::key_renewal::is_renewal(task)
            && self
                .poc_session_task(session)
                .is_some_and(|owner| owner.id != id)
        {
            return Err(crate::poc::wait::SESSION_OWNER.into());
        }
        if live.bound_set != [task.machine.as_str()] {
            return Err(crate::poc::wait::BOUND_MACHINE.into());
        }
        if self.pending_requirements.contains_key(session) {
            return Err(crate::poc::wait::APPROVAL_PENDING.into());
        }
        if !self.accepted_no_brief(session) {
            return Err(crate::poc::wait::ACCEPTANCE.into());
        }
        Ok(live)
    }
    fn poc_session_task(&self, session: &str) -> Option<&Task> {
        self.poc_by_session
            .get(session)
            .and_then(|id| self.poc.get(id))
    }
    fn poc_new_acceptance(&self, session: &str) -> Result<Option<Acceptance>, String> {
        if self.accepted_no_brief(session) {
            return Ok(None);
        }
        let acceptance = Acceptance {
            session: session.into(),
            mode: Mode::NoBrief,
        };
        self.check_acceptance(&acceptance)?;
        Ok(Some(acceptance))
    }
    pub async fn poc_raise(&mut self, id: &str, limits: Limits) -> Result<Task, String> {
        crate::poc::run::check_raise(id)?;
        let task = self.poc_task(id)?;
        self.poc_change(id, task.revision, Change::Raise(limits))
            .await
    }
    pub fn poc_tool(&self, id: &str, session: &str, tool: &Tool) -> Result<(), String> {
        let live = self.poc_authority(id, session)?;
        self.poc_safe(tool)?;
        if !live.bound_set.iter().any(|m| m == tool.machine()) {
            return Err("bound set".into());
        }
        // Reuse the legacy installation check without granting stored goals session authority.
        if matches!(tool, Tool::Exec { .. } | Tool::RequestAiKey { .. }) {
            self.dispatch.check_installation(tool.machine())?;
        }
        Ok(())
    }
    /// Record a safe proposal before testing prerequisites for its eventual effect.
    pub async fn poc_propose(
        &mut self,
        task: &Task,
        session: &str,
        call_id: String,
        mut tool: Tool,
        origin: Option<BlockOrigin>,
    ) -> Result<Task, String> {
        self.poc_authority(&task.id, session)?;
        self.poc_safe(&tool)?;
        #[cfg(target_arch = "wasm32")]
        if let Some(display) = crate::poc::question::display(&tool) {
            self.poc_safe(&display)?;
        }
        // Normalize only new admissions; recorded done calls keep their replay meaning.
        // The control-center template's final check supplies its proof.
        if task.template.as_deref() == Some(crate::poc::template::ID)
            && let Tool::Done { checks, .. } = &mut tool
        {
            checks.clear();
        }
        let change = if let Some(origin) = origin {
            self.poc_safe(&origin)?;
            Change::ProposeBlock {
                call_id,
                tool,
                origin,
            }
        } else if matches!(tool, Tool::AskOperator { .. }) {
            Change::ProposeOperator {
                call_id,
                refusal: crate::poc::question::validate(&tool)
                    .err()
                    .map(str::to_owned),
                tool,
            }
        } else if let Tool::Done { urls, .. } = &tool {
            let unvisited: Vec<_> = urls
                .iter()
                .filter_map(|entry| {
                    (task.template.as_deref() == Some(crate::poc::template::ID))
                        .then(|| crate::poc::template::third_party_label(&entry.url))
                        .flatten()
                        .map(|label| crate::goals::DeliveredUrl {
                            url: entry.url.clone(),
                            label: Some(label.into()),
                        })
                })
                .collect();
            let mut missing_files = Vec::new();
            if task.template.as_deref() == Some(crate::poc::template::ID) {
                let offers = task.file_offers();
                for name in crate::poc::template::REQUIRED_FILES {
                    if !offers
                        .iter()
                        .any(|offer| offer.path.rsplit('/').next() == Some(*name))
                    {
                        missing_files.push((*name).to_owned());
                    }
                }
            }
            Change::ProposeDone {
                call_id,
                tool,
                unvisited_urls: (!unvisited.is_empty()).then_some(unvisited),
                missing_files: (!missing_files.is_empty()).then_some(missing_files),
                control_center_hashes: (task.template.as_deref() == Some(crate::poc::template::ID))
                    .then(|| {
                        crate::poc::template::CONTROL_CENTER
                            .hashes
                            .map(str::to_owned)
                    }),
            }
        } else {
            Change::Propose { call_id, tool }
        };
        self.poc_change(&task.id, task.revision, change).await
    }

    /// An admitted declaration uses the same approval path as other requirements.
    pub fn poc_prepare_execution(&mut self, task: &Task, session: &str) -> Result<(), String> {
        let tool = &task
            .proposal
            .as_ref()
            .ok_or("missing command proposal")?
            .tool;
        self.poc_authority(&task.id, session)?;
        if self.poc_task(&task.id)?.revision != task.revision || task.pending.is_some() {
            return Err("stale task execution".into());
        }
        if task.awaiting_ai_key() {
            return Err("AI key request needs the operator's decision".into());
        }
        if task.awaiting_operator() {
            return Err("The question needs the operator's answer.".into());
        }
        if let Tool::ProposeDeclaration {
            machine,
            declaration,
        } = tool
        {
            self.poc_propose_requirements(
                session,
                &json!({"kind":"declaration", "machine":machine, "declaration":declaration}),
            )?;
            return Err(crate::poc::wait::APPROVAL_PENDING.into());
        }
        if task.preparing_read() {
            self.poc_safe(tool)
        } else {
            self.poc_tool(&task.id, session, tool)
        }
    }

    pub async fn poc_prepare_next(&mut self, task: &Task, session: &str) -> Result<Task, String> {
        self.poc_authority(&task.id, session)?;
        if crate::poc::key_renewal::is_renewal(task) && self.poc_needs_declaration(&task.machine) {
            return Err("AI key renewal is unavailable for this machine.".into());
        }
        if self.poc_needs_declaration(&task.machine) && task.before_setup.is_none() {
            self.poc_change(&task.id, task.revision, Change::PrepareRead)
                .await
        } else {
            Ok(task.clone())
        }
    }

    pub async fn poc_check_command(
        &self,
        binding: &Binding,
        machine: &str,
    ) -> Result<(), AppendRefusal> {
        self.poc_binding_current(binding)
            .map_err(AppendRefusal::Storage)?;
        let task = self
            .poc_task(&binding.task)
            .map_err(AppendRefusal::Storage)?;
        if task.machine != machine {
            return Err(AppendRefusal::Storage("task machine differs".into()));
        }
        if task.preparing_read() {
            self.check_box_job(machine)
        } else {
            self.check(machine).await
        }
    }

    pub fn poc_needs_declaration(&self, machine: &str) -> bool {
        self.dispatch
            .approved_entries
            .get(machine)
            .is_none_or(|entry| entry.declaration.is_none())
    }

    pub async fn poc_reject_requirements(
        &mut self,
        session: &str,
        machine: &str,
        candidate: u64,
    ) -> Result<(), String> {
        if !self.pending_requirements_matches(session, machine, candidate) {
            return Err("stale proposal approval".into());
        }
        if let Some(task) = self.poc_session_task(session).cloned()
            && task
                .proposal
                .as_ref()
                .is_some_and(|p| matches!(p.tool, Tool::ProposeDeclaration { .. }))
        {
            self.poc_change(&task.id, task.revision, Change::RejectDeclaration)
                .await?;
        }
        self.reject_requirements(session, machine, candidate)
    }

    /// Map structured transport reports only after passing the existing protection boundary.
    pub fn poc_refusal(&self, report: &Value) -> String {
        match self.protect_output(report) {
            Ok(safe) => crate::poc::run::refusal_reason(&safe),
            Err(_) => "command refused; diagnostic protection failed; inspect connection and task configuration".into(),
        }
    }
    pub fn poc_collection_reason(&self, pending: &Pending, reports: &[Value]) -> String {
        match self.protect_output(&json!(reports)) {
            Ok(safe) => crate::poc::run::collection_reason(
                pending,
                safe.as_array().expect("protected reports"),
            ),
            Err(_) => {
                crate::poc::wait::COLLECTION_PROTECTION.render(pending.call, &pending.job, "")
            }
        }
    }

    fn poc_check_start(&self, session: &str) -> Result<(), String> {
        let live = self.live_goal_session(session)?;
        self.goal(session).ok_or("missing goal")?;
        if live.bound_set.len() != 1 {
            return Err("task start requires exactly one bound machine".into());
        }
        Ok(())
    }
    /// Acceptance and task inputs share one durable boundary, including a lost append reply.
    pub async fn poc_accept_start(&mut self, session: &str) -> Result<(), String> {
        self.poc_start(session).await.map(|_| ())
    }
    pub(crate) fn renewal_step_for_call(&self, call: u64) -> Option<&'static str> {
        self.poc
            .values()
            .filter(|task| crate::poc::key_renewal::is_renewal(task))
            .find_map(|task| {
                if task
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.call == call)
                {
                    return task
                        .proposal
                        .as_ref()
                        .map(|proposal| crate::poc::key_renewal::step_name(&proposal.call_id));
                }
                task.completed
                    .iter()
                    .find(|(_, _, output)| output["content"]["call"] == call)
                    .map(|(id, _, _)| crate::poc::key_renewal::step_name(id))
            })
    }
    /// Remove renewal output, including encoded job-record streams, at inspection publication.
    pub(crate) fn withhold_renewal_output(&self, value: &mut Value) {
        fn strip(value: &mut Value) {
            match value {
                Value::Object(fields) => {
                    fields.remove("stdout");
                    fields.remove("stderr");
                    for child in fields.values_mut() {
                        strip(child);
                    }
                }
                Value::Array(values) => {
                    for child in values {
                        strip(child);
                    }
                }
                _ => {}
            }
        }
        if value
            .get("call")
            .and_then(Value::as_u64)
            .is_some_and(|call| self.renewal_step_for_call(call).is_some())
        {
            strip(value);
        } else {
            match value {
                Value::Object(fields) => {
                    for child in fields.values_mut() {
                        self.withhold_renewal_output(child);
                    }
                }
                Value::Array(values) => {
                    for child in values {
                        self.withhold_renewal_output(child);
                    }
                }
                _ => {}
            }
        }
    }
    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn poc_renew_ai_key(
        &mut self,
        machine: &str,
        session: &str,
        id: &str,
    ) -> Result<Task, String> {
        let live = self
            .check_connection_session_for(machine, None)
            .map_err(|_| crate::poc::key_renewal::LIVE_REQUIRED)?;
        if live.identity != session {
            return Err(crate::poc::key_renewal::LIVE_REQUIRED.into());
        }
        let session = live.identity.clone();
        self.live_goal_session(&session)?;
        if let Some(task) = self.poc.get(id) {
            if task.machine == machine
                && task.start_session == session
                && crate::poc::key_renewal::is_renewal(task)
            {
                return Ok(task.clone());
            }
            return Err("AI key decision is no longer available".into());
        }
        if let Some(task) = self.poc.values().find(|task| {
            task.machine == machine
                && task.start_session == session
                && crate::poc::key_renewal::is_renewal(task)
                && !task.ended()
        }) {
            return Ok(task.clone());
        }
        let record = Record::RenewAiKey {
            id: id.into(),
            session,
            limits: Limits::default(),
        };
        let task = self.project_poc(self.next, &record)?;
        self.poc_record_safe(&record)?;
        let number = self.commit(&Event::Poc(record.clone())).await?;
        self.apply_poc(number, &record)?;
        Ok(task)
    }
    pub async fn poc_start(&mut self, session: &str) -> Result<Task, String> {
        self.poc_create_inner(session, true).await
    }
    pub async fn poc_page_start(&mut self, session: &str) -> Result<Task, String> {
        self.poc_create(session).await
    }
    pub async fn poc_create(&mut self, session: &str) -> Result<Task, String> {
        self.poc_create_inner(session, false).await
    }
    async fn poc_create_inner(&mut self, session: &str, accept: bool) -> Result<Task, String> {
        self.poc_check_start(session)?;
        if self.pending_requirements.contains_key(session) {
            return Err("proposal approval pending".into());
        }
        if let Some(task) = self.poc_session_task(session) {
            return self.poc_task(&task.id);
        }
        let id = hex::encode(random::<24>()?);
        let session = session.into();
        let limits = Limits::default();
        let record = if accept {
            Record::Start {
                id,
                session,
                limits,
            }
        } else {
            self.check_goal_start(&session)?;
            Record::Create {
                id,
                session,
                limits,
            }
        };
        let task = self.project_poc(self.next, &record)?;
        self.poc_safe(&task)?;
        self.poc_record_safe(&record)?;
        let number = self.commit(&Event::Poc(record.clone())).await?;
        #[cfg(all(target_arch = "wasm32", feature = "tracer"))]
        crate::testonly::session_point("poc_start_committed").await;
        self.apply_poc(number, &record)?;
        Ok(task)
    }
    pub async fn poc_change(
        &mut self,
        id: &str,
        expected: u64,
        mut change: Change,
    ) -> Result<Task, String> {
        #[cfg(target_arch = "wasm32")]
        let timing_started = crate::poc::timings::now();
        #[cfg(target_arch = "wasm32")]
        let timing_label = crate::poc::timings::change_label(&change);
        match &mut change {
            Change::Malformed { reason, .. }
            | Change::CutOff { reason }
            | Change::CutOffAtLimit { reason } => {
                if reason.is_empty() || reason.len() > 512 {
                    return Err("malformed-reply reason exceeds its bound".into());
                }
                if self.protect_output(&json!(reason))? != json!(reason) {
                    return Err("malformed-reply reason contains protected material".into());
                }
            }
            Change::AiKeyDecision { create: true } => {
                // New approvals require the class answer; recorded approvals retain their meaning.
                if self.ai_key_needs_class_answer(&self.poc_task(id)?.machine) {
                    return Err("answer the machine question on the key card first".into());
                }
            }
            Change::Pause(why) | Change::Wait { why, .. } | Change::SkipRead(why) => {
                *why = self
                    .protect_output(&json!(why))
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_else(|| crate::poc::wait::FALLBACK.into());
            }
            _ => {}
        }
        // Pauses and excerpts are data too. Refuse rather than persist a transformed command.
        let record = Record::Change {
            id: id.into(),
            expected,
            change,
        };
        self.poc_record_safe(&record)?;
        let task = self.project_poc(self.next, &record)?;
        #[cfg(target_arch = "wasm32")]
        let timing = {
            use crate::poc::timings::{self, Mark, Timer};
            timings::proposal(&task, &record, timing_started);
            Timer::since(
                timings::recording(id),
                Mark::Journal(timing_label),
                timing_started,
            )
        };
        self.commit(&Event::Poc(record.clone())).await?;
        self.apply_poc_key_class(&record, &task);
        self.poc.insert(id.into(), task.clone());
        #[cfg(target_arch = "wasm32")]
        {
            drop(timing);
            if matches!(
                &record,
                Record::Change {
                    change: Change::Settle,
                    ..
                }
            ) {
                crate::poc::timings::finish(id);
            }
            if matches!(
                &record,
                Record::Change {
                    change: Change::Request,
                    ..
                }
            ) || matches!(task.status, Status::Paused | Status::Waiting)
                || task.ended()
            {
                crate::poc::timings::close_after_settle(id, crate::poc::timings::now());
            }
        }
        Ok(task)
    }
    /// A terminal awaiting its task checkpoint still needs a full current-inventory
    /// release. This durable barrier survives loss of the volatile response reservation.
    pub fn poc_configuration_ready(&self) -> Result<(), String> {
        for task in self.poc.values().filter(|task| !task.ended()) {
            let report = task
                .pending
                .as_ref()
                .and_then(|pending| self.poc_committed(pending));
            if let Some(report) = report.filter(|report| report.settles_call()) {
                if !matches!(report.comparison, crate::jobs::Comparison::AdvisoryMatch) {
                    return Err("inference configuration refused: recorded task result differs from its intent and cannot checkpoint; inspect the finding, then Stop task before configuring; remote effects and command holds remain".into());
                }
                return Err("inference configuration refused: recorded task result awaits recovery; Resume collection in the original session before configuring; then retry configuration".into());
            }
        }
        Ok(())
    }
    pub fn poc_committed(&self, pending: &Pending) -> Option<&crate::jobs::Report> {
        self.dispatch
            .jobs
            .iter()
            .rev()
            .find(|r| r.evidence.call == pending.call && r.evidence.job == pending.job)
    }
    pub fn poc_binding_current(&self, binding: &Binding) -> Result<(), String> {
        self.poc_authority(&binding.task, &binding.session)?;
        let task = self
            .poc
            .get(&binding.task)
            .ok_or(crate::poc::wait::UNKNOWN_TASK)?;
        // After append, current authority also gates the final send and response boundary.
        let revision = if task.pending.is_some() {
            binding.revision.checked_add(1)
        } else {
            Some(binding.revision)
        };
        if revision != Some(task.revision) {
            return Err("stale task command".into());
        }
        Ok(())
    }
    pub async fn poc_append(
        &mut self,
        binding: &Binding,
        entry: &Entry,
        approval: &Approval,
    ) -> Result<u64, AppendRefusal> {
        self.poc_binding_current(binding)
            .map_err(AppendRefusal::Storage)?;
        let task = self
            .poc_task(&binding.task)
            .map_err(AppendRefusal::Storage)?;
        let proposal = task
            .proposal
            .as_ref()
            .ok_or_else(|| AppendRefusal::Storage("missing task proposal".into()))?;
        let replayable = matches!(proposal.tool, Tool::Exec { .. });
        if !task.preparing_read() {
            self.poc_tool(&binding.task, &binding.session, &proposal.tool)
                .map_err(AppendRefusal::Storage)?;
        }
        if task.pending.is_some()
            || task.revision != binding.revision
            || entry.provenance.as_ref().and_then(|p| p.session.as_deref())
                != Some(&binding.session)
        {
            return Err(AppendRefusal::Storage("stale task command".into()));
        }
        self.check_signature(&entry.machine, &entry.command).await?;
        self.poc_check_command(binding, &entry.machine).await?;
        let intent = Intent {
            call: self.next,
            machine: entry.machine.clone(),
            command: hex::encode(&entry.command),
            approval: Some(approval.clone()),
            job: Some(hex::encode(random::<24>().map_err(AppendRefusal::Storage)?)),
            provenance: entry.provenance.clone(),
        };
        // Standard input is deliberately absent from the journal. Only ordinary
        // command wrappers can carry an exact, replayable launch preparation.
        let prepared = if replayable {
            let elevation = self
                .poc_target(&entry.machine)
                .ok_or_else(|| AppendRefusal::Storage("stored target missing".into()))?
                .elevation;
            let wrapper = crate::jobs::launch_with_elevation(
                intent.job.as_deref().expect("new job"),
                &entry.machine,
                &entry.command,
                elevation,
            );
            Some(crate::dispatch::PreparedLaunch {
                call: intent.call,
                job: intent.job.clone().expect("new job"),
                elevation,
                wrapper_sha256: hex::encode(Sha256::digest(wrapper.as_bytes())),
            })
        } else {
            None
        };
        let record = Record::Command {
            binding: binding.clone(),
            intent,
            launch: prepared,
        };
        self.project_poc(self.next, &record)
            .map_err(AppendRefusal::Storage)?;
        self.poc_record_safe(&record)
            .map_err(AppendRefusal::Storage)?;
        let number = self
            .commit(&Event::Poc(record.clone()))
            .await
            .map_err(AppendRefusal::Storage)?;
        self.apply_poc(number, &record)
            .expect("validated task intent applies after commit");
        Ok(number)
    }

    #[cfg(any(
        target_arch = "wasm32",
        all(feature = "history-bench", not(target_arch = "wasm32"))
    ))]
    pub(crate) async fn poc_launch_transmission(
        &mut self,
        call: u64,
        sent: &[u8],
    ) -> Result<(), String> {
        let Some(fence) = self.dispatch.launches.get(&call) else {
            // Historical calls and standard-input jobs retain the original dispatch path.
            return Ok(());
        };
        if hex::encode(Sha256::digest(sent)) != fence.prepared.wrapper_sha256 {
            return Err("prepared launch bytes differ".into());
        }
        let attempt = crate::dispatch::LaunchAttempt {
            call,
            job: fence.prepared.job.clone(),
        };
        self.dispatch.check_launch_attempt(&attempt, false)?;
        self.commit(&Event::LaunchTransmission(attempt.clone()))
            .await?;
        self.dispatch
            .launch_attempt(&attempt, false)
            .expect("validated launch reservation applies after commit");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn poc_resend(
        &mut self,
        binding: &Binding,
        session: &Session,
        call: u64,
        job: &str,
        elevation: crate::jobs::Elevation,
        pinned: &str,
    ) -> Result<Option<Vec<u8>>, AppendRefusal> {
        let storage = AppendRefusal::Storage;
        self.poc_authority(&binding.task, &binding.session)
            .map_err(storage)?;
        self.check_current_session(session).map_err(storage)?;
        let task = self.poc_task(&binding.task).map_err(storage)?;
        if task.revision != binding.revision
            || task.pending.as_ref()
                != Some(&Pending {
                    call,
                    job: job.into(),
                })
        {
            return Err(storage("stale task collection".into()));
        }
        let Some(fence) = self.dispatch.launches.get(&call) else {
            return Ok(None);
        };
        if fence.attempted || fence.resent {
            return Ok(None);
        }
        let intent = self
            .dispatch
            .calls
            .get(&call)
            .ok_or_else(|| storage("unknown launch call".into()))?
            .intent
            .clone();
        if fence.prepared.job != job
            || fence.prepared.elevation != elevation
            || intent.machine != task.machine
            || intent.provenance.as_ref().is_none_or(|p| {
                p.session.as_deref() != Some(&binding.session)
                    || p.target != crate::dispatch::Target::Entry(task.machine.clone())
                    || p.requester != crate::dispatch::Requester::Session
            })
        {
            return Err(storage("prepared launch authority differs".into()));
        }
        if intent.approval
            != Some(Approval::HarnessPin {
                machine: task.machine.clone(),
                fingerprint: pinned.into(),
            })
        {
            return Err(storage("prepared launch approval differs".into()));
        }
        let proposal = task
            .proposal
            .as_ref()
            .ok_or_else(|| storage("missing task proposal".into()))?;
        if !matches!(&proposal.tool, Tool::Exec { machine, command }
            if machine == &intent.machine && hex::encode(command.as_bytes()) == intent.command)
        {
            return Ok(None);
        }
        let preparing = task.preparing_read();
        let machine = task.machine.clone();
        if !preparing {
            self.poc_tool(&binding.task, &binding.session, &proposal.tool)
                .map_err(storage)?;
        }
        let command =
            hex::decode(&intent.command).map_err(|_| storage("launch command hex".into()))?;
        let sent =
            crate::jobs::launch_with_elevation(job, &machine, &command, elevation).into_bytes();
        if hex::encode(Sha256::digest(&sent)) != fence.prepared.wrapper_sha256 {
            return Err(storage("prepared launch bytes differ".into()));
        }
        self.check_signature(&machine, &command).await?;
        // Exempt exactly this call's hold. Its authoritative state stays unresolved.
        self.dispatch
            .check_command_except(&machine, Some(call))
            .map_err(AppendRefusal::Policy)?;
        if !preparing {
            self.dispatch
                .check_installation(&machine)
                .map_err(storage)?;
        }
        if self.pending_machine(&machine) {
            return Err(storage("proposal approval pending".into()));
        }
        let attempt = crate::dispatch::LaunchAttempt {
            call,
            job: job.into(),
        };
        self.dispatch
            .check_launch_attempt(&attempt, true)
            .map_err(storage)?;
        self.commit(&Event::Resend(attempt.clone()))
            .await
            .map_err(storage)?;
        self.dispatch
            .launch_attempt(&attempt, true)
            .expect("validated resend reservation applies after commit");
        Ok(Some(sent))
    }
    pub(super) fn apply_poc(&mut self, number: u64, record: &Record) -> Result<(), String> {
        // Validate the new record, not previously committed transcript bytes. Settle
        // protects its derived outcome separately before checkpointing it.
        self.poc_record_safe(record)?;
        let task = match record {
            Record::Create { .. }
            | Record::Start { .. }
            | Record::RenewAiKey { .. }
            | Record::Rerun { .. } => self.project_poc(number, record)?,
            Record::Change { id, .. }
            | Record::Command {
                binding: Binding { task: id, .. },
                ..
            } => {
                // Replay refuses the store on error; it does not need a rollback copy.
                // Live callers have already projected successfully before committing.
                let task = self.poc.remove(id).ok_or(crate::poc::wait::UNKNOWN_TASK)?;
                self.project_poc_task(number, record, task)?
            }
        };
        self.apply_poc_key_class(record, &task);
        if let Record::Rerun { disposition, .. } = record {
            // project_rerun has checked this exact prefix, including duplicate refusal.
            let report = self.dispatch.disposition(number, disposition.clone());
            if !matches!(report, DispositionReport::Accepted { .. }) {
                return Err("rerun disposition refused".into());
            }
        }
        if let Record::Command { intent, launch, .. } = record {
            self.apply_intent(number, intent.clone())?;
            if let Some(prepared) = launch {
                self.dispatch.prepare_launch(prepared.clone())?;
            }
        }
        if let Record::Start { session, .. } = record
            && let Some(acceptance) = self.poc_new_acceptance(session)?
        {
            self.push_acceptance(acceptance);
        }
        if matches!(record, Record::RenewAiKey { .. }) {
            self.poc_creation_order.push(task.id.clone());
        }
        if matches!(record, Record::Create { .. } | Record::Start { .. }) {
            self.poc_creation_order.push(task.id.clone());
            self.poc_by_session
                .insert(task.start_session.clone(), task.id.clone());
        }
        self.poc.insert(task.id.clone(), task);
        Ok(())
    }
    fn apply_poc_key_class(&mut self, record: &Record, task: &Task) {
        if let Record::Change {
            change:
                Change::AiKeyClassDecision {
                    answer: super::poc_targets::KeyCardAnswer::OnlyMe,
                    at,
                },
            ..
        } = record
        {
            self.apply_key_card_class(&task.machine, *at);
        }
    }
    fn project_poc(&self, number: u64, record: &Record) -> Result<Task, String> {
        if let Record::Rerun {
            confirmation,
            disposition,
            track_command,
        } = record
        {
            return self.project_rerun(number, confirmation, disposition, *track_command);
        }
        if let Record::Create {
            id,
            session,
            limits,
        }
        | Record::Start {
            id,
            session,
            limits,
        }
        | Record::RenewAiKey {
            id,
            session,
            limits,
        } = record
        {
            let renewal = matches!(record, Record::RenewAiKey { .. });
            if matches!(record, Record::Start { .. }) {
                self.poc_new_acceptance(session)?;
            }
            let goal = self.goal(session).ok_or("task requires recorded goal")?;
            let exposure = self
                .session_exposure(session)
                .ok_or("task requires binding")?;
            if self.ended_sessions.contains(session)
                || id.len() != 48
                || hex::decode(id).is_err()
                || self.poc.contains_key(id)
                || (!renewal && self.poc_session_task(session).is_some())
                || exposure.bound_set.len() != 1
                || limits.requests == 0
                || limits.steps == 0
                || ((matches!(record, Record::Create { .. }) || renewal)
                    && !self.accepted_no_brief(session))
            {
                return Err("invalid task creation".into());
            }
            if renewal
                && (self.poc_needs_declaration(&exposure.bound_set[0].machine)
                    || !self
                        .poc_targets
                        .get(&exposure.bound_set[0].machine)
                        .is_some_and(|target| {
                            target
                                .application_inference_keys
                                .iter()
                                .any(|key| key.application == "Hermes Agent")
                        })
                    || self.poc.values().any(|task| {
                        task.machine == exposure.bound_set[0].machine
                            && task.start_session == *session
                            && crate::poc::key_renewal::is_renewal(task)
                            && !task.ended()
                    }))
            {
                return Err("AI key renewal is unavailable for this machine.".into());
            }
            return Ok(Task {
                id: id.clone(),
                start_session: session.clone(),
                goal: if renewal {
                    crate::poc::key_renewal::GOAL.into()
                } else {
                    goal.text.clone()
                },
                template: if renewal {
                    Some(crate::poc::key_renewal::ID.into())
                } else {
                    goal.template.clone()
                },
                options: if renewal { None } else { goal.options.clone() },
                inputs: if renewal { None } else { goal.inputs.clone() },
                machine: exposure.bound_set[0].machine.clone(),
                approved_plan: None,
                completed: vec![],
                proposal: renewal.then(|| Proposal {
                    call_id: crate::poc::key_renewal::KEY.into(),
                    tool: Tool::RequestAiKey {
                        machine: exposure.bound_set[0].machine.clone(),
                        application: "Hermes Agent".into(),
                        purpose: "The control center's own AI agent".into(),
                    },
                    check: None,
                    report: None,
                }),
                ai_key_approved: false,
                pending: None,
                status: if renewal {
                    Status::Waiting
                } else {
                    Status::Running
                },
                pause_reason: None,
                requests: 0,
                steps: 0,
                limits: limits.clone(),
                checks: vec![],
                read_plan: vec![],
                previous_reads: vec![],
                reports: vec![],
                findings: vec![],
                notes: vec![],
                verdict: None,
                verification: vec![],
                verifying: false,
                requesting: false,
                request_recoveries: 0,
                malformed: None,
                completion_tokens: initial_completion_tokens(),
                before_setup: None,
                revision: 0,
                inspection_record: None,
                block_origins: BTreeMap::new(),
                unmet_commands: Vec::new(),
                commands_recorded_as_run: Vec::new(),
            });
        }
        let id = match record {
            Record::Change { id, .. } => id,
            Record::Command { binding, .. } => &binding.task,
            _ => unreachable!(),
        };
        let task = self.poc.get(id).ok_or(crate::poc::wait::UNKNOWN_TASK)?;
        let task = {
            let timing = super::unlock_marks::Timer::new(super::unlock_marks::Mark::TaskCopy);
            timing.count(super::unlock_marks::Counter::TaskCopies, 1);
            timing.count(
                super::unlock_marks::Counter::TaskCopySteps,
                task.completed.len() as u64,
            );
            task.clone()
        };
        self.project_poc_task(number, record, task)
    }

    fn project_poc_task(
        &self,
        number: u64,
        record: &Record,
        mut task: Task,
    ) -> Result<Task, String> {
        let expected = match record {
            Record::Change { expected, .. } => *expected,
            Record::Command { binding, .. } => binding.revision,
            _ => unreachable!(),
        };
        if task.revision != expected || task.ended() {
            return Err(crate::poc::wait::STALE_TASK.into());
        }
        task.unmet_commands = task
            .unmet_commands
            .iter()
            .filter(|command| !self.command_obligation_met(&task, command))
            .cloned()
            .collect();
        task.reconcile_command_findings();
        if self.ended_sessions.contains(&task.start_session)
            && !matches!(
                record,
                Record::Change {
                    change: Change::Abandon,
                    ..
                }
            )
        {
            return Err("task session ended".into());
        }
        match record {
            Record::Command {
                binding,
                intent,
                launch,
            } => {
                let proposal = task.proposal.as_ref().ok_or("missing task proposal")?;
                if let Some(prepared) = launch
                    && (!matches!(proposal.tool, Tool::Exec { .. })
                        || prepared.call != intent.call
                        || intent.job.as_deref() != Some(prepared.job.as_str()))
                {
                    return Err("launch preparation differs from task intent".into());
                }
                let (machine, command) = match &proposal.tool {
                    Tool::Exec { machine, command } => (machine, command.clone()),
                    Tool::RequestAiKey { machine, .. } => {
                        let entry = self
                            .ai_key(&task.id, &proposal.call_id)
                            .ok_or("AI key custody missing")?;
                        if entry.key.is_none() {
                            return Err("AI key custody missing".into());
                        }
                        (
                            machine,
                            super::ai_keys::command(
                                &entry.path,
                                entry.key.as_ref().ok_or("AI key custody missing")?.0.len(),
                            ),
                        )
                    }
                    _ => return Err("task command tool".into()),
                };
                if binding.session != task.start_session
                    || self.ended_sessions.contains(&binding.session)
                    || task.pending.is_some()
                    || task.requesting
                    || intent.call != number
                    || intent.machine != task.machine
                    || machine != &task.machine
                    || intent.command != hex::encode(&command)
                    || intent.provenance.as_ref().is_none_or(|p| {
                        p.session.as_ref() != Some(&binding.session)
                            || p.target != crate::dispatch::Target::Entry(task.machine.clone())
                            || p.requester != crate::dispatch::Requester::Session
                    })
                {
                    return Err("task command association differs".into());
                }
                let job = intent
                    .job
                    .as_ref()
                    .ok_or("task command requires job identity")?
                    .clone();
                self.dispatch.check_intent(number, intent)?;
                if let Some(prepared) = launch {
                    self.dispatch.check_new_launch(intent, prepared)?;
                }
                task.pending = Some(Pending {
                    call: number,
                    job: job.clone(),
                });
                if let Some(index) = proposal.check {
                    if index != task.verification.len() {
                        return Err("verification order".into());
                    }
                    let commands = if proposal.check_batch() {
                        task.checks[index..proposal.check_batch_end(task.checks.len())].to_vec()
                    } else {
                        vec![command.clone()]
                    };
                    task.verification
                        .extend(commands.into_iter().map(|command| Verification {
                            command,
                            job: job.clone(),
                            exit_status: None,
                            excerpt: String::new(),
                            observation: None,
                        }));
                }
                if let Some(index) = proposal.report {
                    let report = task
                        .reports
                        .get_mut(index)
                        .ok_or("missing optional report")?;
                    report.job = Some(job);
                    report.status = "pending".into();
                }
                task.active();
            }
            Record::Change { change, .. } => {
                match change {
                    Change::PrepareRead => {
                        if task.before_setup.is_some()
                            || task.proposal.is_some()
                            || task.pending.is_some()
                            || task.verifying
                            || !self.poc_needs_declaration(&task.machine)
                        {
                            return Err("pre-proposal listeners read is not eligible".into());
                        }
                        task.requesting = false;
                        if task.steps >= task.limits.steps {
                            task.pause("step limit reached; raise limits and Resume");
                        } else if task.requests >= task.limits.requests {
                            task.pause("request limit reached; raise limits and Resume");
                        } else {
                            task.steps += 1;
                            task.before_setup = Some(BeforeSetup {
                                settled: false,
                                observation: None,
                            });
                            task.proposal = Some(Proposal {
                                call_id: format!("$before:{}", task.steps),
                                tool: Tool::Exec {
                                    machine: task.machine.clone(),
                                    command: crate::poc::completion::Read::Listeners.command(),
                                },
                                check: None,
                                report: None,
                            });
                            task.active();
                        }
                    }
                    Change::SkipRead(why) => {
                        if !task.preparing_read() || task.pending.is_some() {
                            return Err("no refused pre-proposal read".into());
                        }
                        task.before_setup.as_mut().expect("attempt").settled = true;
                        let p = task.proposal.take().expect("read");
                        task.completed.push((
                            p.call_id,
                            p.tool,
                            crate::goals::untrusted("tool_output", json!({"refused":why})),
                        ));
                        task.active();
                    }
                    Change::Abandon => {
                        task.status = Status::Abandoned;
                        task.pause_reason = Some(
                        "local orchestration abandoned; remote effects and command holds remain"
                            .into(),
                    );
                        task.requesting = false;
                    }
                    Change::Pause(why) => {
                        if why.trim().is_empty() {
                            return Err("empty pause".into());
                        }
                        if task.verifying
                            && task.proposal.as_ref().is_some_and(|p| p.check.is_some())
                        {
                            task.verdict = None;
                            task.pause(format!("{}. {why}", crate::poc::completion::UNKNOWN));
                        } else {
                            task.pause(why);
                        }
                    }
                    Change::Raise(limits) => {
                        if limits.requests < task.limits.requests
                            || limits.steps < task.limits.steps
                            || limits.requests > 1000
                            || limits.steps > 2000
                        {
                            return Err(
                                "limits may only increase, up to 1000 requests and 2000 steps"
                                    .into(),
                            );
                        }
                        task.limits = limits.clone();
                    }
                    Change::RecoverRequest => {
                        if !task.requesting
                            || task.pending.is_some()
                            || task.proposal.is_some()
                            || task.verifying
                        {
                            return Err("no interrupted task request".into());
                        }
                        // Keep the consumed Request and all committed history. A fresh
                        // Request passes normal readiness and limits before any fetch.
                        task.requesting = false;
                        if task.request_recoveries >= crate::poc::inference::MAX_RETRIES {
                            task.pause("The AI connection was interrupted repeatedly. Check the connection, then Resume to try again.");
                        } else {
                            task.request_recoveries += 1;
                            task.active();
                        }
                    }
                    Change::Request => {
                        if task.pending.is_some() || task.proposal.is_some() || task.verifying {
                            return Err("task has a next action already".into());
                        }
                        task.requesting = false;
                        if task.steps >= task.limits.steps {
                            task.pause("step limit reached; raise limits and Resume");
                        } else if task.requests >= task.limits.requests {
                            task.pause("request limit reached; raise limits and Resume");
                        } else {
                            if task.status == Status::Paused {
                                // Only an explicit Resume reaches a paused task.
                                task.request_recoveries = 0;
                            }
                            if task.status == Status::Paused
                                && task.malformed.as_ref().is_some_and(|m| m.count >= 3)
                            {
                                task.malformed = None;
                            }
                            task.requests += 1;
                            task.requesting = true;
                            task.active();
                        }
                    }
                    Change::Malformed { reason, .. }
                    | Change::CutOff { reason }
                    | Change::CutOffAtLimit { reason } => {
                        if !task.requesting
                            || task.pending.is_some()
                            || task.proposal.is_some()
                            || reason.is_empty()
                            || reason.len() > 512
                        {
                            return Err(
                                "no current request or invalid malformed-reply reason".into()
                            );
                        }
                        let cut_off = matches!(
                            change,
                            Change::CutOff { .. }
                                | Change::CutOffAtLimit { .. }
                                | Change::Malformed { cut_off: true, .. }
                        );
                        // Only legacy CutOff records raise the historical cap without a strike.
                        // Malformed and new fixed-limit cutoffs always count a strike.
                        let raising_cap = matches!(change, Change::CutOff { .. })
                            && task.completion_tokens < 16000;
                        if raising_cap {
                            task.completion_tokens = (task.completion_tokens * 2).min(16000);
                        } else if !cut_off {
                            task.completion_tokens = initial_completion_tokens();
                        }
                        let previous = task.malformed.as_ref().map_or(0, |m| m.count);
                        let count = previous + u32::from(!raising_cap);
                        if count > 3 {
                            return Err("malformed-reply bound exhausted".into());
                        }
                        task.requesting = false;
                        task.request_recoveries = 0;
                        task.malformed = Some(Malformed {
                            count,
                            reason: reason.clone(),
                            cut_off,
                        });
                        if count == 3 {
                            let prefix = if matches!(
                                change,
                                Change::CutOff { .. } | Change::CutOffAtLimit { .. }
                            ) {
                                "the AI's reply was cut off; 3 unusable replies in a row; last reason: "
                            } else {
                                "3 malformed replies in a row; last reason: "
                            };
                            const SUFFIX: &str = ". Resume asks the model again.";
                            let available = 512 - prefix.len() - SUFFIX.len();
                            let last = if reason.len() > available {
                                let mut end = available - "…".len();
                                while !reason.is_char_boundary(end) {
                                    end -= 1;
                                }
                                format!("{}…", &reason[..end])
                            } else {
                                reason.clone()
                            };
                            task.pause(format!("{prefix}{last}{SUFFIX}"));
                        } else {
                            task.active();
                        }
                    }
                    Change::Propose { call_id, tool }
                    | Change::ProposeBlock { call_id, tool, .. }
                    | Change::ProposeDone { call_id, tool, .. }
                    | Change::ProposeOperator { call_id, tool, .. } => {
                        if matches!(change, Change::ProposeBlock { .. })
                            && (task.template.as_deref() != Some(crate::poc::template::ID)
                                || !matches!(tool, Tool::Exec { machine, .. } if machine == &task.machine))
                        {
                            return Err(
                                "block origin requires an exec on the control-center machine"
                                    .into(),
                            );
                        }
                        if matches!(change, Change::ProposeDone { .. })
                            && !matches!(tool, Tool::Done { .. })
                        {
                            return Err("done proposal requires a done tool".into());
                        }
                        let operator_refusal =
                            if let Change::ProposeOperator { refusal, .. } = change {
                                if !matches!(tool, Tool::AskOperator { .. }) {
                                    return Err("No operator question is pending.".into());
                                }
                                refusal.as_ref()
                            } else {
                                if matches!(tool, Tool::AskOperator { .. }) {
                                    return Err("The question needs a recorded admission.".into());
                                }
                                None
                            };
                        if !task.requesting || task.pending.is_some() || task.proposal.is_some() {
                            return Err("no current task request".into());
                        }
                        task.requesting = false;
                        task.request_recoveries = 0;
                        task.malformed = None;
                        task.completion_tokens = initial_completion_tokens();
                        task.ai_key_approved = false;
                        let wire = serde_json::to_value(tool).map_err(|_| "tool encoding")?;
                        Tool::parse(&wire)?;
                        if call_id.is_empty()
                            || call_id.len() > 256
                            || call_id.starts_with('$')
                            || task.completed.iter().any(|(id, _, _)| id == call_id)
                        {
                            return Err("invalid or duplicate task call ID".into());
                        }
                        if let Change::ProposeBlock { origin, .. } = change {
                            task.block_origins.insert(call_id.clone(), origin.clone());
                        }
                        if task.steps >= task.limits.steps {
                            task.pause("step limit reached; raise limits and Resume");
                        } else {
                            task.steps += 1;
                            task.active();
                            if !matches!(tool, Tool::AskOperator { .. })
                                && tool.machine() != task.machine
                            {
                                task.completed.push((
                                    call_id.clone(),
                                    tool.clone(),
                                    crate::goals::untrusted(
                                        "tool_output",
                                        json!({"refused":"bound set"}),
                                    ),
                                ));
                            } else {
                                let admission = match tool {
                                Tool::ProposeDeclaration { declaration, .. } => {
                                    if !self.poc_needs_declaration(&task.machine) { Err("declaration: installation declaration is already approved".into()) }
                                    else { crate::poc::completion::proposal(declaration).and_then(|parsed| self.dispatch.check_proposal(&crate::declaration::Proposal::Declaration { machine: task.machine.clone(), declaration: parsed }).map_err(|why| crate::poc::proposal::semantic(declaration, &why))) }
                                }
                                _ if self.poc_needs_declaration(&task.machine) => Err("propose the installation declaration before commands or done".into()),
                                _ => Ok(()),
                            };
                                if let Err(why) = admission {
                                    task.completed.push((
                                        call_id.clone(),
                                        tool.clone(),
                                        crate::goals::untrusted(
                                            "tool_output",
                                            json!({"refused":why}),
                                        ),
                                    ));
                                } else {
                                    match tool {
                                        Tool::Exec { .. }
                                        | Tool::ProposeDeclaration { .. }
                                        | Tool::RequestAiKey { .. } => {
                                            task.proposal = Some(Proposal {
                                                call_id: call_id.clone(),
                                                tool: tool.clone(),
                                                check: None,
                                                report: None,
                                            });
                                            task.active();
                                        }
                                        Tool::AskOperator { .. } => {
                                            if let Some(reason) = operator_refusal {
                                                task.completed.push((
                                                    call_id.clone(),
                                                    tool.clone(),
                                                    crate::goals::untrusted(
                                                        "tool_output",
                                                        json!({"refused":reason}),
                                                    ),
                                                ));
                                            } else {
                                                task.proposal = Some(Proposal {
                                                    call_id: call_id.clone(),
                                                    tool: tool.clone(),
                                                    check: None,
                                                    report: None,
                                                });
                                                task.active();
                                            }
                                        }
                                        Tool::OfferFile { path, label, .. } => {
                                            let result = if crate::poc::files::allowed_path(path) {
                                                json!({"status":"offered","label":label})
                                            } else {
                                                json!({"refused":"Only absolute file paths outside /var/lib/tau-web/ can be offered."})
                                            };
                                            task.completed.push((
                                                call_id.clone(),
                                                tool.clone(),
                                                crate::goals::untrusted("tool_output", result),
                                            ));
                                        }
                                        Tool::Done { checks, urls, .. } => {
                                            let unvisited = match change {
                                                Change::ProposeDone { unvisited_urls, .. } => {
                                                    unvisited_urls.as_deref().unwrap_or_default()
                                                }
                                                _ => &[],
                                            };
                                            let declaration = self.dispatch.approved_entries
                                                [&task.machine]
                                                .declaration
                                                .as_ref()
                                                .ok_or("approved declaration missing")?;
                                            task.read_plan =
                                                if matches!(change, Change::ProposeDone { .. }) {
                                                    crate::poc::completion::reads_for_urls(
                                                        declaration,
                                                        urls,
                                                    )?
                                                } else {
                                                    crate::poc::completion::reads(declaration)?
                                                };
                                            task.read_plan.retain(|read| {
                                                !matches!(read,
                                                crate::poc::completion::Read::SignIn { url }
                                                if unvisited.iter().any(|entry| &entry.url == url))
                                            });
                                            if task.template.as_deref()
                                                == Some(crate::poc::template::ID)
                                            {
                                                let Change::ProposeDone {
                                                    control_center_hashes: Some(hashes),
                                                    ..
                                                } = change
                                                else {
                                                    return Err("template done requires recorded script hashes".into());
                                                };
                                                if !hashes.iter().all(|hash| {
                                                    hash.len() == 64
                                                        && hash.bytes().all(|b| {
                                                            b.is_ascii_digit()
                                                                || (b'a'..=b'f').contains(&b)
                                                        })
                                                }) {
                                                    return Err(
                                                        "invalid recorded script hashes".into()
                                                    );
                                                }
                                                task.read_plan.push(
                                                    crate::poc::completion::Read::ControlCenter {
                                                        hashes: hashes.clone(),
                                                    },
                                                );
                                            }
                                            task.checks = task
                                                .read_plan
                                                .iter()
                                                .map(crate::poc::completion::Read::command)
                                                .collect();
                                            task.reports = checks
                                                .iter()
                                                .filter(|command| {
                                                    !task
                                                        .checks
                                                        .iter()
                                                        .any(|check| command.trim() == check.trim())
                                                })
                                                .map(|command| OptionalReport {
                                                    command: command.clone(),
                                                    status: "queued".into(),
                                                    job: None,
                                                    exit_status: None,
                                                    excerpt: String::new(),
                                                })
                                                .collect();
                                            task.verifying = true;
                                            task.status = Status::Verifying;
                                            let mut outcome = json!({"verification_required":true});
                                            if !unvisited.is_empty() {
                                                outcome["unvisited_urls"] = json!(unvisited);
                                            }
                                            if let Change::ProposeDone {
                                                missing_files: Some(names),
                                                ..
                                            } = change
                                                && !names.is_empty()
                                            {
                                                outcome["missing_files"] = json!(names);
                                            }
                                            task.completed.push((
                                                call_id.clone(),
                                                tool.clone(),
                                                crate::goals::untrusted("tool_output", outcome),
                                            ));
                                        }
                                        Tool::Job { .. } | Tool::Typed { .. } => {
                                            task.completed.push((call_id.clone(), tool.clone(), crate::goals::untrusted("tool_output", json!({"unavailable":"operation unavailable in this task runner"}))));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Change::OperatorAnswer { call_id, answer } => {
                        let proposal = task
                            .proposal
                            .as_ref()
                            .ok_or("The question is no longer available.")?;
                        let Tool::AskOperator { choices, .. } = &proposal.tool else {
                            return Err("The question is no longer available.".into());
                        };
                        if !task.awaiting_operator()
                            || &proposal.call_id != call_id
                            || !choices.contains(answer)
                        {
                            return Err("The question is no longer available.".into());
                        }
                        let proposal = task.proposal.take().expect("pending question");
                        task.completed.push((
                            proposal.call_id,
                            proposal.tool,
                            json!({"answer":answer}),
                        ));
                        task.active();
                    }
                    Change::AiKeyDecision { create } => {
                        if !task.awaiting_ai_key()
                            || self
                                .ai_key(&task.id, &task.proposal.as_ref().expect("request").call_id)
                                .is_some()
                        {
                            return Err("AI key decision is no longer available".into());
                        }
                        if *create {
                            task.ai_key_approved = true;
                        } else {
                            let proposal = task.proposal.take().expect("request");
                            task.completed.push((
                                proposal.call_id,
                                proposal.tool,
                                crate::goals::untrusted(
                                    "tool_output",
                                    json!({"status":"declined"}),
                                ),
                            ));
                        }
                        task.active();
                        if !create && crate::poc::key_renewal::is_renewal(&task) {
                            task.status = Status::Abandoned;
                        }
                    }
                    Change::AiKeyClassDecision { answer, at } => {
                        if !task.awaiting_ai_key()
                            || !self.ai_key_needs_class_answer(&task.machine)
                            || !self.poc_targets.contains_key(&task.machine)
                            || !self.dispatch.approved_entries.contains_key(&task.machine)
                            || *at == 0
                            || self
                                .ai_key(&task.id, &task.proposal.as_ref().expect("request").call_id)
                                .is_some()
                        {
                            return Err("AI key decision is no longer available".into());
                        }
                        if *answer == super::poc_targets::KeyCardAnswer::OnlyMe {
                            task.ai_key_approved = true;
                        } else {
                            let proposal = task.proposal.take().expect("request");
                            let reason = if *answer == super::poc_targets::KeyCardAnswer::OthersToo
                            {
                                "the operator said this machine may serve others; no key was created"
                            } else {
                                "the operator is not sure this machine serves only them; no key was created"
                            };
                            task.completed.push((
                                proposal.call_id,
                                proposal.tool,
                                crate::goals::untrusted(
                                    "tool_output",
                                    json!({"status":"refused","reason":reason}),
                                ),
                            ));
                        }
                        task.active();
                    }
                    Change::AiKeyFailed(reason) => {
                        let proposal = task.proposal.take().ok_or("AI key request missing")?;
                        if !matches!(proposal.tool, Tool::RequestAiKey { .. })
                            || task.pending.is_some()
                            || reason.trim().is_empty()
                        {
                            return Err("AI key failure record refused".into());
                        }
                        let entry = self.ai_key(&task.id, &proposal.call_id);
                        task.completed.push((proposal.call_id, proposal.tool, crate::goals::untrusted("tool_output", json!({"status":"failed","reason":reason,"path":entry.map(|e| &e.path),"limit_usd":crate::poc::credit::AI_KEY_CAP}))));
                        task.active();
                    }
                    Change::RejectDeclaration => {
                        let proposal = task.proposal.take().ok_or("no declaration proposal")?;
                        if !matches!(proposal.tool, Tool::ProposeDeclaration { .. }) {
                            return Err("no declaration proposal".into());
                        }
                        task.completed.push((proposal.call_id, proposal.tool, crate::goals::untrusted("tool_output", json!({"rejected":"The operator rejected this declaration. Propose a new declaration."}))));
                        task.pause("Installation declaration rejected; Resume to request another proposal.");
                    }
                    Change::SkipReport(why) => {
                        let proposal = task.proposal.take().ok_or("no optional report")?;
                        let index = proposal.report.ok_or("not an optional report")?;
                        if task.pending.is_some() {
                            return Err("optional report has a pending call".into());
                        }
                        task.reports[index].status = "not run".into();
                        task.reports[index].excerpt = why.clone();
                        task.active();
                    }
                    Change::RepairFindings => {
                        if (task.template.as_deref() != Some(crate::poc::template::ID)
                            && !task.findings.iter().any(|finding| {
                                finding.field == crate::delivery::FieldId::UnmetCommand
                            }))
                            || task.status != Status::Paused
                            || task.pause_reason.as_deref()
                                != Some(crate::poc::completion::FINDINGS)
                            || !task.verifying
                            || task.pending.is_some()
                            || task.proposal.is_some()
                            || task.findings.is_empty()
                        {
                            return Err("repair requires paused handover findings".into());
                        }
                        task.previous_reads
                            .push(std::mem::take(&mut task.verification));
                        task.verifying = false;
                        task.verdict = None;
                        task.active();
                    }
                    Change::CommandAlreadyRan { obligation } => {
                        let available = task.unmet_commands.iter().any(|command| {
                            command.created == *obligation
                                && self.command_acknowledgment_available(&task, command)
                        });
                        if !available {
                            return Err("It already ran is available here only for a settled command that the AI cannot repeat, from the findings pause. Nothing was sent.".into());
                        }
                        task.record_command_as_run(*obligation)?;
                        task.restart_checks();
                    }
                    Change::RetryChecks => {
                        if !task.verifying || task.pending.is_some() {
                            return Err("re-check requires no pending call".into());
                        }
                        if task.status != Status::Paused {
                            return Err("re-check requires a paused task".into());
                        }
                        if task.rerun_proposed() {
                            return Err("finish the queued command before re-checking".into());
                        }
                        task.restart_checks();
                    }
                    Change::SkipCheckBatch(why) => {
                        let proposal = task.proposal.as_ref().ok_or("no check batch")?;
                        if !proposal.check_batch() || task.pending.is_some() {
                            return Err("check batch cannot be skipped".into());
                        }
                        let index = proposal.check.expect("batch start");
                        let end = proposal.check_batch_end(task.checks.len());
                        if index != task.verification.len() {
                            return Err("verification order".into());
                        }
                        task.verification
                            .extend(task.checks[index..end].iter().map(|command| Verification {
                                command: command.clone(),
                                job: String::new(),
                                exit_status: None,
                                excerpt: String::new(),
                                observation: None,
                            }));
                        let proposal = task.proposal.take().expect("batch");
                        task.completed.push((
                            proposal.call_id,
                            proposal.tool,
                            crate::goals::untrusted("tool_output", json!({"refused":why})),
                        ));
                        task.active();
                    }
                    Change::PrepareCheck | Change::PrepareCheckBatch | Change::PrepareCheckJobs => {
                        let split = matches!(change, Change::PrepareCheckJobs);
                        let batch = split || matches!(change, Change::PrepareCheckBatch);
                        if !task.verifying || task.proposal.is_some() || task.pending.is_some() {
                            return Err("verification not ready".into());
                        }
                        let declaration = self
                            .dispatch
                            .approved_entries
                            .get(&task.machine)
                            .and_then(|entry| entry.declaration.as_ref())
                            .ok_or("approved declaration missing")?;
                        if let Some(field) = crate::poc::completion::unstated(declaration) {
                            task.verdict = None;
                            task.pause(format!(
                                "{field}: not stated; the task cannot be delivered"
                            ));
                        } else if let Some(index) = task
                            .reports
                            .iter()
                            .position(|report| report.status == "queued")
                        {
                            let remaining =
                                task.checks.len().saturating_sub(task.verification.len());
                            let reserved = if split {
                                let control_centers = task.read_plan[task.verification.len()..]
                                    .iter()
                                    .filter(|read| {
                                        matches!(
                                            read,
                                            crate::poc::completion::Read::ControlCenter { .. }
                                        )
                                    })
                                    .count();
                                control_centers + usize::from(remaining > control_centers)
                            } else if batch {
                                usize::from(remaining > 0)
                            } else {
                                remaining
                            };
                            if (task.limits.steps.saturating_sub(task.steps) as usize) <= reserved {
                                task.reports[index].status = "not run".into();
                                task.reports[index].excerpt =
                                    "Steps reserved for harness reads".into();
                                task.active();
                            } else {
                                task.steps += 1;
                                task.reports[index].status = "attempted".into();
                                task.proposal = Some(Proposal {
                                    call_id: format!("$report:{index}"),
                                    tool: Tool::Exec {
                                        machine: task.machine.clone(),
                                        command: task.reports[index].command.clone(),
                                    },
                                    check: None,
                                    report: Some(index),
                                });
                                task.active();
                            }
                        } else if (!split
                            && task.verification.iter().any(|v| v.observation.is_none()))
                            || task.verification.len() == task.checks.len()
                        {
                            let observations = task
                                .verification
                                .iter()
                                .map(|v| v.observation.clone())
                                .collect::<Vec<_>>();
                            let missing_files = task
                                .completed
                                .iter()
                                .rev()
                                .find(|(_, tool, _)| matches!(tool, Tool::Done { .. }))
                                .and_then(|(_, _, outcome)| {
                                    outcome["content"]["missing_files"].as_array()
                                })
                                .map(|names| {
                                    names.iter().filter_map(Value::as_str).collect::<Vec<_>>()
                                })
                                .unwrap_or_default();
                            let mut result = crate::poc::completion::judge_with_files(
                                declaration,
                                &task.read_plan,
                                &observations,
                                &task.findings,
                                &missing_files,
                            );
                            for command in &task.unmet_commands {
                                result.delivered = false;
                                result.findings.push(crate::delivery::Finding {
                                    field: crate::delivery::FieldId::UnmetCommand,
                                    service: None,
                                    obligation: Some(command.created),
                                    detail: self.command_obligation_finding(command),
                                });
                            }
                            task.findings = result.findings;
                            task.notes = result.notes;
                            if !result.complete {
                                task.verdict = None;
                                task.pause(crate::poc::completion::UNKNOWN);
                            } else if result.delivered {
                                task.verdict = Some(
                                    if task.template.as_deref() == Some(crate::poc::template::ID) {
                                        crate::poc::completion::DELIVERED_CONTROL_CENTER
                                    } else if task.read_plan.iter().any(|read| {
                                        matches!(read, crate::poc::completion::Read::SignIn { .. })
                                    }) {
                                        crate::poc::completion::DELIVERED_SIGN_IN
                                    } else {
                                        crate::poc::completion::DELIVERED
                                    }
                                    .into(),
                                );
                                task.status = Status::Complete;
                                task.pause_reason = None;
                            } else {
                                task.verdict = Some(crate::poc::completion::FINDINGS.into());
                                task.pause(crate::poc::completion::FINDINGS);
                            }
                        } else if task.steps >= task.limits.steps {
                            task.pause(
                                format!("{}; step limit reached during verification; raise limits and Resume", crate::poc::completion::UNKNOWN),
                            );
                        } else {
                            let index = task.verification.len();
                            let end = if split {
                                task.read_plan
                                    .iter()
                                    .enumerate()
                                    .skip(index)
                                    .find(|(_, read)| {
                                        matches!(
                                            read,
                                            crate::poc::completion::Read::ControlCenter { .. }
                                        )
                                    })
                                    .map(|(index, _)| index)
                                    .unwrap_or(task.checks.len())
                            } else {
                                task.checks.len()
                            };
                            // A control-center read has the full job window to itself.
                            let batch = batch && end > index;
                            task.steps += 1;
                            task.proposal = Some(Proposal {
                                call_id: if batch && split {
                                    format!("$verify-batch-to:{end}:{index}:{}", task.steps)
                                } else if batch {
                                    format!("$verify-batch:{index}:{}", task.steps)
                                } else {
                                    format!("$verify:{index}:{}", task.steps)
                                },
                                tool: Tool::Exec {
                                    machine: task.machine.clone(),
                                    command: if batch {
                                        crate::poc::check_batch::command(&task.checks[..end], index)
                                    } else {
                                        task.checks[index].clone()
                                    },
                                },
                                check: Some(index),
                                report: None,
                            });
                            task.active();
                        }
                    }
                    Change::Inspect => {
                        task.inspection_record = Some(number);
                        if task.pending.is_none() {
                            return Err("inspection requires pending identity".into());
                        }
                        task.active();
                        task.pause_reason = Some("inspecting the recorded job; collection may wait for completion; an active collection must finish or be interrupted before Resume".into());
                    }
                    Change::Settle => {
                        let pending = task.pending.as_ref().ok_or(crate::poc::wait::NO_PENDING)?;
                        let report = self
                            .poc_committed(pending)
                            .ok_or(crate::poc::wait::NO_EVIDENCE)?;
                        if !report.settles_call()
                            || !matches!(report.comparison, crate::jobs::Comparison::AdvisoryMatch)
                        {
                            return Err(crate::poc::wait::UNTRUSTWORTHY.into());
                        }
                        let before_setup = task.preparing_read();
                        let proposal = task
                            .proposal
                            .as_ref()
                            .ok_or(crate::poc::wait::NO_PROPOSAL)?;
                        let exit = report.exit_status;
                        let background = report.state == crate::jobs::State::Background;
                        if !background && exit.is_none() && !proposal.check_batch() {
                            return Err(crate::poc::wait::NO_EXIT.into());
                        }
                        let mut outcome = if matches!(proposal.tool, Tool::RequestAiKey { .. }) {
                            if background {
                                return Err("AI key write is still running; inspect the recorded job before Resume".into());
                            }
                            self.ai_key_outcome(&task, exit)?
                        } else if background {
                            report.background_outcome()
                        } else {
                            json!({"call":pending.call,"job":pending.job,"exit_status":exit,"stdout":report.stdout,"stderr":report.stderr})
                        };
                        if crate::poc::key_renewal::is_renewal(&task) {
                            outcome["call"] = json!(pending.call);
                        }
                        let proposal = task.proposal.take().expect("checked proposal");
                        // The checkpoint derives from already committed, protected evidence. Do not
                        // make its bytes depend on credentials that disappear at worker restart.
                        if self.protect_output(&outcome)? != outcome {
                            return Err(crate::poc::wait::CHECKPOINT_PROTECTION.into());
                        }
                        if before_setup {
                            let attempt = task.before_setup.as_mut().expect("attempt");
                            attempt.settled = true;
                            attempt.observation = exit.map(|exit| {
                                crate::poc::completion::Read::Listeners
                                    .observe(exit, &report.stdout)
                            });
                        }
                        if proposal.check_batch() {
                            let start = proposal.check.expect("batch start");
                            let end = proposal.check_batch_end(task.checks.len());
                            let stdout = match &report.evidence.record {
                                crate::jobs::Record::Present { stdout, .. }
                                    if !background && exit == Some(0) =>
                                {
                                    hex::decode(stdout).ok()
                                }
                                _ => None,
                            };
                            let reads = stdout
                                .as_deref()
                                .map(|bytes| crate::poc::check_batch::parse(bytes, start, end))
                                .unwrap_or_default();
                            for index in start..end {
                                let check = task
                                    .verification
                                    .get_mut(index)
                                    .ok_or(crate::poc::wait::NO_VERIFICATION)?;
                                if check.job != pending.job || check.exit_status.is_some() {
                                    return Err(crate::poc::wait::VERIFICATION_MISMATCH.into());
                                }
                                if let Some((exit, bytes)) = reads.get(index - start) {
                                    let stdout = String::from_utf8_lossy(bytes);
                                    if self.protect_output(&json!(stdout))? != json!(stdout) {
                                        return Err(crate::poc::wait::CHECKPOINT_PROTECTION.into());
                                    }
                                    // The standalone supervisor treats statuses above 128
                                    // as signal-or-high-exit evidence, without an exit record.
                                    check.exit_status = (*exit <= 128).then_some(*exit);
                                    check.observation = check
                                        .exit_status
                                        .map(|exit| task.read_plan[index].observe(exit, &stdout));
                                    check.excerpt = stdout.chars().take(1024).collect();
                                    if self.protect_output(&json!(check.excerpt))?
                                        != json!(check.excerpt)
                                    {
                                        return Err(crate::poc::wait::EXCERPT_PROTECTION.into());
                                    }
                                }
                            }
                        } else if let Some(index) = proposal.check {
                            let check = task
                                .verification
                                .get_mut(index)
                                .ok_or(crate::poc::wait::NO_VERIFICATION)?;
                            if check.job != pending.job || check.exit_status.is_some() {
                                return Err(crate::poc::wait::VERIFICATION_MISMATCH.into());
                            }
                            check.exit_status = exit;
                            check.observation = exit
                                .map(|exit| task.read_plan[index].observe(exit, &report.stdout));
                            // Protect complete output before taking the excerpt, then protect it again.
                            check.excerpt = outcome["stdout"]
                                .as_str()
                                .unwrap_or_default()
                                .chars()
                                .take(1024)
                                .collect();
                            if self.protect_output(&json!(check.excerpt))? != json!(check.excerpt) {
                                return Err(crate::poc::wait::EXCERPT_PROTECTION.into());
                            }
                        }
                        if let Some(index) = proposal.report {
                            let optional = &mut task.reports[index];
                            optional.status = if background {
                                "still running in the background"
                            } else {
                                "recorded"
                            }
                            .into();
                            optional.exit_status = exit;
                            optional.excerpt = report.stdout.chars().take(1024).collect();
                        }
                        task.completed.push((
                            proposal.call_id,
                            proposal.tool,
                            crate::goals::untrusted("tool_output", outcome),
                        ));
                        task.pending = None;
                        task.active();
                        if crate::poc::key_renewal::is_renewal(&task) {
                            let call = &task.completed.last().expect("settled command").0;
                            if call == crate::poc::key_renewal::CHECK {
                                if crate::poc::key_renewal::check_passed(exit, &report.stdout) {
                                    task.status = Status::Complete;
                                    task.verdict = Some(
                                        "Hermes's AI key was renewed. The Hermes check passed."
                                            .into(),
                                    );
                                } else {
                                    task.pause(crate::poc::key_renewal::failed(call));
                                }
                            } else if crate::poc::key_renewal::next(self, &task).is_err() {
                                task.pause(crate::poc::key_renewal::failed(call));
                            }
                        }
                    }
                    Change::Wait { why, running } => {
                        if task.pending.is_none() || why.trim().is_empty() {
                            return Err("waiting requires pending identity and reason".into());
                        }
                        if task.verifying
                            && task.proposal.as_ref().is_some_and(|p| p.check.is_some())
                        {
                            task.verdict = None;
                            task.pause(format!("{}. {why}", crate::poc::completion::UNKNOWN));
                        } else {
                            task.pause(why);
                        }
                        if *running
                            && !(task.verifying
                                && task.proposal.as_ref().is_some_and(|p| p.check.is_some()))
                        {
                            task.status = Status::Waiting;
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
        task.revision = task
            .revision
            .checked_add(1)
            .ok_or(crate::poc::wait::REVISION_EXHAUSTED)?;
        Ok(task)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(super) mod tests;

pub(crate) mod disposition;
