//! Owner admission and journal-prefix projection of a pending unknown outcome.
use super::*;
use crate::dispatch::{CallState, Continuation, DispositionRecord};
use crate::jobs::{Record as JobRecord, State};

pub(crate) const UNSENT_RERUN: &str = "Farseed has not sent this command yet, so It already ran is not available; Resume sends it once.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    pub task: String,
    pub revision: u64,
    pub session: String,
    pub machine: String,
    pub pending: Pending,
    pub observation: u64,
    pub read: State,
    pub standing: Option<Standing>,
    pub remaining: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Standing {
    pub number: u64,
    pub continuation: Continuation,
    pub calls: Vec<u64>,
}
impl From<&DispositionRecord> for Standing {
    fn from(record: &DispositionRecord) -> Self {
        Self {
            number: record.number,
            continuation: record.disposition.continuation,
            calls: record.disposition.calls.clone(),
        }
    }
}

impl Task {
    pub(super) fn record_command_as_run(&mut self, obligation: u64) -> Result<(), String> {
        let index = self
            .unmet_commands
            .iter()
            .position(|command| command.created == obligation)
            .ok_or("This command obligation is no longer available; nothing was sent.")?;
        self.commands_recorded_as_run
            .push(self.unmet_commands.remove(index));
        self.reconcile_command_findings();
        Ok(())
    }

    pub(super) fn reconcile_command_findings(&mut self) {
        self.findings.retain(|finding| {
            finding.field != crate::delivery::FieldId::UnmetCommand
                || self
                    .unmet_commands
                    .iter()
                    .any(|command| finding.obligation == Some(command.created))
        });
    }

    pub(super) fn rerun_proposed(&self) -> bool {
        self.proposal
            .as_ref()
            .is_some_and(|proposal| proposal.call_id.starts_with("$rerun:"))
    }

    pub(super) fn restart_checks(&mut self) {
        self.proposal = None;
        for report in &mut self.reports {
            if matches!(report.status.as_str(), "queued" | "attempted") {
                report.status = "not run".into();
                report.excerpt = "Complete re-check schedules only harness reads".into();
            }
        }
        self.previous_reads
            .push(std::mem::take(&mut self.verification));
        self.verdict = None;
        self.requesting = false;
        self.active();
    }

    fn ai_command(&self) -> Option<(&str, &str)> {
        let proposal = self.proposal.as_ref()?;
        if proposal.check.is_some()
            || proposal.report.is_some()
            || (proposal.call_id.starts_with('$') && !proposal.call_id.starts_with("$rerun:"))
        {
            return None;
        }
        match &proposal.tool {
            Tool::Exec { machine, command } => Some((machine, command)),
            _ => None,
        }
    }

    /// The one-press choice applies only to an AI exec, never a harness read/report.
    fn missing_command(&self, read: State) -> bool {
        self.status == Status::Paused
            && read == State::Missing
            && self.proposal.as_ref().is_some_and(|proposal| {
                matches!(proposal.tool, Tool::Exec { .. })
                    && proposal.check.is_none()
                    && proposal.report.is_none()
                    && !proposal.call_id.starts_with('$')
            })
    }

    pub fn disposed_check(&self, check: &Verification) -> bool {
        check.exit_status.is_none()
            && self.completed.iter().any(|(_, _, result)| {
                result["content"]["job"] == check.job
                    && result["content"]["outcome"] == "unknown"
                    && result["content"]["disposition"].is_u64()
            })
    }
}

impl<S: Storage> Store<S> {
    fn disposition_read(&self, task: &Task) -> Result<&crate::jobs::Report, String> {
        let pending = task
            .pending
            .as_ref()
            .ok_or("disposition requires a pending call")?;
        let call = self
            .dispatch
            .calls
            .get(&pending.call)
            .ok_or("pending call is absent")?;
        if call.intent.machine != task.machine
            || call.intent.job.as_ref() != Some(&pending.job)
            || !matches!(call.state, CallState::Unresolved)
        {
            return Err("pending call is settled or its machine/job differs".into());
        }
        let report = self
            .poc_committed(pending)
            .ok_or("pending job has no committed read")?;
        let number = report.number.ok_or("pending read was not committed")?;
        if task
            .inspection_record
            .is_some_and(|inspection| number <= inspection)
        {
            return Err("latest inspection has no eligible committed read".into());
        }
        if !matches!(
            report.state,
            State::Missing | State::Incomplete | State::Ended
        ) {
            return Err("latest committed read is not missing, incomplete or ended".into());
        }
        let (machine, command) = match &report.evidence.record {
            JobRecord::Missing => (None, None),
            JobRecord::Incomplete { machine, command } => (machine.as_ref(), command.as_ref()),
            JobRecord::Present {
                machine, command, ..
            }
            | JobRecord::Background {
                machine, command, ..
            } => (Some(machine), Some(command)),
        };
        if machine.is_some_and(|m| *m != hex::encode(&task.machine))
            || command.is_some_and(|c| *c != call.intent.command)
        {
            return Err("committed read names a foreign machine or mismatched command".into());
        }
        Ok(report)
    }

    pub fn poc_disposition_offer(&self, id: &str, session: &str) -> Result<Confirmation, String> {
        if let Some(why) = &self.failed {
            return Err(why.clone());
        }
        let task = self.poc_task(id)?;
        self.check_task_session(&task, session)?;
        self.poc_authority(id, session)?;
        crate::poc::run::check_raise(id)?;
        #[cfg(target_arch = "wasm32")]
        if crate::harness::inspection_active(session) {
            return Err("collection or wait is active for this session".into());
        }
        self.disposition_confirmation(&task)
    }

    // Prefix-only checks also run on replay, without requiring live session keys.
    fn disposition_confirmation(&self, task: &Task) -> Result<Confirmation, String> {
        if task.status != Status::Paused {
            return Err("disposition requires a paused task".into());
        }
        let standing = self
            .dispatch
            .standing
            .get(&task.machine)
            .map(Standing::from);
        if let Some(standing) = &standing
            && standing.continuation.destructive()
        {
            return Err(format!(
                "standing disposition {} is {:?}; this control cannot replace it",
                standing.number, standing.continuation
            ));
        }
        let pending = task
            .pending
            .clone()
            .ok_or("disposition requires a pending call")?;
        let read = self.disposition_read(task)?;
        Ok(Confirmation {
            task: task.id.clone(),
            revision: task.revision,
            session: task.start_session.clone(),
            machine: task.machine.clone(),
            observation: read.number.expect("committed read"),
            read: read.state,
            standing,
            remaining: self
                .dispatch
                .unresolved(&crate::dispatch::Resource::Entry(task.machine.clone()))
                .into_iter()
                .filter(|call| *call != pending.call)
                .collect(),
            pending,
        })
    }

    pub async fn poc_dispose(
        &mut self,
        confirmation: &Confirmation,
        continuation: Continuation,
    ) -> Result<Task, String> {
        if continuation.destructive() {
            return Err("only continuing assumptions are offered".into());
        }
        let current = self.poc_disposition_offer(&confirmation.task, &confirmation.session)?;
        if &current != confirmation {
            return Err("stale disposition confirmation: task, read or standing disposition changed; review the card again".into());
        }
        let disposition = Disposition {
            machine: confirmation.machine.clone(), calls: vec![confirmation.pending.call], continuation,
            uncertainty: "The owner accepted an unknown outcome; the earlier command may arrive or run late, overlap later commands, and the page will never show it.".into(),
        };
        let original = self.poc_task(&confirmation.task)?;
        if continuation == Continuation::AsIfNotDone && original.missing_command(confirmation.read)
        {
            let record = self.prepare_rerun(&original, confirmation, disposition)?;
            let number = self.commit(&Event::Poc(record.clone())).await?;
            self.apply_poc(number, &record)
                .expect("validated rerun applies after commit");
            return self.poc_task(&confirmation.task);
        }
        let report = self.dispose(disposition).await?;
        if !matches!(report, DispositionReport::Accepted { .. }) {
            return Err("disposition refused; pending call remains held".into());
        }
        self.poc_task(&confirmation.task)
    }

    /// The view and writer use the same refusal checks; a stale card grants nothing.
    fn prepare_rerun(
        &self,
        original: &Task,
        confirmation: &Confirmation,
        disposition: Disposition,
    ) -> Result<Record, String> {
        let record = Record::Rerun {
            confirmation: confirmation.clone(),
            disposition,
            track_command: true,
        };
        let projected = self.project_poc(self.next, &record)?;
        let proposal = projected.proposal.as_ref().expect("rerun proposal");
        if let Some(origin) = projected.block_origins.get(&proposal.call_id) {
            let (resolved, _) =
                crate::poc::inference::resolve_task_block(self, original, origin, &[]).map_err(
                    |why| -> String { match why.as_str() {
                        "only the current step's blocks can run" =>
                            "Cannot run it again: the task has moved to another step.".into(),
                        "Recovery has not been sent for this task" =>
                            "Cannot run it again: this recovery command is no longer available for the task.".into(),
                        _ => "Cannot run it again: the page cannot safely reconstruct this saved command from the current task setup.".into(),
                    } },
                )?;
            if resolved != proposal.tool {
                let Tool::Exec {
                    command: recorded, ..
                } = &proposal.tool
                else {
                    unreachable!("rerun exec")
                };
                let Tool::Exec {
                    command: current, ..
                } = &resolved
                else {
                    unreachable!("resolved block exec")
                };
                return Err(self.command_difference(recorded, current));
            }
        }
        self.poc_tool(&projected.id, &projected.start_session, &proposal.tool)?;
        self.poc_record_safe(&record)?;
        self.poc_safe(proposal)?;
        Ok(record)
    }

    fn command_difference(&self, recorded: &str, current: &str) -> String {
        let protected = self.protect_publication(&json!([recorded, current]), &[]);
        let Ok(protected) = protected else {
            return "Cannot run it again: the command has changed. Recorded and current command summaries were withheld for protection. Nothing will be sent.".into();
        };
        let recorded = protected[0].as_str().expect("protected string");
        let current = protected[1].as_str().expect("protected string");
        let difference = recorded
            .bytes()
            .zip(current.bytes())
            .position(|(old, new)| old != new)
            .unwrap_or(recorded.len().min(current.len()));
        let start = difference.saturating_sub(40);
        let excerpt = |command: &str| {
            let mut start = start.min(command.len());
            while !command.is_char_boundary(start) {
                start -= 1;
            }
            format!(
                "from byte {start}: {}",
                self.command_summary(&command[start..])
            )
        };
        format!(
            "Cannot run it again: the command has changed. Recorded ({}). Current ({}). Nothing will be sent.",
            excerpt(recorded),
            excerpt(current),
        )
    }

    pub(super) fn command_summary(&self, command: &str) -> String {
        // Protect before cutting, then protect the newly exposed boundary as well.
        let summary = self
            .protect_publication(&json!(command), &[])
            .and_then(|safe| {
                let text = safe.as_str().ok_or("command summary encoding")?;
                let mut summary: String = text.chars().take(160).collect();
                if summary.len() < text.len() {
                    summary.push('…');
                }
                self.protect_publication(&json!(summary), &[])
            });
        summary
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| "[command summary withheld]".into())
    }

    /// This small record is the durable link: its own number is the disposition,
    /// and $rerun:<number>:<old call> is the only proposal it can create.
    /// Repeating it on append or replay fails against the original pending prefix.
    pub(super) fn project_rerun(
        &self,
        number: u64,
        confirmation: &Confirmation,
        disposition: &Disposition,
        track_command: bool,
    ) -> Result<Task, String> {
        let original = self.poc_task(&confirmation.task)?;
        if !original.missing_command(confirmation.read)
            || self.disposition_confirmation(&original)? != *confirmation
            || disposition.machine != original.machine
            || disposition.calls != [confirmation.pending.call]
            || disposition.continuation != Continuation::AsIfNotDone
            || !matches!(
                self.dispatch.check_disposition(number, disposition),
                DispositionReport::Accepted { .. }
            )
        {
            return Err("stale or duplicate command rerun".into());
        }
        if original.steps >= original.limits.steps {
            return Err("Cannot run it again: step limit reached; raise limits first.".into());
        }
        let old = original.proposal.as_ref().expect("AI exec checked");
        let mut tasks = self.project_disposition(number, disposition)?;
        if tasks.len() != 1 || tasks[0].id != original.id {
            return Err("rerun disposition must replace exactly its pending task".into());
        }
        let mut task = tasks.pop().expect("one task");
        if track_command {
            let (machine, command) = original.ai_command().expect("AI exec checked");
            task.unmet_commands.push(UnmetCommand {
                created: number,
                call: confirmation.pending.call,
                machine: machine.into(),
                command: command.into(),
            });
        }
        let call_id = format!("$rerun:{number}:{}", confirmation.pending.call);
        if task.completed.iter().any(|(id, _, _)| id == &call_id)
            || task.block_origins.contains_key(&call_id)
        {
            return Err("duplicate command rerun".into());
        }
        if let Some(origin) = original.block_origins.get(&old.call_id) {
            task.block_origins.insert(call_id.clone(), origin.clone());
        }
        task.proposal = Some(Proposal {
            call_id,
            tool: old.tool.clone(),
            check: None,
            report: None,
        });
        task.steps += 1;
        Ok(task)
    }

    pub(crate) fn poc_task_view(&self, task: &Task) -> Value {
        let mut value = task.view();
        if crate::poc::key_renewal::is_renewal(task) {
            return value;
        }
        #[cfg(target_arch = "wasm32")]
        if task.awaiting_operator() {
            let display = task
                .proposal
                .as_ref()
                .and_then(|proposal| crate::poc::question::display(&proposal.tool));
            if let Some(display) = display.filter(|display| self.poc_safe(display).is_ok()) {
                value["operator_question"] = display;
            } else {
                value["proposal"] = Value::Null;
                value["status"] = "paused".into();
                value["pause_reason"] = "The operator question was withheld because its display could not be protected.".into();
            }
        }
        value["acknowledgeable_commands"] = json!(
            task.unmet_commands
                .iter()
                .filter(|command| self.command_acknowledgment_available(task, command))
                .map(|command| command.created)
                .collect::<Vec<_>>()
        );
        if task.status == Status::Paused && task.pending.is_some() {
            match self.poc_disposition_offer(&task.id, &task.start_session) {
                Ok(offer) => {
                    if task.missing_command(offer.read) {
                        let disposition = Disposition {
                            machine: offer.machine.clone(),
                            calls: vec![offer.pending.call],
                            continuation: Continuation::AsIfNotDone,
                            uncertainty: "The owner accepted an unknown outcome; the earlier command may arrive or run late, overlap later commands, and the page will never show it.".into(),
                        };
                        value["rerun_refusal"] = self
                            .prepare_rerun(task, &offer, disposition)
                            .err()
                            .map(|why| self.protect_publication(&json!(why), &[])
                                .unwrap_or_else(|_| json!("Cannot run it again: the reason could not be safely displayed.")))
                            .unwrap_or(Value::Null);
                    }
                    value["disposition_offer"] =
                        serde_json::to_value(offer).expect("confirmation serializes");
                    value["rerun_unsent"] = self.rerun_unsent(task).into();
                }
                Err(why) => value["disposition_refusal"] = why.into(),
            }
        }
        value["disposed_check_retry"] = task
            .verification
            .iter()
            .any(|check| task.disposed_check(check))
            .into();
        #[cfg(target_arch = "wasm32")]
        {
            value["cycle_timings"] = crate::poc::timings::view(&task.id);
            value["reply_tools"] = crate::poc::timings::reply_tools(&task.id);
            if task.requesting
                && !task.ended()
                && !self.ended_sessions.contains(&task.start_session)
                && let Some((revision, why)) = self.poc_reconciliation_failures.get(&task.id)
                && *revision == task.revision
            {
                value["status"] = "paused".into();
                value["pause_reason"] = why.clone().into();
            }
        }
        value
    }

    pub(super) fn command_obligation_met(&self, task: &Task, command: &UnmetCommand) -> bool {
        self.command_obligation_calls(task, command).any(|id| {
            self.dispatch
                .terminals
                .iter()
                .any(|terminal| terminal.terminal.call == id && terminal.number > command.created)
                || self.dispatch.calls.get(&id).is_some_and(|call| {
                    matches!(call.state, CallState::Background { observation } if observation > command.created)
                })
        })
    }

    /// A moved-on playbook can leave a real obligation that repair cannot repeat
    /// by name. Offer the escape only after done, with all commands settled.
    pub(super) fn command_acknowledgment_available(
        &self,
        task: &Task,
        command: &UnmetCommand,
    ) -> bool {
        if task.status != Status::Paused
            || task.pause_reason.as_deref() != Some(crate::poc::completion::FINDINGS)
            || !task.verifying
            || task.pending.is_some()
            || task.proposal.is_some()
            || self.command_obligation_met(task, command)
            || !task.findings.iter().any(|finding| {
                finding.obligation == Some(command.created)
                    && finding.field == crate::delivery::FieldId::UnmetCommand
            })
        {
            return false;
        }
        let origin = task
            .completed
            .iter()
            .find(|(_, _, output)| output["content"]["call"].as_u64() == Some(command.call))
            .and_then(|(id, _, _)| task.block_origins.get(id));
        let Some(origin) = origin else {
            return false;
        };
        // Match the state Resume's RepairFindings will give to the resolver.
        let mut repair = task.clone();
        repair.verifying = false;
        crate::poc::template::CONTROL_CENTER
            .block(
                &repair,
                self.poc_needs_declaration(&task.machine),
                origin.step,
                &origin.block,
            )
            .is_err()
    }

    fn command_obligation_calls<'a>(
        &'a self,
        task: &'a Task,
        command: &'a UnmetCommand,
    ) -> impl Iterator<Item = u64> + 'a {
        task.completed
            .iter()
            .filter_map(|(_, _, output)| output["content"]["call"].as_u64())
            .chain(task.pending.iter().map(|pending| pending.call))
            .filter(move |call| *call > command.created)
            .filter(move |id| {
                self.dispatch.calls.get(id).is_some_and(|call| {
                    call.intent.machine == command.machine
                        && call.intent.command == hex::encode(&command.command)
                })
            })
    }

    pub(super) fn command_obligation_finding(&self, command: &UnmetCommand) -> String {
        let summary = self.command_summary(&command.command);
        format!(
            "A command you chose to run again never ran: {}: {summary}. Resume lets the AI run it, or choose It already ran if you know it did.",
            command.machine,
        )
    }

    /// A pending product re-issue whose launch was prepared but never attempted has not been sent: Resume sends it
    /// once (the i55 first-send recovery). Until then "It already ran" is refused; "Let the AI decide" stays
    /// available, so a launch that can never be sent (e.g. a changed wrapper) still has a way on.
    pub(in crate::store) fn rerun_unsent(&self, task: &Task) -> bool {
        task.rerun_proposed()
            && task.pending.as_ref().is_some_and(|pending| {
                self.dispatch
                    .launches
                    .get(&pending.call)
                    .is_some_and(|fence| !fence.attempted && !fence.resent)
            })
    }

    /// Continuing assumptions never create obligations. Only a pending AI
    /// command recorded as run can clear existing obligations for its bytes.
    pub(in crate::store) fn project_command_disposition(
        &self,
        number: u64,
        disposition: &Disposition,
    ) -> Result<Vec<Task>, String> {
        if disposition.continuation == Continuation::AsIfDone
            && self.poc.values().any(|task| {
                task.pending
                    .as_ref()
                    .is_some_and(|pending| disposition.calls.contains(&pending.call))
                    && self.rerun_unsent(task)
            })
        {
            return Err(UNSENT_RERUN.into());
        }
        let mut tasks = self.project_disposition(number, disposition)?;
        if disposition.continuation != Continuation::AsIfDone {
            return Ok(tasks);
        }
        for task in &mut tasks {
            let original = self.poc.get(&task.id).expect("projected task");
            if let Some((machine, bytes)) = original.ai_command() {
                let recorded: Vec<_> = task
                    .unmet_commands
                    .iter()
                    .filter(|command| command.machine == machine && command.command == bytes)
                    .map(|command| command.created)
                    .collect();
                for obligation in recorded {
                    task.record_command_as_run(obligation)?;
                }
            }
        }
        Ok(tasks)
    }

    #[cfg(all(target_arch = "wasm32", feature = "tracer"))]
    pub(crate) async fn test_pending_context(&mut self, kind: &str) -> Result<(), String> {
        let task = self
            .poc
            .values()
            .find(|task| task.status == Status::Paused && task.pending.is_some())
            .ok_or("paused fixture task")?
            .clone();
        let pending = task.pending.as_ref().expect("fixture pending");
        let command = self.dispatch.calls[&pending.call].intent.command.clone();
        let record = if kind == "incomplete" {
            crate::jobs::Record::Incomplete {
                machine: Some(hex::encode(&task.machine)),
                command: Some(command),
            }
        } else {
            crate::jobs::Record::Present {
                machine: hex::encode(&task.machine),
                command,
                boot: "earlier".into(),
                current_boot: "later".into(),
                pid: 12,
                alive: false,
                exit_status: None,
                stdout: String::new(),
                stderr: String::new(),
            }
        };
        self.job_evidence(&crate::jobs::Evidence {
            call: pending.call,
            job: pending.job.clone(),
            record,
        })
        .await?;
        if kind == "incomplete" {
            let mut calls = Vec::new();
            // Historical fixtures retain older overlapping calls without changing admission.
            for _ in 0..2 {
                let number = self.next;
                let intent = Intent {
                    call: number,
                    machine: task.machine.clone(),
                    command: hex::encode("earlier-command"),
                    approval: Some(crate::dispatch::Approval::HarnessPin {
                        machine: task.machine.clone(),
                        fingerprint: "fixture-pin".into(),
                    }),
                    job: Some(hex::encode(random::<24>()?)),
                    provenance: None,
                };
                self.commit(&Event::Intent(intent.clone())).await?;
                self.apply_intent(number, intent)?;
                calls.push(number);
            }
            self.dispose(Disposition {
                machine: task.machine,
                calls: vec![calls[0]],
                continuation: Continuation::AsIfDone,
                uncertainty: "Owner accepted an unknown outcome.".into(),
            })
            .await?;
        }
        Ok(())
    }

    /// No live authority or transient keys are needed to reconstruct committed history.
    pub(in crate::store) fn project_disposition(
        &self,
        number: u64,
        disposition: &Disposition,
    ) -> Result<Vec<Task>, String> {
        if disposition.continuation.destructive() {
            return Ok(Vec::new());
        }
        let mut projected = Vec::new();
        for original in self.poc.values().filter(|task| {
            !task.ended()
                && !self.ended_sessions.contains(&task.start_session)
                && task.machine == disposition.machine
                && task
                    .pending
                    .as_ref()
                    .is_some_and(|p| disposition.calls.contains(&p.call))
        }) {
            let mut task = original.clone();
            let pending = task.pending.as_ref().expect("pending filter");
            let call = self
                .dispatch
                .calls
                .get(&pending.call)
                .ok_or("pending disposition call absent")?;
            if call.intent.machine != task.machine || call.intent.job.as_ref() != Some(&pending.job)
            {
                return Err("pending disposition identity differs".into());
            }
            let before_setup = task.preparing_read();
            let proposal = task
                .proposal
                .take()
                .ok_or("pending disposition proposal absent")?;
            if proposal.tool
                != (Tool::Exec {
                    machine: task.machine.clone(),
                    command: String::from_utf8(
                        hex::decode(&call.intent.command).map_err(|_| "command bytes")?,
                    )
                    .map_err(|_| "command encoding")?,
                })
                || task
                    .completed
                    .iter()
                    .any(|(id, _, _)| *id == proposal.call_id)
            {
                return Err("pending disposition proposal association differs".into());
            }
            let read = self
                .poc_committed(pending)
                .map(|r| json!({"record":r.number,"state":r.state}));
            let remaining: Vec<_> = self
                .dispatch
                .unresolved(&crate::dispatch::Resource::Entry(task.machine.clone()))
                .into_iter()
                .filter(|call| !disposition.calls.contains(call))
                .collect();
            let mut outcome = json!({"call":pending.call,"job":pending.job,"machine":task.machine,"outcome":"unknown","disposition":number,"continuation":disposition.continuation,"collection_read":read,"remaining_unresolved":remaining,"machine_held":!remaining.is_empty(),"uncertainty":disposition.uncertainty});
            if !remaining.is_empty() {
                outcome["hold_reason"] =
                    format!("The machine remains held by other unresolved calls: {remaining:?}.")
                        .into();
            }
            if self.protect_output(&outcome)? != outcome {
                return Err(crate::poc::wait::CHECKPOINT_PROTECTION.into());
            }
            if let Some(index) = proposal.check {
                let batch = proposal.check_batch();
                let end = if batch {
                    proposal.check_batch_end(task.checks.len())
                } else {
                    index + 1
                };
                if batch
                    && !matches!(&proposal.tool, Tool::Exec {command, ..}
                    if command == &crate::poc::check_batch::command(&task.checks[..end], index))
                {
                    return Err("pending disposition verification differs".into());
                }
                for index in index..end {
                    let check = task
                        .verification
                        .get_mut(index)
                        .ok_or("pending disposition verification absent")?;
                    if check.job != pending.job
                        || check.exit_status.is_some()
                        || task.checks.get(index) != Some(&check.command)
                        || (!batch
                            && !matches!(&proposal.tool, Tool::Exec {command, ..} if command == &check.command))
                    {
                        return Err("pending disposition verification differs".into());
                    }
                    check.excerpt =
                        "Outcome unknown; owner recorded a continuing assumption.".into();
                }
            }
            if let Some(index) = proposal.report {
                task.reports[index].status = "outcome unknown".into();
                task.reports[index].excerpt =
                    "Owner recorded a continuing assumption; this report will not be repeated."
                        .into();
            }
            if before_setup {
                task.before_setup.as_mut().expect("attempt").settled = true;
            }
            task.completed.push((
                proposal.call_id,
                proposal.tool,
                crate::goals::untrusted("tool_output", outcome),
            ));
            task.pending = None;
            task.active();
            task.revision = task
                .revision
                .checked_add(1)
                .ok_or(crate::poc::wait::REVISION_EXHAUSTED)?;
            projected.push(task);
        }
        Ok(projected)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
thread_local! { pub(super) static CRASH: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(in crate::store) async fn crash_point(point: u8) {
    if CRASH.get() == point {
        std::future::pending::<()>().await;
    }
}
