//! Owner admission and journal-prefix projection of a pending unknown outcome.
use super::*;
use crate::dispatch::{CallState, Continuation, DispositionRecord};
use crate::jobs::{Record as JobRecord, State};

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
        let read = self.disposition_read(&task)?;
        let pending = task.pending.clone().expect("read checked pending");
        Ok(Confirmation {
            task: id.into(),
            revision: task.revision,
            session: session.into(),
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
        let report = self.dispose(Disposition {
            machine: confirmation.machine.clone(), calls: vec![confirmation.pending.call], continuation,
            uncertainty: "The owner accepted an unknown outcome; the earlier command may arrive or run late, overlap later commands, and the page will never show it.".into(),
        }).await?;
        if !matches!(report, DispositionReport::Accepted { .. }) {
            return Err("disposition refused; pending call remains held".into());
        }
        self.poc_task(&confirmation.task)
    }

    pub(in crate::store) fn poc_task_view(&self, task: &Task) -> Value {
        let mut value = task.view();
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
        if task.status == Status::Paused && task.pending.is_some() {
            match self.poc_disposition_offer(&task.id, &task.start_session) {
                Ok(offer) => {
                    value["disposition_offer"] =
                        serde_json::to_value(offer).expect("confirmation serializes")
                }
                Err(why) => value["disposition_refusal"] = why.into(),
            }
        }
        value["disposed_check_retry"] = task
            .verification
            .iter()
            .any(|check| task.disposed_check(check))
            .into();
        value
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
