//! Application inference key custody is encrypted; the machine owns its revocation metadata.
use super::*;
use crate::poc::credit::{AI_KEY_CAP, LEGACY_AI_KEY_CAPS, Mint, ResetPeriod, SecretText};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachineKey {
    pub name: String,
    pub record_id: String,
    pub application: String,
    pub path: String,
    pub expires: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RetirementState {
    Needed,
    Pending,
    Failed,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Retirement {
    pub key: MachineKey,
    pub state: RetirementState,
}

pub(crate) struct Entry {
    pub task: String,
    pub call: String,
    pub path: String,
    pub mint: Mint,
    pub key: Option<SecretText>,
    pub configuration: Option<crate::poc::inference::Configuration>,
}

#[cfg(any(target_arch = "wasm32", test))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Preparation {
    Mint,
    Held,
    Unknown,
    AccountRequired,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Record {
    PlanRetirement {
        task: String,
        expected: u64,
        key: MachineKey,
    },
    Retirement {
        task: String,
        issuer_id: String,
        state: RetirementState,
    },
    Request {
        task: String,
        call: String,
        path: String,
        mint: Mint,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        configuration: Option<crate::poc::inference::Configuration>,
    },
    Held {
        machine: String,
        name: String,
        issuer_id: String,
        expires: Option<String>,
        key: SecretText,
    },
}

pub(crate) fn path(task: &poc::Task) -> String {
    // The task identity prevents a later task overwriting an earlier task's file.
    format!("/var/lib/tau-web/secrets/ai-key-{}-{}", task.id, task.steps)
}
pub(crate) fn command(path: &str, bytes: usize) -> String {
    // Only a locally constructed path enters this command. The value arrives on stdin.
    format!(
        "umask 077\nmkdir -p /var/lib/tau-web/secrets && chmod 700 /var/lib/tau-web/secrets || exit 1\n[ ! -e '{path}' ] && [ ! -L '{path}' ] || exit 1\n(set -C; cat > '{path}') && chmod 600 '{path}' && [ \"$(wc -c < '{path}')\" -eq {bytes} ]"
    )
}
impl<S: Storage> Store<S> {
    pub(crate) fn ai_key_retirements_for(&self, task: &poc::Task) -> Option<&Retirement> {
        self.ai_key_retirements.get(&task.id)
    }

    /// Opening old stores is read-only. Resuming an unfinished v1 renewal explicitly
    /// records its replacement and upgrades that task before any further machine work.
    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) async fn prepare_key_retirement(
        &mut self,
        task: &poc::Task,
    ) -> Result<poc::Task, String> {
        if task.template.as_deref() != Some(crate::poc::key_renewal::LEGACY_ID) || task.ended() {
            return Ok(task.clone());
        }
        let key = self
            .installed_hermes_key(&task.machine)
            .cloned()
            .ok_or("installed Hermes key missing")?;
        self.ai_key_commit(Record::PlanRetirement {
            task: task.id.clone(),
            expected: task.revision,
            key,
        })
        .await?;
        self.poc_task(&task.id)
    }

    /// Live ownership guard; replay checks durable transition shape without live authority.
    pub(crate) fn check_key_retirement(&self, task: &poc::Task) -> Result<(), String> {
        if self.poc_task(&task.id)? != *task {
            return Err("key retirement task changed".into());
        }
        let old = &self
            .ai_key_retirements_for(task)
            .ok_or("key retirement missing")?
            .key;
        let current = self
            .installed_hermes_key(&task.machine)
            .ok_or("installed key missing")?;
        let own = self
            .ai_key(&task.id, crate::poc::key_renewal::KEY)
            .ok_or("new key missing")?;
        if !crate::poc::key_renewal::checked(task)
            || task.ended()
            || current.name != own.mint.name
            || old.record_id == current.record_id
            || old.path == current.path
            || !self.poc_targets.get(&task.machine).is_some_and(|record| record.application_inference_keys.contains(old))
            || self.ai_keys.iter().any(|entry| entry.mint.name == old.name && self.poc.get(&entry.task).is_some_and(|user| {
                !user.ended() && !self.ended_sessions.contains(&user.start_session)
            }))
            || self.poc.values().any(|user| user.id != task.id && user.machine == task.machine
                && !user.ended() && !self.ended_sessions.contains(&user.start_session)
                && user.proposal.iter().map(|proposal| &proposal.tool)
                    .chain(user.completed.iter().map(|(_, tool, _)| tool))
                    .any(|tool| matches!(tool, crate::goals::Tool::Exec { command, .. } if command.contains(&old.path))))
        {
            return Err("replaced key is still in use or belongs to another task".into());
        }
        Ok(())
    }

    /// Re-evaluate durable custody on every Resume, before considering another mint.
    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn ai_key_preparation(&self, task: &poc::Task) -> Result<Preparation, String> {
        self.check_task_session(task, &task.start_session)?;
        self.poc_authority(&task.id, &task.start_session)?;
        self.credit_ready()?;
        let proposal = task.proposal.as_ref().ok_or("AI key request missing")?;
        if !matches!(proposal.tool, crate::goals::Tool::RequestAiKey { .. })
            || !task.ai_key_approved
        {
            return Err("AI key request needs the operator's decision".into());
        }
        Ok(match self.ai_key(&task.id, &proposal.call_id) {
            Some(entry) if entry.key.is_some() => Preparation::Held,
            Some(_) => Preparation::Unknown,
            None if !task.ai_key_monthly_approved() => {
                return Err(crate::poc::credit::AI_KEY_APPROVAL_REQUIRED.into());
            }
            None if self.credit_account().is_none() => Preparation::AccountRequired,
            None => Preparation::Mint,
        })
    }
    pub(crate) fn ai_key(&self, task: &str, call: &str) -> Option<&Entry> {
        self.ai_keys
            .iter()
            .find(|e| e.task == task && e.call == call)
    }
    pub(crate) fn ai_key_outcome(
        &self,
        task: &poc::Task,
        exit: Option<u32>,
    ) -> Result<Value, String> {
        let proposal = task.proposal.as_ref().ok_or("AI key request missing")?;
        let entry = self
            .ai_key(&task.id, &proposal.call_id)
            .ok_or("AI key record missing")?;
        let machine_key = self.poc_targets.get(&task.machine).and_then(|record| {
            record
                .application_inference_keys
                .iter()
                .find(|key| key.name == entry.mint.name)
        });
        if exit == Some(0) {
            if entry.key.is_none() || machine_key.is_none() {
                return Err("AI key custody missing; the saved write cannot be confirmed".into());
            }
            let configuration = entry
                .configuration
                .clone()
                .map(Ok)
                .unwrap_or_else(|| self.session_configuration(&task.start_session))?;
            let base_url = configuration
                .endpoint
                .strip_suffix("/chat/completions")
                .unwrap_or(&configuration.endpoint);
            let mut outcome = json!({"status":"created","path":entry.path,"limit_usd":entry.mint.requested_cap,"expires":machine_key.and_then(|key| key.expires.as_ref()),"base_url":base_url,"api":"chat-completions","model":configuration.model});
            if let Some(period) = entry.mint.requested_reset_period {
                outcome["reset_period"] = json!(period);
            }
            Ok(outcome)
        } else {
            Ok(
                json!({"status":"failed","reason":"the machine could not save the AI key","path":entry.path,"limit_usd":entry.mint.requested_cap}),
            )
        }
    }
    fn validate_ai_key(&self, record: &Record) -> Result<(), String> {
        match record {
            Record::PlanRetirement {
                task,
                expected,
                key,
            } => {
                let task = self.poc_task(task)?;
                if task.template.as_deref() != Some(crate::poc::key_renewal::LEGACY_ID)
                    || task.ended()
                    || task.revision != *expected
                    || self.ai_key_retirements.contains_key(&task.id)
                    || self.installed_hermes_key(&task.machine) != Some(key)
                    || task.revision == u64::MAX
                {
                    return Err("legacy key retirement plan refused".into());
                }
            }
            Record::Retirement {
                task,
                issuer_id,
                state,
            } => {
                let task = self.poc_task(task)?;
                let retirement = self
                    .ai_key_retirements_for(&task)
                    .ok_or("key retirement missing")?;
                if issuer_id != &retirement.key.record_id
                    || !crate::poc::key_renewal::checked(&task)
                    || task.ended()
                    || task.pending.is_some()
                    || (retirement.state == RetirementState::Revoked
                        && *state != RetirementState::Revoked)
                    || *state == RetirementState::Needed
                    || (*state != RetirementState::Pending
                        && retirement.state != RetirementState::Pending)
                {
                    return Err("key retirement transition refused".into());
                }
            }
            Record::Request {
                task,
                call,
                path: saved_path,
                mint,
                configuration,
            } => {
                if let Some(configuration) = configuration {
                    crate::poc::inference::Configuration::new(
                        configuration.endpoint.clone(),
                        configuration.model.clone(),
                    )?;
                }
                let task = self.poc_task(task)?;
                let proposal = task.proposal.as_ref().ok_or("AI key request missing")?;
                let policy_valid = match mint.requested_reset_period {
                    None => {
                        (mint.requested_cap == AI_KEY_CAP
                            || LEGACY_AI_KEY_CAPS.contains(&mint.requested_cap))
                            && mint.requested_expiry.is_some_and(|expiry| expiry > 0)
                    }
                    Some(ResetPeriod::Monthly) => {
                        mint.requested_cap == AI_KEY_CAP
                            && task.ai_key_monthly_approved()
                            && mint.requested_expiry.is_none()
                    }
                };
                if !matches!(proposal.tool, crate::goals::Tool::RequestAiKey { .. })
                    || !task.ai_key_approved
                    || !self.poc_targets.contains_key(&task.machine)
                    || proposal.call_id != *call
                    || task.pending.is_some()
                    || self.ai_key(&task.id, call).is_some()
                    || *saved_path != path(&task)
                    || mint.session != task.start_session
                    || !policy_valid
                    || mint.name.len() != 25
                    || !crate::poc::credit::identifier(&mint.name)
                    || self.ai_keys.iter().any(|e| e.mint.name == mint.name)
                    || mint.issuer_id.is_some()
                    || mint.returned_cap.is_some()
                    || mint.returned_expiry.is_some()
                {
                    return Err("AI key request record refused".into());
                }
            }
            Record::Held {
                machine,
                name,
                issuer_id,
                expires,
                key,
            } => {
                let entry = self
                    .ai_keys
                    .iter()
                    .find(|e| e.mint.name == *name)
                    .ok_or("AI key request missing")?;
                crate::poc::inference::valid_key(key.0.as_bytes())?;
                if entry.key.is_some()
                    || self.poc_task(&entry.task)?.machine != *machine
                    || !self.poc_targets.contains_key(machine)
                    || self.poc_targets.values().any(|record| {
                        record
                            .application_inference_keys
                            .iter()
                            .any(|key| key.record_id == *issuer_id)
                    })
                    || !crate::poc::credit::identifier(issuer_id)
                    || !entry.mint.expiry_matches(expires.as_deref())
                {
                    return Err("AI key custody refused".into());
                }
                let metadata =
                    json!({"machine":machine,"name":name,"record_id":issuer_id,"expires":expires});
                if !crate::poc::inference::safe(self, &metadata, &[key.0.as_bytes()]) {
                    return Err("AI key metadata contains protected material".into());
                }
            }
        }
        Ok(())
    }
    pub(super) fn replay_ai_key(&mut self, record: &Record) -> Result<(), String> {
        self.validate_ai_key(record)?;
        match record {
            Record::PlanRetirement { task, key, .. } => {
                let current = self.poc.get_mut(task).expect("validated legacy renewal");
                current.template = Some(crate::poc::key_renewal::ID.into());
                current.revision += 1;
                self.ai_key_retirements.insert(
                    task.clone(),
                    Retirement {
                        key: key.clone(),
                        state: RetirementState::Needed,
                    },
                );
            }
            Record::Retirement { task, state, .. } => {
                self.ai_key_retirements
                    .get_mut(task)
                    .expect("validated retirement")
                    .state = *state;
            }
            Record::Request {
                task,
                call,
                path,
                mint,
                configuration,
            } => self.ai_keys.push(Entry {
                task: task.clone(),
                call: call.clone(),
                path: path.clone(),
                mint: mint.clone(),
                key: None,
                configuration: configuration.clone(),
            }),
            Record::Held {
                machine,
                name,
                issuer_id,
                expires,
                key,
            } => {
                let entry = self
                    .ai_keys
                    .iter_mut()
                    .find(|e| e.mint.name == *name)
                    .expect("validated key record");
                entry.key = Some(SecretText(Zeroizing::new(key.0.to_string())));
                let path = entry.path.clone();
                let task_id = entry.task.clone();
                let task = self.poc_task(&task_id)?;
                let Some(crate::goals::Tool::RequestAiKey { application, .. }) =
                    task.proposal.as_ref().map(|proposal| &proposal.tool)
                else {
                    return Err("AI key request missing".into());
                };
                self.poc_targets
                    .get_mut(machine)
                    .expect("validated machine")
                    .application_inference_keys
                    .push(MachineKey {
                        name: name.clone(),
                        record_id: issuer_id.clone(),
                        application: application.clone(),
                        path,
                        expires: expires.clone(),
                    });
            }
        }
        Ok(())
    }
    pub(crate) async fn ai_key_commit(&mut self, record: Record) -> Result<(), String> {
        self.credit_ready()?;
        self.validate_ai_key(&record)?;
        match &record {
            Record::PlanRetirement { task, .. } => {
                let task = self.poc_task(task)?;
                self.poc_authority(&task.id, &task.start_session)?;
            }
            Record::Retirement { task, .. } => {
                let task = self.poc_task(task)?;
                self.poc_authority(&task.id, &task.start_session)?;
                self.check_key_retirement(&task)?;
            }
            Record::Request { task, .. } => {
                self.poc_authority(task, &self.poc_task(task)?.start_session)?;
            }
            Record::Held {
                machine,
                name,
                issuer_id,
                expires,
                key,
            } => {
                let metadata =
                    json!({"machine":machine,"name":name,"issuer_id":issuer_id,"expires":expires});
                if !crate::poc::inference::safe(self, &metadata, &[key.0.as_bytes()]) {
                    return Err("AI key metadata contains protected material".into());
                }
            }
        }
        if let Record::Request { .. } = &record
            && !crate::poc::inference::safe(
                self,
                &serde_json::to_value(&record).map_err(|_| "AI key request encoding")?,
                &[],
            )
        {
            return Err("AI key request contains protected material".into());
        }
        // Like account custody, the secret-bearing event bypasses public projections and is
        // serialized only inside commit's zeroizing buffer, then encrypted before storage.
        let event = Event::PocAiKey(record);
        self.commit(&event).await?;
        let Event::PocAiKey(record) = &event else {
            unreachable!()
        };
        self.replay_ai_key(record)
    }
}
