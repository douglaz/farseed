//! Application inference key custody is encrypted; the machine owns its revocation metadata.
use super::*;
use crate::poc::credit::{AI_KEY_CAP, Mint, SecretText};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachineKey {
    pub name: String,
    pub record_id: String,
    pub application: String,
    pub path: String,
    pub expires: String,
}

pub(crate) struct Entry {
    pub task: String,
    pub call: String,
    pub path: String,
    pub mint: Mint,
    pub key: Option<SecretText>,
    pub configuration: Option<crate::poc::inference::Configuration>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Record {
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
        expires: String,
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
            Ok(
                json!({"status":"created","path":entry.path,"limit_usd":AI_KEY_CAP,"expires":machine_key.map(|key| &key.expires),"base_url":base_url,"api":"chat-completions","model":configuration.model}),
            )
        } else {
            Ok(
                json!({"status":"failed","reason":"the machine could not save the AI key","path":entry.path,"limit_usd":AI_KEY_CAP}),
            )
        }
    }
    fn validate_ai_key(&self, record: &Record) -> Result<(), String> {
        match record {
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
                if !matches!(proposal.tool, crate::goals::Tool::RequestAiKey { .. })
                    || !task.ai_key_approved
                    || !self.poc_targets.contains_key(&task.machine)
                    || proposal.call_id != *call
                    || task.pending.is_some()
                    || self.ai_key(&task.id, call).is_some()
                    || *saved_path != path(&task)
                    || mint.session != task.start_session
                    || mint.requested_cap != AI_KEY_CAP
                    || mint.requested_expiry == 0
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
                    || !crate::poc::credit::expiry_matches(entry.mint.requested_expiry, expires)
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
                self.remember_poc_credential(key.0.as_bytes());
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
    pub(super) fn ai_key_custody_metadata(event: &Event) -> Option<Value> {
        if let Event::PocAiKey(Record::Held {
            machine,
            name,
            issuer_id,
            expires,
            ..
        }) = event
        {
            Some(
                json!({"journal_version":4,"event":{"poc_ai_key":{"held":{"machine":machine,"name":name,"issuer_id":issuer_id,"expires":expires}}}}),
            )
        } else {
            None
        }
    }
    pub(crate) async fn ai_key_commit(&mut self, record: Record) -> Result<(), String> {
        self.credit_ready()?;
        self.validate_ai_key(&record)?;
        match &record {
            Record::Request { task, .. } => {
                self.poc_authority(task, &self.poc_task(task)?.start_session)?;
            }
            Record::Held { key, .. } => {
                self.remember_poc_credential(key.0.as_bytes());
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
