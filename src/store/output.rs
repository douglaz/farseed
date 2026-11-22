//! Exact held-credential protection for output and command reports.
use super::*;

impl<S: Storage> Store<S> {
    /// Refuse paths changed by the current held-credential publication boundary.
    pub fn check_transmitted_path(&self, path: &str) -> Result<(), String> {
        let value = Value::String(path.into());
        if self
            .protect_publication(&value, &[])
            .is_ok_and(|safe| safe == value)
        {
            Ok(())
        } else {
            Err("This file path cannot be downloaded.".into())
        }
    }

    /// Check original string bytes and field names before serializing an output value.
    pub fn protect_output(&self, value: &Value) -> Result<Value, String> {
        self.protect_output_with(value, &[])
    }

    pub(crate) fn protect_output_with(
        &self,
        value: &Value,
        credentials: &[&[u8]],
    ) -> Result<Value, String> {
        self.protect_value(value, credentials, false, false)
    }

    /// Publication checks complete strings and already-cut boundaries under current holdings.
    /// This entry is never used by journal append, replay or evidence admission.
    pub(crate) fn protect_publication(
        &self,
        value: &Value,
        credentials: &[&[u8]],
    ) -> Result<Value, String> {
        self.protect_value(value, credentials, true, false)
    }

    /// Bound only page/task-details envelopes, never arbitrary model tool output.
    pub(crate) fn protect_page_publication(&self, value: &Value) -> Result<Value, String> {
        self.protect_value(value, &[], true, true)
    }

    fn protect_value(
        &self,
        value: &Value,
        credentials: &[&[u8]],
        publication: bool,
        page: bool,
    ) -> Result<Value, String> {
        let mut held = self.held_credentials()?;
        held.extend_borrowed(credentials);
        fn text(
            text: &str,
            held: &crate::redaction::Held<'_>,
            publication: bool,
        ) -> Result<String, String> {
            let safe = if publication {
                crate::redaction::redact_publication(text.as_bytes(), held)?
            } else {
                crate::redaction::redact(text.as_bytes(), &[], held)?
            };
            Ok(String::from_utf8_lossy(safe.as_bytes()).into_owned())
        }
        fn protect(
            value: &Value,
            held: &crate::redaction::Held<'_>,
            publication: bool,
        ) -> Result<Value, String> {
            Ok(match value {
                Value::String(s) => text(s, held, publication)?.into(),
                Value::Array(a) => a
                    .iter()
                    .map(|v| protect(v, held, publication))
                    .collect::<Result<Vec<_>, _>>()?
                    .into(),
                Value::Object(o) => {
                    let mut result = serde_json::Map::new();
                    for (key, value) in o {
                        // Schema keys retain exact protection; only string values have cuts.
                        let key = text(key, held, false)?;
                        if result
                            .insert(key, protect(value, held, publication)?)
                            .is_some()
                        {
                            return Err(crate::poc::wait::OUTPUT_COLLISION.into());
                        }
                    }
                    Value::Object(result)
                }
                _ => {
                    let raw = value.to_string();
                    let safe = text(&raw, held, false)?;
                    if safe == raw {
                        value.clone()
                    } else {
                        safe.into()
                    }
                }
            })
        }
        let mut safe = protect(value, &held, publication)?;
        if page {
            // Complete fields pass once above; bound the page before its envelope is encoded.
            if let Some(tasks) = safe.get_mut("tasks").and_then(Value::as_array_mut) {
                for task in tasks {
                    super::poc::Task::truncate_view(task, &|cut| text(cut, &held, true))?;
                }
            }
            if let Some(task) = safe.pointer_mut("/task_details/task") {
                super::poc::Task::truncate_view(task, &|cut| text(cut, &held, true))?;
            }
        }
        let bytes = Zeroizing::new(serde_json::to_vec(&safe).map_err(|_| "output JSON encoding")?);
        self.check_output_bytes_with(&bytes, &held)?;
        Ok(safe)
    }

    /// Refuse exact copies introduced by framing or escaping after field protection.
    pub(crate) fn check_output_bytes(&self, bytes: &[u8]) -> Result<(), String> {
        self.check_output_bytes_with_credentials(bytes, &[])
    }

    pub(crate) fn check_output_bytes_with_credentials(
        &self,
        bytes: &[u8],
        credentials: &[&[u8]],
    ) -> Result<(), String> {
        let mut held = self.held_credentials()?;
        held.extend_borrowed(credentials);
        self.check_output_bytes_with(bytes, &held)
    }

    fn check_output_bytes_with(
        &self,
        bytes: &[u8],
        held: &crate::redaction::Held<'_>,
    ) -> Result<(), String> {
        if crate::redaction::redact(bytes, &[], held)?.as_bytes() != bytes {
            return Err(crate::poc::wait::PROTECTED_UNAVAILABLE.into());
        }
        Ok(())
    }

    /// Check every supported final envelope before a terminal changes collection authority.
    /// Use the original journal bytes and immutable privilege route, exactly as transmission does.
    pub(crate) fn preflight_job_release(&self, report: &crate::jobs::Report) -> Result<(), String> {
        let intent = &self
            .dispatch
            .calls
            .get(&report.evidence.call)
            .ok_or("job release intent missing")?
            .intent;
        let command = hex::decode(&intent.command).map_err(|_| "job release command hex")?;
        let elevation = self
            .poc_target(&intent.machine)
            .map_or(crate::jobs::Elevation::None, |target| target.elevation);
        let host_key = match &intent.approval {
            Some(crate::dispatch::Approval::HarnessPin { fingerprint, .. }) => fingerprint.clone(),
            _ => String::new(),
        };
        let forms = if report.state == crate::jobs::State::Background {
            crate::harness::background_release_forms(report, &intent.machine)
        } else {
            let done = crate::harness::Done {
                seq: intent.call,
                sent: crate::jobs::launch_with_elevation(
                    intent
                        .job
                        .as_deref()
                        .ok_or("job release identity missing")?,
                    &intent.machine,
                    &command,
                    elevation,
                )
                .into_bytes(),
                recorded: crate::harness::Entry {
                    machine: intent.machine.clone(),
                    command,
                    provenance: intent.provenance.clone(),
                },
                stdout: report.stdout.as_bytes().to_vec(),
                stderr: report.stderr.as_bytes().to_vec(),
                exit_status: report.exit_status.ok_or("job release exit missing")?,
                terminal: report.number.ok_or("job release number missing")?,
                host_key,
                evidence: report.clone(),
            };
            crate::harness::release_forms(&done)
        };
        // Each is an alternative synchronous release, not an aggregate array on the wire.
        for value in forms {
            self.protect_output(&value)?;
        }
        if self.poc.values().any(|task| {
            task.pending
                .as_ref()
                .is_some_and(|pending| pending.call == intent.call)
        }) {
            // A task releases each terminal independently of the bounded history view.
            let mut result =
                serde_json::to_value(report).map_err(|_| crate::poc::wait::RESULT_ENCODING)?;
            self.protect_output(&json!({"command_result":result}))?;
            crate::jobs::historical(&mut result, "stale result after suspension");
            self.protect_output(&json!({"command_result":result}))?;
        }
        Ok(())
    }

    /// Final command release preserves committed evidence while removing stale action authority.
    pub(crate) fn protect_command_results(&self, value: &Value) -> Result<Value, String> {
        let mut safe = self.protect_output(value)?;
        self.current_command_results(&mut safe);
        self.check_output_bytes(safe.to_string().as_bytes())?;
        Ok(safe)
    }

    /// Called after final encoding as well as scanning. Once a result is historical, its
    /// identities and outcome stay intelligible without requiring ordinary authority.
    pub(crate) fn current_command_results(&self, value: &mut Value) -> bool {
        let mut changed = false;
        if let Some(call) = value.get("call").and_then(Value::as_u64)
            && (value["historical"] != true
                || value["actionable"] != false
                || value.get("done").is_some())
            && let Some(session) = self
                .dispatch
                .calls
                .get(&call)
                .and_then(|call| call.intent.provenance.as_ref())
                .and_then(|p| p.session.as_deref())
            && let Err(why) = self.check_session_authority(session, self.session_pair(session))
        {
            crate::jobs::historical(value, &why);
            changed = true;
        }
        match value {
            Value::Array(values) => {
                for value in values {
                    changed |= self.current_command_results(value);
                }
            }
            Value::Object(values) => {
                for value in values.values_mut() {
                    changed |= self.current_command_results(value);
                }
            }
            _ => {}
        }
        changed
    }

    /// Validate the stored record, then protect original output before deriving report text.
    pub(crate) fn job_report(
        &self,
        evidence: &crate::jobs::Evidence,
        number: Option<u64>,
        machine: &str,
        command: &str,
    ) -> Result<crate::jobs::Report, String> {
        evidence.record.validate()?;
        let mut report = evidence.report(number.unwrap_or(0), machine, command);
        report.number = number;
        self.protect_job_report(report)
    }

    pub(crate) fn protect_job_report(
        &self,
        mut report: crate::jobs::Report,
    ) -> Result<crate::jobs::Report, String> {
        let batch = self.poc.values().find_map(|task| {
            let pending = task.pending.as_ref()?;
            let proposal = task.proposal.as_ref()?;
            (pending.call == report.evidence.call
                && pending.job == report.evidence.job
                && proposal.check_batch())
            .then(|| {
                (
                    proposal.check.expect("batch start"),
                    proposal.check_batch_end(task.checks.len()),
                )
            })
        });
        // Reports duplicate the same output as raw hex and lossy text. Protect the full
        // bytes once, then derive both copies; scan every other field independently.
        let output = if let crate::jobs::Record::Present { stdout, stderr, .. }
        | crate::jobs::Record::Background { stdout, stderr, .. } =
            &mut report.evidence.record
        {
            Some([std::mem::take(stdout), std::mem::take(stderr)])
        } else {
            None
        };
        report.stdout.clear();
        report.stderr.clear();
        let value =
            self.protect_output(&serde_json::to_value(report).map_err(|_| "job report encoding")?)?;
        let mut report: crate::jobs::Report =
            serde_json::from_value(value).map_err(|_| "job report protection")?;
        if let Some(output) = output
            && let crate::jobs::Record::Present { stdout, stderr, .. }
            | crate::jobs::Record::Background { stdout, stderr, .. } =
                &mut report.evidence.record
        {
            for (channel, (raw, encoded, decoded)) in [
                (&output[0], stdout, &mut report.stdout),
                (&output[1], stderr, &mut report.stderr),
            ]
            .into_iter()
            .enumerate()
            {
                let mut bytes =
                    Zeroizing::new(hex::decode(raw).map_err(|_| crate::poc::wait::JOB_OUTPUT_HEX)?);
                if channel == 0
                    && let Some((start, end)) = batch
                {
                    // Parse original bytes before redaction or lossy decoding can shift a
                    // boundary. Protect each read as a standalone output, then reframe it.
                    let mut framed = Zeroizing::new(Vec::new());
                    for (offset, (exit, stdout)) in
                        crate::poc::check_batch::parse(&bytes, start, end)
                            .into_iter()
                            .enumerate()
                    {
                        let safe = crate::redaction::Redacted::for_store(self, stdout, &[])?;
                        crate::poc::check_batch::frame(
                            &mut framed,
                            start + offset,
                            exit,
                            safe.as_bytes(),
                        );
                    }
                    bytes = framed;
                }
                let safe = crate::redaction::Redacted::for_store(self, &bytes, &[])?;
                if channel == 0 && batch.is_some() && safe.as_bytes() != bytes.as_slice() {
                    // A whole-stream substitution could turn read data into a header.
                    // Withhold all observations rather than parse shifted framing.
                    bytes.clear();
                }
                let safe = if channel == 0 && batch.is_some() && bytes.is_empty() {
                    crate::redaction::Redacted::for_store(self, &[], &[])?
                } else {
                    safe
                };
                *encoded = hex::encode(safe.as_bytes());
                *decoded = String::from_utf8_lossy(safe.as_bytes()).into_owned();
                // Encoding or lossy decoding can itself create another credential's
                // spelling. Refuse rather than corrupt the hex or release that junction.
                if crate::redaction::Redacted::for_store(self, encoded.as_bytes(), &[])?.as_bytes()
                    != encoded.as_bytes()
                    || (decoded.as_bytes() != safe.as_bytes()
                        && crate::redaction::Redacted::for_store(self, decoded.as_bytes(), &[])?
                            .as_bytes()
                            != decoded.as_bytes())
                {
                    return Err(crate::poc::wait::PROTECTED_UNAVAILABLE.into());
                }
            }
        }
        let bytes = Zeroizing::new(serde_json::to_vec(&report).map_err(|_| "job report encoding")?);
        self.check_output_bytes(&bytes)?;
        Ok(report)
    }
}
