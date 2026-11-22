//! Deterministic application-key maintenance, using the ordinary durable task runner.
use crate::goals::Tool;
use crate::store::poc::{Change, Task};
use crate::store::{Storage, Store};

pub(crate) const LEGACY_ID: &str = "renew-hermes-ai-key@1";
pub(crate) const ID: &str = "renew-hermes-ai-key@2";
pub(crate) const GOAL: &str = "Renew Hermes's AI key";
pub(crate) const LIVE_REQUIRED: &str = "Renew the AI key while this machine's session is live.";
pub(crate) const KEY: &str = "renew-key";
pub(crate) const WRITE: &str = "renew-secrets";
pub(crate) const REBUILD: &str = "renew-rebuild";
pub(crate) const WAIT: &str = "renew-wait-";
pub(crate) const RESTART: &str = "renew-restart";
pub(crate) const REMOVE: &str = "renew-remove-old-key";
pub(crate) const SUCCESS: &str = "Hermes's AI key was renewed. The Hermes check passed. The old key was revoked and its file removed.";
pub(crate) const RETIRE_FAILED: &str = "Hermes passed its check, but the old key's revocation is not confirmed and its file has not been removed. Resume checks the credit account before retrying revocation.";
pub(crate) const REMOVE_FAILED: &str = "The old key was revoked, but its file could not be removed. Resume retries file removal; it collects any running recorded job first.";
pub(crate) const RETIRE_PENDING: &str = "Hermes passed its check. The old key still needs revocation and file removal. Resume checks the credit account before retrying revocation.";
pub(crate) const CHECK: &str = "renew-check";

pub(crate) fn is_renewal(task: &Task) -> bool {
    matches!(task.template.as_deref(), Some(ID | LEGACY_ID))
}
pub(crate) fn step_name(call: &str) -> &'static str {
    match call {
        KEY => "Create key",
        WRITE => "Write secrets",
        REBUILD => "Rebuild",
        RESTART => "Restart services",
        CHECK => "Check Hermes",
        call if call.starts_with(REMOVE) => "Remove old key file",
        _ => "Wait for rebuild",
    }
}
pub(crate) fn failed(call: &str) -> String {
    if call.starts_with(REMOVE) {
        return REMOVE_FAILED.into();
    }
    format!("AI key renewal stopped: {} failed.", step_name(call))
}

pub(crate) const APPROVAL: &str = "AI key renewal is waiting for requirements approval. Approve or reject the open requirements card, then Resume.";
pub(crate) const UNKNOWN_KEY: &str = "AI key creation has an unknown outcome. The recorded request will not be sent again. Check the credit account and Stop task before starting another renewal.";
pub(crate) const CREDIT: &str = "AI key renewal is waiting for inference credit. Fund or restore the credit account, then Resume.";
pub(crate) const INTERRUPTED: &str = "AI key renewal was interrupted. Restore the live session, then Resume; a recorded key request will not be sent again.";
pub(crate) const PREREQUISITES: &str = "AI key renewal is waiting for execution prerequisites. Check session, connection and credit settings, then Resume.";

/// A completed result, rather than a refusal before execution, establishes step failure.
fn execution_failed(task: &Task) -> bool {
    let Some((call, _, output)) = task.completed.last() else {
        return false;
    };
    let outcome = &output["content"];
    let exit = outcome["exit_status"]
        .as_u64()
        .and_then(|exit| u32::try_from(exit).ok());
    match call.as_str() {
        KEY => outcome["status"] == "failed",
        WRITE | REBUILD | RESTART => exit.is_some_and(|exit| exit != 0),
        call if call.starts_with(REMOVE) => exit.is_some_and(|exit| exit != 0),
        CHECK => {
            exit.is_some() && !check_passed(exit, outcome["stdout"].as_str().unwrap_or_default())
        }
        call if call.starts_with(WAIT) => exit.is_some() && next_result_failed_wait(outcome),
        _ => false,
    }
}
fn next_result_failed_wait(outcome: &serde_json::Value) -> bool {
    let stdout = outcome["stdout"].as_str().unwrap_or_default();
    !((outcome["exit_status"] == 3
        && stdout
            .lines()
            .any(|line| line == "STILL RUNNING. Run the same wait command again."))
        || (outcome["exit_status"] == 0
            && stdout.lines().any(|line| line.starts_with("REBUILD OK "))))
}

/// Only local sentences reach a renewal card. A refusal is not a failed execution.
pub(crate) fn local_change(task: &Task, change: Change, unknown_key: bool) -> Change {
    let call = task.proposal.as_ref().map_or(KEY, |p| p.call_id.as_str());
    match change {
        Change::Pause(why) => {
            let cause = why
                .strip_prefix(
                    "original accepted session authority for the task machine is required: ",
                )
                .unwrap_or(&why);
            let sentence = if [RETIRE_FAILED, RETIRE_PENDING, REMOVE_FAILED].contains(&cause) {
                cause.into()
            } else if unknown_key || cause == UNKNOWN_KEY {
                UNKNOWN_KEY.into()
            } else if cause == super::wait::APPROVAL_PENDING || cause == APPROVAL {
                APPROVAL.into()
            } else if cause == CREDIT || cause == "no inference credit account is available" {
                CREDIT.into()
            } else if cause == "Credit store write hold; unlock again before continuing."
                || cause == "Unlock before using inference credit."
                || cause == "locked"
                || cause.starts_with("journal append outcome uncertain")
            {
                "AI key renewal is waiting for the local credit store. Unlock again, then Resume."
                    .into()
            } else if cause == "AI key request needs the operator's decision" {
                "AI key renewal is waiting for your approval. Choose Create key or Don't on the key card.".into()
            } else if cause == "inference endpoint missing" {
                "AI key renewal is waiting for inference configuration. Restore the endpoint and model, then Resume.".into()
            } else if cause.starts_with("installation facts:") {
                "AI key renewal is waiting for approved installation facts. Review the machine's declaration, then Resume.".into()
            } else if cause == super::wait::TARGET_REQUIRED || cause == super::wait::TARGET_DIFFERS
            {
                "AI key renewal is waiting for its machine connection. Restore the saved target, then Resume.".into()
            } else if cause == INTERRUPTED
                || cause == "Credit operation interrupted."
                || cause == super::wait::SUSPENSION
                || cause == "stale continuation; reconciliation required"
            {
                INTERRUPTED.into()
            } else if task.proposal.is_none()
                && execution_failed(task)
                && task
                    .completed
                    .last()
                    .is_some_and(|(last, _, _)| why == failed(last))
            {
                why
            } else if cause == super::wait::PIN_REQUIRED {
                "AI key renewal is waiting for a trusted host pin. Restore the pin, then Resume."
                    .into()
            } else if cause == super::wait::ACCEPTANCE
                || why.starts_with("original accepted session authority")
            {
                "AI key renewal is waiting for its original live session. Restore session authority, then Resume.".into()
            } else {
                PREREQUISITES.into()
            };
            Change::Pause(sentence)
        }
        Change::Wait { running, .. } => Change::Wait {
            why: format!(
                "AI key renewal: {} {}. Resume collects the recorded job without running it twice.",
                step_name(call),
                if running {
                    "is still running"
                } else {
                    "has an unknown outcome"
                }
            ),
            running,
        },
        other => other,
    }
}

/// The same parsed, vendored shell blocks that run_step_block uses. No model supplies bytes.
pub(crate) fn next<S: Storage>(
    store: &Store<S>,
    task: &Task,
) -> Result<super::inference::ModelReply, String> {
    let (last, _, output) = task
        .completed
        .last()
        .ok_or("AI key renewal has no key request")?;
    let outcome = &output["content"];
    let (call, command) = match last.as_str() {
        KEY if outcome["status"] == "created" => {
            let entry = store
                .ai_key(&task.id, KEY)
                .ok_or("AI key custody missing")?;
            // This path is locally constructed and checked by the existing key record validator.
            if outcome["path"].as_str() != Some(entry.path.as_str()) {
                return Err(failed(KEY));
            }
            (
                WRITE.into(),
                super::template::CONTROL_CENTER.steps[3].blocks["Do"]
                    .replace("AI_KEY_PATH", &entry.path),
            )
        }
        WRITE if outcome["exit_status"] == 0 => {
            (REBUILD.into(), "sh /etc/nixos/cc-rebuild.sh".into())
        }
        REBUILD if outcome["exit_status"] == 0 => (format!("{WAIT}{}", task.steps), wait()),
        call if call.starts_with(WAIT) => {
            let stdout = outcome["stdout"].as_str().unwrap_or_default();
            if outcome["exit_status"] == 3
                && stdout
                    .lines()
                    .any(|line| line == "STILL RUNNING. Run the same wait command again.")
            {
                (format!("{WAIT}{}", task.steps), wait())
            } else if outcome["exit_status"] == 0
                && stdout.lines().any(|line| line.starts_with("REBUILD OK "))
            {
                (
                    RESTART.into(),
                    "systemctl restart hermes-agent hermes-backend t3code".into(),
                )
            } else {
                return Err(failed(call));
            }
        }
        RESTART if outcome["exit_status"] == 0 => (
            CHECK.into(),
            super::template::CONTROL_CENTER.steps[4].blocks["Check"].into(),
        ),
        call if (call == CHECK || call.starts_with(REMOVE))
            && checked(task)
            && task.template.as_deref() == Some(ID) =>
        {
            let retirement = store.ai_key_retirements_for(task).ok_or(RETIRE_FAILED)?;
            if retirement.state != crate::store::ai_keys::RetirementState::Revoked {
                return Err(RETIRE_PENDING.into());
            }
            (
                format!("{REMOVE}-{}", task.steps),
                remove_command(&retirement.key),
            )
        }
        call => return Err(failed(call)),
    };
    Ok((
        call,
        Tool::Exec {
            machine: task.machine.clone(),
            command,
        },
        None,
    ))
}
fn wait() -> String {
    super::template::CONTROL_CENTER.steps[4].blocks["Wait"].into()
}

pub(crate) fn check_passed(exit: Option<u32>, stdout: &str) -> bool {
    exit == Some(0)
        && stdout
            .lines()
            .any(|line| line == "CHECKS hermes PASS" || line.starts_with("CHECKS hermes PASS "))
}

/// A successful recorded check, even while retirement is unfinished, installs the new key.
pub(crate) fn checked(task: &Task) -> bool {
    task.completed.iter().any(|(call, _, output)| {
        call == CHECK
            && check_passed(
                output["content"]["exit_status"]
                    .as_u64()
                    .and_then(|exit| u32::try_from(exit).ok()),
                output["content"]["stdout"].as_str().unwrap_or_default(),
            )
    })
}

pub(crate) fn remove_command(key: &crate::store::ai_keys::MachineKey) -> String {
    format!(
        "rm -f -- '{}' && [ ! -e '{}' ] && [ ! -L '{}' ]",
        key.path, key.path, key.path
    )
}

#[cfg(any(target_arch = "wasm32", test))]
#[allow(async_fn_in_trait)]
pub(crate) trait RetirementRuntime {
    async fn retirement(&mut self) -> Result<crate::store::ai_keys::Retirement, String>;
    async fn record(&mut self, state: crate::store::ai_keys::RetirementState)
    -> Result<(), String>;
    async fn list(&mut self) -> Result<(u16, serde_json::Value), String>;
    async fn delete(&mut self, id: &str) -> Result<u16, String>;
}

/// These DELETE statuses need no response body; a 404 still needs key-specific evidence.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn delete_status_without_body(status: u16) -> bool {
    matches!(status, 200 | 404)
}

/// Shared by the worker and native fake service. Every DELETE requires a fresh account read.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) async fn retire(runtime: &mut impl RetirementRuntime) -> Result<(), String> {
    use crate::store::ai_keys::RetirementState;
    let retirement = runtime.retirement().await.map_err(|_| RETIRE_FAILED)?;
    if retirement.state == RetirementState::Revoked {
        return Ok(());
    }
    // Persist uncertainty before awaiting any external effect, including on the first try.
    runtime
        .record(RetirementState::Pending)
        .await
        .map_err(|_| RETIRE_FAILED)?;
    let result: Result<(), String> = async {
        let (status, value) = runtime.list().await?;
        let evidence = retirement_evidence(status, &value, &retirement.key)?;
        if evidence == RetirementEvidence::Revoked {
            return Ok(());
        }
        // Recheck local ownership before deleting only the recorded issuer id.
        runtime.record(RetirementState::Pending).await?;
        match runtime.delete(&retirement.key.record_id).await? {
            200 => (),
            404 if evidence == RetirementEvidence::Absent => (),
            404 => {
                // A route/proxy 404 can leave a listed key live. Confirm this id
                // with another account read; the DELETE body establishes nothing.
                let (status, value) = runtime.list().await?;
                if retirement_evidence(status, &value, &retirement.key)?
                    == RetirementEvidence::Unconfirmed
                {
                    return Err(RETIRE_FAILED.into());
                }
            }
            _ => return Err(RETIRE_FAILED.into()),
        }
        Ok(())
    }
    .await;
    let state = if result.is_ok() {
        RetirementState::Revoked
    } else {
        RetirementState::Failed
    };
    runtime.record(state).await.map_err(|_| RETIRE_FAILED)?;
    result.map_err(|_| RETIRE_FAILED.into())
}

#[cfg(any(target_arch = "wasm32", test))]
#[derive(PartialEq)]
enum RetirementEvidence {
    Revoked,
    Absent,
    Unconfirmed,
}

/// Only a complete absence or this key's revocation metadata confirms a 404.
#[cfg(any(target_arch = "wasm32", test))]
fn retirement_evidence(
    status: u16,
    value: &serde_json::Value,
    key: &crate::store::ai_keys::MachineKey,
) -> Result<RetirementEvidence, String> {
    if status != 200 || value["status"] != "success" {
        return Err(RETIRE_FAILED.into());
    }
    let keys = value["data"].as_array().ok_or(RETIRE_FAILED)?;
    let incomplete = keys.len() > 128
        || value
            .get("has_more")
            .is_some_and(|v| !v.is_null() && v != false)
        || value.get("next_cursor").is_some_and(|v| !v.is_null());
    if !incomplete
        && keys.iter().any(|entry| {
            entry["_id"]
                .as_str()
                .is_none_or(|id| !super::credit::identifier(id))
        })
    {
        return Err(RETIRE_FAILED.into());
    }
    let mut matches = keys.iter().filter(|entry| entry["_id"] == key.record_id);
    let found = matches.next();
    if matches.next().is_some() {
        return Err(RETIRE_FAILED.into());
    }
    if let Some(found) = found {
        if found["name"] != key.name {
            return Err(RETIRE_FAILED.into());
        }
        return match found.get("deleted_at") {
            Some(serde_json::Value::String(_)) => Ok(RetirementEvidence::Revoked),
            Some(serde_json::Value::Null) | None => Ok(RetirementEvidence::Unconfirmed),
            _ => Err(RETIRE_FAILED.into()),
        };
    }
    Ok(if incomplete {
        RetirementEvidence::Unconfirmed
    } else {
        RetirementEvidence::Absent
    })
}
