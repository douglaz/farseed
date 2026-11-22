//! Deterministic application-key maintenance, using the ordinary durable task runner.
use crate::goals::Tool;
use crate::store::poc::{Change, Task};
use crate::store::{Storage, Store};

pub(crate) const ID: &str = "renew-hermes-ai-key@1";
pub(crate) const GOAL: &str = "Renew Hermes's AI key";
pub(crate) const LIVE_REQUIRED: &str = "Renew the AI key while this machine's session is live.";
pub(crate) const KEY: &str = "renew-key";
pub(crate) const WRITE: &str = "renew-secrets";
pub(crate) const REBUILD: &str = "renew-rebuild";
pub(crate) const WAIT: &str = "renew-wait-";
pub(crate) const RESTART: &str = "renew-restart";
pub(crate) const CHECK: &str = "renew-check";

pub(crate) fn is_renewal(task: &Task) -> bool {
    task.template.as_deref() == Some(ID)
}
pub(crate) fn step_name(call: &str) -> &'static str {
    match call {
        KEY => "Create key",
        WRITE => "Write secrets",
        REBUILD => "Rebuild",
        RESTART => "Restart services",
        CHECK => "Check Hermes",
        _ => "Wait for rebuild",
    }
}
pub(crate) fn failed(call: &str) -> String {
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
            let sentence = if unknown_key || cause == UNKNOWN_KEY {
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
