//! Deterministic application-key maintenance, using the ordinary durable task runner.
use crate::goals::Tool;
use crate::store::poc::Task;
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
