//! Publisher text for the versioned control-center goal; progress comes from full history.
use crate::goals::Tool;
use crate::store::poc::Task;
use std::collections::BTreeMap;
use std::sync::LazyLock;

#[path = "template_blocks.rs"]
mod block_catalogue;

pub const ID: &str = "control-center@1";
pub const NAME: &str = "Control center";
pub const USER_TEXT: &str = "Your own private AI machine. It runs NixOS, has an AI agent with a web dashboard, and only you can reach it. It can install more for you later.";
pub const OPTIONS: &[(&str, &str, bool)] =
    &[("TOR", "Also reach it over Tor (an onion address)", false)];
pub const INPUTS: &[(&str, &str)] = &[(
    "USER_SSH_KEY",
    "Your SSH public key (optional): lets you log in to the machine directly",
)];
pub const INVALID_SSH_KEY: &str =
    "Enter one SSH public key line (for example ssh-ed25519 AAAA… you@host), or leave it empty.";
pub const CLEAR_GOAL: &str = "Clear the goal text to use the Control center template.";
pub const FIXED_FACTS: &[(&str, &str)] = &[("AGENT_MAY_CHANGE_MACHINE", "yes")];
pub const THIRD_PARTY_HOSTS: &[(&str, &str)] =
    &[("app.t3.codes", "T3 app (you sign in with your T3 account)")];
pub const REQUIRED_FILES: &[&str] = &["wireguard.conf", "control-center-login.txt"];

pub fn third_party_label(url: &str) -> Option<&'static str> {
    let authority = url
        .strip_prefix("https://")?
        .split(['/', '?', '#'])
        .next()?;
    if authority.contains([':', '@']) {
        return None;
    }
    #[cfg(target_arch = "wasm32")]
    let host = web_sys::Url::new(url).ok()?.host();
    #[cfg(not(target_arch = "wasm32"))]
    let host = authority.to_owned();
    THIRD_PARTY_HOSTS
        .iter()
        .find_map(|(listed, label)| host.eq_ignore_ascii_case(listed).then_some(*label))
}
pub type Options = BTreeMap<String, bool>;
pub type Inputs = BTreeMap<String, String>;
pub const NEEDS_NIXOS: &str = "The Control center needs a NixOS machine.";
pub const FINISHED: &str =
    "Every step passed. Call done with every address the user should open in urls.";
const SOURCE: &str = include_str!("../../templates/control-center/playbook.md");

pub use block_catalogue::{Step, Template};

pub static CONTROL_CENTER: LazyLock<Template> = LazyLock::new(|| block_catalogue::parse(SOURCE));

pub fn valid_options(options: Option<&Options>) -> bool {
    options.is_none_or(|options| {
        options
            .keys()
            .all(|name| OPTIONS.iter().any(|(fact, _, _)| name == fact))
    })
}

fn valid_ssh_key(line: &str) -> bool {
    use base64::Engine;
    if line.len() > 8192 || !line.bytes().all(|byte| (b' '..=b'~').contains(&byte)) {
        return false;
    }
    let mut parts = line.splitn(3, ' ');
    let kind = parts.next().unwrap_or_default();
    if !matches!(
        kind,
        "ssh-ed25519"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "ssh-rsa"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    ) || parts.clone().nth(1).is_some_and(|comment| {
        comment.len() > 100
            || comment.split(' ').any(|word| {
                word.is_empty()
                    || !word
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"@._+=:/-".contains(&byte))
            })
    }) {
        return false;
    }
    let Some(encoded) = parts.next() else {
        return false;
    };
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    let Some(prefix) = bytes.get(..4) else {
        return false;
    };
    let length = u32::from_be_bytes(prefix.try_into().expect("four-byte length")) as usize;
    length == kind.len() && bytes.get(4..4 + length) == Some(kind.as_bytes())
}

pub fn normalize_inputs(inputs: &mut Option<Inputs>) -> Result<(), String> {
    if let Some(values) = inputs {
        for (name, value) in values.iter_mut() {
            if !INPUTS.iter().any(|(known, _)| name == known) {
                return Err("invalid goal template".into());
            }
            let line = value.trim();
            if !line.is_empty() && !valid_ssh_key(line) {
                return Err(INVALID_SSH_KEY.into());
            }
            *value = line.to_owned();
        }
        values.retain(|_, value| !value.is_empty());
        if values.is_empty() {
            *inputs = None;
        }
    }
    Ok(())
}

pub fn valid_inputs(inputs: Option<&Inputs>) -> bool {
    inputs.is_none_or(|values| {
        values.iter().all(|(name, value)| {
            INPUTS.iter().any(|(known, _)| name == known)
                && value == value.trim()
                && valid_ssh_key(value)
        })
    })
}

pub fn fact(name: &str, options: Option<&Options>) -> &'static str {
    if let Some((_, value)) = FIXED_FACTS.iter().find(|(fact, _)| *fact == name) {
        return value;
    }
    if OPTIONS.iter().any(|(fact, _, default)| {
        *fact == name
            && options
                .and_then(|values| values.get(name))
                .copied()
                .unwrap_or(*default)
    }) {
        "yes"
    } else {
        "no"
    }
}

pub fn facts(options: Option<&Options>) -> impl Iterator<Item = (&'static str, &'static str)> {
    FIXED_FACTS.iter().copied().chain(
        OPTIONS
            .iter()
            .map(move |(name, _, _)| (*name, fact(name, options))),
    )
}

pub fn goal(options: Option<&Options>) -> String {
    format!("Set up my control center (Tor: {}).", fact("TOR", options))
}

pub fn last_line(text: &str) -> &str {
    text.lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default()
}

fn markers(text: &str) -> impl DoubleEndedIterator<Item = (&str, bool)> {
    text.lines().filter_map(|line| {
        let (part, result) = line.trim().strip_prefix("CHECKS ")?.split_once(' ')?;
        let passed = match result.split(' ').next()? {
            "PASS" => true,
            "FAIL" => false,
            _ => return None,
        };
        (!part.is_empty()).then_some((part, passed))
    })
}

fn latest_exec(task: &Task) -> Option<(&str, &str)> {
    task.completed.iter().rev().find_map(|(_, tool, output)| {
        if let Tool::Exec { command, .. } = tool {
            Some((
                command.as_str(),
                output["content"]["stdout"].as_str().unwrap_or_default(),
            ))
        } else {
            None
        }
    })
}

impl Template {
    pub fn recovery_needed(&self, task: &Task) -> bool {
        (!task.verifying && !task.findings.is_empty()) || self.failed(task)
    }

    /// Admission uses the same history and conditional-step rule as the message.
    /// Zero names Recovery, whose blocks are available only when Recovery is sent.
    pub fn block(
        &self,
        task: &Task,
        declaration_needed: bool,
        number: usize,
        name: &str,
    ) -> Result<&'static str, String> {
        if task.template.as_deref() != Some(ID) {
            return Err("run_step_block is only available for Control center tasks".into());
        }
        if declaration_needed {
            return Err("approve the declaration before running a playbook block".into());
        }
        let catalogue = if number == 0 {
            if !self.recovery_needed(task) {
                return Err("Recovery has not been sent for this task".into());
            }
            &self.recovery_blocks
        } else {
            let step = self.steps.get(number - 1).ok_or("unknown playbook step")?;
            if self.current(task, declaration_needed) != Some(step.text) {
                return Err("only the current step's blocks can run".into());
            }
            &step.blocks
        };
        catalogue
            .get(name)
            .copied()
            .ok_or_else(|| "unknown block label for this playbook step".into())
    }

    pub fn current(&self, task: &Task, declaration_needed: bool) -> Option<&'static str> {
        self.current_through(task, declaration_needed, task.completed.len())
    }

    fn current_through(
        &self,
        task: &Task,
        declaration_needed: bool,
        completed: usize,
    ) -> Option<&'static str> {
        if declaration_needed {
            return self.declaration;
        }
        let mut steps = self.steps.iter().filter(|step| {
            step.conditions
                .iter()
                .all(|name| fact(name, task.options.as_ref()) == "yes")
        });
        let mut current = steps.next();
        for (_, tool, output) in &task.completed[..completed] {
            let Some(step) = current else {
                break;
            };
            if matches!(tool, Tool::Exec { .. })
                && output["content"]["stdout"].as_str().is_some_and(|text| {
                    markers(text)
                        .rev()
                        .find(|(part, _)| *part == step.part)
                        .is_some_and(|(_, passed)| passed)
                })
            {
                current = steps.next();
            }
        }
        Some(current.map_or(FINISHED, |step| step.text))
    }

    pub fn failed(&self, task: &Task) -> bool {
        latest_exec(task).is_some_and(|(_, text)| {
            markers(text)
                .rev()
                .find(|(part, _)| self.steps.iter().any(|step| step.part == *part))
                .is_some_and(|(_, passed)| !passed)
        })
    }

    pub fn retry_reason(&self, task: &Task, current: &str) -> Option<String> {
        let step = self.steps.iter().find(|step| step.text == current)?;
        let number = current.strip_prefix("## Step ")?.split([':', ' ']).next()?;
        let latest = task
            .completed
            .iter()
            .rposition(|(_, tool, _)| matches!(tool, Tool::Exec { .. }))?;
        if self.current_through(task, false, latest) != Some(current) {
            return None;
        }
        Some(format!(
            "Step {number} is not passed yet. Continue from the last block and its output; don't start over. Use run_step_block with this step number and the next label for every block, including Steps 4, 5 and 11; never type blocks out. The product fills AI_KEY_PATH, AI_BASE_URL, AI_MODEL, USER_SSH_KEY and MACHINE_ADDRESS itself. Follow any ask_operator, request_ai_key or offer_file instruction. Repeat a block only when its output, If it fails or Recovery says to. Use exec only for reads and fixes. Run Check alone by name; advance only on \"CHECKS {} PASS\".",
            step.part
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::{self, Elevation};

    #[test]
    fn vendored_template_blocks_have_launch_headroom() {
        // TargetRecord::validate accepts at most 64 machine-name bytes. Test both
        // supported target privilege routes, including the larger sudo wrapper.
        let machine = "m".repeat(64);
        // Bounds from valid_ssh_key, Configuration::new and targets::host.
        // ai_keys::path uses a 48-byte task ID and a u64 step counter; 128
        // bytes safely bounds its fixed prefix plus both components.
        let substitutions = [
            (3, "USER_SSH_KEY", "x".repeat(8192)),
            (4, "AI_KEY_PATH", "x".repeat(128)),
            (5, "AI_BASE_URL", "x".repeat(2048)),
            (5, "AI_MODEL", "x".repeat(128)),
            (11, "MACHINE_ADDRESS", "x".repeat(253)),
        ];
        let headroom_limit = jobs::MAX_LAUNCH_BYTES * 90 / 100;
        let mut failures = Vec::new();
        // CONTROL_CENTER is currently the only vendored goal template. Include
        // Recovery (step 0), even though it is admitted only after a failure.
        for (id, template) in [(ID, &*CONTROL_CENTER)] {
            for (number, blocks) in std::iter::once((0, &template.recovery_blocks)).chain(
                template
                    .steps
                    .iter()
                    .enumerate()
                    .map(|(index, step)| (index + 1, &step.blocks)),
            ) {
                for (label, source) in blocks {
                    let mut command = (*source).to_owned();
                    // Match resolve_task_block's step-specific substitutions.
                    // Values contain no placeholder names, so replacement here
                    // has the same result as its immutable-source span filling.
                    for (step, name, value) in &substitutions {
                        if number == *step {
                            command = command.replace(name, value);
                        }
                    }
                    for elevation in [Elevation::None, Elevation::SudoNoninteractive] {
                        let raw = jobs::launch_size_with_elevation(
                            &machine,
                            source.as_bytes(),
                            elevation,
                        );
                        let size = jobs::launch_size_with_elevation(
                            &machine,
                            command.as_bytes(),
                            elevation,
                        );
                        println!(
                            "{id} step {number} {label} {elevation:?}: source={} raw_launch={raw} filled={} launch={size} limit={} headroom_limit={headroom_limit}",
                            source.len(),
                            command.len(),
                            jobs::MAX_LAUNCH_BYTES,
                        );
                        if !jobs::launch_fits(size) || size > headroom_limit {
                            failures.push(format!(
                                "{id} step {number} {label} {elevation:?}: {size} bytes exceeds {headroom_limit} (90% of {})",
                                jobs::MAX_LAUNCH_BYTES,
                            ));
                        }
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
