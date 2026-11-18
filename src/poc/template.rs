//! Publisher text for the versioned control-center goal; progress comes from full history.
use crate::goals::Tool;
use crate::store::poc::Task;
use std::collections::BTreeMap;
use std::sync::LazyLock;

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

pub struct Step {
    pub text: &'static str,
    pub part: &'static str,
    pub conditions: Vec<&'static str>,
}
pub struct Template {
    pub header: &'static str,
    pub facts: &'static str,
    pub declaration: Option<&'static str>,
    pub steps: Vec<Step>,
    pub recovery: &'static str,
    pub hashes: [&'static str; 2],
}

pub static CONTROL_CENTER: LazyLock<Template> = LazyLock::new(|| {
    let sections: Vec<_> = SOURCE.match_indices("\n## ").map(|(i, _)| i + 1).collect();
    let mut header = None;
    let mut facts = None;
    let mut declaration = None;
    let mut recovery = None;
    let mut steps = Vec::new();
    for (index, start) in sections.iter().enumerate() {
        let text = SOURCE[*start..sections.get(index + 1).copied().unwrap_or(SOURCE.len())]
            .trim_end()
            .trim_end_matches("---")
            .trim_end();
        let heading = text.lines().next().expect("template section heading");
        if heading.starts_with("## Header") {
            assert!(header.replace(text).is_none(), "duplicate template Header");
        } else if heading.starts_with("## Facts") {
            assert!(facts.replace(text).is_none(), "duplicate template Facts");
        } else if heading == "## Declaration" {
            assert!(declaration.replace(text).is_none(), "duplicate Declaration");
        } else if heading == "## Recovery" {
            assert!(recovery.replace(text).is_none(), "duplicate Recovery");
        } else if let Some(number) = heading.strip_prefix("## Step ") {
            let number = number.split([':', ' ']).next().expect("step number");
            assert_eq!(
                number.parse::<usize>().expect("numeric template step"),
                steps.len() + 1
            );
            let parts: Vec<_> = text
                .lines()
                .filter_map(|line| {
                    line.strip_prefix("Expect `CHECKS ")?
                        .split_once(" PASS`")
                        .map(|(part, _)| part)
                })
                .collect();
            assert_eq!(parts.len(), 1, "one Expect PASS per template step");
            let part = parts[0];
            assert!(
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "template pass part"
            );
            assert!(
                !steps.iter().any(|step: &Step| step.part == part),
                "duplicate pass part"
            );
            steps.push(Step {
                text,
                part,
                conditions: heading
                    .split("only if `")
                    .skip(1)
                    .filter_map(|rest| {
                        let (name, suffix) = rest.split_once('`')?;
                        suffix.starts_with(" is `yes`").then_some(name)
                    })
                    .collect(),
            });
        }
    }
    assert!(!steps.is_empty(), "at least one template step");
    let prefix = "printf '%s  /etc/nixos/cc-rebuild.sh\\n%s  /etc/nixos/cc-check.sh\\n' ";
    let mut hashes = None;
    for check in steps
        .iter()
        .flat_map(|step| step.text.lines())
        .filter_map(|line| line.strip_prefix(prefix))
    {
        let words: Vec<_> = check.split_whitespace().collect();
        assert!(
            words.len() >= 3 && words[2] == "|",
            "two pinned script hashes"
        );
        let pair = [words[0], words[1]];
        assert!(
            pair.iter().all(|hash| hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            "sha256 script hashes"
        );
        assert!(
            hashes.is_none_or(|previous| previous == pair),
            "consistent script hashes across template steps"
        );
        hashes = Some(pair);
    }
    let hashes = hashes.expect("template script hash check");
    Template {
        header: header.expect("template Header"),
        facts: facts.expect("template Facts"),
        declaration,
        steps,
        recovery: recovery.expect("template Recovery"),
        hashes,
    }
});

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
            "Step {number} is not passed yet. Carry on from the last block you ran, following the step's text and that block's output: run the next block the text gives, including the block for the operator's answer and any ask_operator, request_ai_key or offer_file call it asks for; run a block again only when its output, the step's \"If it fails\" or Recovery tells you to, and don't start the step over. Then run its Check block exactly as written, as one command on its own; go on only when its output shows \"CHECKS {} PASS\".",
            step.part
        ))
    }
}
