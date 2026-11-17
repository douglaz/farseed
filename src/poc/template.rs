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
pub const FIXED_FACTS: &[(&str, &str)] = &[("AGENT_MAY_CHANGE_MACHINE", "yes")];
pub type Options = BTreeMap<String, bool>;
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

impl Template {
    pub fn current(&self, task: &Task, declaration_needed: bool) -> Option<&'static str> {
        if declaration_needed {
            return self.declaration;
        }
        Some(
            self.steps
                .iter()
                .filter(|step| {
                    step.conditions
                        .iter()
                        .all(|name| fact(name, task.options.as_ref()) == "yes")
                })
                .find(|step| {
                    !task.completed.iter().any(|(_, tool, output)| {
                        matches!(tool, Tool::Exec { .. })
                            && output["content"]["stdout"].as_str().is_some_and(|text| {
                                last_line(text).starts_with(&format!("CHECKS {} PASS", step.part))
                            })
                    })
                })
                .map_or(FINISHED, |step| step.text),
        )
    }

    pub fn failed(&self, task: &Task) -> bool {
        task.completed
            .iter()
            .rev()
            .find(|(_, tool, _)| matches!(tool, Tool::Exec { .. }))
            .and_then(|(_, _, output)| output["content"]["stdout"].as_str())
            .is_some_and(|text| {
                self.steps
                    .iter()
                    .any(|step| last_line(text).starts_with(&format!("CHECKS {} FAIL", step.part)))
            })
    }
}
