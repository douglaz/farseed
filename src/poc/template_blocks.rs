//! The same complete publisher template parser runs in the build and at runtime.
use std::collections::BTreeMap;

// Keep the bytes between the fences, including the final newline, so the
// admitted command is the published block.
pub(crate) fn blocks(text: &'static str, recovery: bool) -> BTreeMap<&'static str, &'static str> {
    let mut result = BTreeMap::new();
    let mut label = None;
    let mut start = None;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches('\n');
        if let Some(begin) = start {
            if trimmed == "```" {
                let name = label.take().expect("labelled template shell block");
                assert!(
                    result.insert(name, &text[begin..offset]).is_none(),
                    "unique template block label"
                );
                start = None;
            }
        } else if let Some(rest) = trimmed.strip_prefix("**") {
            let (name, _) = rest.split_once("**").expect("closed template block label");
            label = Some(if recovery {
                let (name, _) = name.split_once(':').expect("Recovery block label");
                assert!(
                    name.strip_prefix('R')
                        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())),
                    "numbered Recovery label"
                );
                name
            } else {
                name
            });
        } else if trimmed == "```sh" {
            assert!(label.is_some(), "labelled template shell block");
            start = Some(offset + line.len());
        } else {
            assert!(!trimmed.starts_with("```"), "template shell fence");
        }
        offset += line.len();
    }
    assert!(start.is_none(), "closed template shell block");
    assert!(!result.is_empty(), "template shell blocks");
    result
}

pub struct Step {
    pub text: &'static str,
    pub part: &'static str,
    pub conditions: Vec<&'static str>,
    pub blocks: BTreeMap<&'static str, &'static str>,
}
pub struct Template {
    pub header: &'static str,
    pub facts: &'static str,
    pub declaration: Option<&'static str>,
    pub steps: Vec<Step>,
    pub recovery: &'static str,
    pub recovery_blocks: BTreeMap<&'static str, &'static str>,
    pub hashes: [&'static str; 2],
}

pub(crate) fn parse(source: &'static str) -> Template {
    let sections: Vec<_> = source.match_indices("\n## ").map(|(i, _)| i + 1).collect();
    let mut header = None;
    let mut facts = None;
    let mut declaration = None;
    let mut recovery = None;
    let mut steps = Vec::new();
    for (index, start) in sections.iter().enumerate() {
        let text = source[*start..sections.get(index + 1).copied().unwrap_or(source.len())]
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
                blocks: blocks(text, false),
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
    let recovery = recovery.expect("template Recovery");
    Template {
        header: header.expect("template Header"),
        facts: facts.expect("template Facts"),
        declaration,
        steps,
        recovery,
        recovery_blocks: blocks(recovery, true),
        hashes,
    }
}
