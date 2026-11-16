//! Offers contain metadata only. File bytes never enter a task or command result.
use crate::goals::Tool;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const LIMIT: usize = 1024 * 1024;

pub fn valid_path(path: &str) -> bool {
    (1..=4096).contains(&path.len()) && !path.bytes().any(|b| matches!(b, 0 | b'\n' | b'\r'))
}

pub fn allowed_path(path: &str) -> bool {
    if !valid_path(path) || !path.starts_with('/') {
        return false;
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    !parts.starts_with(&["var", "lib", "tau-web"])
}

pub fn plain_line(text: &str, max: usize) -> bool {
    !text.trim().is_empty() && text.len() <= max && text.bytes().all(|b| (32..=126).contains(&b))
}

#[derive(Clone, Serialize)]
pub struct Offer {
    pub id: String,
    pub machine: String,
    pub path: String,
    pub label: String,
    pub why: String,
}

impl super::super::store::poc::Task {
    pub fn file_offers(&self) -> Vec<Offer> {
        let mut offers = BTreeMap::new();
        for (_, tool, result) in &self.completed {
            if let Tool::OfferFile {
                machine,
                path,
                label,
                why,
            } = tool
                && result["content"]["status"] == "offered"
            {
                let mut hash = Sha256::new();
                hash.update(machine.as_bytes());
                hash.update([0]);
                hash.update(path.as_bytes());
                let id = hex::encode(hash.finalize());
                offers.insert(
                    id.clone(),
                    Offer {
                        id,
                        machine: machine.clone(),
                        path: path.clone(),
                        label: label.clone(),
                        why: why.clone(),
                    },
                );
            }
        }
        offers.into_values().collect()
    }
}

#[cfg(target_arch = "wasm32")]
pub fn filename(path: &str) -> String {
    let name: String = path
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .bytes()
        .take(100)
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"._-".contains(&b) {
                char::from(b)
            } else {
                '_'
            }
        })
        .collect();
    let name = name.trim_start_matches('.');
    if name.is_empty() {
        "download".into()
    } else {
        name.into()
    }
}
