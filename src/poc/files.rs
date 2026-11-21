//! Offers contain metadata only. File bytes never enter a task or command result.
use crate::goals::Tool;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const LIMIT: usize = 1024 * 1024;
pub const DIRECTORY: &str = "/var/lib/farseed-files";
pub const LIVE_SESSION_REQUIRED: &str =
    "Files can be fetched from this machine while its session is live.";

pub fn valid_name(name: &str) -> bool {
    (1..=100).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

#[derive(Serialize)]
pub struct ListedFile {
    pub name: String,
    pub size: u64,
}

#[derive(Serialize)]
pub struct Listing {
    pub files: Vec<ListedFile>,
    pub truncated: bool,
    pub empty_message: String,
}

impl Listing {
    /// Private response framing: names and sizes never pass through a task or report.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let invalid = "The file list could not be verified. Try again.";
        let text = std::str::from_utf8(bytes).map_err(|_| invalid)?;
        let mut listing = Self {
            files: Vec::new(),
            truncated: false,
            empty_message: format!(
                "No files to get. Put a file in {DIRECTORY} on this machine first."
            ),
        };
        if text == "TAUNONE\n" {
            return Ok(listing);
        }
        let mut lines = text.strip_suffix('\n').ok_or(invalid)?.split('\n');
        let last = lines.next_back().ok_or(invalid)?;
        listing.truncated = match last {
            "TAUEND" => false,
            "TAUMORE" => true,
            _ => return Err(invalid.into()),
        };
        for line in lines {
            let (name, size) = line
                .strip_prefix("TAUENTRY ")
                .and_then(|line| line.split_once(' '))
                .ok_or(invalid)?;
            if !valid_name(name)
                || size.is_empty()
                || !size.bytes().all(|b| b.is_ascii_digit())
                || (size.len() > 1 && size.starts_with('0'))
                || listing.files.len() >= 32
                || listing
                    .files
                    .last()
                    .is_some_and(|file| file.name.as_str() >= name)
            {
                return Err(invalid.into());
            }
            listing.files.push(ListedFile {
                name: name.into(),
                size: size.parse().map_err(|_| invalid)?,
            });
        }
        if listing.truncated && listing.files.len() != 32 {
            return Err(invalid.into());
        }
        Ok(listing)
    }
}

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
