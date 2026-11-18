//! The credential-redaction boundary for adapter responses.

use crate::credential::{
    AttestRecipientKey, AttestSenderKey, PostHarnessCredential, RelayKey, SshClientKey,
};
use crate::store::{Storage, Store};
use std::cell::OnceCell;
use std::collections::HashMap;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const MARKER: &str = "<redacted>";

/// A response that has passed the store's credential boundary. Only the boundary constructs it.
///
/// ```compile_fail
/// use tau_web::redaction::Redacted;
/// let response = Redacted { bytes: vec![] };
/// ```
///
/// ```compile_fail
/// use tau_web::redaction::Redacted;
/// let response = Redacted::from(vec![1u8]);
/// ```
///
/// The same paths and legitimate entry compile without constructing a response from raw bytes:
///
/// ```
/// use tau_web::redaction::Redacted;
/// use tau_web::store::{Storage, Store};
/// async fn response<S: Storage>(store: &mut Store<S>, call: u64) -> Result<Redacted, String> {
///     store.operation_response(call, b"{}", &["/root_password"]).await
/// }
/// ```
pub struct Redacted {
    bytes: Vec<u8>,
}

impl Redacted {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Include the request's transient credentials even after session holdings are cleared.
    pub(crate) fn for_inference<S: Storage>(
        store: &Store<S>,
        body: &[u8],
        credentials: &[&[u8]],
    ) -> Result<Self, String> {
        let mut held = store.held_credentials()?;
        held.extend_borrowed(credentials);
        redact(body, &[], &held)
    }

    /// Refuse a command altered by the exact credential boundary.
    pub(crate) fn inference_value_is_safe<S: Storage>(
        store: &Store<S>,
        value: &serde_json::Value,
        credentials: &[&[u8]],
    ) -> bool {
        store
            .protect_output_with(value, credentials)
            .is_ok_and(|safe| safe == *value)
    }

    pub(crate) fn for_store<S: Storage>(
        store: &Store<S>,
        body: &[u8],
        fields: &[&str],
    ) -> Result<Self, String> {
        let held = store.held_credentials()?;
        // Declared response fields are a protocol operation, not content decoding.
        if fields.is_empty() {
            redact(body, fields, &held)
        } else {
            let value: serde_json::Value = serde_json::from_slice(body)
                .map_err(|_| "response is not JSON for declared fields".to_string())?;
            let safe = store.protect_output(&value)?;
            let bytes = Zeroizing::new(
                serde_json::to_vec(&safe)
                    .map_err(|_| "response JSON cannot be serialized".to_string())?,
            );
            redact(&bytes, fields, &held)
        }
    }
}

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Redacted(..)")
    }
}

/// Transient enumeration: existing holders are borrowed; derived keys and canonical credential
/// text zeroize on drop. No copy extends the lifetime of its holder.
pub(crate) struct Held<'a> {
    borrowed: Vec<&'a [u8]>,
    mnemonic: Zeroizing<String>,
    derived: Vec<Derived>,
    bindings: Vec<std::cell::Ref<'a, Vec<crate::binding::Holding>>>,
}

pub(crate) enum Derived {
    Ssh(SshClientKey),
    Sender(AttestSenderKey),
    Recipient(AttestRecipientKey),
    Relay(RelayKey),
    #[cfg(target_arch = "wasm32")]
    Inference(crate::credential::InferenceAccountCredential),
    #[cfg(target_arch = "wasm32")]
    Session(crate::credential::SessionInferenceKey),
    Handoff(PostHarnessCredential),
    Text(Zeroizing<String>),
    Matcher(OnceCell<Matcher>),
}

impl<'a> Held<'a> {
    pub(crate) fn new(
        borrowed: Vec<&'a [u8]>,
        mnemonic: Zeroizing<String>,
        mut derived: Vec<Derived>,
        bindings: Vec<std::cell::Ref<'a, Vec<crate::binding::Holding>>>,
    ) -> Self {
        // Keep the cache with the derived holdings so all credential-derived allocations
        // share their lifetime. It is not itself a credential value.
        derived.push(Derived::Matcher(OnceCell::new()));
        Self {
            borrowed,
            mnemonic,
            derived,
            bindings,
        }
    }

    pub(crate) fn extend_borrowed(&mut self, credentials: &[&'a [u8]]) {
        for key in &mut self.derived {
            if let Derived::Matcher(matcher) = key {
                matcher.take();
            }
        }
        self.borrowed.extend_from_slice(credentials);
    }

    fn values(&self) -> impl Iterator<Item = &[u8]> {
        self.borrowed
            .iter()
            .copied()
            .chain(
                self.bindings
                    .iter()
                    .flat_map(|given| given.iter().filter_map(|h| h.credential.response_bytes())),
            )
            .chain(std::iter::once(self.mnemonic.as_bytes()))
            .chain(self.derived.iter().filter_map(|key| {
                Some(match key {
                    Derived::Ssh(key) => key.0.as_slice(),
                    Derived::Sender(key) => key.0.as_slice(),
                    Derived::Recipient(key) => key.0.as_slice(),
                    Derived::Relay(key) => key.0.as_slice(),
                    #[cfg(target_arch = "wasm32")]
                    Derived::Inference(key) => key.0.as_slice(),
                    #[cfg(target_arch = "wasm32")]
                    Derived::Session(key) => key.0.as_slice(),
                    Derived::Handoff(key) => key.0.as_slice(),
                    Derived::Text(text) => text.as_bytes(),
                    Derived::Matcher(_) => return None,
                })
            }))
            .filter(|value| !value.is_empty())
    }

    fn matches(&self, bytes: &[u8], mut found: impl FnMut(usize, usize) -> bool) -> bool {
        self.matches_with_boundaries(bytes, false, &mut found)
    }

    fn matches_with_boundaries(
        &self,
        bytes: &[u8],
        publication: bool,
        mut found: impl FnMut(usize, usize) -> bool,
    ) -> bool {
        let matcher = self.derived.iter().find_map(|key| match key {
            Derived::Matcher(matcher) => Some(matcher.get_or_init(|| Matcher::new(self))),
            _ => None,
        });
        if let Some(matcher) = matcher
            && matcher.matches(bytes, publication, &mut found)
        {
            return true;
        }
        for needle in self.values() {
            if (needle.len() < 8 || matcher.is_none())
                && credential_matches(bytes, needle, |start| found(start, start + needle.len()))
            {
                return true;
            }
        }
        false
    }
}

#[derive(Hash, PartialEq, Eq)]
struct Prefix([u8; 8]);

impl Drop for Prefix {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct Matcher {
    prefixes: HashMap<Prefix, Zeroizing<Vec<Zeroizing<Vec<u8>>>>>,
    suffixes: HashMap<Prefix, Zeroizing<Vec<Zeroizing<Vec<u8>>>>>,
}

impl Matcher {
    fn new(held: &Held<'_>) -> Self {
        // Sized up front so inserting never grows the table: growth would free old buckets
        // holding prefix copies without zeroizing them.
        let long = held.values().filter(|value| value.len() >= 8).count();
        let mut prefixes = HashMap::with_capacity(long);
        let mut suffixes = HashMap::with_capacity(long);
        for value in held.values().filter(|value| value.len() >= 8) {
            prefixes
                .entry(Prefix(value[..8].try_into().expect("credential prefix")))
                .or_insert_with(|| Zeroizing::new(Vec::new()))
                .push(Zeroizing::new(value.to_vec()));
            suffixes
                .entry(Prefix(
                    value[value.len() - 8..]
                        .try_into()
                        .expect("credential suffix"),
                ))
                .or_insert_with(|| Zeroizing::new(Vec::new()))
                .push(Zeroizing::new(value.to_vec()));
        }
        Self { prefixes, suffixes }
    }

    fn matches(
        &self,
        bytes: &[u8],
        publication: bool,
        found: &mut impl FnMut(usize, usize) -> bool,
    ) -> bool {
        if self.prefixes.is_empty() {
            return false;
        }
        for (start, window) in bytes.windows(8).enumerate() {
            let prefix = Prefix(window.try_into().expect("eight-byte window"));
            if let Some(candidates) = self.prefixes.get(&prefix) {
                for value in candidates.iter() {
                    if publication {
                        let remaining = &bytes[start..];
                        let matched = value
                            .iter()
                            .zip(remaining)
                            .take_while(|(a, b)| a == b)
                            .count();
                        if (matched == value.len() || matched == remaining.len())
                            && found(start, start + matched)
                        {
                            return true;
                        }
                        // Legacy diagnostics wrap pre-cut text in punctuation. A marker
                        // inside the matching prefix is also an end, without another text pass.
                        if let Some(end) = (8..=matched).find(|end| {
                            remaining[*end..].starts_with("…".as_bytes())
                                || remaining[*end..].starts_with(b"\n[truncated]")
                        }) && found(start, start + end)
                        {
                            return true;
                        }
                    } else if bytes[start..].starts_with(value) && found(start, start + value.len())
                    {
                        return true;
                    }
                }
            }
            if publication && let Some(candidates) = self.suffixes.get(&prefix) {
                let end = start + 8;
                for value in candidates.iter() {
                    if end < value.len() && value.ends_with(&bytes[..end]) && found(0, end) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

impl fmt::Debug for Held<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Held(..)")
    }
}

pub(crate) fn redact(body: &[u8], fields: &[&str], held: &Held<'_>) -> Result<Redacted, String> {
    redact_with_boundaries(body, fields, held, false)
}

/// Publication only: durable checks continue to use exact matching through `redact`.
pub(crate) fn redact_publication(body: &[u8], held: &Held<'_>) -> Result<Redacted, String> {
    redact_with_boundaries(body, &[], held, true)
}

fn redact_with_boundaries(
    body: &[u8],
    fields: &[&str],
    held: &Held<'_>,
    publication: bool,
) -> Result<Redacted, String> {
    let bytes = if fields.is_empty() {
        body.to_vec()
    } else {
        let mut value: serde_json::Value = serde_json::from_slice(body)
            .map_err(|_| "response is not JSON for declared fields".to_string())?;
        for field in fields {
            if let Some(password) = value.pointer_mut(field)
                && !password.is_null()
            {
                *password = MARKER.into();
            }
        }
        serde_json::to_vec(&value).map_err(|_| "response JSON cannot be serialized".to_string())?
    };
    let bytes = Zeroizing::new(bytes);
    // Collect before replacing: overlapping copies must produce a single marker, and replacing
    // one needle must not conceal an overlapping needle from another credential.
    let mut ranges = Vec::new();
    held.matches_with_boundaries(&bytes, publication, |start, end| {
        ranges.push((start, end));
        false
    });
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start < last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    let mut output = Vec::new();
    let mut cursor = 0;
    for (start, end) in merged {
        output.extend_from_slice(&bytes[cursor..start]);
        output.extend_from_slice(MARKER.as_bytes());
        cursor = end;
    }
    output.extend_from_slice(&bytes[cursor..]);
    // The marker itself (or its junction with preserved bytes) could contain a held value.
    // Refuse instead of claiming that such an output passed.
    if held.matches(&output, |_, _| true) {
        return Err(crate::poc::wait::REDACTION_MARKER.into());
    }
    Ok(Redacted { bytes: output })
}

/// Linear exact matching, including overlapping occurrences.
fn credential_matches(bytes: &[u8], needle: &[u8], mut found: impl FnMut(usize) -> bool) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut prefix = Zeroizing::new(vec![0usize; needle.len()]);
    let mut matched = 0;
    for i in 1..needle.len() {
        while matched > 0 && needle[i] != needle[matched] {
            matched = prefix[matched - 1];
        }
        if needle[i] == needle[matched] {
            matched += 1;
        }
        prefix[i] = matched;
    }
    matched = 0;
    for (i, byte) in bytes.iter().enumerate() {
        while matched > 0 && *byte != needle[matched] {
            matched = prefix[matched - 1];
        }
        if *byte == needle[matched] {
            matched += 1;
        }
        if matched == needle.len() {
            if found(i + 1 - matched) {
                return true;
            }
            matched = prefix[matched - 1];
        }
    }
    false
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn overlapping_empty_and_marker_matches() {
        let held = Held {
            borrowed: vec![b"abc", b"bcd", b""],
            mnemonic: Zeroizing::new(String::new()),
            derived: vec![],
            bindings: vec![],
        };
        assert_eq!(
            redact(b"zabcd!abc", &[], &held).unwrap().as_bytes(),
            b"z<redacted>!<redacted>"
        );
        let held = Held {
            borrowed: vec![b"red"],
            ..held
        };
        let error = redact(b"red", &[], &held).unwrap_err();
        assert_eq!(error, "redaction marker cannot exclude held credentials");
        assert_eq!(format!("{held:?}"), "Held(..)");
    }
}

/// Exact credential check for a transient boundary without a store.
pub(crate) fn contains(bytes: &[u8], credential: &[u8]) -> bool {
    credential_matches(bytes, credential, |_| true)
}
