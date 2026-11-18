//! The credential-redaction boundary for adapter responses.

use crate::allocation::{Family, Identity, Metadata};
use crate::credential::{
    AttestRecipientKey, AttestSenderKey, PostHarnessCredential, RelayKey, SshClientKey,
};
use crate::seed::Seed;
use crate::store::{Storage, Store, unlock_marks};
use std::cell::{OnceCell, Ref};
use std::collections::HashMap;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const MARKER: &str = "<redacted>";
/// Whole published strings shorter than this are exempt from the publication boundary rule when
/// they consist of nothing but a held value's prefix or suffix (B524). No cut leaves a string this
/// short: the smallest cut segment, one half of a short model-history excerpt of one of three
/// streams, keeps about 100 bytes ((768 - 64) / 3 per stream, less the omission notice, halved).
const SHORT_WHOLE: usize = 64;

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

/// Seed-derived keys and their matcher stay in the unlocked store; other holders are borrowed
/// per check, with canonical text and browser-key copies scoped to this enumeration. Seed keys
/// are wiped at lock or drop on a best-effort basis (STA-23).
pub(crate) struct Held<'a> {
    borrowed: Vec<&'a [u8]>,
    mnemonic: Zeroizing<String>,
    derived: Vec<CheckValue<'a>>,
    bindings: Vec<std::cell::Ref<'a, Vec<crate::binding::Holding>>>,
}

pub(crate) enum Derived {
    Ssh(SshClientKey),
    Sender(AttestSenderKey),
    Recipient(AttestRecipientKey),
    Relay(RelayKey),
    Handoff(PostHarnessCredential),
}

impl Derived {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Ssh(key) => &key.0,
            Self::Sender(key) => &key.0,
            Self::Recipient(key) => &key.0,
            Self::Relay(key) => &key.0,
            Self::Handoff(key) => &key.0,
        }
    }
}

pub(crate) enum CheckValue<'a> {
    #[cfg(target_arch = "wasm32")]
    Inference(crate::credential::InferenceAccountCredential),
    #[cfg(target_arch = "wasm32")]
    Session(crate::credential::SessionInferenceKey),
    Text(Zeroizing<String>),
    Matcher {
        seed: SeedKeys<'a>,
        combined: OnceCell<Matcher>,
    },
}

pub(crate) enum SeedKeys<'a> {
    Borrowed(Ref<'a, SeedKeyCache>),
    Owned(Box<SeedKeyCache>),
}

impl SeedKeys<'_> {
    fn matcher(&self) -> &Matcher {
        match self {
            Self::Borrowed(cache) => &cache.matcher,
            Self::Owned(cache) => &cache.matcher,
        }
    }
}

/// Only seed-derived secrets belong here. Boxes keep key bytes stationary when extending.
pub(crate) struct SeedKeyCache {
    seed: String,
    allocation_seed: String,
    derivation_version: u32,
    identities: Vec<Identity>,
    #[allow(
        clippy::vec_box,
        reason = "key bytes must not move during cache extension"
    )]
    keys: Vec<Box<Derived>>,
    matcher: Matcher,
}

impl SeedKeyCache {
    pub(crate) fn is_current(&self, seed: &Seed, allocation: &Metadata) -> bool {
        let seed_id = seed.id();
        self.seed == seed_id
            && self.allocation_seed == allocation.seed()
            && self.derivation_version == allocation.derivation_version()
            && allocation
                .entries()
                .iter()
                .map(|entry| &entry.identity)
                .filter(|identity| identity.seed == seed_id)
                .eq(self.identities.iter())
    }

    pub(crate) fn synchronize(
        slot: &mut Option<Self>,
        seed: &Seed,
        allocation: &Metadata,
        timing: &unlock_marks::Timer,
    ) -> Result<(), String> {
        let seed_id = seed.id();
        let identities = || {
            allocation
                .entries()
                .iter()
                .map(|entry| &entry.identity)
                .filter(|identity| identity.seed == seed_id)
        };
        let same_seed = slot.as_ref().is_some_and(|cache| {
            cache.seed == seed_id
                && cache.allocation_seed == allocation.seed()
                && cache.derivation_version == allocation.derivation_version()
        });
        // Compare actual identities, including their seed and version, before every use.
        // Status changes do not remove tombstoned keys from protection.
        if same_seed
            && slot
                .as_ref()
                .is_some_and(|cache| identities().eq(cache.identities.iter()))
        {
            return Ok(());
        }
        let extends = same_seed
            && slot.as_ref().is_some_and(|cache| {
                identities()
                    .take(cache.identities.len())
                    .eq(cache.identities.iter())
            });
        let key_count = identities()
            .map(|identity| match identity.family {
                Family::Machines => 3,
                Family::Passes | Family::Handoffs => 1,
            })
            .sum();
        let mut keys = Vec::with_capacity(key_count);
        let old = slot.take();
        let start = if extends {
            let old = old.expect("extension has a cache");
            // Drop secret-bearing map buckets before building their replacement. Moving
            // boxes into the precisely sized vector moves pointers, never key bytes.
            drop(old.matcher);
            keys.extend(old.keys);
            old.identities.len()
        } else {
            // A changed seed/version, reordered list or removal invalidates everything.
            drop(old);
            0
        };
        for identity in identities().skip(start) {
            let (v, i) = (identity.derivation_version, identity.index);
            let mut derive = |result: Result<Derived, crate::seed::DeriveError>| {
                result
                    .map(|key| {
                        timing.count(unlock_marks::Counter::DerivedKeys, 1);
                        keys.push(Box::new(key));
                    })
                    .map_err(|_| crate::poc::wait::DERIVATION.to_string())
            };
            match identity.family {
                Family::Machines => {
                    derive(seed.ssh_client_key(v, i).map(Derived::Ssh))?;
                    derive(seed.attest_sender_key(v, i).map(Derived::Sender))?;
                    derive(seed.attest_recipient_key(v, i).map(Derived::Recipient))?;
                }
                Family::Passes => {
                    derive(seed.relay_key(v, i).map(Derived::Relay))?;
                }
                Family::Handoffs => {
                    derive(seed.post_harness_credential(v, i).map(Derived::Handoff))?;
                }
            }
        }
        let matcher = Matcher::new(|| keys.iter().map(|key| key.bytes()));
        let mut current_identities = Vec::with_capacity(identities().count());
        current_identities.extend(identities().cloned());
        *slot = Some(Self {
            seed: seed_id.clone(),
            allocation_seed: allocation.seed().into(),
            derivation_version: allocation.derivation_version(),
            identities: current_identities,
            keys,
            matcher,
        });
        Ok(())
    }
}

impl<'a> Held<'a> {
    pub(crate) fn new(
        borrowed: Vec<&'a [u8]>,
        mnemonic: Zeroizing<String>,
        mut derived: Vec<CheckValue<'a>>,
        bindings: Vec<std::cell::Ref<'a, Vec<crate::binding::Holding>>>,
        seed: SeedKeys<'a>,
    ) -> Self {
        // The final slot gives constant-time access without walking cached key material.
        derived.push(CheckValue::Matcher {
            seed,
            combined: OnceCell::new(),
        });
        Self {
            borrowed,
            mnemonic,
            derived,
            bindings,
        }
    }

    pub(crate) fn extend_borrowed(&mut self, credentials: &[&'a [u8]]) {
        if let Some(CheckValue::Matcher { combined, .. }) = self.derived.last_mut() {
            combined.take();
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
                    #[cfg(target_arch = "wasm32")]
                    CheckValue::Inference(key) => key.0.as_slice(),
                    #[cfg(target_arch = "wasm32")]
                    CheckValue::Session(key) => key.0.as_slice(),
                    CheckValue::Text(text) => text.as_bytes(),
                    CheckValue::Matcher { .. } => return None,
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
        let indexed = if let Some(CheckValue::Matcher { seed, combined }) = self.derived.last() {
            let seed = seed.matcher();
            let matcher = combined.get_or_init(|| Matcher::with_seed(|| self.values(), Some(seed)));
            if matcher.matches(seed, bytes, publication, &mut found) {
                return true;
            }
            true
        } else {
            false
        };
        for needle in self.values() {
            if (needle.len() < 8 || !indexed)
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
    index: HashMap<Prefix, Candidates>,
    values: Vec<MatchValue>,
}

#[derive(Clone, Copy, Default)]
struct Candidates {
    prefix: Option<usize>,
    suffix: Option<usize>,
}

struct MatchValue {
    value: Zeroizing<Vec<u8>>,
    prefix_next: Option<usize>,
    suffix_next: Option<usize>,
}

impl Matcher {
    fn new<'a, I: Iterator<Item = &'a [u8]>>(values: impl Fn() -> I) -> Self {
        Self::with_seed(values, None)
    }

    fn with_seed<'a, I: Iterator<Item = &'a [u8]>>(
        values: impl Fn() -> I,
        seed: Option<&Self>,
    ) -> Self {
        // Size every secret-bearing collection before inserting. Linked candidate indices
        // avoid growing bucket vectors, even when many values share a prefix or suffix.
        let long = values().filter(|value| value.len() >= 8).count();
        let seed_len = seed.map_or(0, |seed| seed.values.len());
        let mut index = HashMap::with_capacity(seed.map_or(0, |seed| seed.index.len()) + 2 * long);
        if let Some(seed) = seed {
            // Copy only cached eight-byte index keys and candidate indices, never full seed
            // values. This O(cached keys) copy is paid once per Held, not once per scan.
            for (prefix, candidates) in &seed.index {
                index.insert(Prefix(prefix.0), *candidates);
            }
        }
        let mut entries = Vec::with_capacity(long);
        for value in values().filter(|value| value.len() >= 8) {
            // Cached candidates address seed.values; appended candidates address this
            // Held's overlay values after that range. Chains can cross into the seed list.
            let candidate = seed_len + entries.len();
            let prefix_next = index
                .entry(Prefix(value[..8].try_into().expect("credential prefix")))
                .or_default()
                .prefix
                .replace(candidate);
            let suffix_next = index
                .entry(Prefix(
                    value[value.len() - 8..]
                        .try_into()
                        .expect("credential suffix"),
                ))
                .or_default()
                .suffix
                .replace(candidate);
            entries.push(MatchValue {
                value: Zeroizing::new(value.to_vec()),
                prefix_next,
                suffix_next,
            });
        }
        Self {
            index,
            values: entries,
        }
    }

    fn candidate<'a>(&'a self, seed: &'a Self, index: usize) -> &'a MatchValue {
        if index < seed.values.len() {
            &seed.values[index]
        } else {
            &self.values[index - seed.values.len()]
        }
    }

    fn matches(
        &self,
        seed: &Self,
        bytes: &[u8],
        publication: bool,
        found: &mut impl FnMut(usize, usize) -> bool,
    ) -> bool {
        if self.index.is_empty() {
            return false;
        }
        for (start, window) in bytes.windows(8).enumerate() {
            let prefix = Prefix(window.try_into().expect("eight-byte window"));
            // Prefix and publication-suffix chains share one standard keyed hash lookup.
            let Some(candidates) = self.index.get(&prefix) else {
                continue;
            };
            if let Some(candidate) = candidates.prefix {
                let mut next = Some(candidate);
                while let Some(candidate) = next {
                    let entry = self.candidate(seed, candidate);
                    next = entry.prefix_next;
                    let value = &entry.value;
                    if publication {
                        let remaining = &bytes[start..];
                        let matched = value
                            .iter()
                            .zip(remaining)
                            .take_while(|(a, b)| a == b)
                            .count();
                        // A whole string under SHORT_WHOLE bytes that is only a value's prefix is a
                        // fixed value (a status, a protocol word), never a cut text: every cut keeps
                        // hundreds of bytes. Longer strings and partial ends are still checked.
                        if (matched == value.len()
                            || (matched == remaining.len()
                                && (start > 0 || bytes.len() >= SHORT_WHOLE)))
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
            if publication && let Some(candidate) = candidates.suffix {
                let end = start + 8;
                let mut next = Some(candidate);
                while let Some(candidate) = next {
                    let entry = self.candidate(seed, candidate);
                    next = entry.suffix_next;
                    let value = &entry.value;
                    if end < value.len()
                        && (end < bytes.len() || bytes.len() >= SHORT_WHOLE)
                        && value.ends_with(&bytes[..end])
                        && found(0, end)
                    {
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
