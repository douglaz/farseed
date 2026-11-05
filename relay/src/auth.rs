use crate::policy::Destination;
use k256::schnorr::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize, Clone)]
pub struct Auth {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}
impl Auth {
    fn tag(&self, name: &str, values: &[&str]) -> bool {
        let mut tags = self
            .tags
            .iter()
            .filter(|t| t.first().is_some_and(|s| s == name));
        tags.next().is_some_and(|t| {
            t.iter()
                .skip(1)
                .map(String::as_str)
                .eq(values.iter().copied())
        }) && tags.next().is_none()
    }
    pub fn shape(&self, relay: &str, dest: &Destination, now: u64, skew: u64) -> bool {
        self.kind == 22242
            && self.created_at.abs_diff(now) <= skew
            && self.tag("relay", &[relay])
            && self.tag("destination", &[&dest.host, &dest.port.to_string()])
    }
    pub fn signature(&self) -> bool {
        let canonical = serde_json::json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content
        ]);
        let hash: [u8; 32] = Sha256::digest(canonical.to_string().as_bytes()).into();
        if hex::encode(hash) != self.id
            || self.pubkey.len() != 64
            || !self
                .pubkey
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return false;
        }
        let Ok(bytes) = hex::decode(&self.pubkey) else {
            return false;
        };
        let Ok(key) = VerifyingKey::from_bytes(&bytes) else {
            return false;
        };
        let Ok(sig) = hex::decode(&self.sig) else {
            return false;
        };
        let Ok(sig) = Signature::try_from(sig.as_slice()) else {
            return false;
        };
        key.verify_raw(&hash, &sig).is_ok()
    }
    pub fn challenge(&self, challenge: &str) -> bool {
        self.tag("challenge", &[challenge])
    }
}
