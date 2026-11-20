//! Single-use host-certificate verification for CHN-R5a.
use crate::store::attest::Introduction;
use ssh_key::{Certificate, HashAlg, PublicKey, certificate::CertType};

// Stands in for bundle/timing.toml's key until the spec pin includes it.
// This value is unmeasured; measure slowest first boot plus time to first contact.
pub const ATTEST_CERTIFICATE_DEADLINE_SECONDS: u64 = 1800;

/// `None` is a bare public key. Parsing failures never reach certificate admission.
pub fn verify(
    certificate: Option<&Certificate>,
    introduction: &Introduction,
    now: u64,
) -> Result<String, String> {
    let cert = certificate.ok_or("attest requires a host certificate")?;
    if now >= introduction.deadline_unix {
        return Err("attest introduction expired".into());
    }
    if cert.cert_type() != CertType::Host || !cert.public_key().is_ed25519() {
        return Err("attest requires an Ed25519 host certificate".into());
    }
    let ca = PublicKey::from_openssh(&introduction.ca_public)
        .map_err(|_| "invalid journaled attest authority")?;
    if !ca.key_data().is_ed25519() || cert.signature_key() != ca.key_data() {
        return Err("attest authority differs".into());
    }
    if cert.valid_principals() != [introduction.principal.as_str()] {
        return Err("attest principal differs".into());
    }
    if !cert.critical_options().is_empty() || !cert.extensions().is_empty() {
        return Err("attest certificate has unsupported options or extensions".into());
    }
    // ssh-key exposes no reserved-field accessor. Refuse a nonempty reserved field,
    // rather than silently treating a future certificate field as understood.
    let bytes = cert.to_bytes().map_err(|_| "attest certificate encoding")?;
    if !empty_reserved(&bytes) {
        return Err("attest certificate has an unknown reserved field".into());
    }
    if cert.valid_after() > now
        || now >= cert.valid_before()
        || cert.valid_before() > introduction.deadline_unix
    {
        return Err("attest certificate outside validity or deadline".into());
    }
    cert.validate_at(now, [&ca.fingerprint(HashAlg::Sha256)])
        .map_err(|_| "attest certificate signature or validity")?;
    Ok(cert.public_key().fingerprint(HashAlg::Sha256).to_string())
}

fn empty_reserved(mut bytes: &[u8]) -> bool {
    fn string<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
        let size = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
        let value = bytes.get(4..4_usize.checked_add(size)?)?;
        *bytes = bytes.get(4 + size..)?;
        Some(value)
    }
    let mut check = || -> Option<bool> {
        // Algorithm, nonce, Ed25519 key; serial and type; id and principals;
        // validity; critical options, extensions, reserved.
        for _ in 0..3 {
            string(&mut bytes)?;
        }
        bytes = bytes.get(12..)?;
        for _ in 0..2 {
            string(&mut bytes)?;
        }
        bytes = bytes.get(16..)?;
        for _ in 0..2 {
            string(&mut bytes)?;
        }
        Some(string(&mut bytes)?.is_empty())
    };
    check() == Some(true)
}

pub(crate) fn now_unix() -> Result<u64, String> {
    #[cfg(target_arch = "wasm32")]
    {
        let now = js_sys::Date::now() / 1000.0;
        if !now.is_finite() || now < 0.0 || now > crate::clock::MAX_UTC as f64 {
            return Err("attest clock unavailable".into());
        }
        Ok(now as u64)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|time| time.as_secs())
            .map_err(|_| "attest clock unavailable".into())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::store::attest::Route;
    use ssh_key::{
        PrivateKey,
        certificate::Builder,
        private::{Ed25519Keypair, KeypairData},
        public::{KeyData, OpaquePublicKey},
    };

    fn key() -> PrivateKey {
        let mut seed = zeroize::Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).unwrap();
        PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&seed)), "").unwrap()
    }

    #[test]
    fn hostcert_verifier_table() {
        let ca = key();
        let other_ca = key();
        let host = key();
        let intro = Introduction {
            machine: "machine-a".into(),
            route: Route::AttestCertificate,
            ca_public: ca.public_key().to_openssh().unwrap(),
            principal: "machine-a".into(),
            deadline_unix: 2000,
            begun_unix: 200,
            installation_binding: "0-0".into(),
        };
        assert!(verify(None, &intro, 1000).is_err(), "bare key");
        for case in [
            "accept",
            "other-authority",
            "user",
            "non-ed25519",
            "wrong-principal",
            "extra-principal",
            "no-principal",
            "critical-option",
            "extension",
            "before-valid-after",
            "at-valid-before",
            "after-valid-before",
            "beyond-deadline",
            "at-deadline",
            "after-deadline",
            "bad-signature",
            "unknown-reserved",
        ] {
            let subject = if case == "non-ed25519" {
                KeyData::Other(OpaquePublicKey::new(
                    vec![1; 32],
                    ssh_key::Algorithm::new("unknown-key@example.invalid").unwrap(),
                ))
            } else {
                host.public_key().key_data().clone()
            };
            let after = if case == "before-valid-after" {
                1001
            } else {
                900
            };
            let before = match case {
                "at-valid-before" => 1000,
                "after-valid-before" => 999,
                "beyond-deadline" => 2001,
                _ => 1900,
            };
            let mut builder = Builder::new(vec![7; 32], subject, after, before).unwrap();
            builder
                .cert_type(if case == "user" {
                    CertType::User
                } else {
                    CertType::Host
                })
                .unwrap();
            if case == "no-principal" {
                builder.all_principals_valid().unwrap();
            } else {
                builder
                    .valid_principal(if case == "wrong-principal" {
                        "machine-b"
                    } else {
                        "machine-a"
                    })
                    .unwrap();
            }
            if case == "extra-principal" {
                builder.valid_principal("machine-b").unwrap();
            }
            if case == "critical-option" {
                builder.critical_option("force-command", "true").unwrap();
            }
            if case == "extension" {
                builder.extension("unknown-extension", "").unwrap();
            }
            let mut cert = builder
                .sign(if case == "other-authority" {
                    &other_ca
                } else {
                    &ca
                })
                .unwrap();
            if case == "bad-signature" {
                let mut bytes = cert.to_bytes().unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                cert = Certificate::from_bytes(&bytes).unwrap();
            }
            if case == "unknown-reserved" {
                // Immediately before the final two strings (CA and signature) is reserved.
                let bytes = cert.to_bytes().unwrap();
                let mut positions = Vec::new();
                let mut pos = 0;
                for field in 0..10 {
                    positions.push(pos);
                    let len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
                    pos += 4 + len;
                    if field == 2 {
                        pos += 12;
                    }
                    if field == 4 {
                        pos += 16;
                    }
                }
                let start = positions[7];
                let mut changed = bytes.clone();
                changed.splice(start..start + 4, [0, 0, 0, 1, 42]);
                cert = Certificate::from_bytes(&changed).unwrap();
            }
            let now = match case {
                "at-deadline" => 2000,
                "after-deadline" => 2001,
                _ => 1000,
            };
            let result = verify(Some(&cert), &intro, now);
            if case == "accept" {
                assert_eq!(
                    result.unwrap(),
                    host.public_key().fingerprint(HashAlg::Sha256).to_string()
                );
            } else {
                assert!(result.is_err(), "{case}");
            }
        }
        assert!(Certificate::from_openssh("malformed").is_err());
    }
}
