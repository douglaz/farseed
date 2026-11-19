use super::*;

pub(super) fn positive_id(s: &str) -> bool {
    s.parse::<u64>()
        .ok()
        .is_some_and(|n| n > 0 && n.to_string() == s)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CreateReply {
    Accepted(CreateAck),
    Unpaid { order: u64 },
    MissingLogin,
}

pub(super) fn create_error(raw: &Value) -> Result<CreateReply, String> {
    let object = raw.as_object().ok_or(REFUSED)?;
    if let Some(order) = object.get("order_id") {
        let order = order.as_u64().filter(|n| *n > 0).ok_or(REFUSED)?;
        return Ok(CreateReply::Unpaid { order });
    }
    // A message is never proof. A complete login-only validation map is required.
    let errors = object
        .get("errors")
        .and_then(Value::as_object)
        .ok_or(REFUSED)?;
    if errors.is_empty() || errors.len() > 2 {
        return Err(REFUSED.into());
    }
    for (key, values) in errors {
        if !matches!(key.as_str(), "ssh_keys" | "password") {
            return Err(REFUSED.into());
        }
        let values = values.as_array().ok_or(REFUSED)?;
        if values.is_empty()
            || values.len() > 16
            || values.iter().any(|v| {
                v.as_str().is_none_or(|s| {
                    s.is_empty() || s.len() > 512 || s.chars().any(char::is_control)
                })
            })
        {
            return Err(REFUSED.into());
        }
    }
    Ok(CreateReply::MissingLogin)
}

pub(crate) fn validate_create_ack(ack: &CreateAck) -> Result<(), String> {
    if ack.id == 0
        || ack.hostname.is_empty()
        || ack.hostname.len() > 128
        || ack.hostname.chars().any(char::is_control)
        || ack.billing_cycle != 1
        || matches!(ack.status, ServerStatus::Unknown(_))
        || ack.plan.id == 0
        || ack.plan.key.is_empty()
        || ack.plan.key.len() > 128
        || ack.plan.key.chars().any(char::is_control)
        || ack.plan.price_with_vat == 0
        || ack.created_at > crate::clock::MAX_UTC
        || ack.expiry_at > crate::clock::MAX_UTC
        || ack.expiry_at <= ack.created_at
    {
        return Err(REFUSED.into());
    }
    Ok(())
}

pub(crate) fn validate_detail(detail: &Detail) -> Result<(), String> {
    validate_create_ack(&detail.server)?;
    if detail.public_ipv4.is_some_and(|ip| !public_ipv4(ip))
        || detail
            .lock_reason
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        || detail.startup_script.as_ref().is_some_and(|s| {
            s.kind
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 64 || s.chars().any(char::is_control))
                || s.sha256
                    .as_ref()
                    .is_some_and(|s| s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()))
        })
    {
        return Err(REFUSED.into());
    }
    Ok(())
}
pub(super) fn public_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let first = ip.octets()[0];
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_documentation()
        && first != 0
        && first < 224
        && !(first == 100 && (64..=127).contains(&ip.octets()[1]))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SshKeyFact {
    pub id: u64,
    pub name: String,
    pub fingerprint: String,
    pub key: String,
}
pub(super) fn ssh_key_fact(v: &Value) -> Result<SshKeyFact, String> {
    let key = text(v, "key", 256)?;
    ssh_key::PublicKey::from_openssh(key).map_err(|_| REFUSED)?;
    // VPSBG reports MD5 colon-hex. This is bounded vendor text, not our key identity.
    let fingerprint = text(v, "fingerprint", 47)?;
    if fingerprint.len() != 47
        || !fingerprint.bytes().enumerate().all(|(i, b)| {
            if i % 3 == 2 {
                b == b':'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(REFUSED.into());
    }
    Ok(SshKeyFact {
        id: id(v)?,
        name: text(v, "name", 128)?.into(),
        fingerprint: fingerprint.into(),
        key: key.into(),
    })
}

pub(crate) fn budget_fits(now: u64, deadline: u64) -> bool {
    now.checked_add(BOOT_BUDGET)
        .and_then(|n| n.checked_add(RELAY_BUDGET))
        .is_some_and(|end| end < deadline)
}

pub(crate) const HOOK_BODY: &str = include_str!("hook-body.sh");

fn deadline_text(epoch: u64) -> Result<String, String> {
    if epoch > crate::clock::MAX_UTC {
        return Err(REFUSED.into());
    }
    // Gregorian civil date from Unix days (400-year eras); no local timezone.
    let z = i64::try_from(epoch / 86400).map_err(|_| REFUSED)? + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Ok(format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}",
        epoch / 3600 % 24,
        epoch / 60 % 60,
        epoch % 60
    ))
}

/// The authority and composed script remain in zeroizing, invocation-local memory.
pub(crate) fn compose_user_data(
    intro: &crate::store::attest::AttestIntroduction,
    public_client_key: &str,
) -> Result<Zeroizing<String>, String> {
    let principal = &intro.principal;
    if principal.len() != 43
        || !principal.starts_with("tau-attest-")
        || !principal[11..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(REFUSED.into());
    }
    let client = ssh_key::PublicKey::from_openssh(public_client_key).map_err(|_| REFUSED)?;
    if client.algorithm() != ssh_key::Algorithm::Ed25519
        || client.to_openssh().map_err(|_| REFUSED)? != public_client_key
        || public_client_key.len() > 128
        || public_client_key.contains(['\n', '\r', '\'', '"'])
    {
        return Err(REFUSED.into());
    }
    let private = intro.ca_private_openssh.as_str();
    if private.len() > 60_000
        || !private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        || !private.ends_with("-----END OPENSSH PRIVATE KEY-----\n")
        || private
            .lines()
            .any(|line| line == "CAKEY" || line.contains(['\r', '\'', '"']))
    {
        return Err(REFUSED.into());
    }
    let parsed = ssh_key::PrivateKey::from_openssh(private.as_bytes()).map_err(|_| REFUSED)?;
    if parsed.algorithm() != ssh_key::Algorithm::Ed25519
        || parsed.public_key().to_openssh().map_err(|_| REFUSED)? != intro.ca_public_openssh
        || crate::store::attest::attest_principal(parsed.public_key())? != *principal
    {
        return Err(REFUSED.into());
    }
    let deadline = deadline_text(intro.deadline_unix)?;
    let output = Zeroizing::new(format!(
        "#!/bin/sh\n# tau-web CHN-R5a first-boot hook. Composed by harness code; no model supplies any of it.\nP='{principal}'\nDEADLINE='{deadline}'\nDEADLINE_EPOCH='{}'\nCLIENT='{public_client_key}'\numask 077\nmkdir -p /run/tau-attest\ncat > /run/tau-attest/ca <<'CAKEY'\n{private}CAKEY\n{HOOK_BODY}",
        intro.deadline_unix
    ));
    if output.len() > 65_536 {
        return Err(REFUSED.into());
    }
    Ok(output)
}
