//! LNVPS protocol, recipes and projections. No transport or journal ownership.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use k256::schnorr::SigningKey;
use serde_json::json;
use sha2::{Digest, Sha256};

pub const ORIGIN: &str = "https://api.lnvps.net";
pub(super) const NAME: &str = "LNVPS";
pub(crate) const EMAIL_REQUIRED: &str = "Email verification is required before creating a VM";

pub(super) fn default_user() -> String {
    "arch".into()
}

pub(super) fn request_policy(method: &str, url: &str) -> RequestPolicy {
    let mutation = method == "PATCH"
        || method == "POST" && !url.ends_with("/api/v1/vm/custom-template/price")
        || url.contains("/renew?");
    let email_refusal = method == "POST"
        && (url.ends_with("/api/v1/vm") || url.ends_with("/api/v1/vm/custom-template"));
    RequestPolicy {
        mutation,
        missing_read: missing_read(method, url),
        email_refusal,
    }
}

pub(super) fn decode_response(body: &[u8]) -> Result<Value, String> {
    let value: Value = serde_json::from_slice(body).map_err(|_| REFUSED)?;
    let data = value.get("data").ok_or(REFUSED)?.clone();
    Ok(data)
}

pub(super) fn owns_read(path: &str, vm: u64, payment: Option<&Value>) -> bool {
    path == format!("/api/v1/vm/{vm}")
        || path == format!("/api/v1/vm/{vm}/payments?limit=100&offset=0")
        || payment
            .and_then(|pay| payment_id(pay).ok())
            .is_some_and(|pay| path == format!("/api/v1/payment/{pay}"))
}

pub(super) fn account_fields() -> AccountFields {
    AccountFields {
        email: "email",
        verified: "email_verified",
        contact_flags: [
            "contact_nip17",
            "contact_email",
            "contact_telegram",
            "contact_whatsapp",
        ],
    }
}

pub(super) fn account(body: Option<Value>) -> VendorRequest {
    VendorRequest {
        method: if body.is_some() { "PATCH" } else { "GET" },
        path: "/api/v1/account".into(),
        body,
    }
}
pub(super) fn notification_channels() -> VendorRequest {
    VendorRequest {
        method: "GET",
        path: "/api/v1/notification/channels".into(),
        body: None,
    }
}
pub(super) fn catalogue() -> VendorRequest {
    VendorRequest {
        method: "GET",
        path: "/api/v1/vm/templates".into(),
        body: None,
    }
}
pub(super) fn images() -> VendorRequest {
    VendorRequest {
        method: "GET",
        path: "/api/v1/image".into(),
        body: None,
    }
}
pub(super) fn custom_price(resources: Value) -> VendorRequest {
    VendorRequest {
        method: "POST",
        path: "/api/v1/vm/custom-template/price".into(),
        body: Some(resources),
    }
}
pub(super) fn keys() -> VendorRequest {
    VendorRequest {
        method: "GET",
        path: "/api/v1/ssh-key".into(),
        body: None,
    }
}
pub(super) fn register_key(public: &Value, identity_index: u32) -> VendorRequest {
    VendorRequest {
        method: "POST",
        path: "/api/v1/ssh-key".into(),
        body: Some(
            json!({"name":format!("tau-{identity_index}"),"key_data":public["authorized_keys"]}),
        ),
    }
}
pub(super) fn list() -> VendorRequest {
    VendorRequest {
        method: "GET",
        path: "/api/v1/vm".into(),
        body: None,
    }
}
pub(super) fn get(vm_id: u64) -> VendorRequest {
    VendorRequest {
        method: "GET",
        path: format!("/api/v1/vm/{vm_id}"),
        body: None,
    }
}
pub(super) fn invoice_history(vm_id: u64) -> VendorRequest {
    VendorRequest {
        method: "GET",
        path: format!("/api/v1/vm/{vm_id}/payments?limit=100&offset=0"),
        body: None,
    }
}
pub(super) fn invoice_quote(vm_id: u64) -> VendorRequest {
    VendorRequest {
        method: "GET",
        path: format!("/api/v1/vm/{vm_id}/renew/quote?method=lightning&intervals=1"),
        body: None,
    }
}
pub(super) fn invoice(vm_id: u64) -> VendorRequest {
    VendorRequest {
        method: "GET",
        path: format!("/api/v1/vm/{vm_id}/renew?method=lightning&intervals=1"),
        body: None,
    }
}
pub(super) fn payment(payment_id: &str) -> VendorRequest {
    VendorRequest {
        method: "GET",
        path: format!("/api/v1/payment/{payment_id}"),
        body: None,
    }
}

pub(super) fn readiness_state(vm: &Value) -> &Value {
    &vm["status"]["state"]
}
pub(super) fn auto_renewal_enabled(vm: &Value) -> Option<&Value> {
    vm.get("auto_renewal_enabled")
}
pub(super) fn product(selected: &Selection) -> Result<&str, String> {
    text(&selected.offer, "name", 128)
}
pub(super) fn selection_region(selected: &Selection) -> Result<&str, String> {
    text(&selected.offer["region"], "name", 128)
}
pub(super) fn publication(origin: &str, vm_id: &Value, vm: &Value, key: Value) -> Value {
    json!({"origin":origin,"vm_id":vm_id,"created":vm["created"],"selected_key":key,"host_ssh_keys":vm["host_ssh_keys"]})
}

macro_rules! readiness_message {
    ($message:ident, $prefix:ident, $start:literal, $end:literal) => {
        pub(super) const $message: &str = concat!($start, $end);
        const $prefix: &str = $start;
    };
}
readiness_message!(
    BOOT_WAIT,
    BOOT_PREFIX,
    "Waiting for provider boot readiness",
    "; unknown state is not ready. Refresh later."
);
readiness_message!(
    KEY_WAIT,
    KEY_PREFIX,
    "Waiting for an unambiguous supported published host key",
    "; Refresh later."
);
const ADDRESS_WAIT: &str = "Waiting for one allocated IPv4 address.";

pub(super) fn readiness_kind(result: &Result<(), String>) -> &'static str {
    match result {
        Ok(()) => "ready",
        Err(why) if why.starts_with(BOOT_PREFIX) => "starting",
        Err(why) if why.starts_with(KEY_PREFIX) => "published_key",
        Err(why) if why == ADDRESS_WAIT => "address",
        Err(_) => "refused",
    }
}

pub(super) const CLOSE_REFUSED: &str = "Close is only for a purchase with no recorded payment whose machine the provider no longer has.";
pub(super) fn close_payment_eligible(pay: &Value, now: u64) -> bool {
    pay["is_paid"] == false
        && text(pay, "expires", 40)
            .and_then(timestamp)
            .is_ok_and(|expires| expires <= now)
}
pub(super) fn missing_pause(vm: u64) -> String {
    format!(
        "The provider reports machine {vm} or its payment not found. LNVPS deletes a machine left unpaid for about an hour, with its payments. Close purchase checks that the provider has no record of the machine or any payment for it and that this purchase meets the closing conditions, then closes it. These checks cannot establish whether you paid."
    )
}
pub(super) fn closed_message(vm: &Value, payment: Option<&Value>) -> String {
    let vm = &vm["id"];
    let mut message = format!(
        "Closed: the provider no longer has machine {vm} or any payment record for it, and this purchase recorded no payment. You can approve a new purchase."
    );
    if let Some(payment) = payment {
        message.push_str(&format!(" If you paid invoice {}, the provider no longer has a record of that payment; keep your proof of payment.", payment["id"].as_str().expect("saved payment id")));
    }
    message
}

/// Store authority supplies the entire URL to both preparation and dispatch.
pub(crate) fn request_url(origin: &str, path: &str) -> Result<String, String> {
    if provider_origin(origin)? != origin
        || !path.starts_with("/api/v1/")
        || path.contains(['#', '%', '\\', '\r', '\n'])
    {
        return Err(REFUSED.into());
    }
    Ok(format!("{origin}{path}"))
}

/// Only the recorded provider's exact account URL admits an additional mutation method.
pub(crate) fn request_method_allowed(origin: &str, method: &str, url: &str) -> bool {
    matches!(method, "GET" | "POST")
        || method == "PATCH"
            && request_url(origin, "/api/v1/account").is_ok_and(|account| url == account)
}

/// One encrypted provider identity for this store.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountRecord {
    pub key: crate::poc::credit::SecretText,
    pub source: AccountSource,
    pub origin: String,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccountSource {
    Generated,
    Entered,
}
impl AccountRecord {
    pub(crate) fn account(&self) -> Result<Account, String> {
        if self.key.0.len() != 64
            || !self
                .key
                .0
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || provider_origin(&self.origin)? != self.origin
        {
            return Err("Invalid provider account record.".into());
        }
        Account::parse(self.key.0.as_bytes())
    }
}

/// Separate from inference credential admission: a hexadecimal scalar is required here.
pub struct Account(Zeroizing<[u8; 32]>);
impl Account {
    pub fn parse(input: &[u8]) -> Result<Self, String> {
        if input.len() != 64 || !input.iter().all(u8::is_ascii_hexdigit) {
            return Err("Enter a valid 64-hex provider account private key.".into());
        }
        let mut bytes = Zeroizing::new([0; 32]);
        hex::decode_to_slice(input, bytes.as_mut()).map_err(|_| REFUSED)?;
        SigningKey::from_bytes(bytes.as_ref()).map_err(|_| "Invalid provider account scalar.")?;
        Ok(Self(bytes))
    }
    pub(crate) fn record(&self, source: AccountSource, origin: String) -> AccountRecord {
        AccountRecord {
            key: crate::poc::credit::SecretText(Zeroizing::new(hex::encode(*self.0))),
            source,
            origin,
        }
    }
    pub(crate) fn copy(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }
    pub fn public(&self) -> String {
        hex::encode(
            SigningKey::from_bytes(self.0.as_ref())
                .expect("validated scalar")
                .verifying_key()
                .to_bytes(),
        )
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
    /// A random nonce changes the event id even for repeated reads in the same second.
    pub fn authorization(
        &self,
        url: &str,
        method: &str,
        body: Option<&[u8]>,
        now: u64,
        nonce: &[u8; 32],
    ) -> Result<Zeroizing<String>, String> {
        let key = SigningKey::from_bytes(self.0.as_ref()).map_err(|_| REFUSED)?;
        let public = self.public();
        let mut tags = json!([
            ["u", url],
            ["method", method],
            ["nonce", hex::encode(nonce)]
        ]);
        if let Some(body) = body {
            tags.as_array_mut()
                .expect("tags")
                .push(json!(["payload", hex::encode(Sha256::digest(body))]));
        }
        let id = crate::relay_auth::event_id(&public, now, 27235, &tags, "");
        let signature = key.sign_raw(&id, nonce).map_err(|_| REFUSED)?;
        let event = Zeroizing::new(json!({"id":hex::encode(id),"pubkey":public,"created_at":now,"kind":27235,"tags":tags,"content":"","sig":hex::encode(signature.to_bytes())}).to_string());
        Ok(Zeroizing::new(format!(
            "Nostr {}",
            STANDARD.encode(event.as_bytes())
        )))
    }
}

/// Only the existing machine/detail/history and saved-payment read routes qualify.
pub(crate) fn missing_read(method: &str, url: &str) -> bool {
    if method != "GET" {
        return false;
    }
    let Some((_, path)) = url.split_once("/api/v1/") else {
        return false;
    };
    if let Some(id) = path.strip_prefix("payment/") {
        return !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit());
    }
    let Some(tail) = path.strip_prefix("vm/") else {
        return false;
    };
    let id = tail
        .strip_suffix("/payments?limit=100&offset=0")
        .unwrap_or(tail);
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())
}

pub(crate) fn decoded_missing(method: &str, url: &str, status: u16, body: &[u8]) -> bool {
    status == 404
        && missing_read(method, url)
        && serde_json::from_slice::<Value>(body)
            .ok()
            .is_some_and(|v| v.is_object() && v.get("error").is_some_and(Value::is_string))
}

/// Only a complete, exact refusal from an order establishes that no VM was created.
pub(crate) fn decoded_email_required(method: &str, url: &str, status: u16, body: &[u8]) -> bool {
    status == 403
        && method == "POST"
        && (url.ends_with("/api/v1/vm") || url.ends_with("/api/v1/vm/custom-template"))
        && serde_json::from_slice::<Value>(body)
            .ok()
            .is_some_and(|value| value["error"].as_str() == Some(EMAIL_REQUIRED))
}

pub(crate) fn validate_vm(vm: &Value) -> Result<(), String> {
    id(vm)?;
    timestamp(text(vm, "created", 40)?)?;
    id(&vm["image"])?;
    id(&vm["template"])?;
    id(&vm["ssh_key"])?;
    resources(&vm["template"], "disk_size")?;
    transfer_allowance(&vm["template"])?;
    region(&vm["template"]["region"])?;
    let cost = &vm["template"]["cost_plan"];
    number(cost, "amount")?;
    number(cost, "interval_amount")?;
    text(cost, "currency", 3)?;
    text(cost, "interval_type", 5)?;
    array(&vm["ip_assignments"])?;
    array(&vm["host_ssh_keys"])?;
    if !vm["status"].is_object() {
        return Err(REFUSED.into());
    }
    Ok(())
}

impl Charge {
    pub(super) fn lnvps_parse(v: &Value) -> Result<Self, String> {
        let charge = Self {
            currency: text(v, "currency", 3)?.into(),
            amount: number(v, "amount")?,
            interval_amount: number(v, "interval_amount")?,
            interval_type: text(v, "interval_type", 5)?.into(),
        };
        if !matches!(charge.currency.as_str(), "BTC" | "EUR" | "USD")
            || charge.amount == 0
            || !(1..=12).contains(&charge.interval_amount)
            || !matches!(charge.interval_type.as_str(), "day" | "month" | "year")
        {
            return Err("Hourly credit plans or unknown charge terms are unsupported.".into());
        }
        Ok(charge)
    }
}

fn region(v: &Value) -> Result<(), String> {
    id(v)?;
    text(v, "name", 128)?;
    number(v, "company_id")?;
    Ok(())
}
fn resources(v: &Value, disk: &str) -> Result<(), String> {
    if !(1..=256).contains(&number(v, "cpu")?)
        || !(128 * 1024 * 1024..=16 * 1024u64.pow(4)).contains(&number(v, "memory")?)
        || !(1024u64.pow(3)..=1024u64.pow(5)).contains(&number(v, disk)?)
        || !matches!(text(v, "disk_type", 3)?, "hdd" | "ssd")
        || !matches!(text(v, "disk_interface", 4)?, "sata" | "scsi" | "pcie")
    {
        return Err(REFUSED.into());
    }
    Ok(())
}

/// Only documented, bounded catalogue fields may reach a page or an approval candidate.
pub(crate) fn catalogue_public(
    mut offers: Value,
    mut images: Value,
) -> Result<(Value, Value), String> {
    fn keep(value: &mut Value, names: &[&str]) -> Result<(), String> {
        value
            .as_object_mut()
            .ok_or(REFUSED)?
            .retain(|name, _| names.contains(&name.as_str()));
        Ok(())
    }
    fn bounded(value: &Value, depth: usize) -> Result<(), String> {
        if depth > 12 {
            return Err(REFUSED.into());
        }
        match value {
            Value::String(s) if s.len() > 8192 || s.chars().any(char::is_control) => {
                Err(REFUSED.into())
            }
            Value::Array(a) => {
                if a.len() > 128 {
                    return Err(REFUSED.into());
                }
                for v in a {
                    bounded(v, depth + 1)?;
                }
                Ok(())
            }
            Value::Object(o) => {
                if o.len() > 64 || o.keys().any(|k| k.len() > 64) {
                    return Err(REFUSED.into());
                }
                for v in o.values() {
                    bounded(v, depth + 1)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    keep(&mut offers, &["templates", "custom_template"])?;
    for (field, is_custom) in [("templates", false), ("custom_template", true)] {
        if field == "custom_template" && offers.get(field).is_none() {
            continue;
        }
        unique_ids(&offers[field])?;
        for offer in offers[field].as_array_mut().ok_or(REFUSED)? {
            keep(
                offer,
                &[
                    "id",
                    "name",
                    "created",
                    "expires",
                    "cpu",
                    "cpu_mfg",
                    "cpu_arch",
                    "cpu_features",
                    "memory",
                    "disk_size",
                    "disk_type",
                    "disk_interface",
                    "cost_plan",
                    "region",
                    "limits",
                    "transfer_gb",
                    "min_cpu",
                    "max_cpu",
                    "min_memory",
                    "max_memory",
                    "disks",
                    "interval_amount",
                    "interval_type",
                    "transfer",
                    "network",
                ],
            )?;
            id(offer)?;
            text(offer, "name", 128)?;
            keep(
                &mut offer["region"],
                &["id", "name", "country_code", "company_id"],
            )?;
            region(&offer["region"])?;
            if let Some(country) = offer["region"].get("country_code").filter(|v| !v.is_null())
                && !country
                    .as_str()
                    .is_some_and(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_alphabetic()))
            {
                return Err(REFUSED.into());
            }
            normalize_cpu(offer)?;
            transfer_allowance(offer)?;
            if is_custom {
                for (min, max) in [("min_cpu", "max_cpu"), ("min_memory", "max_memory")] {
                    if number(offer, min)? == 0 || number(offer, min)? > number(offer, max)? {
                        return Err(REFUSED.into());
                    }
                }
                if array(&offer["disks"])?.is_empty() {
                    return Err(REFUSED.into());
                }
                for disk in offer["disks"].as_array_mut().ok_or(REFUSED)? {
                    keep(
                        disk,
                        &["min_disk", "max_disk", "disk_type", "disk_interface"],
                    )?;
                    if number(disk, "min_disk")? == 0
                        || number(disk, "min_disk")? > number(disk, "max_disk")?
                        || !matches!(text(disk, "disk_type", 3)?, "ssd" | "hdd")
                        || !matches!(text(disk, "disk_interface", 4)?, "sata" | "scsi" | "pcie")
                    {
                        return Err(REFUSED.into());
                    }
                }
                for field in ["transfer", "network"] {
                    if let Some(range) = offer.get_mut(field) {
                        keep(range, &["min", "max", "default"])?;
                        if number(range, "min")? > number(range, "default")?
                            || number(range, "default")? > number(range, "max")?
                        {
                            return Err(REFUSED.into());
                        }
                    }
                }
            } else {
                resources(offer, "disk_size")?;
                timestamp(text(offer, "created", 40)?)?;
                keep(
                    &mut offer["cost_plan"],
                    &[
                        "id",
                        "name",
                        "currency",
                        "amount",
                        "interval_amount",
                        "interval_type",
                    ],
                )?;
                id(&offer["cost_plan"])?;
                text(&offer["cost_plan"], "name", 128)?;
            }
            let mut terms = if is_custom {
                json!({"currency":"BTC","amount":1,"interval_amount":offer["interval_amount"],"interval_type":offer["interval_type"]})
            } else {
                offer["cost_plan"].clone()
            };
            if terms["interval_type"] == "hour" {
                terms["interval_type"] = "day".into();
            }
            Charge::lnvps_parse(&terms)?;
            if !offer["limits"].is_object() {
                return Err(REFUSED.into());
            }
            if let Some(limits) = offer.get_mut("limits") {
                keep(
                    limits,
                    &[
                        "disk_iops_read",
                        "disk_iops_write",
                        "disk_mbps_read",
                        "disk_mbps_write",
                        "network_mbps",
                        "cpu_limit",
                        "firewall_rule_limit",
                    ],
                )?;
                if limits
                    .as_object()
                    .ok_or(REFUSED)?
                    .values()
                    .any(|v| v.as_f64().is_none_or(|n| !n.is_finite() || n < 0.0))
                {
                    return Err(REFUSED.into());
                }
            }
            bounded(offer, 0)?;
        }
    }
    unique_ids(&images)?;
    for image in images.as_array_mut().ok_or(REFUSED)? {
        keep(
            image,
            &[
                "id",
                "distribution",
                "flavour",
                "version",
                "release_date",
                "cpu_arch",
                "default_username",
                "encrypted",
                "popularity",
            ],
        )?;
        for field in ["distribution", "flavour", "version"] {
            text(image, field, 128)?;
        }
        for field in ["cpu_arch", "default_username"] {
            if image.get(field).is_some_and(|v| !v.is_null()) {
                text(image, field, 64)?;
            }
        }
        timestamp(text(image, "release_date", 40)?)?;
        if !image["encrypted"].is_boolean()
            || image["popularity"]
                .as_f64()
                .is_none_or(|n| !(0.0..=1.0).contains(&n))
        {
            return Err(REFUSED.into());
        }
        bounded(image, 0)?;
    }
    Ok((offers, images))
}
pub fn supported_image(image: &Value) -> bool {
    id(image).is_ok()
        && matches!(image["distribution"].as_str(), Some("archlinux" | "nixos"))
        && image["encrypted"] == false
        && image_user(image).is_ok()
        && text(image, "flavour", 128).is_ok()
        && text(image, "version", 128).is_ok()
}
pub(crate) fn image_user(image: &Value) -> Result<&str, String> {
    let user = match image.get("default_username") {
        None if image["distribution"] == "archlinux" => "arch",
        Some(value) => value.as_str().ok_or(REFUSED)?,
        None => return Err(REFUSED.into()),
    };
    if !crate::poc::targets::valid_login_user(user) {
        return Err(REFUSED.into());
    }
    Ok(user)
}
fn optional_cpu(value: &Value, field: &str) -> Result<Option<String>, String> {
    if value.get(field).is_none_or(Value::is_null) {
        return Ok(None);
    }
    Ok(Some(text(value, field, 32)?.to_ascii_lowercase()))
}
fn cpu_features(value: &Value) -> Result<std::collections::BTreeSet<String>, String> {
    if value.get("cpu_features").is_none_or(Value::is_null) {
        return Ok(Default::default());
    }
    array(&value["cpu_features"])?
        .iter()
        .map(|feature| {
            feature
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control))
                .map(str::to_ascii_lowercase)
                .ok_or_else(|| REFUSED.to_string())
        })
        .collect()
}
fn normalize_cpu(value: &mut Value) -> Result<(), String> {
    for field in ["cpu_arch", "cpu_mfg"] {
        match optional_cpu(value, field)? {
            Some(v) => value[field] = v.into(),
            None => {
                value.as_object_mut().ok_or(REFUSED)?.remove(field);
            }
        }
    }
    let features = cpu_features(value)?;
    if features.is_empty() {
        value.as_object_mut().ok_or(REFUSED)?.remove("cpu_features");
    } else {
        value["cpu_features"] = json!(features);
    }
    Ok(())
}
fn same_limits(approved: &Value, observed: &Value) -> bool {
    let (Some(approved), Some(observed)) = (approved.as_object(), observed.as_object()) else {
        return false;
    };
    approved.len() == observed.len()
        && approved.iter().all(|(key, expected)| {
            expected.as_f64().is_some_and(|number| {
                number.is_finite()
                    && number >= 0.0
                    && observed.get(key).and_then(Value::as_f64) == Some(number)
            })
        })
}
fn cpu_matches(offer: &Value, image: &Value, vm: &Value) -> Result<bool, String> {
    let template = &vm["template"];
    for field in ["cpu_arch", "cpu_mfg"] {
        let approved = optional_cpu(offer, field)?;
        let observed = optional_cpu(template, field)?;
        if approved.is_some() && approved != observed {
            return Ok(false);
        }
    }
    let approved_features = cpu_features(offer)?;
    if !approved_features.is_subset(&cpu_features(template)?) {
        return Ok(false);
    }
    let image_arch = optional_cpu(image, "cpu_arch")?;
    let template_arch = optional_cpu(template, "cpu_arch")?;
    let host_arch = optional_cpu(vm, "cpu_arch")?;
    if let Some(expected) = image_arch
        && (template_arch.as_ref().is_some_and(|a| a != &expected)
            || host_arch.as_ref().is_some_and(|a| a != &expected)
            || template_arch.is_none() && host_arch.is_none())
    {
        return Ok(false);
    }
    if template_arch.is_some() && host_arch.is_some() && template_arch != host_arch {
        return Ok(false);
    }
    Ok(true)
}

/// Image statistics do not identify the installed image. Missing optional fields and null
/// both mean unspecified; every stable identity/configuration field must otherwise agree.
fn same_image(left: &Value, right: &Value) -> bool {
    [
        "id",
        "distribution",
        "flavour",
        "version",
        "release_date",
        "cpu_arch",
        "default_username",
        "encrypted",
    ]
    .iter()
    .all(|field| left[*field] == right[*field])
}
impl Selection {
    pub(super) fn lnvps_same_terms(&self, other: &Self) -> bool {
        self.offer == other.offer
            && same_image(&self.image, &other.image)
            && self.resources == other.resources
            && self.charge == other.charge
    }

    pub(super) fn lnvps_validate(&self) -> Result<(), String> {
        transfer_allowance(&self.offer)?;
        if !self.offer["limits"].is_object() {
            return Err(REFUSED.into());
        }
        id(&self.offer)?;
        region(&self.offer["region"])?;
        text(&self.offer, "name", 128)?;
        if !supported_image(&self.image) {
            return Err(
                "Choose a supported unencrypted image; console unlock is unsupported.".into(),
            );
        }
        if let (Some(a), Some(b)) = (
            self.offer["cpu_arch"].as_str(),
            self.image["cpu_arch"].as_str(),
        ) && a != b
        {
            return Err(REFUSED.into());
        }
        let charge =
            Charge::lnvps_parse(&serde_json::to_value(&self.charge).map_err(|_| REFUSED)?)?;
        if let Some(r) = &self.resources {
            resources(r, "disk")?;
            if !r.as_object().is_some_and(|o| {
                o.keys().all(|k| {
                    [
                        "pricing_id",
                        "cpu",
                        "memory",
                        "disk",
                        "disk_type",
                        "disk_interface",
                        "ip4_count",
                        "ip6_count",
                        "transfer_gb",
                        "network_mbps",
                    ]
                    .contains(&k.as_str())
                })
            }) || number(r, "pricing_id")? != id(&self.offer)?
            {
                return Err(REFUSED.into());
            }
            for (field, min, max) in [
                ("cpu", "min_cpu", "max_cpu"),
                ("memory", "min_memory", "max_memory"),
            ] {
                let n = number(r, field)?;
                if n < number(&self.offer, min)? || n > number(&self.offer, max)? {
                    return Err(REFUSED.into());
                }
            }
            if !array(&self.offer["disks"])?.iter().any(|d| {
                d["disk_type"] == r["disk_type"]
                    && d["disk_interface"] == r["disk_interface"]
                    && number(d, "min_disk")
                        .is_ok_and(|min| number(r, "disk").is_ok_and(|n| n >= min))
                    && number(d, "max_disk")
                        .is_ok_and(|max| number(r, "disk").is_ok_and(|n| n <= max))
            }) {
                return Err(REFUSED.into());
            }
            if number(r, "ip4_count")? != 1 || number(r, "ip6_count")? > 1 {
                return Err(REFUSED.into());
            }
            for (field, range) in [("transfer_gb", "transfer"), ("network_mbps", "network")] {
                if self.offer.get(range).is_some() {
                    let n = number(r, field)?;
                    if n < number(&self.offer[range], "min")?
                        || n > number(&self.offer[range], "max")?
                    {
                        return Err(REFUSED.into());
                    }
                } else if r.get(field).is_some() {
                    return Err(REFUSED.into());
                }
            }
            if charge.interval_amount != number(&self.offer, "interval_amount")?
                || charge.interval_type != text(&self.offer, "interval_type", 5)?
            {
                return Err(REFUSED.into());
            }
        } else {
            resources(&self.offer, "disk_size")?;
            if charge != Charge::lnvps_parse(&self.offer["cost_plan"])? {
                return Err(REFUSED.into());
            }
        }
        Ok(())
    }
    pub(super) fn lnvps_create(&self, key: u64) -> (&'static str, Value) {
        if let Some(resources) = &self.resources {
            let mut body = resources.clone();
            body["image_id"] = self.image["id"].clone();
            body["ssh_key_id"] = key.into();
            ("/api/v1/vm/custom-template", body)
        } else {
            (
                "/api/v1/vm",
                json!({"template_id":self.offer["id"],"image_id":self.image["id"],"ssh_key_id":key}),
            )
        }
    }
    /// Sufficient association requires creation, key, image, region, price and every resource.
    /// `latest` is the last send of the same Order ID, the first send unless it was sent again.
    pub(super) fn lnvps_matches(&self, vm: &Value, key: u64, not_before: u64, latest: u64) -> bool {
        let check = || -> Result<bool, String> {
            validate_vm(vm)?;
            if !self.offer["limits"].is_object() {
                return Ok(false);
            }
            let created = timestamp(text(vm, "created", 40)?)?;
            // Authentication permits 60s clock skew; journal/dispatch work shares the 60s action bound.
            if created.saturating_add(60) < not_before
                || created > latest.max(not_before).saturating_add(120)
                || !cpu_matches(&self.offer, &self.image, vm)?
                || id(&vm["ssh_key"])? != key
                || !same_image(&vm["image"], &self.image)
                || vm["template"]["region"] != self.offer["region"]
                || Charge::lnvps_parse(&vm["template"]["cost_plan"])? != self.charge
            {
                return Ok(false);
            }
            let template = &vm["template"];
            resources(template, "disk_size")?;
            let expected = self.resources.as_ref().unwrap_or(&self.offer);
            // Omission is an approved unmetered service, not permission to add a cap.
            if transfer_allowance(expected)? != transfer_allowance(template)? {
                return Ok(false);
            }
            if self.resources.is_none() {
                if id(template)? != id(&self.offer)? {
                    return Ok(false);
                }
                if let Some(limits) = self.offer.get("limits")
                    && !same_limits(limits, &template["limits"])
                {
                    return Ok(false);
                }
            }
            for field in ["cpu", "memory", "disk_type", "disk_interface"] {
                if template[field] != expected[field] {
                    return Ok(false);
                }
            }
            if template["disk_size"]
                != expected[if self.resources.is_some() {
                    "disk"
                } else {
                    "disk_size"
                }]
            {
                return Ok(false);
            }
            if let Some(r) = &self.resources {
                // Chosen network speed overrides only that inherited cap. Omitted
                // cap fields mean uncapped, so extra observed caps also conflict.
                let mut limits = self
                    .offer
                    .get("limits")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if let Some(network) = r.get("network_mbps") {
                    limits["network_mbps"] = network.clone();
                }
                if !same_limits(&limits, &template["limits"]) {
                    return Ok(false);
                }
                if let Some(value) = r.get("network_mbps")
                    && template.pointer("/limits/network_mbps") != Some(value)
                {
                    return Ok(false);
                }
                // The published address counts must agree, including pending allocation.
                let ips = array(&vm["ip_assignments"])?;
                let v4 = ips
                    .iter()
                    .filter(|ip| ip["ip"].as_str().is_some_and(|s| s.contains('.')))
                    .count() as u64;
                let v6 = ips
                    .iter()
                    .filter(|ip| ip["ip"].as_str().is_some_and(|s| s.contains(':')))
                    .count() as u64;
                if v4 != number(r, "ip4_count")? || v6 != number(r, "ip6_count")? {
                    return Ok(false);
                }
            }
            Ok(true)
        };
        check().unwrap_or(false)
    }
}
fn transfer_allowance(value: &Value) -> Result<Option<u64>, String> {
    value
        .get("transfer_gb")
        .map(|_| number(value, "transfer_gb"))
        .transpose()
}

pub fn payment_id(payment: &Value) -> Result<&str, String> {
    text(payment, "id", 128).and_then(|s| {
        if s.len() >= 2 && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(s)
        } else {
            Err(REFUSED.into())
        }
    })
}
impl BillingTerms {
    pub(super) fn lnvps_parse(value: &Value) -> Result<Self, String> {
        let terms = Self {
            amount: number(value, "amount")?,
            tax: number(value, "tax")?,
            processing_fee: number(value, "processing_fee")?,
            currency: text(value, "currency", 3)?.into(),
            time: number(value, "time")?,
        };
        if terms.amount == 0 || terms.time == 0 || terms.currency != "BTC" {
            return Err(REFUSED.into());
        }
        Ok(terms)
    }
    pub(super) fn lnvps_validate(&self) -> Result<(), String> {
        Self::lnvps_parse(&serde_json::to_value(self).map_err(|_| REFUSED)?).map(|_| ())
    }
}
pub fn suitable_payment(payment: &Value, vm: u64, expected: &BillingTerms, created: u64) -> bool {
    let check = || -> Result<bool, String> {
        payment_id(payment)?;
        let invoice = text(&payment["data"], "lightning", 8192)?;
        let made = timestamp(text(payment, "created", 40)?)?;
        let expires = timestamp(text(payment, "expires", 40)?)?;
        expected.lnvps_validate()?;
        Ok(number(payment, "vm_id")? == vm
            && payment["is_upgrade"] == false
            && payment["is_paid"].is_boolean()
            && payment["currency"] == expected.currency
            && number(payment, "amount")? == expected.amount
            && number(payment, "time")? == expected.time
            && number(payment, "tax")? == expected.tax
            && number(payment, "processing_fee")? == expected.processing_fee
            && made >= created
            && expires > made
            && invoice.starts_with("lnbc")
            && invoice
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
    };
    check().unwrap_or(false)
}

pub(super) fn lightning_invoice_terms(payment: &Value) -> Option<LightningInvoiceTerms> {
    let invoice = text(&payment["data"], "lightning", 8192).ok()?;
    let (prefix, data) = invoice.rsplit_once('1')?;
    let amount = prefix.strip_prefix("lnbc")?;
    let (digits, multiplier) = match amount.as_bytes().last()? {
        b'm' => (&amount[..amount.len() - 1], 1_000_000_000),
        b'u' => (&amount[..amount.len() - 1], 1_000_000),
        b'n' => (&amount[..amount.len() - 1], 1000),
        b'p' => (&amount[..amount.len() - 1], 1),
        _ => (amount, 1_000_000_000_000),
    };
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let tenths = digits.parse::<u64>().ok()?.checked_mul(multiplier)?;
    // The data contains seven timestamp words, a signature and six checksum words.
    if tenths == 0 || !tenths.is_multiple_of(10) || data.len() < 117 {
        return None;
    }
    const ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const GENERATORS: [u32; 5] = [
        0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3,
    ];
    let prefix_words = prefix
        .bytes()
        .map(|byte| Some(u32::from(byte >> 5)))
        .chain(std::iter::once(Some(0)))
        .chain(prefix.bytes().map(|byte| Some(u32::from(byte & 31))));
    let data_words = data
        .bytes()
        .map(|byte| ALPHABET.iter().position(|&symbol| symbol == byte).map(|word| word as u8))
        .collect::<Option<Vec<_>>>()?;
    // BOLT11 uses the Bech32 checksum. The wallet still validates the invoice signature.
    let mut checksum = 1_u32;
    for word in prefix_words.chain(data_words.iter().map(|&word| Some(u32::from(word)))) {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ word?;
        for (bit, generator) in GENERATORS.into_iter().enumerate() {
            if (top >> bit) & 1 != 0 {
                checksum ^= generator;
            }
        }
    }
    if checksum != 1 {
        return None;
    }

    let created = base32_number(&data_words[..7])?;
    let mut fields = &data_words[7..data_words.len() - 110];
    let mut hash = None;
    let mut expiry = None;
    while let [tag, high, low, rest @ ..] = fields {
        let size = (usize::from(*high) << 5) | usize::from(*low);
        let (field, next) = rest.split_at_checked(size)?;
        fields = next;
        match ALPHABET[usize::from(*tag)] {
            b'p' if hash.is_none() && field.len() == 52 && field[51] & 15 == 0 => {
                let mut bytes = [0_u8; 32];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    let bit = index * 8;
                    let offset = bit / 5;
                    let word = (u16::from(field[offset]) << 10)
                        | (u16::from(field[offset + 1]) << 5)
                        | u16::from(field[offset + 2]);
                    *byte = (word >> (7 - bit % 5)) as u8;
                }
                hash = Some(bytes);
            }
            b'x' if expiry.is_none() && !field.is_empty() => expiry = Some(base32_number(field)?),
            b'p' | b'x' => return None,
            _ => (),
        }
    }
    let mut id = [0_u8; 32];
    hex::decode_to_slice(payment_id(payment).ok()?, &mut id).ok()?;
    if !fields.is_empty() || hash? != id {
        return None;
    }
    Some(LightningInvoiceTerms {
        amount_millisats: tenths / 10,
        expires: created.checked_add(expiry.unwrap_or(3600))?,
    })
}

fn base32_number(words: &[u8]) -> Option<u64> {
    words.iter().try_fold(0_u64, |number, &word| {
        number.checked_mul(32)?.checked_add(u64::from(word))
    })
}

/// Support Ed25519 first, which the existing SSH client also negotiates first.
pub fn published_pin(vm: &Value) -> Result<(Value, String), String> {
    let mut supported = Vec::new();
    for key in array(&vm["host_ssh_keys"])? {
        if key["key_type"] != "ssh-ed25519" {
            continue;
        }
        let blob = STANDARD
            .decode(text(key, "public_key", 256)?)
            .map_err(|_| REFUSED)?;
        if blob.len() != 51 || &blob[..19] != b"\0\0\0\x0bssh-ed25519\0\0\0\x20" {
            return Err(REFUSED.into());
        }
        let bytes: [u8; 32] = blob[19..].try_into().map_err(|_| REFUSED)?;
        let public = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| REFUSED)?;
        if public.is_weak() {
            return Err(REFUSED.into());
        }
        let fingerprint = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob))
        );
        if key["fingerprint_sha256"] != fingerprint {
            return Err(REFUSED.into());
        }
        supported.push((key.clone(), fingerprint));
    }
    supported.sort_by(|a, b| a.1.cmp(&b.1));
    supported.dedup();
    if supported.len() != 1 {
        return Err(KEY_WAIT.into());
    }
    Ok(supported.remove(0))
}
pub fn allocated_ipv4(vm: &Value) -> Result<String, String> {
    let mut found = std::collections::BTreeSet::new();
    for ip in array(&vm["ip_assignments"])? {
        let text = text(ip, "ip", 64)?;
        if text.contains(':') {
            continue;
        }
        let (address, prefix) = text.split_once('/').ok_or(REFUSED)?;
        if prefix.parse::<u8>().ok().is_none_or(|p| p > 32) {
            return Err(REFUSED.into());
        }
        let address = address.parse::<std::net::Ipv4Addr>().map_err(|_| REFUSED)?;
        if address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || address.is_broadcast()
            || address.is_link_local()
        {
            return Err(REFUSED.into());
        }
        found.insert(address.to_string());
    }
    if found.len() != 1 {
        return Err(ADDRESS_WAIT.into());
    }
    Ok(found.into_iter().next().expect("one"))
}

/// Status means the provider state, not incidental uptime or utilization counters.
pub(crate) fn same_readiness(old: &Value, fresh: &Value) -> Result<bool, String> {
    let keys = |vm: &Value| -> Result<std::collections::BTreeSet<String>, String> {
        Ok(array(&vm["host_ssh_keys"])?
            .iter()
            .map(Value::to_string)
            .collect())
    };
    // Preserve address diagnostics even when the selected facts otherwise match.
    let addresses = (allocated_ipv4(old), allocated_ipv4(fresh));
    let same_address = match addresses {
        (Ok(a), Ok(b)) => a == b,
        (Err(a), Err(b)) => a == b,
        _ => false,
    };
    Ok(old["status"]["state"] == fresh["status"]["state"]
        && keys(old)? == keys(fresh)?
        && same_address)
}

pub(super) fn catalogue_shape(catalogue: &Value) -> Result<(), String> {
    array(&catalogue["templates"])?;
    if let Some(custom) = catalogue.get("custom_template") {
        array(custom)?;
    }
    Ok(())
}

/// Only an explicit JSON true makes a Honouring provider; any other value or its absence does not.
pub(super) fn honours_order_id(catalogue: &Value) -> bool {
    catalogue.get("honours_order_id") == Some(&Value::Bool(true))
}

pub(super) fn selection_inputs(
    catalogue: &Value,
    resources: Option<&Value>,
    offer_id: u64,
    image_id: u64,
) -> Result<(Value, Value), String> {
    let field = if resources.is_some() {
        "custom_template"
    } else {
        "templates"
    };
    let offers = array(&catalogue["offers"][field])?;
    let offer = offers
        .iter()
        .find(|o| id(o).ok() == Some(offer_id))
        .ok_or(REFUSED)?
        .clone();
    let image = array(&catalogue["images"])?
        .iter()
        .find(|i| id(i).ok() == Some(image_id))
        .ok_or(REFUSED)?
        .clone();
    Ok((offer, image))
}

pub(super) fn validate_custom(offer: &Value, image: &Value, r: &Value) -> Result<(), String> {
    // Validate resources with provisional terms before making even the price request.
    let provisional = Selection {
        offer: offer.clone(),
        image: image.clone(),
        resources: Some(r.clone()),
        charge: Charge {
            currency: "BTC".into(),
            amount: 1,
            interval_amount: number(offer, "interval_amount")?,
            interval_type: text(offer, "interval_type", 5)?.into(),
        },
    };
    provisional.lnvps_validate()?;
    Ok(())
}

pub(super) fn offer_charge(offer: &Value) -> Result<Charge, String> {
    Charge::lnvps_parse(&offer["cost_plan"])
}

pub(super) fn validate_registered(key: &Value) -> Result<(), String> {
    id(key)?;
    text(key, "name", 128)?;
    timestamp(text(key, "created", 40)?)?;
    Ok(())
}

pub(super) fn parse_history(result: &Value, vm: u64) -> Result<Vec<Value>, String> {
    let rows = array(result)?;
    if rows.len() >= 100 {
        return Err("Payment history incomplete; Refresh without issuing another invoice.".into());
    }
    let mut ids = std::collections::BTreeSet::new();
    for row in rows {
        if !ids.insert(payment_id(row)?) || number(row, "vm_id")? != vm {
            return Err(REFUSED.into());
        }
    }
    Ok(rows.clone())
}

pub(super) fn payment_changed(old: &Value, payment: &Value) -> bool {
    old["id"] != payment["id"]
        || ["created", "expires"].into_iter().any(|field| {
            !matches!(
                (
                    text(old, field, 40).and_then(timestamp),
                    text(payment, field, 40).and_then(timestamp),
                ),
                (Ok(saved), Ok(reading)) if saved == reading
            )
        })
        || old["data"] != payment["data"]
        || (old["is_paid"] == true && payment["is_paid"] != true)
}

pub(super) fn raw_id(value: &Value) -> &Value {
    &value["id"]
}
pub(super) fn created(value: &Value) -> Result<u64, String> {
    timestamp(text(value, "created", 40)?)
}
pub(super) fn same_vm_identity(old: &Value, vm: &Value) -> bool {
    old["id"] == vm["id"] && old["created"] == vm["created"]
}
pub(super) fn same_vm_id(old: &Value, vm: &Value) -> bool {
    old["id"] == vm["id"]
}
pub(super) fn paid(payment: &Value) -> bool {
    payment["is_paid"] == true
}
pub(super) fn payment_expires(payment: &Value) -> Result<u64, String> {
    timestamp(text(payment, "expires", 40)?)
}
pub(super) fn has_billing_evidence(vm: &Value) -> bool {
    vm.get("expires").is_some_and(|v| !v.is_null())
}
