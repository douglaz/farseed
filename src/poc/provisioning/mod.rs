//! Bounded provider protocol. Responses are observations, never instructions.
#[cfg(test)]
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
#[cfg(test)]
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

mod lnvps;
pub(crate) mod vpsbg;
pub use lnvps::Account;
pub(crate) use lnvps::{AccountRecord, AccountSource};
pub const ORIGIN: &str = lnvps::ORIGIN;
pub(crate) const EMAIL_REQUIRED: &str = lnvps::EMAIL_REQUIRED;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Vendor {
    #[default]
    Lnvps,
    Vpsbg,
}

#[derive(Debug)]
pub struct UnsupportedVendor;

impl<'de> Deserialize<'de> for Vendor {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let id = String::deserialize(deserializer)?;
        Self::from_id(Some(&id)).map_err(|_| serde::de::Error::custom("unsupported vendor"))
    }
}

pub(crate) struct VendorRequest {
    pub method: &'static str,
    pub path: String,
    pub body: Option<Value>,
}

pub(crate) struct RequestPolicy {
    pub mutation: bool,
    pub missing_read: bool,
    pub email_refusal: bool,
}

pub(crate) struct AccountFields {
    pub email: &'static str,
    pub verified: &'static str,
    pub contact_flags: [&'static str; 4],
}

impl Vendor {
    pub(crate) fn admit_action(self, action: &str) -> Result<(), String> {
        if self == Self::Vpsbg
            && matches!(
                action,
                "approve"
                    | "resume"
                    | "payment_check"
                    | "email_check"
                    | "initial_invoice"
                    | "close"
                    | "email_send"
                    | "email_reissue"
            )
        {
            return Err(vpsbg::READ_ONLY.into());
        }
        Ok(())
    }
    pub(crate) fn describe(self) -> Value {
        serde_json::json!({"id":self,"name":self.name(),"billing":if self == Self::Vpsbg {"PrepaidBalance"} else {"Invoice"},"host_key_route":if self == Self::Vpsbg {"AttestCertificate"} else {"ProviderPublication"}})
    }
    pub(crate) fn capabilities(self) -> Value {
        match self {
            Self::Vpsbg => {
                serde_json::json!({"billing":"PrepaidBalance","host_key_route":"AttestCertificate","delete":true,"renew":false,"auto_renew_switch":false,"user_data":true,"user_data_exposure":{"api_read_back":"yes","metadata":"unknown"}})
            }
            Self::Lnvps => {
                serde_json::json!({"billing":"Invoice","host_key_route":"ProviderPublication"})
            }
        }
    }
    pub fn is_lnvps(&self) -> bool {
        matches!(self, Self::Lnvps)
    }
    pub fn from_id(id: Option<&str>) -> Result<Self, UnsupportedVendor> {
        match id {
            None | Some("lnvps") => Ok(Self::Lnvps),
            Some("vpsbg") => Ok(Self::Vpsbg),
            Some(_) => Err(UnsupportedVendor),
        }
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Vpsbg => "VPS.BG Ltd (Bulgaria)",
            Self::Lnvps => lnvps::NAME,
        }
    }
    pub(crate) fn default_user(self) -> String {
        match self {
            Self::Vpsbg => "nixos".into(),
            Self::Lnvps => lnvps::default_user(),
        }
    }
    pub(crate) fn request_url(self, origin: &str, path: &str) -> Result<String, String> {
        match self {
            Self::Vpsbg => vpsbg::request_url(origin, path),
            Self::Lnvps => lnvps::request_url(origin, path),
        }
    }
    pub(crate) fn request_method_allowed(self, origin: &str, method: &str, url: &str) -> bool {
        match self {
            Self::Vpsbg => vpsbg::request_method_allowed(origin, method, url),
            Self::Lnvps => lnvps::request_method_allowed(origin, method, url),
        }
    }
    pub(crate) fn request_policy(self, method: &str, url: &str) -> RequestPolicy {
        match self {
            Self::Vpsbg => RequestPolicy {
                mutation: method != "GET",
                missing_read: false,
                email_refusal: false,
            },
            Self::Lnvps => lnvps::request_policy(method, url),
        }
    }
    pub(crate) fn authorization(
        self,
        account: &Account,
        url: &str,
        method: &str,
        body: Option<&[u8]>,
        now: u64,
        nonce: &[u8; 32],
    ) -> Result<Zeroizing<String>, String> {
        match self {
            Self::Vpsbg => Err(vpsbg::READ_ONLY.into()),
            Self::Lnvps => account.authorization(url, method, body, now, nonce),
        }
    }
    pub(crate) fn decoded_missing(self, method: &str, url: &str, status: u16, body: &[u8]) -> bool {
        match self {
            Self::Vpsbg => false,
            Self::Lnvps => lnvps::decoded_missing(method, url, status, body),
        }
    }
    pub(crate) fn decoded_email_required(
        self,
        method: &str,
        url: &str,
        status: u16,
        body: &[u8],
    ) -> bool {
        match self {
            Self::Vpsbg => false,
            Self::Lnvps => lnvps::decoded_email_required(method, url, status, body),
        }
    }
    pub(crate) fn reduce_response(
        self,
        method: &str,
        path: &str,
        status: u16,
        bytes: &[u8],
        scan_bytes: impl Fn(&[u8]) -> Result<(), String>,
        scan_value: impl Fn(&Value) -> bool,
    ) -> Result<Value, String> {
        match self {
            Self::Vpsbg => {
                vpsbg::reduce_response(method, path, status, bytes, scan_bytes, scan_value)
            }
            Self::Lnvps => lnvps::decode_response(bytes),
        }
    }
    pub(crate) fn decode_response(self, body: &[u8]) -> Result<Value, String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => lnvps::decode_response(body),
        }
    }
    pub(crate) fn owns_read(self, path: &str, vm: u64, payment: Option<&Value>) -> bool {
        match self {
            Self::Vpsbg => path == "/v1/servers",
            Self::Lnvps => lnvps::owns_read(path, vm, payment),
        }
    }
    pub(crate) fn account_fields(self) -> AccountFields {
        match self {
            Self::Vpsbg => AccountFields {
                email: "",
                verified: "",
                contact_flags: [""; 4],
            },
            Self::Lnvps => lnvps::account_fields(),
        }
    }
    pub(crate) fn account(self, body: Option<Value>) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::unavailable(),
            Self::Lnvps => lnvps::account(body),
        }
    }
    pub(crate) fn notification_channels(self) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::unavailable(),
            Self::Lnvps => lnvps::notification_channels(),
        }
    }
    pub(crate) fn catalogue(self) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::read("/v1/servers/plans"),
            Self::Lnvps => lnvps::catalogue(),
        }
    }
    pub(crate) fn images(self) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::unavailable(),
            Self::Lnvps => lnvps::images(),
        }
    }
    pub(crate) fn custom_price(self, resources: Value) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::unavailable(),
            Self::Lnvps => lnvps::custom_price(resources),
        }
    }
    pub(crate) fn keys(self) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::unavailable(),
            Self::Lnvps => lnvps::keys(),
        }
    }
    pub(crate) fn register_key(self, public: &Value, identity_index: u32) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::unavailable(),
            Self::Lnvps => lnvps::register_key(public, identity_index),
        }
    }
    pub(crate) fn list(self) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::read("/v1/servers"),
            Self::Lnvps => lnvps::list(),
        }
    }
    pub(crate) fn get(self, vm_id: u64) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::unavailable(),
            Self::Lnvps => lnvps::get(vm_id),
        }
    }
    pub(crate) fn invoice_history(self, vm_id: u64) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::unavailable(),
            Self::Lnvps => lnvps::invoice_history(vm_id),
        }
    }
    pub(crate) fn invoice_quote(self, vm_id: u64) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::unavailable(),
            Self::Lnvps => lnvps::invoice_quote(vm_id),
        }
    }
    pub(crate) fn invoice(self, vm_id: u64) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::unavailable(),
            Self::Lnvps => lnvps::invoice(vm_id),
        }
    }
    pub(crate) fn payment(self, payment_id: &str) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::unavailable(),
            Self::Lnvps => lnvps::payment(payment_id),
        }
    }
    pub(crate) fn create(self, selected: &Selection, key: u64) -> VendorRequest {
        match self {
            Self::Vpsbg => vpsbg::unavailable(),
            Self::Lnvps => {
                let (path, body) = selected.lnvps_create(key);
                VendorRequest {
                    method: "POST",
                    path: path.into(),
                    body: Some(body),
                }
            }
        }
    }
    pub(crate) fn parse_charge(self, value: &Value) -> Result<Charge, String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => Charge::lnvps_parse(value),
        }
    }
    pub(crate) fn catalogue_public(
        self,
        offers: Value,
        images: Value,
    ) -> Result<(Value, Value), String> {
        match self {
            Self::Vpsbg => Ok((offers, images)),
            Self::Lnvps => lnvps::catalogue_public(offers, images),
        }
    }
    pub(crate) fn validate_selection(self, selected: &Selection) -> Result<(), String> {
        match self {
            Self::Vpsbg => vpsbg::validate_selection(selected),
            Self::Lnvps => selected.lnvps_validate(),
        }
    }
    pub(crate) fn same_terms(self, selection: &Selection, other: &Selection) -> bool {
        match self {
            Self::Vpsbg => {
                vpsbg::validate_selection(selection).is_ok()
                    && vpsbg::validate_selection(other).is_ok()
                    && selection == other
            }
            Self::Lnvps => selection.lnvps_same_terms(other),
        }
    }
    pub(crate) fn matches(
        self,
        selection: &Selection,
        vm: &Value,
        key: u64,
        not_before: u64,
    ) -> bool {
        match self {
            Self::Vpsbg => false,
            Self::Lnvps => selection.lnvps_matches(vm, key, not_before),
        }
    }
    pub(crate) fn validate_vm(self, vm: &Value) -> Result<(), String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => lnvps::validate_vm(vm),
        }
    }
    pub(crate) fn image_user(self, image: &Value) -> Result<&str, String> {
        match self {
            Self::Vpsbg => {
                if *image == vpsbg::image() {
                    Ok("nixos")
                } else {
                    Err(REFUSED.into())
                }
            }
            Self::Lnvps => lnvps::image_user(image),
        }
    }
    pub(crate) fn parse_billing(self, value: &Value) -> Result<BillingTerms, String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => BillingTerms::lnvps_parse(value),
        }
    }
    pub(crate) fn validate_billing(self, terms: &BillingTerms) -> Result<(), String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => terms.lnvps_validate(),
        }
    }
    pub(crate) fn suitable_payment(
        self,
        payment: &Value,
        vm: u64,
        expected: &BillingTerms,
        created: u64,
    ) -> bool {
        match self {
            Self::Vpsbg => false,
            Self::Lnvps => lnvps::suitable_payment(payment, vm, expected, created),
        }
    }
    pub(crate) fn published_pin(self, vm: &Value) -> Result<(Value, String), String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => lnvps::published_pin(vm),
        }
    }
    pub(crate) fn allocated_ipv4(self, vm: &Value) -> Result<String, String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => lnvps::allocated_ipv4(vm),
        }
    }
    pub(crate) fn same_readiness(self, old: &Value, fresh: &Value) -> Result<bool, String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => lnvps::same_readiness(old, fresh),
        }
    }
    pub(crate) fn readiness_state(self, vm: &Value) -> &Value {
        match self {
            Self::Vpsbg => &Value::Null,
            Self::Lnvps => lnvps::readiness_state(vm),
        }
    }
    pub(crate) fn auto_renewal_enabled(self, vm: &Value) -> Option<&Value> {
        match self {
            Self::Vpsbg => None,
            Self::Lnvps => lnvps::auto_renewal_enabled(vm),
        }
    }
    pub(crate) fn product(self, selection: &Selection) -> Result<&str, String> {
        match self {
            Self::Vpsbg => text(&selection.offer, "name", 128),
            Self::Lnvps => lnvps::product(selection),
        }
    }
    pub(crate) fn region(self, selection: &Selection) -> Result<&str, String> {
        match self {
            Self::Vpsbg => Ok("Bulgaria"),
            Self::Lnvps => lnvps::selection_region(selection),
        }
    }
    pub(crate) fn publication(self, origin: &str, vm_id: &Value, vm: &Value, key: Value) -> Value {
        match self {
            Self::Vpsbg => Value::Null,
            Self::Lnvps => lnvps::publication(origin, vm_id, vm, key),
        }
    }
    pub(crate) fn readiness_kind(self, result: &Result<(), String>) -> &'static str {
        match self {
            Self::Vpsbg => "paused",
            Self::Lnvps => lnvps::readiness_kind(result),
        }
    }
    pub(crate) fn boot_wait(self) -> &'static str {
        match self {
            Self::Vpsbg => vpsbg::READ_ONLY,
            Self::Lnvps => lnvps::BOOT_WAIT,
        }
    }
    pub(crate) fn close_refused(self) -> &'static str {
        match self {
            Self::Vpsbg => vpsbg::READ_ONLY,
            Self::Lnvps => lnvps::CLOSE_REFUSED,
        }
    }
    pub(crate) fn close_payment_eligible(self, payment: &Value, now: u64) -> bool {
        match self {
            Self::Vpsbg => false,
            Self::Lnvps => lnvps::close_payment_eligible(payment, now),
        }
    }
    pub(crate) fn missing_pause(self, vm: u64) -> String {
        match self {
            Self::Vpsbg => "VPSBG read unavailable; no provider changes were sent.".into(),
            Self::Lnvps => lnvps::missing_pause(vm),
        }
    }
    pub(crate) fn closed_message(self, vm: &Value, payment: Option<&Value>) -> String {
        match self {
            Self::Vpsbg => "VPSBG purchase closed.".into(),
            Self::Lnvps => lnvps::closed_message(vm, payment),
        }
    }
    pub(crate) fn catalogue_shape(self, catalogue: &Value) -> Result<(), String> {
        match self {
            Self::Vpsbg => array(catalogue).map(|_| ()),
            Self::Lnvps => lnvps::catalogue_shape(catalogue),
        }
    }
    pub(crate) fn selection_inputs(
        self,
        catalogue: &Value,
        resources: Option<&Value>,
        offer_id: u64,
        image_id: u64,
    ) -> Result<(Value, Value), String> {
        match self {
            Self::Vpsbg => vpsbg::selection_inputs(catalogue, resources, offer_id, image_id),
            Self::Lnvps => lnvps::selection_inputs(catalogue, resources, offer_id, image_id),
        }
    }
    pub(crate) fn validate_custom(
        self,
        offer: &Value,
        image: &Value,
        r: &Value,
    ) -> Result<(), String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => lnvps::validate_custom(offer, image, r),
        }
    }
    pub(crate) fn offer_charge(self, offer: &Value) -> Result<Charge, String> {
        match self {
            Self::Vpsbg => vpsbg::offer_charge(offer),
            Self::Lnvps => lnvps::offer_charge(offer),
        }
    }
    pub(crate) fn validate_registered(self, key: &Value) -> Result<(), String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => lnvps::validate_registered(key),
        }
    }
    pub(crate) fn parse_history(self, result: &Value, vm: u64) -> Result<Vec<Value>, String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => lnvps::parse_history(result, vm),
        }
    }
    pub(crate) fn payment_changed(self, old: &Value, payment: &Value) -> bool {
        match self {
            Self::Vpsbg => true,
            Self::Lnvps => lnvps::payment_changed(old, payment),
        }
    }
    pub(crate) fn raw_id(self, value: &Value) -> &Value {
        match self {
            Self::Vpsbg => &value["id"],
            Self::Lnvps => lnvps::raw_id(value),
        }
    }
    pub(crate) fn created(self, value: &Value) -> Result<u64, String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => lnvps::created(value),
        }
    }
    pub(crate) fn same_vm_identity(self, old: &Value, vm: &Value) -> bool {
        match self {
            Self::Vpsbg => false,
            Self::Lnvps => lnvps::same_vm_identity(old, vm),
        }
    }
    pub(crate) fn same_vm_id(self, old: &Value, vm: &Value) -> bool {
        match self {
            Self::Vpsbg => false,
            Self::Lnvps => lnvps::same_vm_id(old, vm),
        }
    }
    pub(crate) fn paid(self, payment: &Value) -> bool {
        match self {
            Self::Vpsbg => false,
            Self::Lnvps => lnvps::paid(payment),
        }
    }
    pub(crate) fn payment_expires(self, payment: &Value) -> Result<u64, String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => lnvps::payment_expires(payment),
        }
    }
    pub(crate) fn has_billing_evidence(self, vm: &Value) -> bool {
        match self {
            Self::Vpsbg => false,
            Self::Lnvps => lnvps::has_billing_evidence(vm),
        }
    }
    pub(crate) fn payment_id(self, payment: &Value) -> Result<&str, String> {
        match self {
            Self::Vpsbg => Err(REFUSED.into()),
            Self::Lnvps => lnvps::payment_id(payment),
        }
    }
}

pub const REFUSED: &str = "Provider response refused; saved identities remain unchanged.";
pub const INCOMPLETE: &str = "Provider request incomplete or browser access unavailable; unlock and Refresh the saved purchase. Uncertain operations are never resent.";
pub const BODY_LIMIT: usize = 256 * 1024;

/// Strict origin grammar, checked before any URL parser can repair forbidden input.
pub(crate) fn provider_origin(input: &str) -> Result<String, String> {
    const INVALID: &str = "Enter an HTTPS provider origin with a DNS or IP host and optional port; no credentials, path, query, fragment, whitespace or backslash.";
    let refuse = || INVALID.to_string();
    if input.len() > 320
        || input.chars().any(|c| c.is_whitespace() || c.is_control())
        || input.contains(['@', '?', '#', '\\', '%'])
    {
        return Err(refuse());
    }
    let authority = input.strip_prefix("https://").ok_or_else(refuse)?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty() || authority.contains('/') {
        return Err(refuse());
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']').ok_or_else(refuse)?;
        let ip = host.parse::<std::net::Ipv6Addr>().map_err(|_| refuse())?;
        // Browsers serialize mapped IPv6 using hexadecimal segments as well.
        let host = if let Some(ip4) = ip.to_ipv4_mapped() {
            let bytes = ip4.octets();
            format!(
                "::ffff:{:x}:{:x}",
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]])
            )
        } else {
            ip.to_string()
        };
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or_else(refuse)?)
        };
        (format!("[{host}]"), port)
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)));
        let host = host.to_ascii_lowercase();
        let dns = host.strip_suffix('.').unwrap_or(&host);
        if dns.is_empty()
            || dns.len() > 253
            || dns.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label.as_bytes()[0].is_ascii_alphanumeric()
                    || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(refuse());
        }
        let last = dns.rsplit('.').next().ok_or_else(refuse)?;
        // Refuse alternative numeric IPv4 forms that fetch would reinterpret.
        if (last.bytes().all(|b| b.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .is_some_and(|s| s.bytes().all(|b| b.is_ascii_hexdigit())))
            && (host.parse::<std::net::Ipv4Addr>().is_err() || host != dns)
        {
            return Err(refuse());
        }
        (host, port)
    };
    let port = port
        .map(|p| {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(refuse());
            }
            p.parse::<u16>().map_err(|_| refuse())
        })
        .transpose()?;
    Ok(match port {
        Some(port) if port != 443 => format!("https://{host}:{port}"),
        _ => format!("https://{host}"),
    })
}

pub(crate) const READ_REFUSED: &str =
    "Provider read refused; saved operation identities remain unchanged.";

/// Missing evidence is distinct from transport, authentication and decoding failures.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadError {
    Refused(String),
    NotFound,
    EmailRequired,
}
impl From<String> for ReadError {
    fn from(value: String) -> Self {
        Self::Refused(value)
    }
}
impl From<&str> for ReadError {
    fn from(value: &str) -> Self {
        Self::Refused(value.into())
    }
}
impl ReadError {
    pub(crate) fn message(self) -> String {
        match self {
            Self::Refused(message) => message,
            Self::NotFound => READ_REFUSED.into(),
            Self::EmailRequired => EMAIL_REQUIRED.into(),
        }
    }
}

#[allow(async_fn_in_trait)]
pub(crate) trait Api {
    /// One exchange; no retries. All successful data must pass store credential protection.
    async fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, ReadError>;
    fn check_vendor(&self, vendor: Vendor) -> Result<(), String> {
        if vendor != Vendor::Lnvps {
            return Err(REFUSED.into());
        }
        Ok(())
    }
    fn take_vpsbg_response(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        None
    }
    fn response_status(&self) -> u16 {
        200
    }
    fn account(&self) -> String;
    fn now(&self) -> u64;
    fn current(&self) -> Result<(), String>;
}

pub(crate) fn number(v: &Value, name: &str) -> Result<u64, String> {
    v[name]
        .as_u64()
        .filter(|n| *n <= 9_007_199_254_740_991)
        .ok_or_else(|| REFUSED.into())
}
pub(crate) fn id(v: &Value) -> Result<u64, String> {
    number(v, "id").and_then(|id| if id > 0 { Ok(id) } else { Err(REFUSED.into()) })
}
pub(crate) fn text<'a>(v: &'a Value, name: &str, max: usize) -> Result<&'a str, String> {
    v[name]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control))
        .ok_or_else(|| REFUSED.into())
}
pub(crate) fn array(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array()
        .filter(|a| a.len() <= 128)
        .ok_or_else(|| REFUSED.into())
}
pub(crate) fn unique_ids(v: &Value) -> Result<Vec<u64>, String> {
    let ids = array(v)?.iter().map(id).collect::<Result<Vec<_>, _>>()?;
    if ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len() {
        return Err(REFUSED.into());
    }
    Ok(ids)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Charge {
    pub currency: String,
    pub amount: u64,
    pub interval_amount: u64,
    pub interval_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub offer: Value,
    pub image: Value,
    pub resources: Option<Value>,
    pub charge: Charge,
}

/// ISO-8601 UTC provider dates, optionally fractional. No locale or permissive date parser.
pub fn timestamp(text: &str) -> Result<u64, String> {
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes.len() > 30
        || &bytes[4..5] != b"-"
        || &bytes[7..8] != b"-"
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last().ok_or(REFUSED)? != b'Z'
    {
        return Err(REFUSED.into());
    }
    if bytes.len() > 20
        && (bytes[19] != b'.' || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return Err(REFUSED.into());
    }
    let n = |start: usize, end: usize| {
        std::str::from_utf8(&bytes[start..end])
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| REFUSED.to_string())
    };
    let (year, month, day, hour, minute, second) = (
        n(0, 4)?,
        n(5, 7)?,
        n(8, 10)?,
        n(11, 13)?,
        n(14, 16)?,
        n(17, 19)?,
    );
    let leap = |y: u64| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    if !(1970..=2200).contains(&year)
        || !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(REFUSED.into());
    }
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > months[month as usize - 1] {
        return Err(REFUSED.into());
    }
    let days = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + months[..month as usize - 1].iter().sum::<u64>()
        + day
        - 1;
    Ok(days * 86400 + hour * 3600 + minute * 60 + second)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingTerms {
    pub amount: u64,
    pub tax: u64,
    pub processing_fee: u64,
    pub currency: String,
    pub time: u64,
}

#[cfg(target_arch = "wasm32")]
pub(crate) mod browser;
#[cfg(test)]
pub(crate) mod tests;

pub(crate) const READINESS_STOP: &str = "Published host-key wait expired after three hours from recorded payment. First contact is stopped; this page cannot reinstall or abandon a paid purchase.";

fn readiness_seconds(name: &str) -> u64 {
    let timing = crate::BUNDLE
        .iter()
        .find(|(name, _)| *name == "timing.toml")
        .expect("compiled timing input")
        .1;
    let value = timing
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == name).then(|| value.trim().trim_matches('"'))
        })
        .expect("published-key timing");
    let (number, unit) = value.split_at(value.len() - 1);
    number.parse::<u64>().expect("timing number")
        * match unit {
            "m" => 60,
            "h" => 3600,
            "s" => 1,
            _ => panic!("timing unit"),
        }
}
pub(crate) fn readiness_poll_seconds() -> u64 {
    readiness_seconds("published_key_poll_interval")
}
pub(crate) fn readiness_wait_seconds() -> u64 {
    readiness_seconds("published_key_wait_max")
}

pub(crate) fn default_origin() -> String {
    ORIGIN.into()
}

impl Charge {
    pub fn parse(value: &Value) -> Result<Self, String> {
        Vendor::Lnvps.parse_charge(value)
    }
}

impl Selection {
    pub fn same_terms(&self, other: &Self) -> bool {
        Vendor::Lnvps.same_terms(self, other)
    }
    pub fn validate(&self) -> Result<(), String> {
        Vendor::Lnvps.validate_selection(self)
    }
    pub fn create(&self, key: u64) -> (&'static str, Value) {
        self.lnvps_create(key)
    }
    pub fn matches(&self, vm: &Value, key: u64, not_before: u64) -> bool {
        Vendor::Lnvps.matches(self, vm, key, not_before)
    }
}

impl BillingTerms {
    pub fn parse(value: &Value) -> Result<Self, String> {
        Vendor::Lnvps.parse_billing(value)
    }
    pub fn validate(&self) -> Result<(), String> {
        Vendor::Lnvps.validate_billing(self)
    }
}

pub fn supported_image(image: &Value) -> bool {
    lnvps::supported_image(image)
}
pub fn payment_id(payment: &Value) -> Result<&str, String> {
    lnvps::payment_id(payment)
}

#[cfg(test)]
pub(crate) use lnvps::{
    catalogue_public, decoded_email_required, decoded_missing, request_method_allowed,
    same_readiness,
};

pub fn suitable_payment(payment: &Value, vm: u64, expected: &BillingTerms, created: u64) -> bool {
    Vendor::Lnvps.suitable_payment(payment, vm, expected, created)
}

pub fn published_pin(vm: &Value) -> Result<(Value, String), String> {
    Vendor::Lnvps.published_pin(vm)
}

pub fn allocated_ipv4(vm: &Value) -> Result<String, String> {
    Vendor::Lnvps.allocated_ipv4(vm)
}
