//! VPS.BG's bounded read protocol. This slice has no mutation recipes.
use super::*;
use serde_json::json;

#[cfg(test)]
mod tests;

pub const ORIGIN: &str = "https://api.vpsbg.eu";
pub const READ_ONLY: &str =
    "VPSBG purchases are read-only in this build; no money or provider changes were sent.";
pub type Cents = u64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Currency {
    Eur,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Balance {
    pub amount: Cents,
    pub minimum_deposit: Cents,
    pub balance_limit: Cents,
    pub currency: Currency,
    pub has_valid_card: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentPlan {
    pub balance: Cents,
    pub price: Cents,
    pub minimum: Cents,
    pub top_up: Cents,
    pub first_period: Cents,
    pub left_as_credit: Cents,
    pub currency: Currency,
    pub read_at: u64,
}
impl PaymentPlan {
    pub fn preview(balance: &Balance, selected: &Selection, read_at: u64) -> Result<Self, String> {
        validate_selection(selected)?;
        let price = selected.charge.amount;
        let top_up = if balance.amount >= price {
            0
        } else {
            (price - balance.amount).max(balance.minimum_deposit)
        };
        let total = balance.amount.checked_add(top_up).ok_or(REFUSED)?;
        if top_up > 50_000 || (top_up > 0 && total > balance.balance_limit) {
            return Err(REFUSED.into());
        }
        Ok(Self {
            balance: balance.amount,
            price,
            minimum: balance.minimum_deposit,
            top_up,
            first_period: price,
            left_as_credit: total.checked_sub(price).ok_or(REFUSED)?,
            currency: Currency::Eur,
            read_at,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub id: u64,
    pub key: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub vcpus: u64,
    pub dedicated_cpu: bool,
    pub memory: u64,
    pub disk: u64,
    pub bandwidth: u64,
    pub network_speed: u64,
    pub minimum_billing_cycle: u64,
    pub available: bool,
    pub price_with_vat: Cents,
    pub billing_cycle: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionFact {
    pub id: u64,
    pub created_at: u64,
    pub amount_with_vat: i64,
    pub order_id: u64,
    pub payment_method: String,
    pub description: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderFact {
    pub id: u64,
    pub created_at: u64,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanFact {
    pub id: u64,
    pub key: String,
    pub price_with_vat: Cents,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerStatus {
    Processing,
    Active,
    Suspended,
    Stopped,
    Unknown(String),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAck {
    pub id: u64,
    pub hostname: String,
    pub billing_cycle: u32,
    pub plan: PlanFact,
    pub status: ServerStatus,
    pub created_at: u64,
    pub expiry_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootState {
    pub running: Option<bool>,
    pub cloud_init_installing: Option<bool>,
    pub cloud_init_failed: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartupScriptFact {
    pub exists: bool,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub bytes: Option<u64>,
    pub sha256: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detail {
    pub server: CreateAck,
    pub public_ipv4: Option<std::net::Ipv4Addr>,
    pub auto_renew: Option<bool>,
    pub locked: Option<bool>,
    pub lock_reason: Option<String>,
    pub state: Option<BootState>,
    pub startup_script: Option<StartupScriptFact>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminatedStatus {
    Terminated,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terminated {
    pub id: u64,
    pub hostname: String,
    pub status: TerminatedStatus,
    pub delete_refund_total: Option<Cents>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerFact {
    Live(Box<Detail>),
    Terminated(Terminated),
}
impl ServerFact {
    pub fn id(&self) -> u64 {
        match self {
            Self::Live(d) => d.server.id,
            Self::Terminated(d) => d.id,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page<T> {
    pub data: Vec<T>,
    pub current_page: u64,
    pub last_page: u64,
    pub total: u64,
    pub per_page: u64,
}

pub(crate) fn read(path: &str) -> VendorRequest {
    VendorRequest {
        method: "GET",
        path: path.into(),
        body: None,
    }
}
// Unsupported legacy recipes have no route at this origin and fail transport admission.
pub(super) fn unavailable() -> VendorRequest {
    read("/unsupported-in-read-only-vpsbg")
}
pub(super) fn path_allowed(path: &str) -> bool {
    if matches!(path, "/v1/servers/plans" | "/v1/balance") {
        return true;
    }
    let (base, page) = match path.split_once('?') {
        Some((base, query)) => (
            base,
            query.strip_prefix("page=").filter(|n| canonical_page(n)),
        ),
        None => (path, Some("1")),
    };
    page.is_some()
        && matches!(
            base,
            "/v1/balance/transactions" | "/v1/orders" | "/v1/servers"
        )
}
fn canonical_page(s: &str) -> bool {
    s.parse::<u64>()
        .ok()
        .is_some_and(|n| (1..=16).contains(&n) && n.to_string() == s)
}
pub(super) fn request_url(origin: &str, path: &str) -> Result<String, String> {
    if origin != ORIGIN || !path_allowed(path) {
        return Err(REFUSED.into());
    }
    Ok(format!("{ORIGIN}{path}"))
}
pub(super) fn request_method_allowed(origin: &str, method: &str, url: &str) -> bool {
    origin == ORIGIN && method == "GET" && url.strip_prefix(ORIGIN).is_some_and(path_allowed)
}

pub(crate) fn token_text(input: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(input).ok().filter(|s| !s.is_empty() && s.len() <= 4096
        && !s.chars().any(|c| c.is_whitespace() || c.is_control()))
        .ok_or_else(|| "Enter a nonempty UTF-8 VPSBG token without whitespace or control characters (at most 4096 bytes).".into())
}

/// Preserve decimal number lexemes before serde_json can convert them to f64.
/// Exponents are deliberately unsupported; JSON string contents are copied verbatim.
fn exact_json(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if bytes.len() > BODY_LIMIT {
        return Err(REFUSED.into());
    }
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            out.push(bytes[i]);
            i += 1;
            loop {
                let b = *bytes.get(i).ok_or(REFUSED)?;
                out.push(b);
                i += 1;
                if b == b'"' {
                    break;
                }
                if b == b'\\' {
                    out.push(*bytes.get(i).ok_or(REFUSED)?);
                    i += 1;
                }
            }
        } else if bytes[i] == b'-' || bytes[i].is_ascii_digit() {
            let start = i;
            if bytes[i] == b'-' {
                i += 1;
            }
            let digits = i;
            while bytes.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            if i == digits || (i - digits > 1 && bytes[digits] == b'0') {
                return Err(REFUSED.into());
            }
            let decimal = bytes.get(i) == Some(&b'.');
            if decimal {
                i += 1;
                let fraction = i;
                while bytes.get(i).is_some_and(u8::is_ascii_digit) {
                    i += 1;
                }
                if i == fraction {
                    return Err(REFUSED.into());
                }
            }
            if matches!(bytes.get(i), Some(b'e' | b'E')) {
                return Err(REFUSED.into());
            }
            if decimal {
                out.push(b'"');
            }
            out.extend_from_slice(&bytes[start..i]);
            if decimal {
                out.push(b'"');
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}
fn bounded(value: &Value, depth: usize) -> Result<(), String> {
    if depth > 24 {
        return Err(REFUSED.into());
    }
    match value {
        Value::String(s) if s.len() > 65536 => return Err(REFUSED.into()),
        Value::Array(a) => {
            if a.len() > 128 {
                return Err(REFUSED.into());
            }
            for v in a {
                bounded(v, depth + 1)?;
            }
        }
        Value::Object(o) => {
            if o.len() > 128 || o.keys().any(|s| s.len() > 256) {
                return Err(REFUSED.into());
            }
            for v in o.values() {
                bounded(v, depth + 1)?;
            }
        }
        _ => (),
    }
    Ok(())
}
/// Both scans run over the whole body, including discarded and error fields.
pub(crate) fn reduce_response(
    method: &str,
    path: &str,
    status: u16,
    bytes: &[u8],
    scan_bytes: impl Fn(&[u8]) -> Result<(), String>,
    scan_value: impl Fn(&Value) -> bool,
) -> Result<Value, String> {
    scan_bytes(bytes)?;
    let exact = exact_json(bytes)?;
    crate::store::unique_provider_json(&exact)?;
    let value = crate::poc::credit::decode(&exact).map_err(|_| REFUSED)?;
    bounded(&value.0, 0)?;
    if !scan_value(&value.0)
        || method != "GET"
        || !path_allowed(path)
        || !(200..300).contains(&status)
    {
        return Err(REFUSED.into());
    }
    let raw = &value.0;
    let base = path.split('?').next().ok_or(REFUSED)?;
    match base {
        "/v1/servers/plans" => {
            if raw.get("meta").is_some() {
                return Err(REFUSED.into());
            }
            let plans = array(&raw["data"])?
                .iter()
                .map(plan)
                .collect::<Result<Vec<_>, _>>()?;
            unique_ids(&json!(plans))?;
            Ok(json!(plans))
        }
        "/v1/balance" => {
            let v = raw.get("data").unwrap_or(raw);
            if v["currency"] != "EUR" {
                return Err(REFUSED.into());
            }
            Ok(json!(Balance {
                amount: money(&v["balance"])?,
                minimum_deposit: money(&v["minimum_deposit"])?,
                balance_limit: money(&v["balance_limit"])?,
                currency: Currency::Eur,
                has_valid_card: v["has_valid_card"].as_bool().ok_or(REFUSED)?
            }))
        }
        "/v1/balance/transactions" => page(raw, path, transaction),
        "/v1/orders" => page(raw, path, order),
        "/v1/servers" => page(raw, path, server),
        _ => Err(REFUSED.into()),
    }
}
fn page<T: Serialize>(
    raw: &Value,
    path: &str,
    reduce: impl Fn(&Value) -> Result<T, String>,
) -> Result<Value, String> {
    let meta = &raw["meta"];
    let current_page = number(meta, "current_page")?;
    let last_page = number(meta, "last_page")?;
    let total = number(meta, "total")?;
    let per_page = number(meta, "per_page")?;
    let requested = path
        .split_once("?page=")
        .map_or(Ok(1), |(_, n)| n.parse::<u64>().map_err(|_| REFUSED))?;
    let rows = array(&raw["data"])?;
    if current_page != requested
        || !(1..=16).contains(&last_page)
        || current_page > last_page
        || total > 128
        || !(1..=128).contains(&per_page)
        || last_page != total.div_ceil(per_page).max(1)
        || rows.len() as u64
            != if current_page < last_page {
                per_page
            } else {
                total.saturating_sub((current_page - 1) * per_page)
            }
    {
        return Err(REFUSED.into());
    }
    unique_ids(&raw["data"])?;
    let data = rows.iter().map(reduce).collect::<Result<Vec<_>, _>>()?;
    Ok(json!(Page {
        data,
        current_page,
        last_page,
        total,
        per_page
    }))
}
fn decimal(v: &Value) -> Result<String, String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) if n.is_u64() || n.is_i64() => Ok(n.to_string()),
        _ => Err(REFUSED.into()),
    }
}
pub(crate) fn cents(s: &str) -> Result<Cents, String> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || (whole.len() > 1 && whole.starts_with('0'))
        || frac.len() > 2
        || !frac.bytes().all(|b| b.is_ascii_digit())
        || (s.contains('.') && frac.is_empty())
    {
        return Err(REFUSED.into());
    }
    let whole = whole.parse::<u64>().map_err(|_| REFUSED)?;
    let fraction = match frac.len() {
        0 => 0,
        1 => frac.parse::<u64>().map_err(|_| REFUSED)? * 10,
        _ => frac.parse::<u64>().map_err(|_| REFUSED)?,
    };
    whole
        .checked_mul(100)
        .and_then(|n| n.checked_add(fraction))
        .ok_or_else(|| REFUSED.into())
}
fn money(v: &Value) -> Result<Cents, String> {
    cents(&decimal(v)?)
}
fn signed_money(v: &Value) -> Result<i64, String> {
    let s = decimal(v)?;
    let (negative, unsigned) = s
        .strip_prefix('-')
        .map_or((false, s.as_str()), |s| (true, s));
    let n = i64::try_from(cents(unsigned)?).map_err(|_| REFUSED)?;
    Ok(if negative { -n } else { n })
}
fn plan(v: &Value) -> Result<Plan, String> {
    let minimum_billing_cycle = number(v, "minimum_billing_cycle")?;
    let price_with_vat = money(&v["price_with_vat"])?;
    if minimum_billing_cycle == 0 || price_with_vat == 0 {
        return Err(REFUSED.into());
    }
    Ok(Plan {
        id: id(v)?,
        key: text(v, "key", 128)?.into(),
        name: text(v, "name", 128)?.into(),
        kind: text(v, "type", 64)?.into(),
        vcpus: number(v, "vcpus")?,
        dedicated_cpu: v["dedicated_cpu"].as_bool().ok_or(REFUSED)?,
        memory: number(v, "memory")?,
        disk: number(v, "disk")?,
        bandwidth: number(v, "bandwidth")?,
        network_speed: number(v, "network_speed")?,
        minimum_billing_cycle,
        available: v["available"].as_bool().ok_or(REFUSED)?,
        price_with_vat,
        billing_cycle: "1".into(),
    })
}
fn transaction(v: &Value) -> Result<TransactionFact, String> {
    if v.get("currency").is_some_and(|c| c != "EUR") || number(v, "order_id")? == 0 {
        return Err(REFUSED.into());
    }
    Ok(TransactionFact {
        id: id(v)?,
        created_at: vpsbg_timestamp(text(v, "created_at", 40)?)?,
        amount_with_vat: signed_money(&v["amount_with_vat"])?,
        order_id: number(v, "order_id")?,
        payment_method: text(v, "payment_method", 64)?.into(),
        description: text(v, "description", 256)?.into(),
    })
}
fn order(v: &Value) -> Result<OrderFact, String> {
    // Orders dates and association have no reviewed wire fixture yet. Empty lists are usable;
    // nonempty lists pause rather than inventing the unverified account contract (B963).
    let _ = v;
    Err("Check this order at VPSBG".into())
}
pub(crate) fn preflight_order_allowed(row: &OrderFact) -> bool {
    row.status == "paid"
}
fn optional_bool(v: &Value, field: &str) -> Result<Option<bool>, String> {
    match v.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_bool().map(Some).ok_or_else(|| REFUSED.into()),
    }
}
fn optional_text(v: &Value, field: &str, max: usize) -> Result<Option<String>, String> {
    match v.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => Ok(Some(text(v, field, max)?.into())),
    }
}
fn server(v: &Value) -> Result<ServerFact, String> {
    let server_id = id(v)?;
    let hostname = text(v, "hostname", 128)?.to_string();
    if v["status"] == "terminated" {
        return Ok(ServerFact::Terminated(Terminated {
            id: server_id,
            hostname,
            status: TerminatedStatus::Terminated,
            delete_refund_total: v
                .get("delete_refund_total")
                .filter(|v| !v.is_null())
                .map(money)
                .transpose()?,
        }));
    }
    let status = match text(v, "status", 64)? {
        "processing" => ServerStatus::Processing,
        "active" => ServerStatus::Active,
        "suspended" => ServerStatus::Suspended,
        "stopped" => ServerStatus::Stopped,
        other => ServerStatus::Unknown(other.into()),
    };
    let billing_cycle = match &v["billing_cycle"] {
        Value::String(s) => s.parse::<u32>().map_err(|_| REFUSED)?,
        _ => u32::try_from(number(v, "billing_cycle")?).map_err(|_| REFUSED)?,
    };
    if billing_cycle == 0 {
        return Err(REFUSED.into());
    }
    let plan = &v["plan"];
    let ack = CreateAck {
        id: server_id,
        hostname,
        billing_cycle,
        status,
        plan: PlanFact {
            id: id(plan)?,
            key: text(plan, "key", 128)?.into(),
            price_with_vat: money(&plan["price_with_vat"])?,
        },
        created_at: vpsbg_timestamp(text(v, "created_at", 40)?)?,
        expiry_at: vpsbg_timestamp(text(v, "expiry_at", 40)?)?,
    };
    let mut public_ipv4 = None;
    if let Some(addresses) = v.get("ip_addresses") {
        for a in array(addresses)? {
            let main = a["main"].as_bool().ok_or(REFUSED)?;
            let version = number(a, "version")?;
            if version != 4 && version != 6 {
                return Err(REFUSED.into());
            }
            let address = text(a, "ip_address", 64)?
                .parse::<std::net::IpAddr>()
                .map_err(|_| REFUSED)?;
            if address.is_ipv4() != (version == 4) {
                return Err(REFUSED.into());
            }
            if main && let std::net::IpAddr::V4(ip) = address {
                let first = ip.octets()[0];
                if public_ipv4.is_some()
                    || ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_unspecified()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                    || first == 0
                    || first >= 224
                    || (first == 100 && (64..=127).contains(&ip.octets()[1]))
                {
                    return Err(REFUSED.into());
                }
                public_ipv4 = Some(ip);
            }
        }
    }
    let state = v
        .get("state")
        .filter(|v| !v.is_null())
        .map(|s| {
            if !s.is_object() {
                return Err(REFUSED.to_string());
            }
            let flag = |field: &str| {
                s.get(field)
                    .map(|value| value.as_bool().ok_or_else(|| REFUSED.to_string()))
                    .transpose()
            };
            Ok(BootState {
                running: flag("running")?,
                cloud_init_installing: flag("cloud_init_installing")?,
                cloud_init_failed: flag("cloud_init_failed")?,
            })
        })
        .transpose()?;
    let startup_script = v
        .get("startup_script")
        .filter(|v| !v.is_null())
        .map(|s| {
            let sha256 = optional_text(s, "sha256", 64)?;
            if sha256
                .as_ref()
                .is_some_and(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(REFUSED.to_string());
            }
            Ok(StartupScriptFact {
                exists: s["exists"].as_bool().ok_or(REFUSED)?,
                kind: optional_text(s, "type", 64)?,
                bytes: s
                    .get("bytes")
                    .filter(|v| !v.is_null())
                    .map(|_| number(s, "bytes"))
                    .transpose()?,
                sha256,
            })
        })
        .transpose()?;
    Ok(ServerFact::Live(Box::new(Detail {
        server: ack,
        public_ipv4,
        auto_renew: optional_bool(v, "auto_renew")?,
        locked: optional_bool(v, "locked")?,
        lock_reason: optional_text(v, "lock_reason", 128)?,
        state,
        startup_script,
    })))
}

pub(crate) fn vpsbg_timestamp(s: &str) -> Result<u64, String> {
    if !s.is_ascii() || s.len() > 40 || s.len() < 20 {
        return Err(REFUSED.into());
    }
    let (base, offset) = if let Some(base) = s.strip_suffix('Z') {
        (base, 0i64)
    } else {
        let start = s.len().checked_sub(6).ok_or(REFUSED)?;
        let offset = &s[start..];
        if !matches!(offset.as_bytes()[0], b'+' | b'-')
            || offset.as_bytes()[3] != b':'
            || !offset.as_bytes()[1..3].iter().all(u8::is_ascii_digit)
            || !offset.as_bytes()[4..].iter().all(u8::is_ascii_digit)
        {
            return Err(REFUSED.into());
        }
        let h = offset[1..3].parse::<i64>().map_err(|_| REFUSED)?;
        let m = offset[4..].parse::<i64>().map_err(|_| REFUSED)?;
        if h > 23 || m > 59 {
            return Err(REFUSED.into());
        }
        (
            &s[..start],
            (h * 3600 + m * 60) * if offset.starts_with('-') { -1 } else { 1 },
        )
    };
    let (whole, fraction) = base
        .split_once('.')
        .map_or((base, None), |(a, b)| (a, Some(b)));
    if whole.len() != 19
        || fraction
            .is_some_and(|f| f.is_empty() || f.len() > 9 || !f.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(REFUSED.into());
    }
    if whole
        .bytes()
        .enumerate()
        .any(|(i, b)| !matches!(i, 4 | 7 | 10 | 13 | 16) && !b.is_ascii_digit())
    {
        return Err(REFUSED.into());
    }
    let utc = timestamp(&format!("{whole}Z"))?;
    u64::try_from(
        i64::try_from(utc)
            .map_err(|_| REFUSED)?
            .checked_sub(offset)
            .ok_or(REFUSED)?,
    )
    .map_err(|_| REFUSED.into())
}

pub(crate) fn image() -> Value {
    json!({"id":1,"name":"Deployment image","default_username":"nixos","source":"deployment"})
}
pub(super) fn offer_charge(offer: &Value) -> Result<Charge, String> {
    let p: Plan = serde_json::from_value(offer.clone()).map_err(|_| REFUSED)?;
    if p.id == 0
        || p.key.is_empty()
        || p.key.len() > 128
        || p.name.is_empty()
        || p.name.len() > 128
        || p.key.chars().chain(p.name.chars()).any(char::is_control)
        || p.vcpus == 0
        || p.memory == 0
        || p.disk == 0
        || p.minimum_billing_cycle != 1
        || p.billing_cycle != "1"
        || !p.available
        || p.price_with_vat == 0
    {
        return Err(REFUSED.into());
    }
    Ok(Charge {
        currency: "EUR".into(),
        amount: p.price_with_vat,
        interval_amount: 1,
        interval_type: "month".into(),
    })
}
pub(super) fn validate_selection(selected: &Selection) -> Result<(), String> {
    if selected.resources.is_some()
        || selected.image != image()
        || selected.charge != offer_charge(&selected.offer)?
    {
        return Err(REFUSED.into());
    }
    Ok(())
}
pub(super) fn selection_inputs(
    catalogue: &Value,
    resources: Option<&Value>,
    offer_id: u64,
    image_id: u64,
) -> Result<(Value, Value), String> {
    if resources.is_some() || image_id != 1 {
        return Err(REFUSED.into());
    }
    let offer = array(&catalogue["offers"])?
        .iter()
        .find(|p| id(p).ok() == Some(offer_id))
        .ok_or(REFUSED)?
        .clone();
    offer_charge(&offer)?;
    Ok((offer, image()))
}
