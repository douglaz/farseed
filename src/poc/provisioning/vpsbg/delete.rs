//! Fixed delete recipe and evidence predicates; no status discovery.
use super::*;

pub(crate) const DELETE_REASON: &str = "No longer required";
pub(crate) const DELETE_STEP_UP: &str =
    "Delete was refused. Delete this machine in the VPSBG console, then check again here.";
// B963: no non-paid terminal meaning has yet been confirmed by the account check.
pub(crate) const CONFIRMED_CANCELLED_ORDER_STATUSES: &[&str] = &[];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Money {
    pub amount: Cents,
    pub currency: Currency,
}

pub(crate) fn server_detail_path(path: &str) -> bool {
    path.strip_prefix("/v1/servers/").is_some_and(positive_id)
}
fn encoded(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
pub(crate) fn delete_server(id: u64, hostname: &str) -> Result<VendorRequest, String> {
    let purchase = hostname.strip_prefix("tau-web-").ok_or(REFUSED)?;
    if id == 0
        || purchase.len() != 32
        || !purchase
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(REFUSED.into());
    }
    Ok(VendorRequest {
        method: "DELETE",
        path: format!(
            "/v1/servers/{id}?reason={}&hostname={}",
            encoded(DELETE_REASON),
            encoded(hostname)
        ),
        body: None,
    })
}
pub(crate) fn delete_path_allowed(path: &str) -> bool {
    let Some((route, query)) = path.split_once('?') else {
        return false;
    };
    let Some(id) = route
        .strip_prefix("/v1/servers/")
        .filter(|id| positive_id(id))
    else {
        return false;
    };
    let Some(hostname) = query.strip_prefix("reason=No%20longer%20required&hostname=") else {
        return false;
    };
    delete_server(id.parse().unwrap_or(0), hostname).is_ok_and(|request| request.path == path)
}
pub(crate) fn order_cancelled(
    order: &OrderFact,
    confirmed: &[&str],
    unresolved_pay: bool,
    no_servers: bool,
    no_other_create: bool,
) -> bool {
    order.id > 0
        && order.status != "paid"
        && confirmed.contains(&order.status.as_str())
        && !unresolved_pay
        && no_servers
        && no_other_create
}
pub(crate) fn order_debit(t: &TransactionFact, order: u64) -> bool {
    t.id > 0 && t.order_id == order && t.amount_with_vat < 0 && t.description == "Order Payment"
}
pub(crate) fn charged_server_gone(
    order: &OrderFact,
    debit: Option<&TransactionFact>,
    server: &Terminated,
    hostname: &str,
) -> bool {
    order.id > 0
        && server.id > 0
        && server.hostname == hostname
        && debit.is_none_or(|t| order_debit(t, order.id))
        && (order.status == "paid" || debit.is_some_and(|t| order_debit(t, order.id)))
        && order.server_id.is_none_or(|id| id == server.id)
}
