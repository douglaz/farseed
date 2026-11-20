//! Durable procurement. Possibly-sent intents are never retried.
use super::*;
use crate::dispatch::{
    Access, ApprovedEntry, BillingInterval, ClassAnswer, MachineEntry, Period, RecurringCost, Unit,
};
use crate::poc::provisioning::{
    self as protocol, Api, BillingTerms, REFUSED, Selection, Vendor, VendorRequest, array, id,
    unique_ids,
};
#[cfg(test)]
use crate::poc::provisioning::{text, timestamp};
use crate::poc::targets::TargetRecord;

fn close_eligible(p: &Purchase, now: u64) -> bool {
    p.vm.is_some()
        && p.target.is_none()
        && p.payment
            .as_ref()
            .is_none_or(|pay| p.vendor.close_payment_eligible(pay, now))
}
const ENTERED_REFUSED: &str = "This page no longer starts purchases on a provider account you entered yourself. Your existing machines keep working here.";
const ENTERED_ISSUANCE_REFUSED: &str = "This page can't pay for this purchase, because it no longer issues invoices on a provider account you entered yourself. Leave it with Stop this purchase or Close purchase below. Your existing machines keep working here.";
const SECOND_INVOICE: &str = "The provider made a second invoice for this machine by mistake. It is not shown here; don't pay any invoice except the one on this page. It expires unpaid.";
const PAID_TWICE: &str =
    "The provider shows this machine paid twice. Contact the provider about the second payment.";

fn stopped_message(p: &Purchase, stage: StopStage, entered: bool) -> String {
    match stage {
        StopStage::BeforeMachine => {
            "Stopped: order abandoned; no machine adopted. Any late order will be ignored.".into()
        }
        StopStage::PaymentConflict => {
            let vm =
                p.vm.as_ref()
                    .map(|vm| &vm["id"])
                    .expect("stopped associated purchase");
            if entered {
                format!(
                    "Stopped: this purchase's payment couldn't be confirmed here. Machine {vm} is left as it is at the provider; manage it there."
                )
            } else {
                format!(
                    "Stopped: this purchase's payment couldn't be confirmed here. Machine {vm} is left as it is at the provider. This purchase will never use, invoice or pay for it; if it is unpaid, the provider deletes it within about an hour."
                )
            }
        }
    }
}
fn stop_prompt(p: &Purchase, stop: &Stopped, entered: bool) -> String {
    if stop.stage == StopStage::PaymentConflict {
        return stopped_message(p, stop.stage, entered)
            .trim_start_matches("Stopped: this purchase's payment couldn't be confirmed here. ")
            .into();
    }
    if stop.failing_ids.is_empty() {
        "No machine has appeared for this order. Stopping doesn't cancel anything at the provider: if an order arrived there, it stays unpaid and expires by itself within about an hour. This page will never use or invoice it. Nothing has been charged.".into()
    } else {
        let mut text = stop
            .failing_ids
            .iter()
            .map(|id| {
                format!(
                    "Machine {id} matches this order but can't be used here; it is left as it is."
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        text.push_str(" Stopping cancels nothing at the provider, and this purchase will never use or invoice any machine.");
        text
    }
}
fn closed_message(p: &Purchase, entered: bool) -> String {
    if p.vendor == Vendor::Vpsbg {
        return "VPSBG purchase closed. Earlier top-ups may still settle as VPSBG credit.".into();
    }
    if let Some(stop) = &p.stopped {
        return stopped_message(p, stop.stage, entered);
    }
    p.vendor.closed_message(
        p.vm.as_ref().expect("closed associated purchase"),
        p.payment.as_ref(),
    )
}
fn default_purchase_user() -> String {
    Vendor::Lnvps.default_user()
}

// Only EmailEntered carries personal data, in encrypted journal custody. This projection
// publishes booleans only; historical addresses remain held against every output boundary.
#[derive(Default)]
pub(super) struct EmailState {
    required: bool,
    expected: Option<Zeroizing<String>>,
}

fn valid_email(email: &str) -> bool {
    !email.is_empty()
        && email.len() <= 254
        && email.contains('@')
        && email.contains('.')
        && !email.chars().any(|c| c.is_control() || c.is_whitespace())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Purchase {
    #[serde(default, skip_serializing_if = "Vendor::is_lnvps")]
    pub vendor: Vendor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpsbg: Option<super::vpsbg::VpsbgPurchase>,
    pub origin: String,
    pub machine: String,
    pub identity: Identity,
    pub relay_identity: Identity,
    pub class_answer: ClassAnswer,
    pub account: String,
    pub relay: String,
    pub selected: Selection,
    #[serde(default = "default_purchase_user")]
    pub user: String,
    pub approved_at: u64,
    #[serde(default)]
    pub pending_selection: Option<Selection>,
    pub registration_sent: bool,
    pub ssh_key: Option<Value>,
    pub create: Option<Create>,
    pub vm: Option<Value>,
    pub invoice: Option<Invoice>,
    #[serde(default)]
    pub billing: Option<Billing>,
    pub payment: Option<Value>,
    pub paid_at: Option<u64>,
    pub publication: Option<Value>,
    pub target: Option<TargetRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate_orders: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<Stopped>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopStage {
    BeforeMachine,
    PaymentConflict,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stopped {
    pub checked_at: u64,
    pub stage: StopStage,
    pub read_status: u16,
    pub failing_ids: Vec<Value>,
    pub history: Vec<Value>,
}
#[derive(Default)]
pub(super) struct Recovery {
    candidates: Vec<Value>,
    stop: Option<Stopped>,
    payment_notice: Option<&'static str>,
}
struct Reconciliation {
    candidates: Vec<Value>,
    failing: Vec<u64>,
    ignored: Vec<u64>,
    status: u16,
    checked_at: u64,
}
// `expires` must be present and null. `deleting_on` may be absent: LNVPS added it to the VM status on 2026-07-15
// (e9e0427b), so an older deployment omits it; when present it must be null.
fn unpaid_machine(vm: &Value) -> bool {
    vm.get("expires").is_some_and(Value::is_null)
        && vm.get("deleting_on").is_none_or(Value::is_null)
}
fn failing_payments(p: &Purchase, history: &[Value]) -> Result<Vec<Value>, String> {
    let vm = p.vm.as_ref().ok_or(REFUSED)?;
    let billing = p.billing.as_ref().ok_or(REFUSED)?;
    let mut failing = Vec::new();
    for row in history {
        if !p
            .vendor
            .suitable_payment(row, id(vm)?, &billing.terms, p.vendor.created(vm)?)
        {
            failing.push(json!(p.vendor.payment_id(row)?.to_ascii_lowercase()));
        }
    }
    failing.sort_by_key(Value::to_string);
    Ok(failing)
}
fn initial_history(p: &Purchase, value: &Value) -> Result<Vec<Value>, String> {
    let rows = array(value)?;
    if rows.len() >= 100 {
        return Err("Payment history incomplete; Refresh without issuing another invoice.".into());
    }
    let mut ids = std::collections::BTreeSet::new();
    for row in rows {
        if !ids.insert(p.vendor.payment_id(row)?.to_ascii_lowercase()) {
            return Err(REFUSED.into());
        }
    }
    // Keep conflicting machine ids as evidence; suitability decides whether a row is usable.
    Ok(rows.clone())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PurchaseShape {
    #[serde(default, skip_serializing_if = "Vendor::is_lnvps")]
    pub vendor: Vendor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpsbg: Option<super::vpsbg::VpsbgPurchase>,
    pub origin: String,
    pub machine: String,
    pub identity: Identity,
    pub relay_identity: Identity,
    pub class_answer: ClassAnswer,
    pub account: String,
    pub relay: String,
    pub selected: Selection,
    #[serde(default = "default_purchase_user")]
    pub user: String,
    pub approved_at: u64,
    #[serde(default)]
    pub pending_selection: Option<Selection>,
    pub registration_sent: bool,
    pub ssh_key: Option<Value>,
    pub create: Option<Create>,
    pub vm: Option<Value>,
    pub invoice: Option<Invoice>,
    #[serde(default)]
    pub billing: Option<Billing>,
    pub payment: Option<Value>,
    pub paid_at: Option<u64>,
    pub publication: Option<Value>,
    pub target: Option<TargetRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate_orders: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<Stopped>,
}
impl<'de> Deserialize<'de> for Purchase {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let shape = PurchaseShape::deserialize(d)?;
        let p = Self {
            vendor: shape.vendor,
            vpsbg: shape.vpsbg,
            origin: shape.origin,
            machine: shape.machine,
            identity: shape.identity,
            relay_identity: shape.relay_identity,
            class_answer: shape.class_answer,
            account: shape.account,
            relay: shape.relay,
            selected: shape.selected,
            user: shape.user,
            approved_at: shape.approved_at,
            pending_selection: shape.pending_selection,
            registration_sent: shape.registration_sent,
            ssh_key: shape.ssh_key,
            create: shape.create,
            vm: shape.vm,
            invoice: shape.invoice,
            billing: shape.billing,
            payment: shape.payment,
            paid_at: shape.paid_at,
            publication: shape.publication,
            target: shape.target,
            duplicate_orders: shape.duplicate_orders,
            stopped: shape.stopped,
        };
        match (p.vendor, &p.vpsbg) {
            (Vendor::Lnvps, None) => (),
            (Vendor::Vpsbg, Some(extension)) => extension
                .validate(&p)
                .map_err(|_| serde::de::Error::custom("invalid VPSBG purchase"))?,
            _ => return Err(serde::de::Error::custom("inconsistent purchase vendor")),
        }
        Ok(p)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    pub before: Vec<Value>,
    pub started: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Billing {
    pub vm_id: u64,
    pub terms: BillingTerms,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invoice {
    pub before: Vec<String>,
    pub started: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Record {
    Approved(Box<Purchase>),
    TermsChanged(Selection),
    Reapproved {
        selected: Selection,
        approved_at: u64,
    },
    Closed {
        vm_id: u64,
        inventory_status: u16,
        detail_status: u16,
        history_status: u16,
        checked_at: u64,
    },
    RegistrationSent,
    Registered(Value),
    CreateSent(Create),
    EmailRequired,
    EmailEntered {
        email: String,
    },
    EmailVerified,
    CreateEmailRefused,
    Associated(Value),
    DuplicateOrders {
        vm_ids: Vec<u64>,
    },
    PurchaseStopped(Stopped),
    BillingQuoted(Billing),
    InvoiceSent(Invoice),
    Payment {
        payment: Value,
        paid_at: Option<u64>,
    },
    Observation(Value),
    Handoff {
        target: TargetRecord,
        publication: Value,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approval {
    pub origin: String,
    pub machine: String,
    pub relay: String,
    pub class_answer: ClassAnswer,
    pub approve_charge: bool,
    pub approve_maintained_access: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Choice {
    pub offer_id: u64,
    pub image_id: u64,
    pub resources: Option<Value>,
}

impl<S: Storage> Store<S> {
    pub(super) fn procurement_ready(&self) -> Result<(), String> {
        self.authority.ordinary()?;
        if self.inference.ended || self.failed.is_some() || self.allocation().seed_backup_owed() {
            return Err("Complete unlock and seed backup before procurement.".into());
        }
        Ok(())
    }
    pub(crate) fn procurement_account(&self, account: &str) -> Result<(), String> {
        self.procurement_ready()?;
        if self
            .procurement
            .as_ref()
            .is_some_and(|p| p.vendor == Vendor::Lnvps && p.account != account)
        {
            return Err("The recorded provider account does not match this purchase.".into());
        }
        Ok(())
    }
    pub(crate) fn procurement_vendor(&self) -> Vendor {
        self.procurement
            .as_ref()
            .filter(|p| {
                p.target.is_none() || (p.vendor == Vendor::Vpsbg && !self.vpsbg_is_ready(p))
            })
            .map_or(self.vendor_choice.unwrap_or(Vendor::Lnvps), |p| p.vendor)
    }
    pub(crate) fn procurement_origin(&self) -> &str {
        if self.procurement_vendor() == Vendor::Vpsbg {
            return protocol::vpsbg::ORIGIN;
        }
        self.procurement
            .as_ref()
            .filter(|p| p.target.is_none())
            .map_or(&self.provider_origin, |p| &p.origin)
    }
    pub(crate) async fn procurement_configure(
        &mut self,
        _account: &protocol::Account,
        _secret: &[u8],
        _origin: &str,
    ) -> Result<(), String> {
        Err(ENTERED_REFUSED.into())
    }
    fn check_api(&self, api: &impl Api) -> Result<(), String> {
        api.current()?;
        if let Some(context) = api.vpsbg_context() {
            self.vpsbg_context_current(context)?;
            if api.account() != context.account {
                return Err(REFUSED.into());
            }
            api.check_vendor(context.vendor)?;
            return self.procurement_ready();
        }
        api.check_vendor(self.procurement_vendor())?;
        if self.procurement_vendor() == Vendor::Vpsbg {
            self.procurement_ready()?;
            if self
                .vpsbg_token
                .as_ref()
                .is_none_or(|r| r.account != api.account())
            {
                return Err(REFUSED.into());
            }
            Ok(())
        } else {
            self.procurement_account(&api.account())
        }
    }
    async fn provider_response(
        &mut self,
        api: &mut impl Api,
        request: VendorRequest,
    ) -> Result<(u16, Value), protocol::ReadError> {
        self.check_api(api)?;
        let vendor = api
            .vpsbg_context()
            .map_or(self.procurement_vendor(), |c| c.vendor);
        let origin = api
            .vpsbg_context()
            .map_or(self.procurement_origin(), |c| c.origin.as_str());
        let url = vendor.request_url(origin, &request.path)?;
        self.check_api(api)?;
        let result = api.request(request.method, &url, request.body).await;
        self.check_api(api)?;
        let mut value = result?;
        if vendor == Vendor::Vpsbg {
            let raw = api.take_vpsbg_response().ok_or(REFUSED)?;
            value = vendor.reduce_response(
                request.method,
                &request.path,
                api.response_status(),
                &raw,
                |bytes| self.check_output_bytes(bytes),
                |value| self.vpsbg_value_safe(value),
            )?;
        }
        if !crate::poc::inference::safe(self, &value, &[]) {
            return Err(REFUSED.into());
        }
        Ok((api.response_status(), value))
    }
    pub(super) async fn provider_read(
        &mut self,
        api: &mut impl Api,
        request: VendorRequest,
    ) -> Result<Value, String> {
        let method = request.method;
        let path = request.path.clone();
        match self.provider_response(api, request).await {
            Ok((_, value)) => Ok(value),
            Err(protocol::ReadError::NotFound) => {
                let p = self.procurement.as_ref();
                if let Some(vm) = p.and_then(|p| p.vm.as_ref()).and_then(|vm| id(vm).ok()) {
                    let vendor = p.map_or(self.procurement_vendor(), |p| p.vendor);
                    let own = vendor.owns_read(&path, vm, p.and_then(|p| p.payment.as_ref()));
                    if method == "GET" && own {
                        return Err(vendor.missing_pause(vm));
                    }
                }
                Err(protocol::READ_REFUSED.into())
            }
            Err(error) => Err(error.message()),
        }
    }
    // Account replies are private: compare email in worker memory and discard every other
    // field. The ordinary provider_read boundary would reject our own held address.
    async fn private_account(
        &mut self,
        api: &mut impl Api,
        body: Option<Value>,
    ) -> Result<Value, String> {
        self.check_api(api)?;
        let request = self.procurement_vendor().account(body);
        let url = self
            .procurement_vendor()
            .request_url(self.procurement_origin(), &request.path)?;
        let method = request.method;
        let result = api.request(method, &url, request.body).await;
        self.check_api(api)?;
        // Never forward provider errors or account fields to any publication boundary.
        let account = result.map_err(|_| if method == "PATCH" {
            "The email update could not be confirmed. Open the link if it arrived, then Check again. Sending again requires your explicit request."
        } else {
            "Could not read the provider account. Check again; no new order was sent."
        })?;
        if !(200..300).contains(&api.response_status()) || !account.is_object() {
            return Err(
                "Could not read the provider account. Check again; no new order was sent.".into(),
            );
        }
        Ok(account)
    }
    pub(crate) fn procurement_email_eligible(&self) -> bool {
        self.procurement_email.required
            && self.procurement.as_ref().is_some_and(|p| {
                p.create.is_none() && p.vm.is_none() && p.pending_selection.is_none()
            })
    }
    async fn procurement_check_email(&mut self, api: &mut impl Api) -> Result<bool, String> {
        let account = match self.private_account(api, None).await {
            Ok(account) => account,
            // A saved address remains binding after EmailVerified and across interruptions.
            Err(error) if self.procurement_email.expected.is_some() => return Err(error),
            // An optional preflight cannot establish a provider requirement on failure.
            // A previously recorded gate still needs its matching verified account.
            Err(_) => return Ok(!self.procurement_email.required),
        };
        let fields = self.procurement_vendor().account_fields();
        let verified = account[fields.verified].as_bool();
        let matches = self
            .procurement_email
            .expected
            .as_ref()
            .is_none_or(|email| account[fields.email].as_str() == Some(email.as_str()));
        if verified == Some(true) && matches {
            if self.procurement_email.required {
                self.procurement_commit(Record::EmailVerified).await?;
            }
            return Ok(true);
        }
        if self.procurement_email.expected.is_some()
            && (verified.is_none() || account[fields.email].as_str().is_none())
        {
            return Err(
                "Could not read the provider account. Check again; no new order was sent.".into(),
            );
        }
        if self.procurement_email.expected.is_none() {
            if verified != Some(false) {
                return Ok(!self.procurement_email.required);
            }
            let channels = match self
                .provider_response(api, self.procurement_vendor().notification_channels())
                .await
            {
                Ok((status, channels)) if (200..300).contains(&status) => channels,
                _ => return Ok(!self.procurement_email.required),
            };
            match channels[fields.email].as_bool() {
                Some(false) => {
                    if self.procurement_email.required {
                        self.procurement_commit(Record::EmailVerified).await?;
                    }
                    return Ok(true);
                }
                Some(true) => (),
                None => return Ok(!self.procurement_email.required),
            }
        }
        if !self.procurement_email.required {
            self.procurement_commit(Record::EmailRequired).await?;
        }
        Ok(false)
    }
    pub(crate) async fn procurement_email_send(
        &mut self,
        api: &mut impl Api,
        entered: Option<String>,
    ) -> Result<(), String> {
        self.procurement_no_money()?;
        self.check_api(api)?;
        if !self.procurement_email_eligible() {
            return Err("Email entry is only available before the machine order.".into());
        }
        let email = entered
            .or_else(|| {
                self.procurement_email
                    .expected
                    .as_ref()
                    .map(|email| email.to_string())
            })
            .ok_or("Enter your email address first.")?;
        if !valid_email(&email) {
            return Err("Enter a valid email address.".into());
        }
        let account = self.private_account(api, None).await?;
        let fields = self.procurement_vendor().account_fields();
        let mut body = json!({(fields.email):email});
        // This provider requires the first two flags and overwrites the other two even
        // when omitted. Preserve all four; never copy billing or read-only account fields.
        for field in fields.contact_flags {
            body[field] = json!(account[field].as_bool().ok_or(
                "Provider notification settings are unavailable; the email update was not sent."
            )?);
        }
        self.procurement_commit(Record::EmailEntered { email })
            .await?;
        // A lost PATCH response cannot verify anything and is never automatically resent.
        self.private_account(api, Some(body)).await?;
        self.procurement_resume(api, false).await
    }
    /// Fresh absence evidence is usable only by this explicit action.
    pub(crate) async fn procurement_close(&mut self, api: &mut impl Api) -> Result<(), String> {
        if self.procurement_vendor() == Vendor::Vpsbg {
            if !self
                .procurement
                .as_ref()
                .and_then(|p| p.vpsbg.as_ref())
                .is_some_and(|v| self.vpsbg_close_allowed(&v.purchase))
            {
                return Err(protocol::vpsbg::READ_ONLY.into());
            }
            api.current()?;
            return self.vpsbg_close(api.now()).await;
        }
        self.procurement_no_money()?;
        self.check_api(api)?;
        let p = self
            .procurement
            .as_ref()
            .filter(|p| close_eligible(p, api.now()))
            .ok_or(self.procurement_vendor().close_refused())?;
        let vendor = p.vendor;
        let vm_id = id(p
            .vm
            .as_ref()
            .ok_or(self.procurement_vendor().close_refused())?)?;
        let (inventory_status, inventory) = self
            .provider_response(api, vendor.list())
            .await
            .map_err(protocol::ReadError::message)?;
        if !(200..300).contains(&inventory_status) || unique_ids(&inventory)?.contains(&vm_id) {
            return Err(REFUSED.into());
        }
        for vm in array(&inventory)? {
            vendor.validate_vm(vm)?;
        }
        for request in [vendor.get(vm_id), vendor.invoice_history(vm_id)] {
            match self.provider_response(api, request).await {
                Err(protocol::ReadError::NotFound) => (),
                _ => return Err(REFUSED.into()),
            }
        }
        self.check_api(api)?;
        let checked_at = api.now();
        if self
            .procurement
            .as_ref()
            .is_none_or(|p| !close_eligible(p, checked_at))
        {
            return Err(self.procurement_vendor().close_refused().into());
        }
        self.procurement_commit(Record::Closed {
            vm_id,
            inventory_status,
            detail_status: 404,
            history_status: 404,
            checked_at,
        })
        .await
    }
    // Only completed procurements may precede another purchase in this store.
    pub(super) fn procurement_can_start(&self) -> bool {
        self.procurement.as_ref().is_none_or(|p| {
            if p.vendor == Vendor::Vpsbg {
                self.vpsbg_is_ready(p)
            } else {
                p.target.is_some()
            }
        }) && self
            .completed_purchases
            .iter()
            .all(|p| p.vendor != Vendor::Vpsbg || self.vpsbg_is_ready(p))
            && self
                .dispatch
                .approved_entries
                .iter()
                .all(|(machine, entry)| {
                    if self.vpsbg_tombstoned_entry(machine, &entry.approved.identity) {
                        return true;
                    }
                    self.completed_purchases
                        .iter()
                        .chain(self.procurement.iter())
                        .any(|p| {
                            p.machine == *machine
                                && p.identity == entry.approved.identity
                                && p.target.as_ref() == self.poc_target(machine)
                                && p.target.is_some()
                                && (p.vendor != Vendor::Vpsbg || self.vpsbg_is_ready(p))
                        })
                })
            && self.poc_targets.keys().all(|machine| {
                self.dispatch.approved_entries.contains_key(machine)
                    || self.closed_purchases.iter().any(|p| {
                        p.vendor == Vendor::Vpsbg
                            && p.machine == *machine
                            && self.vpsbg_tombstoned_entry(machine, &p.identity)
                    })
            })
    }
    pub(crate) fn procurement_review_selection(&self) -> Option<&Selection> {
        if self.procurement_vendor() == Vendor::Vpsbg {
            return self.procurement_selection.as_ref().or_else(|| {
                self.procurement
                    .as_ref()
                    .filter(|p| !self.vpsbg_is_ready(p))
                    .and_then(|p| p.pending_selection.as_ref().or(Some(&p.selected)))
            });
        }
        match &self.procurement {
            Some(purchase) if purchase.target.is_none() => purchase.pending_selection.as_ref(),
            _ => self.procurement_selection.as_ref(),
        }
    }
    pub(crate) fn procurement_billing(&self) -> Option<&Billing> {
        self.procurement.as_ref().and_then(|p| p.billing.as_ref())
    }
    pub(crate) fn procurement_view(&self) -> Value {
        let mut view = self.procurement_current_view();
        // VPSBG closures are published below as their own cards, never with an LNVPS-shaped message.
        view["archive"] = json!(self.closed_purchases.iter().filter(|p| p.vendor != Vendor::Vpsbg).map(|p| json!({"machine":p.machine,"vm_id":p.vm.as_ref().map(|vm|p.vendor.raw_id(vm)),"message":closed_message(p, self.provider_account_entered())})).collect::<Vec<_>>());
        self.vpsbg_view(&mut view);
        let archived_vpsbg: Vec<_> = self.closed_purchases.iter().filter(|p| p.vendor == Vendor::Vpsbg).map(|p| {
            let mut card = json!({"machine":p.machine,"origin":p.origin,"vendor":p.vendor.describe(),"closed":true});
            self.vpsbg_machine_view(&mut card, p, crate::hostcert::now_unix().unwrap_or(u64::MAX));
            if let Some(reason) = p.vpsbg.as_ref().and_then(|v| self.vpsbg_purchases.get(&v.purchase)).and_then(|s| s.closure.as_ref()) {
                card["closure"] = json!(reason);
            }
            card
        }).collect();
        if !archived_vpsbg.is_empty() {
            // `closed` stays the string the page reads; the VPSBG card is published beside it.
            if view.get("closed").is_some()
                && self
                    .closed_purchases
                    .last()
                    .is_some_and(|p| p.vendor == Vendor::Vpsbg)
            {
                view["closed_card"] = archived_vpsbg.last().cloned().unwrap_or(Value::Null);
            }
            if let Some(archive) = view["archive"].as_array_mut() {
                archive.extend(archived_vpsbg);
            } else {
                view["archive"] = json!(archived_vpsbg);
            }
        }
        let handed_off = self.procurement.as_ref().filter(|p| {
            self.vpsbg_is_ready(p) || (p.target.is_some() && p.vendor != self.procurement_vendor())
        });
        if !self.completed_purchases.is_empty() || handed_off.is_some() {
            view["completed"] = self.completed_purchases.iter().chain(handed_off).map(|p| {
                let mut completed = json!({"machine":p.machine,"origin":p.origin,"vm_id":p.vm.as_ref().map(|vm|p.vendor.raw_id(vm)),"payment_id":p.payment.as_ref().map(|pay|p.vendor.raw_id(pay)),"is_paid":p.payment.as_ref().is_some_and(|pay|p.vendor.paid(pay)),"target_saved":p.target.is_some()});
                if p.vendor == Vendor::Vpsbg {
                    completed["vendor"] = p.vendor.describe();
                    self.vpsbg_machine_view(&mut completed, p, crate::hostcert::now_unix().unwrap_or(u64::MAX));
                }
                completed
            }).collect();
        }
        view
    }
    fn procurement_current_view(&self) -> Value {
        // A new vendor's draft must not inherit the previous purchase's facts.
        let Some(p) = self.procurement.as_ref().filter(|p| {
            !self.vpsbg_is_ready(p) && (p.target.is_none() || p.vendor == self.procurement_vendor())
        }) else {
            return json!({"origin":self.procurement_origin(),"selection":self.procurement_selection,"closed":self.closed_purchases.last().map(|p| closed_message(p, self.provider_account_entered()))});
        };
        let phase = if p.pending_selection.is_some() {
            "terms_changed"
        } else if p.target.is_some() && (p.vendor != Vendor::Vpsbg || self.vpsbg_is_ready(p)) {
            "handed_off"
        } else if p.payment.is_some() {
            "payment_readiness"
        } else if p.invoice.is_some() {
            "invoice_uncertain"
        } else if p.vm.is_some() {
            "initial_invoice"
        } else if p.create.is_some() {
            "create_uncertain"
        } else if self.procurement_email.required {
            "email_verification"
        } else if p.ssh_key.is_some() {
            "registered"
        } else if p.registration_sent {
            "registration_uncertain"
        } else {
            "approved"
        };
        let selection = if p.vendor == Vendor::Vpsbg {
            self.procurement_review_selection()
        } else if p.target.is_some() {
            self.procurement_selection.as_ref()
        } else {
            Some(p.pending_selection.as_ref().unwrap_or(&p.selected))
        };
        let mut view = json!({"origin":p.origin,"phase":phase,"machine":p.machine,"account":p.account,"selection":selection,"approved_selection":p.selected,"relay":p.relay,"class_answer":p.class_answer,"identity":p.identity,"ssh_key_id":p.ssh_key.as_ref().map(|k|p.vendor.raw_id(k)),"vm_id":p.vm.as_ref().map(|vm|p.vendor.raw_id(vm)),"billing":p.billing,"payment":p.payment,"paid_at":p.paid_at,"readiness_poll_seconds":protocol::readiness_poll_seconds(),"readiness_wait_seconds":protocol::readiness_wait_seconds(),"readiness_state":p.vm.as_ref().map(|vm|p.vendor.readiness_state(vm)),"auto_renewal_enabled":p.vm.as_ref().and_then(|vm|p.vendor.auto_renewal_enabled(vm)),"target":p.target,"publication":p.publication,"public_keys":self.poc_identity_public_keys(&p.machine,&p.identity).ok()});
        if phase == "email_verification" {
            view["email_entered"] = json!(self.procurement_email.expected.is_some());
        }
        view["duplicate_orders"] = json!(p.duplicate_orders);
        view["candidates"] = json!(self.procurement_recovery.candidates.iter().map(|vm| json!({"id":vm["id"],"created":vm["created"],"addresses":vm["ip_assignments"]})).collect::<Vec<_>>());
        view["stop"] = json!(self.procurement_recovery.stop.as_ref().map(|stop| json!({"stage":stop.stage,"checked_at":stop.checked_at,"read_status":stop.read_status,"failing_ids":stop.failing_ids,"message":stop_prompt(p, stop, self.provider_account_entered())})));
        view["payment_notice"] = json!(self.procurement_recovery.payment_notice);
        view["stop_after"] = json!(
            p.create
                .as_ref()
                .filter(|_| p.vm.is_none())
                .map(|c| c.started.saturating_add(300))
        );
        view
    }
    pub(crate) async fn procurement_catalogue(
        &mut self,
        api: &mut impl Api,
    ) -> Result<Value, String> {
        self.check_api(api)?;
        if self.procurement_vendor() == Vendor::Vpsbg {
            return self.vpsbg_read_catalogue(api).await;
        }
        let catalogue = self
            .provider_read(api, self.procurement_vendor().catalogue())
            .await?;
        self.procurement_vendor().catalogue_shape(&catalogue)?;
        let images = self
            .provider_read(api, self.procurement_vendor().images())
            .await?;
        let (catalogue, images) = self
            .procurement_vendor()
            .catalogue_public(catalogue, images)?;
        Ok(json!({"offers":catalogue,"images":images}))
    }
    pub(crate) async fn procurement_select(
        &mut self,
        api: &mut impl Api,
        choice: Choice,
    ) -> Result<(), String> {
        if self.procurement.as_ref().is_some_and(|p| {
            p.vendor == Vendor::Vpsbg
                && !self.vpsbg_is_ready(p)
                && p.vpsbg.as_ref().is_some_and(|v| {
                    self.vpsbg_purchases
                        .get(&v.purchase)
                        .is_some_and(|s| !s.creates.is_empty())
                })
        }) {
            return Err("The saved VPSBG plan cannot change after a possible create.".into());
        }
        // Invalidate the prior candidate even when the replacement fails validation.
        self.procurement_selection = None;
        self.check_api(api)?;
        if !self.procurement_can_start()
            && self.procurement.as_ref().is_none_or(|p| p.create.is_some())
        {
            return Err("Complete the saved purchase before reviewing another machine.".into());
        }
        let selected = self.procurement_fetch_selection(api, choice).await?;
        if self.procurement_vendor() == Vendor::Vpsbg {
            self.procurement_selection = Some(selected);
            return Ok(());
        }
        if self
            .procurement
            .as_ref()
            .is_some_and(|p| p.target.is_none())
        {
            self.procurement_commit(Record::TermsChanged(selected))
                .await
        } else {
            self.procurement_selection = Some(selected);
            Ok(())
        }
    }
    async fn procurement_fetch_selection(
        &mut self,
        api: &mut impl Api,
        choice: Choice,
    ) -> Result<Selection, String> {
        let catalogue = self.procurement_catalogue(api).await?;
        let (offer, image) = self.procurement_vendor().selection_inputs(
            &catalogue,
            choice.resources.as_ref(),
            choice.offer_id,
            choice.image_id,
        )?;
        let charge = if let Some(r) = &choice.resources {
            self.procurement_vendor()
                .validate_custom(&offer, &image, r)?;
            let price = self
                .provider_read(api, self.procurement_vendor().custom_price(r.clone()))
                .await?;
            self.procurement_vendor().parse_charge(&price)?
        } else {
            self.procurement_vendor().offer_charge(&offer)?
        };
        let selected = Selection {
            offer,
            image,
            resources: choice.resources,
            charge,
        };
        self.procurement_vendor().validate_selection(&selected)?;
        Ok(selected)
    }
    pub(crate) async fn procurement_approve(
        &mut self,
        api: &mut impl Api,
        approval: Approval,
    ) -> Result<(), String> {
        self.procurement_no_money()?;
        self.check_api(api)?;
        if approval.origin != self.procurement_origin() {
            return Err("The displayed provider origin is stale; review the current origin and selection again.".into());
        }
        // Refuse unsafe authority before selecting identities or recording approval.
        if !crate::poc::inference::safe(
            self,
            &serde_json::to_value(&approval).map_err(|_| "approval encoding")?,
            &[],
        ) {
            return Err("Purchase authority contains protected or unscannable material.".into());
        }
        if !approval.approve_charge || !approval.approve_maintained_access {
            return Err(
                "Explicit exact charge and maintained-access approvals are required.".into(),
            );
        }
        let existing = self.procurement.clone().filter(|p| p.target.is_none());
        if existing.is_none()
            && self.procurement_vendor().is_lnvps()
            && self.provider_account_entered()
        {
            return Err(ENTERED_REFUSED.into());
        }
        if let Some(p) = &existing {
            if p.create.is_some() || p.pending_selection.is_none() {
                return Err(
                    "Saved purchase terms cannot be changed after a possible create; Refresh only."
                        .into(),
                );
            }
            if approval.machine != p.machine
                || approval.relay != p.relay
                || approval.class_answer != p.class_answer
            {
                return Err(
                    "Renewed approval must retain the saved machine, relay and class.".into(),
                );
            }
        } else if !self.procurement_can_start() {
            return Err("Complete the saved purchase before approving another machine.".into());
        }
        if existing.is_none()
            && self
                .dispatch
                .approved_entries
                .contains_key(&approval.machine)
        {
            return Err("Choose a new machine name; earlier machine records are kept.".into());
        }
        let selected = existing
            .as_ref()
            .and_then(|p| p.pending_selection.clone())
            .or_else(|| self.procurement_selection.clone())
            .ok_or("Fetch and choose an offer before approval.")?;
        // Approval authorizes exactly the displayed terms, never a newly fetched change.
        let fresh = self
            .procurement_fetch_selection(
                api,
                Choice {
                    offer_id: id(&selected.offer)?,
                    image_id: id(&selected.image)?,
                    resources: selected.resources.clone(),
                },
            )
            .await?;
        if !self.procurement_vendor().same_terms(&fresh, &selected) {
            if existing.is_some() {
                self.procurement_commit(Record::TermsChanged(fresh)).await?;
            } else {
                self.procurement_selection = Some(fresh);
            }
            return Err("The offer or price changed; review and approve the new terms.".into());
        }
        if existing.is_some() {
            return self
                .procurement_commit(Record::Reapproved {
                    selected,
                    approved_at: api.now(),
                })
                .await;
        }
        let record = Purchase {
            vendor: self.procurement_vendor(),
            vpsbg: None,
            origin: self.procurement_origin().into(),
            machine: approval.machine,
            identity: self
                .allocation()
                .issue(Family::Machines)
                .map_err(|e| e.to_string())?,
            relay_identity: match super::poc_targets::eligible_pass(self.allocation()) {
                Some(i) => i.clone(),
                None => self
                    .allocation()
                    .issue(Family::Passes)
                    .map_err(|e| e.to_string())?,
            },
            class_answer: approval.class_answer,
            account: api.account(),
            relay: approval.relay,
            user: self
                .procurement_vendor()
                .image_user(&selected.image)?
                .into(),
            selected,
            approved_at: api.now(),
            pending_selection: None,
            registration_sent: false,
            ssh_key: None,
            create: None,
            vm: None,
            invoice: None,
            billing: None,
            payment: None,
            paid_at: None,
            publication: None,
            target: None,
            duplicate_orders: Vec::new(),
            stopped: None,
        };
        self.procurement_commit(Record::Approved(Box::new(record)))
            .await?;
        self.procurement_selection = None;
        self.vendor_choice = None;
        Ok(())
    }
    fn procurement_projection(&self, record: &Record) -> Result<Purchase, String> {
        let purchase = if let Record::Approved(p) = record {
            Some(p.as_ref())
        } else {
            self.procurement.as_ref()
        };
        if let Some(p) = purchase {
            match (p.vendor, &p.vpsbg) {
                (Vendor::Lnvps, None) => (),
                (Vendor::Vpsbg, Some(extension)) => {
                    extension.validate(p)?;
                    return Err(protocol::vpsbg::READ_ONLY.into());
                }
                _ => return Err(REFUSED.into()),
            }
        }
        if let Record::Approved(p) = record {
            if !self.procurement_can_start()
                || self.dispatch.approved_entries.contains_key(&p.machine)
                || self.poc_targets.contains_key(&p.machine)
                || self
                    .commands
                    .iter()
                    .any(|(_, entry)| entry.machine == p.machine)
                || self
                    .dispatch
                    .calls
                    .values()
                    .any(|call| call.intent.machine == p.machine)
                || self.exposure_ledger.iter().any(|exposure| {
                    exposure
                        .bound_set
                        .iter()
                        .any(|bound| bound.machine == p.machine)
                })
                || self.procurement.as_ref().is_some_and(|old| {
                    old.vendor == p.vendor && (old.origin != p.origin || old.account != p.account)
                })
                || self.completed_purchases.iter().any(|old| {
                    old.vendor == p.vendor && (old.origin != p.origin || old.account != p.account)
                })
            {
                return Err(REFUSED.into());
            }
            p.vendor.validate_selection(&p.selected)?;
            if p.user != p.vendor.image_user(&p.selected.image)? {
                return Err(REFUSED.into());
            }
            if protocol::provider_origin(&p.origin)? != p.origin {
                return Err(REFUSED.into());
            }
            if p.account.len() != 64
                || !p.account.bytes().all(|b| b.is_ascii_hexdigit())
                || !crate::poc::targets::valid_relay(&p.relay)
                || p.machine.is_empty()
                || p.machine.len() > 64
                || !p.machine.as_bytes()[0].is_ascii_alphanumeric()
                || !p
                    .machine
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                || p.pending_selection.is_some()
                || p.registration_sent
                || p.ssh_key.is_some()
                || p.create.is_some()
                || p.vm.is_some()
                || p.billing.is_some()
                || p.invoice.is_some()
                || p.paid_at.is_some()
                || p.payment.is_some()
                || p.target.is_some()
                || p.publication.is_some()
                || !p.duplicate_orders.is_empty()
                || p.stopped.is_some()
            {
                return Err(REFUSED.into());
            }
            if p.identity
                != self
                    .allocation()
                    .issue(Family::Machines)
                    .map_err(|e| e.to_string())?
            {
                return Err(REFUSED.into());
            }
            let relay = super::poc_targets::eligible_pass(self.allocation())
                .cloned()
                .map(Ok)
                .unwrap_or_else(|| {
                    self.allocation()
                        .issue(Family::Passes)
                        .map_err(|e| e.to_string())
                })?;
            if relay != p.relay_identity {
                return Err(REFUSED.into());
            }
            return Ok(*p.clone());
        }
        let mut p = self.procurement.clone().ok_or(REFUSED)?;
        if p.stopped.is_some() {
            return Err(REFUSED.into());
        }
        // Archived VM and payment identities remain consumed.
        for closed in self
            .closed_purchases
            .iter()
            .chain(&self.completed_purchases)
        {
            // Vendors never share an origin. Any account at this origin: ids are provider-unique.
            if closed.origin != p.origin {
                continue;
            }
            let reused = match record {
                Record::Associated(vm) => {
                    closed
                        .vm
                        .as_ref()
                        .is_some_and(|old| closed.vendor.same_vm_id(old, vm))
                        || id(vm).is_ok_and(|id| closed.duplicate_orders.contains(&id))
                }
                Record::Payment { payment, .. } => closed
                    .payment
                    .as_ref()
                    .and_then(|old| closed.vendor.payment_id(old).ok())
                    .zip(p.vendor.payment_id(payment).ok())
                    .is_some_and(|(old, new)| old.eq_ignore_ascii_case(new)),
                _ => false,
            };
            if reused {
                return Err(REFUSED.into());
            }
        }
        match record {
            Record::Approved(_) => unreachable!(),
            Record::EmailRequired | Record::EmailEntered { .. } | Record::EmailVerified => {
                if p.create.is_some() || p.vm.is_some() || p.target.is_some() {
                    return Err(REFUSED.into());
                }
                match record {
                    Record::EmailEntered { email } if !valid_email(email) => {
                        return Err("Enter a valid email address.".into());
                    }
                    Record::EmailVerified if !self.procurement_email.required => {
                        return Err(REFUSED.into());
                    }
                    _ => (),
                }
            }
            Record::CreateEmailRefused => {
                if p.create.is_none() || p.vm.is_some() || p.target.is_some() {
                    return Err(REFUSED.into());
                }
                // Only the exact decoded order-time refusal establishes no creation.
                p.create = None;
            }
            Record::Closed {
                vm_id,
                inventory_status,
                detail_status,
                history_status,
                checked_at,
            } => {
                if !close_eligible(&p, *checked_at)
                    || p.vm.as_ref().and_then(|vm| id(vm).ok()) != Some(*vm_id)
                    || !(200..300).contains(inventory_status)
                    || *detail_status != 404
                    || *history_status != 404
                {
                    return Err(REFUSED.into());
                }
            }
            Record::PurchaseStopped(stop) => {
                if p.target.is_some() || !(200..300).contains(&stop.read_status) {
                    return Err(REFUSED.into());
                }
                match stop.stage {
                    StopStage::BeforeMachine => {
                        if p.create
                            .as_ref()
                            .is_none_or(|c| stop.checked_at < c.started.saturating_add(300))
                            || p.vm.is_some()
                            || p.invoice.is_some()
                            || p.payment.is_some()
                            || !stop.history.is_empty()
                            || stop.failing_ids.len() > 128
                            || stop
                                .failing_ids
                                .iter()
                                .any(|v| id(&json!({"id":v})).is_err())
                        {
                            return Err(REFUSED.into());
                        }
                    }
                    StopStage::PaymentConflict => {
                        if p.payment.is_some()
                            || p.invoice
                                .as_ref()
                                .is_none_or(|i| stop.checked_at < i.started)
                        {
                            return Err(REFUSED.into());
                        }
                        let vm = p.vm.as_ref().ok_or(REFUSED)?;
                        id(vm)?;
                        let history = initial_history(&p, &json!(stop.history))?;
                        let failing = failing_payments(&p, &history)?;
                        if failing.is_empty() || failing != stop.failing_ids {
                            return Err(REFUSED.into());
                        }
                    }
                }
                if stop
                    .failing_ids
                    .iter()
                    .map(Value::to_string)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != stop.failing_ids.len()
                {
                    return Err(REFUSED.into());
                }
                p.stopped = Some(stop.clone());
            }
            Record::TermsChanged(selected) => {
                if p.create.is_some() || p.vm.is_some() || p.target.is_some() {
                    return Err(REFUSED.into());
                }
                p.vendor.validate_selection(selected)?;
                p.pending_selection = Some(selected.clone());
            }
            Record::Reapproved {
                selected,
                approved_at,
            } => {
                if p.create.is_some()
                    || p.vm.is_some()
                    || p.target.is_some()
                    || p.pending_selection.as_ref() != Some(selected)
                    || *approved_at < p.approved_at
                {
                    return Err(REFUSED.into());
                }
                p.vendor.validate_selection(selected)?;
                p.user = p.vendor.image_user(&selected.image)?.into();
                p.selected = selected.clone();
                p.approved_at = *approved_at;
                p.pending_selection = None;
            }
            Record::RegistrationSent => {
                if p.registration_sent {
                    return Err(REFUSED.into());
                }
                p.registration_sent = true;
            }
            Record::Registered(key) => {
                if !p.registration_sent || p.ssh_key.is_some() {
                    return Err(REFUSED.into());
                }
                p.vendor.validate_registered(key)?;
                p.ssh_key = Some(key.clone());
            }
            Record::CreateSent(intent) => {
                if p.pending_selection.is_some()
                    || self.procurement_email.required
                    || p.ssh_key.is_none()
                    || p.create.is_some()
                    || p.vm.is_some()
                    || intent.started < p.approved_at
                    || intent.before.len() > 128
                    || unique_ids(&json!(intent.before)).is_err()
                {
                    return Err(REFUSED.into());
                }
                for vm in &intent.before {
                    p.vendor.validate_vm(vm)?;
                }
                p.create = Some(intent.clone());
            }
            Record::Associated(vm) => {
                let intent = p.create.as_ref().ok_or(REFUSED)?;
                if p.vm.is_some()
                    || p.duplicate_orders
                        .iter()
                        .any(|duplicate| id(vm).is_ok_and(|associated| associated >= *duplicate))
                    || intent.before.iter().any(|old| p.vendor.same_vm_id(old, vm))
                    || !p.vendor.matches(
                        &p.selected,
                        vm,
                        id(p.ssh_key.as_ref().ok_or(REFUSED)?)?,
                        intent.started,
                    )
                {
                    return Err(REFUSED.into());
                }
                p.vm = Some(vm.clone());
            }
            Record::DuplicateOrders { vm_ids } => {
                let intent = p.create.as_ref().ok_or(REFUSED)?;
                if self.provider_account_entered()
                    || vm_ids.is_empty()
                    || vm_ids.len() > 7
                    || p.invoice.is_some()
                    || p.payment.is_some()
                    || p.target.is_some()
                    || vm_ids.windows(2).any(|ids| ids[0] >= ids[1])
                    || vm_ids.iter().any(|vm| {
                        *vm == 0
                            || intent.before.iter().any(|old| id(old).ok() == Some(*vm))
                            || p.vm
                                .as_ref()
                                .is_some_and(|own| id(own).is_ok_and(|own| *vm <= own))
                    })
                {
                    return Err(REFUSED.into());
                }
                p.duplicate_orders.extend(vm_ids);
                p.duplicate_orders.sort_unstable();
                p.duplicate_orders.dedup();
            }
            Record::BillingQuoted(billing) => {
                let vm = p.vm.as_ref().ok_or(REFUSED)?;
                if billing.vm_id != id(vm)? || p.invoice.is_some() || p.payment.is_some() {
                    return Err(REFUSED.into());
                }
                p.vendor.validate_billing(&billing.terms)?;
                p.billing = Some(billing.clone());
            }
            Record::InvoiceSent(intent) => {
                if p.billing
                    .as_ref()
                    .is_none_or(|b| p.vm.as_ref().is_none_or(|vm| id(vm).ok() != Some(b.vm_id)))
                    || p.vm.is_none()
                    || p.invoice.is_some()
                    || p.payment.is_some()
                    || !intent.before.is_empty()
                {
                    return Err(REFUSED.into());
                }
                p.invoice = Some(intent.clone());
            }
            Record::Payment { payment, paid_at } => {
                let vm = p.vm.as_ref().ok_or(REFUSED)?;
                if !p.vendor.suitable_payment(
                    payment,
                    id(vm)?,
                    &p.billing
                        .as_ref()
                        .filter(|b| id(vm).ok() == Some(b.vm_id))
                        .ok_or(REFUSED)?
                        .terms,
                    p.vendor.created(vm)?,
                ) || p
                    .payment
                    .as_ref()
                    .is_some_and(|old| p.vendor.payment_changed(old, payment))
                {
                    return Err(REFUSED.into());
                }
                if p.vendor.paid(payment) != paid_at.is_some()
                    || p.paid_at.is_some_and(|saved| Some(saved) != *paid_at)
                {
                    return Err(REFUSED.into());
                }
                p.paid_at = *paid_at;
                p.payment = Some(payment.clone());
            }
            Record::Observation(vm) => {
                let old = p.vm.as_ref().ok_or(REFUSED)?;
                if !p.vendor.same_vm_identity(old, vm)
                    || !p.vendor.matches(
                        &p.selected,
                        vm,
                        id(p.ssh_key.as_ref().ok_or(REFUSED)?)?,
                        p.create.as_ref().ok_or(REFUSED)?.started,
                    )
                {
                    return Err(REFUSED.into());
                }
                if let Some(target) = &p.target {
                    let (_, pin) = p.vendor.published_pin(vm)?;
                    if target.pin != pin || target.host != p.vendor.allocated_ipv4(vm)? {
                        return Err(
                            "Published identity conflicts with the immutable target.".into()
                        );
                    }
                }
                p.vm = Some(vm.clone());
            }
            Record::Handoff {
                target,
                publication,
            } => {
                let vm = p.vm.as_ref().ok_or(REFUSED)?;
                let (key, pin) = p.vendor.published_pin(vm)?;
                let expected = TargetRecord {
                    machine: p.machine.clone(),
                    relay: p.relay.clone(),
                    profile: "v1".into(),
                    host: p.vendor.allocated_ipv4(vm)?,
                    port: 22,
                    user: p.user.clone(),
                    elevation: crate::jobs::Elevation::SudoNoninteractive,
                    pin,
                };
                if p.target.is_some()
                    || p.payment.as_ref().is_none_or(|pay| !p.vendor.paid(pay))
                    || p.vendor.readiness_state(vm) != "running"
                    || target != &expected
                    || publication
                        != &p
                            .vendor
                            .publication(&p.origin, p.vendor.raw_id(vm), vm, key)
                {
                    return Err(REFUSED.into());
                }
                target.validate()?;
                p.target = Some(target.clone());
                p.publication = Some(publication.clone());
            }
        }
        Ok(p)
    }
    fn apply_procurement(
        &mut self,
        number: u64,
        record: &Record,
        p: Purchase,
    ) -> Result<(), String> {
        if matches!(record, Record::Closed { .. } | Record::PurchaseStopped(_)) {
            self.procurement_recovery = Default::default();
            self.procurement_email = Default::default();
            self.dispatch.approved_entries.remove(&p.machine);
            self.dispatch.associations.retain(|a| a.entry != p.machine);
            self.dispatch.current_installations.remove(&p.machine);
            self.dispatch.setup_approval = None;
            self.dispatch.purchase_approvals.remove(&p.machine);
            self.provider_origin = p.origin.clone();
            self.procurement = None;
            self.procurement_selection = None;
            self.closed_purchases.push(p);
            return Ok(());
        }
        match record {
            Record::Approved(_) => {
                self.procurement_email = Default::default();
                self.procurement_recovery = Default::default();
            }
            Record::EmailRequired | Record::CreateEmailRefused => {
                self.procurement_email.required = true;
            }
            Record::EmailEntered { email } => {
                self.procurement_email.required = true;
                self.procurement_email.expected = Some(Zeroizing::new(email.clone()));
                if !self.provider_emails.iter().any(|old| old.as_str() == email) {
                    self.provider_emails.push(Zeroizing::new(email.clone()));
                }
            }
            Record::EmailVerified => self.procurement_email.required = false,
            _ => (),
        }
        if matches!(record, Record::Approved(_) | Record::Reapproved { .. }) {
            let charge = &p.selected.charge;
            let approved = ApprovedEntry {
                entry: MachineEntry {
                    machine: p.machine.clone(),
                    vendor: p.vendor.name().into(),
                    product: p.vendor.product(&p.selected)?.into(),
                    region: p.vendor.region(&p.selected)?.into(),
                    cost: RecurringCost {
                        amount: charge.amount,
                        unit: match charge.currency.as_str() {
                            "BTC" => Unit::Millisat,
                            "EUR" => Unit::EurCent,
                            _ => Unit::UsdCent,
                        },
                        period: Period::Billing {
                            count: charge.interval_amount,
                            interval: match charge.interval_type.as_str() {
                                "day" => BillingInterval::Day,
                                "month" => BillingInterval::Month,
                                _ => BillingInterval::Year,
                            },
                        },
                    },
                },
                identity: p.identity.clone(),
                access: Some(Access::ad_hoc()),
            };
            let mut dispatch = self.measured_dispatch_copy();
            let mut allocation = self.allocation().clone();
            if matches!(record, Record::Approved(_)) {
                dispatch.apply_poc_purchase(&mut allocation, approved, p.class_answer)?;
            } else {
                let old = dispatch
                    .approved_entries
                    .get_mut(&p.machine)
                    .ok_or(REFUSED)?;
                if old.approved.identity != p.identity
                    || old.answer != Some(p.class_answer)
                    || old.approved.access != approved.access
                {
                    return Err(REFUSED.into());
                }
                old.approved = approved;
            }
            if let Some(pass) = super::poc_targets::eligible_pass(&allocation) {
                if pass != &p.relay_identity {
                    return Err(REFUSED.into());
                }
            } else {
                allocation
                    .apply(&allocation::Event::Reserve(p.relay_identity.clone()))
                    .map_err(|e| e.to_string())?;
            }
            dispatch.setup_approval = Some(number);
            dispatch
                .purchase_approvals
                .insert(p.machine.clone(), number);
            self.dispatch = dispatch;
            self.allocation = Some(allocation);
        }
        if matches!(record, Record::Approved(_))
            && let Some(previous) = self.procurement.take()
        {
            self.completed_purchases.push(previous);
        }
        self.procurement = Some(p.clone());
        if let Record::Handoff { target, .. } = record {
            let record = Self::purchase_target_record(
                target.clone(),
                p.identity,
                p.relay_identity,
                p.class_answer,
            );
            self.replay_poc_target(number, &record)?;
        }
        Ok(())
    }
    pub(super) fn replay_procurement(
        &mut self,
        number: u64,
        record: &Record,
    ) -> Result<(), String> {
        let next = self.procurement_projection(record)?;
        self.apply_procurement(number, record, next)
    }
    async fn procurement_commit(&mut self, record: Record) -> Result<(), String> {
        self.procurement_ready()?;
        let next = self.procurement_projection(&record)?;
        let number = self.commit(&Event::Procurement(record.clone())).await?;
        self.apply_procurement(number, &record, next)
    }
    async fn history(&mut self, api: &mut impl Api, vm: u64) -> Result<Vec<Value>, String> {
        let vendor = self.procurement.as_ref().ok_or(REFUSED)?.vendor;
        let result = self.provider_read(api, vendor.invoice_history(vm)).await?;
        vendor.parse_history(&result, vm)
    }
    async fn reconcile_create(&mut self, api: &mut impl Api) -> Result<Reconciliation, String> {
        self.procurement_recovery = Default::default();
        let p = self.procurement.clone().ok_or(REFUSED)?;
        let intent = p.create.as_ref().ok_or(REFUSED)?;
        let key = id(p.ssh_key.as_ref().ok_or(REFUSED)?)?;
        let checked_at = api.now();
        let (status, inventory) = self
            .provider_response(api, p.vendor.list())
            .await
            .map_err(protocol::ReadError::message)?;
        if !(200..300).contains(&status) {
            return Err(REFUSED.into());
        }
        // Other keys and the before-list never consume the detail/history budget.
        let rows: Vec<_> = inventory
            .as_array()
            .ok_or(REFUSED)?
            .iter()
            .filter(|vm| {
                vm["ssh_key"]["id"].as_u64() == Some(key)
                    && !intent.before.iter().any(|old| p.vendor.same_vm_id(old, vm))
            })
            .collect();
        let ids = unique_ids(&json!(rows))?;
        let mut result = Reconciliation {
            candidates: Vec::new(),
            failing: Vec::new(),
            ignored: Vec::new(),
            status,
            checked_at,
        };
        if rows.len() > 8 {
            result.failing = ids;
            return Ok(result);
        }
        for vm in rows {
            let vm_id = id(vm)?;
            if p.duplicate_orders.contains(&vm_id) {
                result.ignored.push(vm_id);
                continue;
            }
            if !p.vendor.matches(&p.selected, vm, key, intent.started) || !unpaid_machine(vm) {
                result.failing.push(vm_id);
                continue;
            }
            let detail = self.provider_read(api, p.vendor.get(vm_id)).await;
            let usable = if let Ok(detail) = detail {
                if p.vendor.matches(&p.selected, &detail, key, intent.started)
                    && p.vendor.same_vm_identity(vm, &detail)
                    && unpaid_machine(&detail)
                    && self
                        .history(api, vm_id)
                        .await
                        .is_ok_and(|history| history.is_empty())
                {
                    result.candidates.push(detail);
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if !usable {
                result.failing.push(vm_id);
            }
        }
        self.check_api(api)?;
        result
            .candidates
            .sort_by_key(|vm| id(vm).expect("validated candidate"));
        result.failing.sort_unstable();
        Ok(result)
    }
    fn offer_create_stop(&mut self, result: &Reconciliation) {
        let Some(p) = &self.procurement else {
            return;
        };
        if p.vm.is_none()
            && p.invoice.is_none()
            && p.target.is_none()
            && p.create
                .as_ref()
                .is_some_and(|c| result.checked_at >= c.started.saturating_add(300))
            && (result.candidates.is_empty() || !result.failing.is_empty())
        {
            self.procurement_recovery.stop = Some(Stopped {
                checked_at: result.checked_at,
                stage: StopStage::BeforeMachine,
                read_status: result.status,
                failing_ids: result
                    .failing
                    .iter()
                    .chain(&result.ignored)
                    .map(|id| json!(id))
                    .collect(),
                history: Vec::new(),
            });
        }
    }
    async fn associate_create(
        &mut self,
        api: &mut impl Api,
        choice: Option<u64>,
    ) -> Result<(), String> {
        let mut result = self.reconcile_create(api).await?;
        self.offer_create_stop(&result);
        if !result.failing.is_empty() {
            return Err("Create evidence incomplete or conflicting; no order is retried.".into());
        }
        if result.candidates.is_empty() {
            return Err(
                "Create outcome unknown: no evidenced machine. Refresh later; no order is retried."
                    .into(),
            );
        }
        let vm = if self.provider_account_entered() {
            let Some(choice) = choice else {
                self.procurement_recovery.candidates = result.candidates;
                return Err("The provider holds machines that match this order. Confirm the one this purchase uses; the others are left as they are and never invoiced here.".into());
            };
            let index = result
                .candidates
                .iter()
                .position(|vm| id(vm).ok() == Some(choice))
                .ok_or(REFUSED)?;
            result.candidates.remove(index)
        } else {
            if choice.is_some() {
                return Err(REFUSED.into());
            }
            let vm = result.candidates.remove(0);
            let vm_ids: Vec<_> = result.candidates.iter().map(id).collect::<Result<_, _>>()?;
            if !vm_ids.is_empty() {
                self.procurement_commit(Record::DuplicateOrders { vm_ids })
                    .await?;
            }
            vm
        };
        self.procurement_commit(Record::Associated(vm)).await?;
        self.procurement_recovery = Default::default();
        Ok(())
    }
    pub(crate) async fn procurement_choose(
        &mut self,
        api: &mut impl Api,
        vm_id: u64,
    ) -> Result<(), String> {
        self.check_api(api)?;
        if !self.provider_account_entered()
            || self.procurement.as_ref().is_none_or(|p| p.vm.is_some())
        {
            return Err(REFUSED.into());
        }
        self.associate_create(api, Some(vm_id)).await
    }
    pub(crate) async fn procurement_stop(
        &mut self,
        api: &mut impl Api,
        stage: StopStage,
    ) -> Result<(), String> {
        self.check_api(api)?;
        self.procurement_recovery.stop = None;
        match stage {
            StopStage::BeforeMachine => {
                let p = self.procurement.as_ref().ok_or(REFUSED)?;
                if p.vm.is_some()
                    || p.invoice.is_some()
                    || p.target.is_some()
                    || p.create
                        .as_ref()
                        .is_none_or(|c| api.now() < c.started.saturating_add(300))
                {
                    return Err(REFUSED.into());
                }
                let result = self.reconcile_create(api).await?;
                self.offer_create_stop(&result);
            }
            StopStage::PaymentConflict => {
                let p = self.procurement.as_ref().ok_or(REFUSED)?;
                if p.invoice.is_none() || p.payment.is_some() || p.target.is_some() {
                    return Err(REFUSED.into());
                }
                let vm = id(p.vm.as_ref().ok_or(REFUSED)?)?;
                let checked_at = api.now();
                let (status, value) = self
                    .provider_response(api, self.procurement_vendor().invoice_history(vm))
                    .await
                    .map_err(protocol::ReadError::message)?;
                let history = initial_history(self.procurement.as_ref().ok_or(REFUSED)?, &value)?;
                self.offer_payment_stop(history, status, checked_at)?;
            }
        }
        self.check_api(api)?;
        let stop = self.procurement_recovery.stop.clone().ok_or(REFUSED)?;
        self.procurement_commit(Record::PurchaseStopped(stop)).await
    }
    fn offer_payment_stop(
        &mut self,
        history: Vec<Value>,
        read_status: u16,
        checked_at: u64,
    ) -> Result<(), String> {
        let p = self.procurement.as_ref().ok_or(REFUSED)?;
        let failing_ids = failing_payments(p, &history)?;
        if (200..300).contains(&read_status)
            && p.invoice.is_some()
            && p.payment.is_none()
            && !failing_ids.is_empty()
        {
            self.procurement_recovery.stop = Some(Stopped {
                checked_at,
                stage: StopStage::PaymentConflict,
                read_status,
                failing_ids,
                history,
            });
        }
        Ok(())
    }
    async fn initial_billing_quote(&mut self, api: &mut impl Api) -> Result<Billing, String> {
        let p = self.procurement.clone().ok_or(REFUSED)?;
        let vm_id = id(p.vm.as_ref().ok_or(REFUSED)?)?;
        // The quote is for this same approved machine, not an unverified current configuration.
        let vm = self.provider_read(api, p.vendor.get(vm_id)).await?;
        self.procurement_commit(Record::Observation(vm)).await?;
        let value = self
            .provider_read(api, p.vendor.invoice_quote(vm_id))
            .await?;
        Ok(Billing {
            vm_id,
            terms: p.vendor.parse_billing(&value)?,
        })
    }
    async fn associate_payment(&mut self, api: &mut impl Api, issue: bool) -> Result<(), String> {
        let p = self.procurement.clone().ok_or(REFUSED)?;
        let vm = p.vm.as_ref().ok_or(REFUSED)?;
        let vm_id = id(vm)?;
        self.procurement_recovery.stop = None;
        let checked_at = api.now();
        let value = self
            .provider_read(api, p.vendor.invoice_history(vm_id))
            .await?;
        let history = initial_history(&p, &value)?;
        let history_status = api.response_status();
        if !(200..300).contains(&history_status) {
            return Err(REFUSED.into());
        }
        if !history.is_empty() {
            if p.invoice.is_none() && history.len() != 1 {
                return Err(
                    "Initial payment evidence conflicts or is ambiguous; no invoice issued.".into(),
                );
            }
            if p.billing.is_none() {
                let billing = self.initial_billing_quote(api).await?;
                self.procurement_commit(Record::BillingQuoted(billing))
                    .await?;
            }
            let saved = self.procurement.as_ref().ok_or(REFUSED)?;
            if !failing_payments(saved, &history)?.is_empty() {
                self.offer_payment_stop(history, history_status, checked_at)?;
                return Err("Initial payment evidence conflicts or cannot be established from the saved one-period quote; no invoice issued.".into());
            }
            let paid = history.iter().filter(|row| p.vendor.paid(row)).count();
            let mut ranked = Vec::new();
            for row in &history {
                if paid == 0 || p.vendor.paid(row) {
                    let made = protocol::text(row, "created", 40)?;
                    let fraction = made
                        .split_once('.')
                        .map_or("", |(_, fraction)| fraction.trim_end_matches('Z'));
                    ranked.push((
                        (
                            p.vendor.created(row)?,
                            format!("{fraction:0<9}"),
                            p.vendor.payment_id(row)?.to_ascii_lowercase(),
                        ),
                        row,
                    ));
                }
            }
            ranked.sort_by(|left, right| left.0.cmp(&right.0));
            let payment = ranked.first().ok_or(REFUSED)?.1.clone();
            self.procurement_commit(self.payment_record(payment, api.now()))
                .await?;
            self.procurement_recovery.payment_notice = if paid >= 2 {
                Some(PAID_TWICE)
            } else if history.len() >= 2 {
                Some(SECOND_INVOICE)
            } else {
                None
            };
            return Ok(());
        }
        if p.invoice.is_some() {
            return Err("Initial invoice outcome unknown; Refresh payment history later. It will never be reissued.".into());
        }
        if p.vendor.is_lnvps() && self.provider_account_entered() {
            return Err(ENTERED_ISSUANCE_REFUSED.into());
        }
        let fresh = self.initial_billing_quote(api).await?;
        if p.billing.as_ref() != Some(&fresh) {
            self.procurement_commit(Record::BillingQuoted(fresh))
                .await?;
            return Err("Review the current initial Lightning quote and explicitly approve issuance for the first approved billing period.".into());
        }
        if !issue {
            return Err("Approve issuance of the initial Lightning invoice for the first approved billing period.".into());
        }
        let current = self
            .procurement
            .as_ref()
            .and_then(|p| p.vm.as_ref())
            .ok_or(REFUSED)?;
        if p.vendor.has_billing_evidence(current) {
            return Err("Existing billing evidence prevents initial invoice issuance.".into());
        }
        self.procurement_commit(Record::InvoiceSent(Invoice {
            before: Vec::new(),
            started: api.now(),
        }))
        .await?;
        let payment = self.provider_read(api, p.vendor.invoice(vm_id)).await?;
        self.procurement_commit(self.payment_record(payment, api.now()))
            .await
    }
    /// Explicit bounded progress. Refresh never sends a create or invoice whose intent exists.
    /// Automatic observation can only read the saved payment, never issue an invoice.
    pub(crate) async fn procurement_payment_check(
        &mut self,
        api: &mut impl Api,
    ) -> Result<(), String> {
        self.procurement_no_money()?;
        self.check_api(api)?;
        let purchase = self.procurement.as_ref().ok_or(REFUSED)?;
        if purchase.target.is_some() {
            return Ok(());
        }
        let payment = purchase
            .payment
            .as_ref()
            .ok_or("No saved machine invoice to check.")?;
        if purchase.vendor.paid(payment) {
            return Ok(());
        }
        let request = purchase
            .vendor
            .payment(purchase.vendor.payment_id(payment)?);
        let updated = self.provider_read(api, request).await?;
        self.procurement_commit(self.payment_record(updated, api.now()))
            .await
    }

    pub(crate) async fn procurement_resume(
        &mut self,
        api: &mut impl Api,
        issue_invoice: bool,
    ) -> Result<(), String> {
        self.procurement_no_money()?;
        self.check_api(api)?;
        let mut p = self
            .procurement
            .clone()
            .ok_or("Approve a fetched selection first.")?;
        if p.target.is_some() {
            return Ok(());
        }
        if p.pending_selection.is_some() {
            return Err(
                "The offer or price changed; review and approve the new terms before creating."
                    .into(),
            );
        }
        if p.create.is_none() && p.vm.is_none() && !self.procurement_check_email(api).await? {
            return Ok(());
        }
        if p.paid_at.is_some() {
            self.readiness_current(api, &p)?;
        }
        if p.registration_sent && p.ssh_key.is_none() {
            self.provider_read(api, p.vendor.keys()).await?;
            return Err("SSH registration outcome unknown. The provider list has no public-key material to prove a match; no insertion or order is retried.".into());
        }
        if p.ssh_key.is_none() {
            let public = self.poc_identity_public_keys(&p.machine, &p.identity)?;
            self.procurement_commit(Record::RegistrationSent).await?;
            let key = self
                .provider_read(api, p.vendor.register_key(&public, p.identity.index))
                .await?;
            self.procurement_commit(Record::Registered(key)).await?;
            p = self.procurement.clone().ok_or(REFUSED)?;
        }
        if p.vm.is_none() {
            if p.create.is_none() {
                let fresh = self
                    .procurement_fetch_selection(
                        api,
                        Choice {
                            offer_id: id(&p.selected.offer)?,
                            image_id: id(&p.selected.image)?,
                            resources: p.selected.resources.clone(),
                        },
                    )
                    .await?;
                if !p.vendor.same_terms(&fresh, &p.selected) {
                    self.procurement_commit(Record::TermsChanged(fresh)).await?;
                    return Err("The offer or price changed; review and approve the new terms before creating.".into());
                }
                let before = self.provider_read(api, p.vendor.list()).await?;
                unique_ids(&before)?;
                for vm in array(&before)? {
                    p.vendor.validate_vm(vm)?;
                }
                let before = array(&before)?.clone();
                let started = api.now();
                self.procurement_commit(Record::CreateSent(Create { before, started }))
                    .await?;
                #[cfg(all(feature = "tracer", target_arch = "wasm32"))]
                crate::testonly::session_point("procurement_create_intent").await;
                self.check_api(api)?;
                let request = p
                    .vendor
                    .create(&p.selected, id(p.ssh_key.as_ref().ok_or(REFUSED)?)?);
                match self.provider_read(api, request).await {
                    Err(why) if why == protocol::EMAIL_REQUIRED => {
                        self.procurement_commit(Record::CreateEmailRefused).await?;
                        return Ok(());
                    }
                    result => {
                        result?;
                    }
                }
            }
            self.associate_create(api, None).await?;
            #[cfg(all(feature = "tracer", target_arch = "wasm32"))]
            crate::testonly::session_point("procurement_associated").await;
            p = self.procurement.clone().ok_or(REFUSED)?;
        }
        if p.payment.is_none() {
            self.associate_payment(api, issue_invoice).await?;
            p = self.procurement.clone().ok_or(REFUSED)?;
        }
        let payment = p.payment.as_ref().ok_or(REFUSED)?;
        let updated = self
            .provider_read(api, p.vendor.payment(p.vendor.payment_id(payment)?))
            .await?;
        self.procurement_commit(self.payment_record(updated.clone(), api.now()))
            .await?;
        if !p.vendor.paid(&updated) {
            if p.vendor.payment_expires(&updated)? <= api.now() {
                return Err("Initial invoice expired; this purchase remains paused with the same VM/payment. Reissue is unsupported.".into());
            }
            return Err(
                "Waiting for external payment of the displayed initial invoice; Refresh later."
                    .into(),
            );
        }
        self.procurement_readiness(api, false).await
    }

    fn payment_record(&self, payment: Value, now: u64) -> Record {
        let paid_at = self
            .procurement
            .as_ref()
            .is_some_and(|p| p.vendor.paid(&payment))
            .then(|| {
                self.procurement
                    .as_ref()
                    .and_then(|p| p.paid_at)
                    .unwrap_or(now)
            });
        Record::Payment { payment, paid_at }
    }

    pub(crate) fn procurement_readiness_eligible(&self) -> bool {
        self.procurement.as_ref().is_some_and(|p| {
            p.payment.as_ref().is_some_and(|pay| p.vendor.paid(pay))
                && p.paid_at.is_some()
                && p.target.is_none()
                && p.pending_selection.is_none()
        })
    }

    fn readiness_current(&self, api: &impl Api, purchase: &Purchase) -> Result<(), String> {
        self.check_api(api)?;
        if !self.procurement_readiness_eligible()
            || self
                .procurement
                .as_ref()
                .is_none_or(|p| p.identity != purchase.identity)
        {
            return Err(REFUSED.into());
        }
        if api.now()
            >= purchase
                .paid_at
                .ok_or(REFUSED)?
                .saturating_add(protocol::readiness_wait_seconds())
        {
            return Err(protocol::READINESS_STOP.into());
        }
        Ok(())
    }

    /// Automatic observation has no route to registration, ordering, billing or payment reads.
    pub(crate) async fn procurement_readiness_check(
        &mut self,
        api: &mut impl Api,
    ) -> Result<(), String> {
        if !self.procurement_readiness_eligible() {
            return Ok(());
        }
        self.procurement_readiness(api, true).await
    }

    async fn procurement_readiness(
        &mut self,
        api: &mut impl Api,
        automatic: bool,
    ) -> Result<(), String> {
        let p = self.procurement.clone().ok_or(REFUSED)?;
        self.readiness_current(api, &p)?;
        let vm_id = id(p.vm.as_ref().ok_or(REFUSED)?)?;
        let fresh = self.provider_read(api, p.vendor.get(vm_id)).await?;
        self.readiness_current(api, &p)?;
        let observation = Record::Observation(fresh.clone());
        // Validate the complete fresh response before considering suppression.
        self.procurement_projection(&observation)?;
        if !automatic
            || !p
                .vendor
                .same_readiness(p.vm.as_ref().ok_or(REFUSED)?, &fresh)?
        {
            self.procurement_commit(observation).await?;
            self.readiness_current(api, &p)?;
        }
        #[cfg(all(feature = "tracer", target_arch = "wasm32"))]
        crate::testonly::session_point("procurement_readiness_observed").await;
        self.readiness_current(api, &p)?;
        // Publication must agree exactly with the recorded VM, even after a reordered key set.
        let saved = self.procurement.clone().ok_or(REFUSED)?;
        let vm = saved.vm.as_ref().ok_or(REFUSED)?;
        if p.vendor.readiness_state(vm) != "running" {
            return Err(p.vendor.boot_wait().into());
        }
        let (key, pin) = p.vendor.published_pin(vm)?;
        let target = TargetRecord {
            machine: p.machine.clone(),
            relay: p.relay.clone(),
            profile: "v1".into(),
            host: p.vendor.allocated_ipv4(vm)?,
            port: 22,
            user: p.user.clone(),
            elevation: crate::jobs::Elevation::SudoNoninteractive,
            pin,
        };
        self.readiness_current(api, &p)?;
        self.procurement_commit(Record::Handoff {
            target,
            publication: p.vendor.publication(&p.origin, &json!(vm_id), vm, key),
        })
        .await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
