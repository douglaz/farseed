//! Separate VPSBG custody and volatile reads; no money transition is enabled in b2a.
use super::*;
use crate::poc::provisioning::{self as protocol, Vendor, vpsbg as wire};

#[cfg(test)]
mod tests;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenRecord {
    pub account: String,
    pub generation: u64,
    pub token: crate::poc::credit::SecretText,
}
impl std::fmt::Debug for TokenRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VpsbgTokenEntered(<redacted>)")
    }
}
impl TokenRecord {
    pub(crate) fn validate(&self) -> Result<(), String> {
        wire::token_text(self.token.0.as_bytes())?;
        if self.generation != 1
            || self.account.len() != 64
            || !self
                .account
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(protocol::REFUSED.into());
        }
        Ok(())
    }
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn copy(&self) -> Self {
        Self {
            account: self.account.clone(),
            generation: self.generation,
            token: crate::poc::credit::SecretText(Zeroizing::new(self.token.0.to_string())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachinePassBinding {
    pub purchase: String,
    pub machine: String,
    pub machine_identity: Identity,
    pub pass_identity: Identity,
}
/// Typed extension reserves the one-way format boundary. Approval is disabled in this slice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpsbgPurchase {
    pub purchase: String,
    pub name: String,
    pub binding: MachinePassBinding,
    pub payment_plan: wire::PaymentPlan,
    pub approved_card: bool,
    pub approval_revision: u64,
}
impl VpsbgPurchase {
    pub(crate) fn validate(&self, p: &provisioning::Purchase) -> Result<(), String> {
        if p.vendor != Vendor::Vpsbg
            || p.origin != wire::ORIGIN
            || self.purchase.len() != 32
            || !self
                .purchase
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.name != format!("tau-web-{}", self.purchase)
            || self.binding.purchase != self.purchase
            || self.binding.machine != p.machine
            || self.binding.machine_identity != p.identity
            || self.binding.pass_identity != p.relay_identity
            || p.identity.family != Family::Machines
            || p.relay_identity.family != Family::Passes
            || p.identity.seed != p.relay_identity.seed
            || p.identity.derivation_version != p.relay_identity.derivation_version
            || self.payment_plan.price != p.selected.charge.amount
            || self.payment_plan.first_period != self.payment_plan.price
            || self.payment_plan.top_up
                != if self.payment_plan.balance >= self.payment_plan.price {
                    0
                } else {
                    (self.payment_plan.price - self.payment_plan.balance)
                        .max(self.payment_plan.minimum)
                }
            || self
                .payment_plan
                .balance
                .checked_add(self.payment_plan.top_up)
                .and_then(|n| n.checked_sub(self.payment_plan.price))
                != Some(self.payment_plan.left_as_credit)
            || self.payment_plan.top_up > 50_000
            || self.approval_revision == 0
        {
            return Err(protocol::REFUSED.into());
        }
        p.vendor.validate_selection(&p.selected)
    }
}

#[derive(Default)]
pub(super) struct ReadState {
    pub balance: Option<(wire::Balance, u64)>,
    pub checked_at: Option<u64>,
    pub refused: bool,
    pub transactions: Vec<wire::TransactionFact>,
    pub orders: Vec<wire::OrderFact>,
    pub servers: Vec<wire::ServerFact>,
}

impl<S: Storage> Store<S> {
    pub(super) fn vpsbg_value_safe(&self, value: &Value) -> bool {
        match value {
            Value::String(s) => self.check_output_bytes(s.as_bytes()).is_ok(),
            Value::Array(a) => a.iter().all(|v| self.vpsbg_value_safe(v)),
            Value::Object(o) => o.iter().all(|(k, v)| {
                self.check_output_bytes(k.as_bytes()).is_ok() && self.vpsbg_value_safe(v)
            }),
            _ => self
                .check_output_bytes(value.to_string().as_bytes())
                .is_ok(),
        }
    }
    pub(crate) fn vpsbg_token(&self) -> Option<&TokenRecord> {
        self.vpsbg_token.as_ref()
    }
    pub(crate) fn vpsbg_token_entry_ready(&self) -> Result<(), String> {
        if self.vpsbg_token.is_some()
            || self
                .procurement
                .iter()
                .chain(&self.completed_purchases)
                .chain(&self.closed_purchases)
                .any(|p| p.vendor == Vendor::Vpsbg)
        {
            return Err("VPSBG token entry is unavailable after a token or VPSBG purchase has been recorded.".into());
        }
        Ok(())
    }
    pub(crate) async fn vpsbg_token_install(&mut self, input: &[u8]) -> Result<(), String> {
        self.procurement_ready()?;
        self.vpsbg_token_entry_ready()?;
        let token = wire::token_text(input)?;
        #[cfg(target_arch = "wasm32")]
        if crate::poc::inference::response_pending() {
            return Err(protocol::REFUSED.into());
        }
        let account = hex::encode(random::<32>()?);
        let record = TokenRecord {
            account: account.clone(),
            generation: 1,
            token: crate::poc::credit::SecretText(Zeroizing::new(token.into())),
        };
        record.validate()?;
        self.commit(&Event::VpsbgTokenEntered(record)).await?;
        // The journal owns the first copy only until commit returns. Install from the input,
        // which is held through that append and wiped by the bytes-only browser entry point.
        self.vpsbg_token = Some(TokenRecord {
            account,
            generation: 1,
            token: crate::poc::credit::SecretText(Zeroizing::new(token.into())),
        });
        self.vpsbg_reads = ReadState::default();
        Ok(())
    }
    pub(super) fn replay_vpsbg_token(&mut self, record: &TokenRecord) -> Result<(), String> {
        self.vpsbg_token_entry_ready()?;
        record.validate()?;
        let metadata = json!({"account":record.account,"generation":record.generation});
        let credentials = [record.token.0.as_bytes()];
        if !self
            .protect_output_with(&metadata, &credentials)
            .is_ok_and(|safe| safe == metadata)
        {
            return Err(protocol::REFUSED.into());
        }
        self.vpsbg_token = Some(TokenRecord {
            account: record.account.clone(),
            generation: record.generation,
            token: crate::poc::credit::SecretText(Zeroizing::new(record.token.0.to_string())),
        });
        Ok(())
    }
    pub(crate) fn procurement_no_money(&self) -> Result<(), String> {
        if self.procurement_vendor() == Vendor::Vpsbg {
            Err(wire::READ_ONLY.into())
        } else {
            Ok(())
        }
    }
    pub(crate) fn procurement_vendor_choice_open(&self) -> bool {
        self.procurement_ready().is_ok() && self.procurement_can_start()
    }
    pub(crate) fn procurement_choose_vendor(&mut self, vendor: Vendor) -> Result<(), String> {
        if !self.procurement_vendor_choice_open() {
            return Err("Complete the saved purchase before choosing a vendor.".into());
        }
        self.vendor_choice = Some(vendor);
        self.procurement_selection = None;
        self.vpsbg_reads = ReadState::default();
        Ok(())
    }
    pub(super) fn vpsbg_view(&self, view: &mut Value) {
        let vendor = self.procurement_vendor();
        // Even a handed-off LNVPS purchase retains its exact legacy Details view.
        if vendor == Vendor::Lnvps && self.procurement.is_some() {
            return;
        }
        let choice_open = self.procurement_vendor_choice_open();
        if choice_open || vendor == Vendor::Vpsbg {
            view["vendor_choice_open"] = json!(choice_open);
            view["vendor_choice"] = json!(self.vendor_choice);
            view["vendors_available"] = json!([Vendor::Lnvps.describe(), Vendor::Vpsbg.describe()]);
        }
        if vendor != Vendor::Vpsbg {
            return;
        }
        if self.procurement.as_ref().is_none_or(|p| p.target.is_none())
            || self.vendor_choice.is_some()
        {
            view["vendor"] = vendor.describe();
        }
        view["capabilities"] = Vendor::Vpsbg.capabilities();
        view["trust"] = json!({"route":"AttestCertificate","residual":"VPS.BG boots the image it downloaded; the page cannot check those bytes."});
        view["vendor_account"] = json!({"vendor":"vpsbg", "key_set":self.vpsbg_token.is_some(),
            "check":if self.vpsbg_reads.refused {"refused"} else if self.vpsbg_reads.checked_at.is_some() {"works"} else {"unchecked"},
            "checked_at":self.vpsbg_reads.checked_at, "entry_allowed":self.vpsbg_token_entry_ready().is_ok()});
        view["balance"] = Value::Null;
        view["paid_until"] = Value::Null;
        view["renewal"] = json!("unknown");
        view["close_allowed"] = json!(false);
        if let Some((balance, read_at)) = &self.vpsbg_reads.balance {
            view["balance"] = json!({"amount":balance.amount,"currency":"EUR","read_at":read_at,"has_valid_card":balance.has_valid_card});
            if let Some(selected) = self.procurement_review_selection()
                && let Ok(preview) = wire::PaymentPlan::preview(balance, selected, *read_at)
            {
                view["payment_plan"] = json!(preview);
                view["payment_plan"]["currency"] = json!("EUR");
                view["payment_plan"]["top_up_allowed_from"] = Value::Null;
            }
        }
    }
    pub(super) async fn vpsbg_read_catalogue(
        &mut self,
        api: &mut impl protocol::Api,
    ) -> Result<Value, String> {
        let plans = self
            .provider_read(api, wire::read("/v1/servers/plans"))
            .await?;
        self.vpsbg_read_balance(api).await?;
        Ok(json!({"offers":plans,"images":[wire::image()]}))
    }
    async fn vpsbg_read_balance(&mut self, api: &mut impl protocol::Api) -> Result<(), String> {
        self.vpsbg_reads.balance = None;
        let result = self.provider_read(api, wire::read("/v1/balance")).await;
        match result {
            Ok(balance) => {
                self.vpsbg_reads.balance = Some((
                    serde_json::from_value(balance).map_err(|_| protocol::REFUSED)?,
                    api.now(),
                ));
                self.vpsbg_reads.checked_at = Some(api.now());
                self.vpsbg_reads.refused = false;
                Ok(())
            }
            Err(error) => {
                self.vpsbg_reads.checked_at = Some(api.now());
                self.vpsbg_reads.refused = true;
                Err(error)
            }
        }
    }
    pub(crate) async fn vpsbg_read_account(
        &mut self,
        api: &mut impl protocol::Api,
    ) -> Result<(), String> {
        if self.procurement_vendor() != Vendor::Vpsbg {
            return Err(protocol::REFUSED.into());
        }
        self.vpsbg_reads = ReadState::default();
        self.vpsbg_read_balance(api).await?;
        // No partial list reaches a predicate. Reads never establish readiness or a paid purchase.
        self.vpsbg_reads.transactions = self
            .vpsbg_pages(
                api,
                "/v1/balance/transactions",
                |r: &wire::TransactionFact| r.id,
            )
            .await?;
        self.vpsbg_reads.servers = self
            .vpsbg_pages(api, "/v1/servers", wire::ServerFact::id)
            .await?;
        self.vpsbg_reads.orders = self
            .vpsbg_pages(api, "/v1/orders", |r: &wire::OrderFact| r.id)
            .await?;
        if !self
            .vpsbg_reads
            .orders
            .iter()
            .all(wire::preflight_order_allowed)
        {
            return Err("Check this order at VPSBG".into());
        }
        Ok(())
    }
    async fn vpsbg_pages<T: serde::de::DeserializeOwned>(
        &mut self,
        api: &mut impl protocol::Api,
        path: &str,
        row_id: impl Fn(&T) -> u64,
    ) -> Result<Vec<T>, String> {
        let mut rows = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        let mut expected = None;
        for n in 1..=16 {
            let response = self
                .provider_read(api, wire::read(&format!("{path}?page={n}")))
                .await?;
            let page: wire::Page<T> =
                serde_json::from_value(response).map_err(|_| protocol::REFUSED)?;
            let metadata = (page.last_page, page.total, page.per_page);
            if expected.is_some_and(|old| old != metadata)
                || page.current_page != n
                || page.total > 128
                || page.last_page < n
                || page.last_page > 16
            {
                return Err(protocol::REFUSED.into());
            }
            expected = Some(metadata);
            for row in page.data {
                if !ids.insert(row_id(&row)) {
                    return Err(protocol::REFUSED.into());
                }
                rows.push(row);
            }
            if rows.len() > 128 {
                return Err(protocol::REFUSED.into());
            }
            if n == page.last_page {
                if rows.len() as u64 != page.total {
                    return Err(protocol::REFUSED.into());
                }
                return Ok(rows);
            }
        }
        Err(protocol::REFUSED.into())
    }
}
