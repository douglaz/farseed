//! Separate VPSBG custody, purchase journal and deposit reconciliation.
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
/// Approval's immutable purchase id and atomically reserved machine/pass pair.
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
    // Absence means unreconciled since open, or a covering read awaiting suppression.
    // Only a complete reconciliation below F (or a freshly preflighted issuance) clears an attempt.
    pub deposit_clear: std::collections::BTreeSet<(String, u32)>,
    pub checked_at: Option<u64>,
    pub refused: bool,
    pub transactions: Vec<wire::TransactionFact>,
    pub orders: Vec<wire::OrderFact>,
    pub servers: Vec<wire::ServerFact>,
    pub pause: Option<Value>,
    pub terms_changed: bool,
    pub preflight_at: Option<u64>,
    pub image_state: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DepositRef {
    pub purchase: String,
    pub attempt: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MoneyReview {
    pub payment_plan: wire::PaymentPlan,
    pub approved_card: bool,
    pub revision: u64,
    pub replaces_deposit: Vec<DepositRef>,
    pub late_credit_disclosed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub purchase: String,
    pub change: Change,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ClosureReason {
    AbandonedBeforeCreate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum SuppressionReason {
    CoveredFromElsewhere,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Change {
    Approved {
        purchase: Box<provisioning::Purchase>,
        replaces_deposit: Vec<DepositRef>,
        late_credit_disclosed: bool,
    },
    ApprovalRevised {
        revision: u64,
        selected: protocol::Selection,
        payment_plan: wire::PaymentPlan,
        approved_card: bool,
        approved_at: u64,
        replaces_deposit: Vec<DepositRef>,
        late_credit_disclosed: bool,
    },
    ImageSent {
        url: String,
        name: String,
        started: u64,
    },
    ImageReady {
        image: wire::ImageFact,
        checked_at: u64,
    },
    DepositSent {
        attempt: u32,
        approval_revision: u64,
        amount: wire::Cents,
        started: u64,
        replaces: Vec<DepositRef>,
    },
    DepositIssued {
        attempt: u32,
        invoice: wire::DepositInvoice,
    },
    DepositSettled {
        attempt: u32,
        order: u64,
        transaction: wire::TransactionFact,
        checked_at: u64,
    },
    DepositSuppressed {
        attempt: u32,
        order: Option<u64>,
        reason: SuppressionReason,
        balance: wire::Cents,
        first_period: wire::Cents,
        checked_at: u64,
    },
    Closed {
        reason: ClosureReason,
        closed_at: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Attempt {
    pub attempt: u32,
    pub revision: u64,
    pub amount: wire::Cents,
    pub started: u64,
    pub replaces: Vec<DepositRef>,
    pub invoice: Option<wire::DepositInvoice>,
    pub transaction: Option<wire::TransactionFact>,
    pub suppressed: bool,
}
impl Attempt {
    fn release(&self) -> Result<u64, String> {
        self.invoice
            .as_ref()
            .map_or_else(
                || self.started.checked_add(3600),
                |i| i.expires.checked_add(600),
            )
            .ok_or_else(|| protocol::REFUSED.into())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PurchaseState {
    pub approvals: Vec<MoneyReview>,
    pub image_sent: Option<(String, String, u64)>,
    pub image: Option<wire::ImageFact>,
    pub deposits: Vec<Attempt>,
    pub closed_at: Option<u64>,
}

struct Projection {
    purchase: provisioning::Purchase,
    state: PurchaseState,
    allocations: Option<(Metadata, Dispatch)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PollContext {
    pub purchase: String,
    pub machine: String,
    pub binding: MachinePassBinding,
}

impl<S: Storage> Store<S> {
    pub(crate) fn procurement_admit_action(&self, action: &str) -> Result<(), String> {
        if self.procurement_vendor() == Vendor::Vpsbg {
            if matches!(action, "read" | "approve" | "close") {
                Ok(())
            } else {
                Err(wire::READ_ONLY.into())
            }
        } else {
            Vendor::Lnvps.admit_action(action)
        }
    }
    fn vpsbg_api(&self, api: &impl protocol::Api, purchase: Option<&str>) -> Result<(), String> {
        self.procurement_ready()?;
        api.current()?;
        api.check_vendor(Vendor::Vpsbg)?;
        let account = api.account();
        if self
            .vpsbg_token
            .as_ref()
            .is_none_or(|r| r.account != account)
            || purchase.is_some_and(|id| {
                self.vpsbg_purchase(id)
                    .is_none_or(|p| p.account != account || p.origin != wire::ORIGIN)
            })
        {
            return Err(protocol::REFUSED.into());
        }
        Ok(())
    }
    async fn vpsbg_response(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: Option<&str>,
        request: protocol::VendorRequest,
    ) -> Result<crate::poc::credit::ClearedValue, String> {
        self.vpsbg_api(api, purchase)?;
        let url = Vendor::Vpsbg.request_url(wire::ORIGIN, &request.path)?;
        api.request(request.method, &url, request.body)
            .await
            .map_err(protocol::ReadError::message)?;
        self.vpsbg_api(api, purchase)?;
        let raw = api.take_vpsbg_response().ok_or(protocol::REFUSED)?;
        let value = crate::poc::credit::ClearedValue(Vendor::Vpsbg.reduce_response(
            request.method,
            &request.path,
            api.response_status(),
            &raw,
            |b| self.check_output_bytes(b),
            |v| self.vpsbg_value_safe(v),
        )?);
        if !crate::poc::inference::safe(self, &value.0, &[]) {
            return Err(protocol::REFUSED.into());
        }
        Ok(value)
    }
    async fn vpsbg_collect<T: serde::de::DeserializeOwned>(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: Option<&str>,
        path: &str,
        row_id: impl Fn(&T) -> u64,
    ) -> Result<Vec<T>, String> {
        let mut rows = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        let mut expected = None;
        for n in 1..=16 {
            let mut value = self
                .vpsbg_response(api, purchase, wire::read(&format!("{path}?page={n}")))
                .await?;
            let page: wire::Page<T> =
                serde_json::from_value(value.0.take()).map_err(|_| protocol::REFUSED)?;
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
    fn vpsbg_cache_balance(&mut self, balance: wire::Balance, read_at: u64) {
        // A covering read withholds exactly the attempts it observed. A balance-only
        // refresh below F cannot clear them; that needs complete transactions too.
        if let Some(p) = self
            .procurement
            .as_ref()
            .filter(|p| p.vendor == Vendor::Vpsbg)
            && let Some(v) = &p.vpsbg
            && balance.amount >= v.payment_plan.first_period
            && let Some(state) = self.vpsbg_purchases.get(&v.purchase)
            && state.closed_at.is_none()
        {
            for a in &state.deposits {
                if !a.suppressed && a.transaction.is_none() {
                    self.vpsbg_reads
                        .deposit_clear
                        .remove(&(v.purchase.clone(), a.attempt));
                }
            }
        }
        self.vpsbg_reads.balance = Some((balance, read_at));
    }
    fn vpsbg_image_unresolved(&self, account: &str, url: &str) -> bool {
        self.vpsbg_purchases.iter().any(|(id, state)| {
            state.image.is_none()
                && state
                    .image_sent
                    .as_ref()
                    .is_some_and(|(sent, _, _)| sent == url)
                && self
                    .vpsbg_purchase(id)
                    .is_some_and(|p| p.account == account && p.origin == wire::ORIGIN)
        })
    }
    async fn vpsbg_balance(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: Option<&str>,
    ) -> Result<wire::Balance, String> {
        self.vpsbg_reads.balance = None;
        let mut value = self
            .vpsbg_response(api, purchase, wire::read("/v1/balance"))
            .await?;
        let balance: wire::Balance =
            serde_json::from_value(value.0.take()).map_err(|_| protocol::REFUSED)?;
        self.vpsbg_cache_balance(balance.clone(), api.now());
        self.vpsbg_reads.checked_at = Some(api.now());
        self.vpsbg_reads.refused = false;
        Ok(balance)
    }
    async fn vpsbg_preflight(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: Option<&str>,
    ) -> Result<wire::Balance, String> {
        self.vpsbg_preflight_with_transactions(api, purchase, false)
            .await
    }
    async fn vpsbg_preflight_with_transactions(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: Option<&str>,
        transactions_read: bool,
    ) -> Result<wire::Balance, String> {
        self.vpsbg_reads.preflight_at = None;
        let balance = self.vpsbg_balance(api, purchase).await?;
        if !transactions_read {
            self.vpsbg_reads.transactions = self
                .vpsbg_collect(
                    api,
                    purchase,
                    "/v1/balance/transactions",
                    |r: &wire::TransactionFact| r.id,
                )
                .await?;
        }
        let orders: Vec<wire::OrderFact> = match self
            .vpsbg_collect(api, purchase, "/v1/orders", |r: &wire::OrderFact| r.id)
            .await
        {
            Ok(rows) => rows,
            Err(_) => {
                self.vpsbg_reads.pause = Some(json!({"kind":"unpaid_order","pay_allowed":false}));
                return Err("Check this order at VPSBG".into());
            }
        };
        if let Some(order) = orders.iter().find(|r| !wire::preflight_order_allowed(r)) {
            self.vpsbg_reads.pause =
                Some(json!({"kind":"unpaid_order","order":order.id,"pay_allowed":false}));
            return Err("Check this order at VPSBG".into());
        }
        self.vpsbg_reads.orders = orders;
        self.vpsbg_reads.preflight_at = Some(api.now());
        self.vpsbg_reads.pause = None;
        Ok(balance)
    }
    async fn vpsbg_second_writer(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: Option<&str>,
    ) -> Result<(), String> {
        let servers = self
            .vpsbg_collect(api, purchase, "/v1/servers", wire::ServerFact::id)
            .await?;
        let now = api.now();
        for row in &servers {
            let (name, created) = match row {
                wire::ServerFact::Live(d) => (&d.server.hostname, Some(d.server.created_at)),
                wire::ServerFact::Terminated(d) => (&d.hostname, None),
            };
            let owned = self.vpsbg_history().any(|p| {
                p.vendor == Vendor::Vpsbg
                    && p.account == api.account()
                    && p.vpsbg.as_ref().is_some_and(|v| &v.name == name)
            });
            if name.starts_with("tau-web-")
                && !owned
                && created.is_none_or(|at| at > now || now - at <= 86400)
            {
                self.vpsbg_reads.pause = Some(json!({"kind":"another_writer"}));
                return Err(
                    "Another VPSBG writer may be active. Check the account before fresh approval."
                        .into(),
                );
            }
        }
        self.vpsbg_reads.servers = servers;
        Ok(())
    }
    fn vpsbg_review(
        &self,
        selected: &protocol::Selection,
        balance: &wire::Balance,
        now: u64,
    ) -> Result<MoneyReview, String> {
        let (refs, _) =
            self.vpsbg_fence(&self.vpsbg_token.as_ref().ok_or(protocol::REFUSED)?.account)?;
        Ok(MoneyReview {
            payment_plan: wire::PaymentPlan::preview(balance, selected, now)?,
            approved_card: balance.has_valid_card,
            revision: self
                .procurement
                .as_ref()
                .and_then(|p| p.vpsbg.as_ref())
                .map(|v| v.approval_revision.checked_add(1).ok_or(protocol::REFUSED))
                .transpose()?
                .unwrap_or(1),
            late_credit_disclosed: !refs.is_empty(),
            replaces_deposit: refs,
        })
    }
    pub(crate) async fn vpsbg_approve(
        &mut self,
        api: &mut impl protocol::Api,
        approval: provisioning::Approval,
        displayed: MoneyReview,
    ) -> Result<(), String> {
        self.vpsbg_api(api, None)?;
        if approval.origin != wire::ORIGIN
            || !approval.approve_charge
            || !approval.approve_maintained_access
            || !crate::poc::inference::safe(
                self,
                &serde_json::to_value(&approval).map_err(|_| protocol::REFUSED)?,
                &[],
            )
        {
            return Err(protocol::REFUSED.into());
        }
        let selected = self
            .procurement_review_selection()
            .cloned()
            .ok_or("Review the VPSBG selection and money plan first.")?;
        let mut plans = self
            .vpsbg_response(api, None, wire::read("/v1/servers/plans"))
            .await?;
        let offer = protocol::array(&plans.0)?
            .iter()
            .find(|r| r["id"] == selected.offer["id"])
            .ok_or(protocol::REFUSED)?
            .clone();
        let fresh = protocol::Selection {
            charge: Vendor::Vpsbg.offer_charge(&offer)?,
            offer,
            image: wire::image(),
            resources: None,
        };
        plans.0 = Value::Null;
        let balance = self.vpsbg_preflight(api, None).await?;
        self.vpsbg_second_writer(api, None).await?;
        let mut current = self.vpsbg_review(&fresh, &balance, api.now())?;
        // A new read timestamp is not a price change, but the displayed snapshot must be genuine.
        if displayed.payment_plan.read_at > api.now() {
            return Err(protocol::REFUSED.into());
        }
        current.payment_plan.read_at = displayed.payment_plan.read_at;
        if !Vendor::Vpsbg.same_terms(&selected, &fresh) || current != displayed {
            self.vpsbg_reads.terms_changed = true;
            self.procurement_selection = Some(fresh);
            return Err("VPSBG terms changed; review and approve the displayed money plan and card flag again.".into());
        }
        current.payment_plan.read_at = api.now();
        self.vpsbg_check_fence(
            &api.account(),
            api.now(),
            current.payment_plan.top_up,
            &current.replaces_deposit,
            current.late_credit_disclosed,
        )?;
        let existing = self
            .procurement
            .clone()
            .filter(|p| p.vendor == Vendor::Vpsbg);
        let purchase = if let Some(p) = existing {
            if approval.machine != p.machine
                || approval.relay != p.relay
                || approval.class_answer != p.class_answer
            {
                return Err(protocol::REFUSED.into());
            }
            let id = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?.purchase.clone();
            self.vpsbg_commit(
                &id,
                Change::ApprovalRevised {
                    revision: current.revision,
                    selected: fresh,
                    payment_plan: current.payment_plan,
                    approved_card: current.approved_card,
                    approved_at: api.now(),
                    replaces_deposit: current.replaces_deposit,
                    late_credit_disclosed: current.late_credit_disclosed,
                },
            )
            .await?;
            id
        } else {
            let id = hex::encode(random::<16>()?);
            let identity = self
                .allocation()
                .issue(Family::Machines)
                .map_err(|e| e.to_string())?;
            let relay_identity = self
                .allocation()
                .issue(Family::Passes)
                .map_err(|e| e.to_string())?;
            let p = provisioning::Purchase {
                vendor: Vendor::Vpsbg,
                origin: wire::ORIGIN.into(),
                vpsbg: Some(VpsbgPurchase {
                    purchase: id.clone(),
                    name: format!("tau-web-{id}"),
                    binding: MachinePassBinding {
                        purchase: id.clone(),
                        machine: approval.machine.clone(),
                        machine_identity: identity.clone(),
                        pass_identity: relay_identity.clone(),
                    },
                    payment_plan: current.payment_plan,
                    approved_card: current.approved_card,
                    approval_revision: 1,
                }),
                machine: approval.machine,
                identity,
                relay_identity,
                class_answer: approval.class_answer,
                account: api.account(),
                relay: approval.relay,
                selected: fresh,
                user: "nixos".into(),
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
            };
            self.vpsbg_commit(
                &id,
                Change::Approved {
                    purchase: Box::new(p),
                    replaces_deposit: current.replaces_deposit,
                    late_credit_disclosed: current.late_credit_disclosed,
                },
            )
            .await?;
            id
        };
        self.vpsbg_reads.terms_changed = false;
        self.vpsbg_progress(api, &purchase, true).await
    }
    async fn vpsbg_ensure_image(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
        add: bool,
    ) -> Result<bool, String> {
        let url = wire::IMAGE_URL;
        let state = &self.vpsbg_purchases[purchase];
        if state
            .image_sent
            .as_ref()
            .is_some_and(|(old, _, _)| old != url)
            || state.image.as_ref().is_some_and(|old| old.url != url)
        {
            return Err(
                "The saved VPSBG image differs from this build; approve a fresh purchase.".into(),
            );
        }
        let images = self
            .vpsbg_collect(
                api,
                Some(purchase),
                "/v1/custom-server-images",
                |r: &wire::ImageFact| r.id,
            )
            .await?;
        if let Some(image) = images
            .iter()
            .find(|i| i.ready(url, api.now()) && i.size == wire::IMAGE_SIZE)
        {
            if self.vpsbg_purchases[purchase].image.as_ref() != Some(image) {
                self.vpsbg_commit(
                    purchase,
                    Change::ImageReady {
                        image: image.clone(),
                        checked_at: api.now(),
                    },
                )
                .await?;
            }
            self.vpsbg_reads.image_state = Some("ready");
            return Ok(true);
        }
        let state = &self.vpsbg_purchases[purchase];
        let wait_started = state
            .image_sent
            .as_ref()
            .map(|(_, _, start)| *start)
            .unwrap_or(
                self.vpsbg_purchase(purchase)
                    .ok_or(protocol::REFUSED)?
                    .approved_at,
            );
        if api.now().saturating_sub(wait_started) >= 1800 {
            self.vpsbg_reads.image_state = Some("unknown");
            return Err("VPSBG image wait reached 1800 seconds; check the image at VPSBG.".into());
        }
        if images.iter().any(|i| {
            i.url == url
                && i.deleted_at.is_none()
                && matches!(i.status.as_str(), "downloading" | "pending")
        }) {
            self.vpsbg_reads.image_state = Some("downloading");
            return Ok(false);
        }
        if images
            .iter()
            .any(|i| i.url == url && i.deleted_at.is_none() && i.status == "failed")
        {
            self.vpsbg_reads.image_state = Some("failed");
            return Err("VPSBG image download failed; no money was sent.".into());
        }
        if state.image.is_some() {
            self.vpsbg_reads.image_state = Some("unknown");
            return Err("The saved VPSBG image is no longer ready for at least one hour; no money was sent.".into());
        }
        let account = &self
            .vpsbg_purchase(purchase)
            .ok_or(protocol::REFUSED)?
            .account;
        if self.vpsbg_image_unresolved(account, url) || !add {
            self.vpsbg_reads.image_state = Some("unknown");
            return Ok(false);
        }
        if images.iter().filter(|i| i.deleted_at.is_none()).count() >= 2 {
            self.vpsbg_reads.pause = Some(json!({"kind":"image_list_full"}));
            return Err(
                "VPSBG image_list_full; remove an image in the console before any money is sent."
                    .into(),
            );
        }
        api.vpsbg_mutation_budget()?;
        self.vpsbg_commit(
            purchase,
            Change::ImageSent {
                url: url.into(),
                name: "tau-web-attest".into(),
                started: api.now(),
            },
        )
        .await?;
        self.vpsbg_reads.image_state = Some("asking");
        // Ignore the acknowledgment as readiness evidence; the next invocation lists only.
        self.vpsbg_response(api, Some(purchase), wire::post_image(url))
            .await?;
        Ok(false)
    }
    pub(crate) async fn vpsbg_progress(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
        _approved_invocation: bool,
    ) -> Result<(), String> {
        self.vpsbg_api(api, Some(purchase))?;
        let transactions_read = !self.vpsbg_purchases[purchase].deposits.is_empty();
        if transactions_read {
            self.vpsbg_deposit_check(api, purchase).await?;
        }
        if self.vpsbg_purchases[purchase].closed_at.is_some() {
            return Ok(());
        }
        // The durable current approval authorizes the first image add after reload as well.
        // ImageSent permanently removes that authority; it is never derived from a lost reply.
        let image = self.vpsbg_ensure_image(api, purchase, true).await?;
        if !image {
            return Ok(());
        }
        let p = self
            .vpsbg_purchase(purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        let v = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?;
        let state = &self.vpsbg_purchases[purchase];
        // One intent per approval, including unknown responses. Wakes never grant replacement authority.
        if v.payment_plan.top_up == 0
            || state
                .deposits
                .iter()
                .any(|a| a.revision == v.approval_revision)
        {
            return Ok(());
        }
        let balance = self
            .vpsbg_preflight_with_transactions(api, Some(purchase), transactions_read)
            .await?;
        self.vpsbg_second_writer(api, Some(purchase)).await?;
        let plans = self
            .vpsbg_response(api, Some(purchase), wire::read("/v1/servers/plans"))
            .await?;
        let offer = protocol::array(&plans.0)?
            .iter()
            .find(|r| r["id"] == p.selected.offer["id"])
            .ok_or(protocol::REFUSED)?;
        let fresh = protocol::Selection {
            offer: offer.clone(),
            image: wire::image(),
            resources: None,
            charge: Vendor::Vpsbg.offer_charge(offer)?,
        };
        if !Vendor::Vpsbg.same_terms(&p.selected, &fresh) {
            self.vpsbg_reads.terms_changed = true;
            return Err("VPSBG terms changed; approve again.".into());
        }
        let _ = balance;
        // Last provider read before the committed intent and POST.
        let balance = self.vpsbg_balance(api, Some(purchase)).await?;
        if balance.amount >= v.payment_plan.first_period {
            // No invoice was requested; a zero top-up approval is needed for the new balance.
            self.vpsbg_reads.terms_changed = true;
            return Err(
                "VPSBG terms changed; balance now covers the first period. Approve again.".into(),
            );
        }
        let mut preview = wire::PaymentPlan::preview(&balance, &fresh, v.payment_plan.read_at)?;
        preview.read_at = v.payment_plan.read_at;
        if preview != v.payment_plan || balance.has_valid_card != v.approved_card {
            self.vpsbg_reads.terms_changed = true;
            return Err("VPSBG terms changed; review the top-up and card flag again.".into());
        }
        self.vpsbg_api(api, Some(purchase))?;
        let state = &self.vpsbg_purchases[purchase];
        let approval = state.approvals.last().ok_or(protocol::REFUSED)?;
        self.vpsbg_check_fence(
            &p.account,
            api.now(),
            preview.top_up,
            &approval.replaces_deposit,
            approval.late_credit_disclosed,
        )?;
        let attempt = u32::try_from(state.deposits.len()).map_err(|_| protocol::REFUSED)?;
        let replaces = approval.replaces_deposit.clone();
        if state
            .image
            .as_ref()
            .is_none_or(|i| !i.ready(wire::IMAGE_URL, api.now()) || i.size != wire::IMAGE_SIZE)
        {
            return Err(protocol::REFUSED.into());
        }
        api.vpsbg_mutation_budget()?;
        self.vpsbg_commit(
            purchase,
            Change::DepositSent {
                attempt,
                approval_revision: v.approval_revision,
                amount: preview.top_up,
                started: api.now(),
                replaces,
            },
        )
        .await?;
        self.vpsbg_api(api, Some(purchase))?;
        let mut response = self
            .vpsbg_response(api, Some(purchase), wire::post_deposit(preview.top_up)?)
            .await?;
        let invoice: wire::DepositInvoice =
            serde_json::from_value(response.0.take()).map_err(|_| protocol::REFUSED)?;
        self.vpsbg_commit(purchase, Change::DepositIssued { attempt, invoice })
            .await?;
        // This invocation completed the preflight and the final below-F balance read.
        // Keep this outside apply/replay: a recovered invoice needs fresh reconciliation.
        self.vpsbg_reads
            .deposit_clear
            .insert((purchase.into(), attempt));
        Ok(())
    }
    pub(crate) async fn vpsbg_deposit_check(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
    ) -> Result<(), String> {
        self.vpsbg_api(api, Some(purchase))?;
        self.vpsbg_reads
            .deposit_clear
            .retain(|(id, _)| id != purchase);
        let result = self.vpsbg_reconcile_deposits(api, purchase).await;
        let current = self
            .procurement
            .as_ref()
            .and_then(|p| p.vpsbg.as_ref())
            .is_some_and(|v| v.purchase == purchase);
        if current {
            if let Err(error) = &result {
                self.vpsbg_reads
                    .deposit_clear
                    .retain(|(id, _)| id != purchase);
                self.vpsbg_reads.pause = Some(json!({"kind":"reconciliation","message":error}));
            } else if self
                .vpsbg_reads
                .pause
                .as_ref()
                .is_some_and(|p| p["kind"] == "reconciliation")
            {
                self.vpsbg_reads.pause = None;
            }
        }
        result
    }
    async fn vpsbg_reconcile_deposits(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
    ) -> Result<(), String> {
        let balance = self.vpsbg_balance(api, Some(purchase)).await?;
        self.vpsbg_reads.transactions = self
            .vpsbg_collect(
                api,
                Some(purchase),
                "/v1/balance/transactions",
                |r: &wire::TransactionFact| r.id,
            )
            .await?;
        let state = self
            .vpsbg_purchases
            .get(purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        let p = self
            .vpsbg_purchase(purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        let v = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?;
        let current = state.closed_at.is_none()
            && self
                .procurement
                .as_ref()
                .and_then(|p| p.vpsbg.as_ref())
                .is_some_and(|v| v.purchase == purchase);
        // Settle every exact order first. A different attempt's changed terms must
        // never prevent this pass, including for replaced or suppressed invoices.
        for a in &state.deposits {
            if let Some(invoice) = &a.invoice {
                let rows = self
                    .vpsbg_reads
                    .transactions
                    .iter()
                    .filter(|t| {
                        t.order_id == invoice.order
                            && t.payment_method == "bitcoin-ln"
                            && t.amount_with_vat > 0
                    })
                    .collect::<Vec<_>>();
                if rows.len() > 1 {
                    return Err("Conflicting VPSBG deposit transactions; check the account.".into());
                }
                if let Some(row) = rows.first() {
                    if a.transaction.as_ref().is_some_and(|old| old != *row) {
                        return Err(protocol::REFUSED.into());
                    }
                    if a.transaction.is_none() {
                        self.vpsbg_commit(
                            purchase,
                            Change::DepositSettled {
                                attempt: a.attempt,
                                order: invoice.order,
                                transaction: (*row).clone(),
                                checked_at: api.now(),
                            },
                        )
                        .await?;
                    }
                }
            }
        }
        let unresolved = self.vpsbg_purchases[purchase]
            .deposits
            .iter()
            .filter(|a| a.transaction.is_none() && !a.suppressed)
            .cloned()
            .collect::<Vec<_>>();
        if current && balance.amount >= v.payment_plan.first_period && !unresolved.is_empty() {
            // Plan and card remain bound; coverage never establishes settlement.
            let plans = self
                .vpsbg_response(api, Some(purchase), wire::read("/v1/servers/plans"))
                .await?;
            let offer = protocol::array(&plans.0)?
                .iter()
                .find(|r| r["id"] == p.selected.offer["id"])
                .ok_or(protocol::REFUSED)?;
            if Vendor::Vpsbg.offer_charge(offer)? != p.selected.charge
                || balance.has_valid_card != v.approved_card
            {
                self.vpsbg_reads.terms_changed = true;
                return Err("VPSBG terms changed; approve again.".into());
            }
            for a in &unresolved {
                self.vpsbg_commit(
                    purchase,
                    Change::DepositSuppressed {
                        attempt: a.attempt,
                        order: a.invoice.as_ref().map(|i| i.order),
                        reason: SuppressionReason::CoveredFromElsewhere,
                        balance: balance.amount,
                        first_period: v.payment_plan.first_period,
                        checked_at: api.now(),
                    },
                )
                .await?;
            }
        } else if balance.amount < v.payment_plan.first_period {
            // Neither a failed page nor a balance-only refresh can reach this point.
            for a in &unresolved {
                self.vpsbg_reads
                    .deposit_clear
                    .insert((purchase.into(), a.attempt));
            }
        }
        if current
            && self
                .vpsbg_fence(&p.account)?
                .1
                .is_some_and(|at| api.now() >= at)
        {
            self.vpsbg_preflight_with_transactions(api, Some(purchase), true)
                .await?;
        }
        if current
            && self.vpsbg_purchases[purchase]
                .deposits
                .iter()
                .any(|a| a.suppressed || a.transaction.is_some())
            && balance.amount < v.payment_plan.first_period
        {
            self.vpsbg_reads.pause = Some(json!({"kind":"balance_short"}));
        } else if current
            && self
                .vpsbg_reads
                .pause
                .as_ref()
                .is_some_and(|p| p["kind"] == "balance_short")
        {
            self.vpsbg_reads.pause = None;
        }
        Ok(())
    }
    pub(crate) fn vpsbg_poll_contexts(&self) -> Vec<PollContext> {
        if self.procurement_ready().is_err() || self.vpsbg_token.is_none() {
            return Vec::new();
        }
        self.vpsbg_purchases
            .iter()
            .filter(|(id, state)| {
                state.deposits.iter().any(|a| a.transaction.is_none())
                    || (state.closed_at.is_none()
                        && self
                            .procurement
                            .as_ref()
                            .and_then(|p| p.vpsbg.as_ref())
                            .is_some_and(|v| {
                                &v.purchase == *id
                                    && (state.image.is_none()
                                        || (v.payment_plan.top_up > 0
                                            && !state
                                                .deposits
                                                .iter()
                                                .any(|a| a.revision == v.approval_revision)))
                            }))
            })
            .filter_map(|(id, _)| {
                let p = self.vpsbg_purchase(id)?;
                Some(PollContext {
                    purchase: id.clone(),
                    machine: p.machine.clone(),
                    binding: p.vpsbg.as_ref()?.binding.clone(),
                })
            })
            .collect()
    }
}
impl<S: Storage> Store<S> {
    fn vpsbg_history(&self) -> impl Iterator<Item = &provisioning::Purchase> {
        self.procurement
            .iter()
            .chain(&self.completed_purchases)
            .chain(&self.closed_purchases)
    }
    pub(crate) fn vpsbg_purchase(&self, purchase: &str) -> Option<&provisioning::Purchase> {
        self.vpsbg_history().find(|p| {
            p.vendor == Vendor::Vpsbg && p.vpsbg.as_ref().is_some_and(|v| v.purchase == purchase)
        })
    }
    fn vpsbg_fence(&self, account: &str) -> Result<(Vec<DepositRef>, Option<u64>), String> {
        let mut refs = Vec::new();
        let mut release = None;
        for (purchase, state) in &self.vpsbg_purchases {
            let p = self.vpsbg_purchase(purchase).ok_or(protocol::REFUSED)?;
            if p.account != account {
                continue;
            }
            for a in state.deposits.iter().filter(|a| a.transaction.is_none()) {
                let at = a.release()?;
                release = Some(release.map_or(at, |old: u64| old.max(at)));
                refs.push(DepositRef {
                    purchase: purchase.clone(),
                    attempt: a.attempt,
                });
            }
        }
        Ok((refs, release))
    }
    fn vpsbg_check_fence(
        &self,
        account: &str,
        now: u64,
        amount: u64,
        replaces: &[DepositRef],
        disclosed: bool,
    ) -> Result<(), String> {
        let (refs, release) = self.vpsbg_fence(account)?;
        if amount > 0
            && (refs != replaces
                || (!refs.is_empty() && (!disclosed || release.is_some_and(|at| now < at))))
        {
            return Err("The earlier top-up is not known yet. Wait, check the account, and approve the disclosed new top-up.".into());
        }
        if amount == 0 && !replaces.is_empty() && refs != replaces {
            return Err(protocol::REFUSED.into());
        }
        Ok(())
    }
    fn vpsbg_reserve(&self, p: &provisioning::Purchase) -> Result<(Metadata, Dispatch), String> {
        use crate::dispatch::{
            Access, ApprovedEntry, BillingInterval, MachineEntry, Period, RecurringCost, Unit,
        };
        let mut allocation = self.allocation().clone();
        let mut dispatch = self.measured_dispatch_copy();
        dispatch.apply_poc_purchase(
            &mut allocation,
            ApprovedEntry {
                entry: MachineEntry {
                    machine: p.machine.clone(),
                    vendor: p.vendor.name().into(),
                    product: p.vendor.product(&p.selected)?.into(),
                    region: p.vendor.region(&p.selected)?.into(),
                    cost: RecurringCost {
                        amount: p.selected.charge.amount,
                        unit: Unit::EurCent,
                        period: Period::Billing {
                            count: 1,
                            interval: BillingInterval::Month,
                        },
                    },
                },
                identity: p.identity.clone(),
                access: Some(Access::ad_hoc()),
            },
            p.class_answer,
        )?;
        allocation
            .apply(&allocation::Event::Reserve(p.relay_identity.clone()))
            .map_err(|e| e.to_string())?;
        Ok((allocation, dispatch))
    }
    fn vpsbg_projection(&self, record: &Record) -> Result<Projection, String> {
        let refused = protocol::REFUSED;
        if let Change::Approved {
            purchase,
            replaces_deposit,
            late_credit_disclosed,
        } = &record.change
        {
            let p = purchase.as_ref();
            let v = p.vpsbg.as_ref().ok_or(refused)?;
            v.validate(p)?;
            if record.purchase != v.purchase
                || self.vpsbg_purchases.contains_key(&record.purchase)
                || !self.procurement_can_start()
                || v.approval_revision != 1
                || self
                    .vpsbg_token
                    .as_ref()
                    .is_none_or(|r| r.account != p.account)
                || self.vpsbg_history().any(|old| {
                    old.machine == p.machine
                        || old
                            .vpsbg
                            .as_ref()
                            .is_some_and(|old| old.purchase == v.purchase || old.name == v.name)
                })
                || self.dispatch.approved_entries.contains_key(&p.machine)
                || self.poc_targets.contains_key(&p.machine)
                || self.commands.iter().any(|(_, e)| e.machine == p.machine)
                || self
                    .dispatch
                    .calls
                    .values()
                    .any(|c| c.intent.machine == p.machine)
                || self
                    .exposure_ledger
                    .iter()
                    .any(|e| e.bound_set.iter().any(|b| b.machine == p.machine))
                || p.machine.is_empty()
                || p.machine.len() > 64
                || !p.machine.as_bytes()[0].is_ascii_alphanumeric()
                || !p
                    .machine
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                || !crate::poc::targets::valid_relay(&p.relay)
                || p.user != "nixos"
                || p.identity
                    != self
                        .allocation()
                        .issue(Family::Machines)
                        .map_err(|e| e.to_string())?
                || p.relay_identity
                    != self
                        .allocation()
                        .issue(Family::Passes)
                        .map_err(|e| e.to_string())?
                || p.pending_selection.is_some()
                || p.registration_sent
                || p.ssh_key.is_some()
                || p.create.is_some()
                || p.vm.is_some()
                || p.invoice.is_some()
                || p.billing.is_some()
                || p.payment.is_some()
                || p.paid_at.is_some()
                || p.publication.is_some()
                || p.target.is_some()
                || v.payment_plan.read_at != p.approved_at
            {
                return Err(refused.into());
            }
            self.vpsbg_check_fence(
                &p.account,
                p.approved_at,
                v.payment_plan.top_up,
                replaces_deposit,
                *late_credit_disclosed,
            )?;
            let allocations = self.vpsbg_reserve(p)?;
            return Ok(Projection {
                purchase: p.clone(),
                allocations: Some(allocations),
                state: PurchaseState {
                    approvals: vec![MoneyReview {
                        payment_plan: v.payment_plan.clone(),
                        approved_card: v.approved_card,
                        revision: 1,
                        replaces_deposit: replaces_deposit.clone(),
                        late_credit_disclosed: *late_credit_disclosed,
                    }],
                    image_sent: None,
                    image: None,
                    deposits: Vec::new(),
                    closed_at: None,
                },
            });
        }
        let mut p = self
            .vpsbg_purchase(&record.purchase)
            .ok_or(refused)?
            .clone();
        let mut state = self
            .vpsbg_purchases
            .get(&record.purchase)
            .ok_or(refused)?
            .clone();
        let v = p.vpsbg.as_mut().ok_or(refused)?;
        let late = matches!(
            record.change,
            Change::DepositSettled { .. }
                | Change::DepositSuppressed { .. }
                | Change::DepositIssued { .. }
        );
        if state.closed_at.is_some() && !late {
            return Err(refused.into());
        }
        match &record.change {
            Change::Approved { .. } => unreachable!(),
            Change::ApprovalRevised {
                revision,
                selected,
                payment_plan,
                approved_card,
                approved_at,
                replaces_deposit,
                late_credit_disclosed,
            } => {
                if v.approval_revision.checked_add(1) != Some(*revision)
                    || *approved_at < p.approved_at
                    || payment_plan.read_at != *approved_at
                    || p.create.is_some()
                    || p.vm.is_some()
                    || p.target.is_some()
                {
                    return Err(refused.into());
                }
                self.vpsbg_check_fence(
                    &p.account,
                    *approved_at,
                    payment_plan.top_up,
                    replaces_deposit,
                    *late_credit_disclosed,
                )?;
                p.selected = selected.clone();
                p.approved_at = *approved_at;
                p.pending_selection = None;
                v.payment_plan = payment_plan.clone();
                v.approved_card = *approved_card;
                v.approval_revision = *revision;
                state.approvals.push(MoneyReview {
                    payment_plan: payment_plan.clone(),
                    approved_card: *approved_card,
                    revision: *revision,
                    replaces_deposit: replaces_deposit.clone(),
                    late_credit_disclosed: *late_credit_disclosed,
                });
            }
            Change::ImageSent { url, name, started } => {
                wire::validate_image_url(url)?;
                if state.image_sent.is_some()
                    || self.vpsbg_image_unresolved(&p.account, url)
                    || state.image.is_some()
                    || !state.deposits.is_empty()
                    || name != "tau-web-attest"
                    || *started < p.approved_at
                {
                    return Err(refused.into());
                }
                state.image_sent = Some((url.clone(), name.clone(), *started));
            }
            Change::ImageReady { image, checked_at } => {
                wire::validate_image_url(&image.url)?;
                if !image.ready(&image.url, *checked_at)
                    || *checked_at < p.approved_at
                    || state
                        .image_sent
                        .as_ref()
                        .is_some_and(|(url, _, _)| url != &image.url)
                    || state.image.as_ref().is_some_and(|old| old.url != image.url)
                {
                    return Err(refused.into());
                }
                state.image = Some(image.clone());
            }
            Change::DepositSent {
                attempt,
                approval_revision,
                amount,
                started,
                replaces,
            } => {
                let approval = state.approvals.last().ok_or(refused)?;
                if usize::try_from(*attempt).ok() != Some(state.deposits.len())
                    || state.deposits.len() >= 128
                    || *approval_revision != v.approval_revision
                    || *amount == 0
                    || *amount != v.payment_plan.top_up
                    || *started < p.approved_at
                    || state
                        .deposits
                        .iter()
                        .any(|a| a.revision == *approval_revision)
                    || (!state.deposits.is_empty()
                        && state.deposits.iter().all(|a| a.transaction.is_some()))
                    || state
                        .image
                        .as_ref()
                        .is_none_or(|i| !i.ready(&i.url, *started))
                    || replaces != &approval.replaces_deposit
                {
                    return Err(refused.into());
                }
                self.vpsbg_check_fence(
                    &p.account,
                    *started,
                    *amount,
                    replaces,
                    approval.late_credit_disclosed,
                )?;
                state.deposits.push(Attempt {
                    attempt: *attempt,
                    revision: *approval_revision,
                    amount: *amount,
                    started: *started,
                    replaces: replaces.clone(),
                    invoice: None,
                    transaction: None,
                    suppressed: false,
                });
            }
            Change::DepositIssued { attempt, invoice } => {
                invoice.validate()?;
                if self
                    .vpsbg_purchases
                    .values()
                    .flat_map(|s| &s.deposits)
                    .filter_map(|a| a.invoice.as_ref())
                    .any(|i| i.order == invoice.order || i.payment_hash == invoice.payment_hash)
                {
                    return Err(refused.into());
                }
                let a = state.deposits.get_mut(*attempt as usize).ok_or(refused)?;
                let decoded = wire::bolt11::decode(&invoice.bolt11)?;
                if a.invoice.is_some()
                    || invoice.amount != a.amount
                    || decoded.timestamp.saturating_add(300) < a.started
                    || invoice.expires <= a.started
                {
                    return Err(refused.into());
                }
                a.invoice = Some(invoice.clone());
            }
            Change::DepositSettled {
                attempt,
                order,
                transaction,
                checked_at,
            } => {
                let a = state.deposits.get_mut(*attempt as usize).ok_or(refused)?;
                let invoice = a.invoice.as_ref().ok_or(refused)?;
                if *order != invoice.order
                    || transaction.order_id != *order
                    || transaction.id == 0
                    || transaction.payment_method != "bitcoin-ln"
                    || transaction.amount_with_vat <= 0
                    || u64::try_from(transaction.amount_with_vat).ok() != Some(a.amount)
                    || matches!(transaction.description.as_str(), "Order Payment" | "Refund")
                    || *checked_at < a.started
                    || transaction.created_at.saturating_add(300) < a.started
                    || transaction.created_at > *checked_at
                    || a.transaction.is_some()
                    || self
                        .vpsbg_purchases
                        .values()
                        .flat_map(|s| &s.deposits)
                        .filter_map(|a| a.transaction.as_ref())
                        .any(|t| t.id == transaction.id)
                {
                    return Err(refused.into());
                }
                a.transaction = Some(transaction.clone());
            }
            Change::DepositSuppressed {
                attempt,
                order,
                reason: SuppressionReason::CoveredFromElsewhere,
                balance,
                first_period,
                checked_at,
            } => {
                let a = state.deposits.get_mut(*attempt as usize).ok_or(refused)?;
                if a.suppressed
                    || a.transaction.is_some()
                    || *first_period != v.payment_plan.first_period
                    || balance < first_period
                    || *checked_at < a.started
                    || *order != a.invoice.as_ref().map(|i| i.order)
                {
                    return Err(refused.into());
                }
                a.suppressed = true;
            }
            Change::Closed {
                reason: ClosureReason::AbandonedBeforeCreate,
                closed_at,
            } => {
                if self.procurement.as_ref().is_none_or(|p| {
                    p.vpsbg
                        .as_ref()
                        .is_none_or(|v| v.purchase != record.purchase)
                }) || p.create.is_some()
                    || p.vm.is_some()
                    || p.target.is_some()
                    || *closed_at < p.approved_at
                    || [&p.identity, &p.relay_identity].iter().any(|identity| {
                        self.allocation()
                            .entries()
                            .iter()
                            .find(|entry| &entry.identity == *identity)
                            .is_none_or(|entry| entry.status != allocation::Status::Reserved)
                    })
                {
                    return Err(refused.into());
                }
                state.closed_at = Some(*closed_at);
            }
        }
        p.vpsbg.as_ref().ok_or(refused)?.validate(&p)?;
        Ok(Projection {
            purchase: p,
            state,
            allocations: None,
        })
    }
    fn apply_vpsbg(&mut self, number: u64, record: &Record, projection: Projection) {
        let Projection {
            purchase: p,
            state,
            allocations,
        } = projection;
        let closed = state.closed_at.is_some();
        let reapproved = matches!(record.change, Change::ApprovalRevised { .. });
        self.vpsbg_reads.deposit_clear.retain(|(id, attempt)| {
            id != &record.purchase
                || (!closed
                    && !reapproved
                    && state
                        .deposits
                        .iter()
                        .any(|a| a.attempt == *attempt && !a.suppressed && a.transaction.is_none()))
        });
        self.vpsbg_purchases.insert(record.purchase.clone(), state);
        if let Some((allocation, mut dispatch)) = allocations {
            dispatch
                .purchase_approvals
                .insert(p.machine.clone(), number);
            self.allocation = Some(allocation);
            self.dispatch = dispatch;
            if let Some(previous) = self.procurement.take() {
                self.completed_purchases.push(previous);
            }
            self.procurement = Some(p);
            self.procurement_selection = None;
            self.vendor_choice = None;
            return;
        }
        if matches!(record.change, Change::Closed { .. }) {
            // No server or first contact exists in this slice. Retain identity tombstones and all history.
            self.dispatch.approved_entries.remove(&p.machine);
            self.dispatch.associations.retain(|a| a.entry != p.machine);
            self.dispatch.current_installations.remove(&p.machine);
            self.dispatch.purchase_approvals.remove(&p.machine);
            self.poc_targets.remove(&p.machine);
            for exposure in &self.exposure_ledger {
                if exposure
                    .bound_set
                    .iter()
                    .any(|bound| bound.machine == p.machine)
                {
                    self.ended_sessions.insert(exposure.session.clone());
                }
            }
            for session in &self.sessions {
                if session.bound_set.contains(&p.machine) {
                    self.ended_sessions.insert(session.identity.clone());
                    session.ended.set(true);
                    session.given.borrow_mut().clear();
                }
            }
            for identity in [&p.identity, &p.relay_identity] {
                self.allocation
                    .as_mut()
                    .expect("validated allocation")
                    .apply(&allocation::Event::Failed(identity.clone()))
                    .expect("reserved approval identity");
            }
            self.procurement = None;
            self.procurement_selection = None;
            self.vendor_choice = None;
            self.closed_purchases.push(p);
        } else if let Some(old) = self.procurement.as_mut().filter(|old| {
            old.vpsbg
                .as_ref()
                .is_some_and(|v| v.purchase == record.purchase)
        }) {
            *old = p;
        } else {
            let archive = if closed {
                &mut self.closed_purchases
            } else {
                &mut self.completed_purchases
            };
            if let Some(old) = archive.iter_mut().find(|old| {
                old.vpsbg
                    .as_ref()
                    .is_some_and(|v| v.purchase == record.purchase)
            }) {
                *old = p;
            }
        }
    }
    pub(super) fn replay_vpsbg(&mut self, number: u64, record: &Record) -> Result<(), String> {
        let projection = self.vpsbg_projection(record)?;
        self.apply_vpsbg(number, record, projection);
        Ok(())
    }
    async fn vpsbg_commit(&mut self, purchase: &str, change: Change) -> Result<(), String> {
        self.procurement_ready()?;
        let record = Record {
            purchase: purchase.into(),
            change,
        };
        let projection = self.vpsbg_projection(&record)?;
        let number = self.commit(&Event::Vpsbg(record.clone())).await?;
        self.apply_vpsbg(number, &record, projection);
        Ok(())
    }
    pub(crate) fn vpsbg_close_allowed(&self, purchase: &str) -> bool {
        self.procurement_ready().is_ok()
            && self.procurement.as_ref().is_some_and(|p| {
                p.vendor == Vendor::Vpsbg
                    && p.vpsbg.as_ref().is_some_and(|v| v.purchase == purchase)
                    && p.create.is_none()
                    && p.vm.is_none()
                    && p.target.is_none()
                    && [&p.identity, &p.relay_identity].iter().all(|identity| {
                        self.allocation().entries().iter().any(|entry| {
                            &entry.identity == *identity
                                && entry.status == allocation::Status::Reserved
                        })
                    })
            })
            && self
                .vpsbg_purchases
                .get(purchase)
                .is_some_and(|s| s.closed_at.is_none())
    }
    /// The browser captured this vendor and purchase before dispatching Close.
    pub(crate) fn vpsbg_closed_dispatch(&self, vendor: Vendor, purchase: &str) -> bool {
        vendor == Vendor::Vpsbg
            && self
                .vpsbg_purchases
                .get(purchase)
                .is_some_and(|s| s.closed_at.is_some())
            && self.closed_purchases.iter().any(|p| {
                p.vendor == vendor && p.vpsbg.as_ref().is_some_and(|v| v.purchase == purchase)
            })
    }
    pub(crate) async fn vpsbg_close(&mut self, now: u64) -> Result<(), String> {
        self.procurement_ready()?;
        let purchase = self
            .procurement
            .as_ref()
            .and_then(|p| p.vpsbg.as_ref())
            .ok_or(protocol::REFUSED)?
            .purchase
            .clone();
        self.vpsbg_commit(
            &purchase,
            Change::Closed {
                reason: ClosureReason::AbandonedBeforeCreate,
                closed_at: now,
            },
        )
        .await
    }
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
        view["disclosures"] = json!(wire::DISCLOSURES);
        view["late_credit_disclosure"] = json!(wire::LATE_CREDIT);
        if self.vpsbg_reads.terms_changed {
            view["phase"] = json!("terms_changed");
        }
        let now = crate::hostcert::now_unix().unwrap_or(u64::MAX);
        let account = self
            .vpsbg_token
            .as_ref()
            .map(|r| r.account.as_str())
            .unwrap_or("");
        let fence = self.vpsbg_fence(account).ok();
        if let Some((balance, read_at)) = &self.vpsbg_reads.balance {
            view["balance"] = json!({"amount":balance.amount,"currency":"EUR","read_at":read_at,"has_valid_card":balance.has_valid_card});
            if let Some(selected) = self.procurement_review_selection()
                && let Ok(preview) = wire::PaymentPlan::preview(balance, selected, *read_at)
            {
                view["payment_plan"] = json!(preview);
                view["payment_plan"]["currency"] = json!("EUR");
                view["payment_plan"]["top_up_allowed_from"] =
                    json!(fence.as_ref().and_then(|(_, at)| *at));
                if let Ok(review) = self.vpsbg_review(selected, balance, *read_at) {
                    view["money_review"] = json!(review);
                }
            }
        }
        if let Some(p) = self
            .procurement
            .as_ref()
            .filter(|p| p.vendor == Vendor::Vpsbg)
            && let Some(v) = &p.vpsbg
            && let Some(state) = self.vpsbg_purchases.get(&v.purchase)
        {
            view["purchase"] = json!(v.purchase);
            view["approval_revision"] = json!(v.approval_revision);
            view["approved_card"] = json!(v.approved_card);
            view["approved_payment_plan"] = json!(v.payment_plan);
            if view.get("payment_plan").is_none() {
                view["payment_plan"] = json!(v.payment_plan);
                view["payment_plan"]["currency"] = json!("EUR");
                view["payment_plan"]["top_up_allowed_from"] =
                    json!(fence.as_ref().and_then(|(_, at)| *at));
            }
            view["close_allowed"] = json!(self.vpsbg_close_allowed(&v.purchase));
            view["pause"] = json!(self.vpsbg_reads.pause);
            let changed_top_up = !state
                .deposits
                .iter()
                .any(|a| a.revision == v.approval_revision)
                && self
                    .vpsbg_reads
                    .balance
                    .as_ref()
                    .is_some_and(|(balance, read_at)| {
                        wire::PaymentPlan::preview(balance, &p.selected, *read_at).is_ok_and(
                            |plan| {
                                plan.minimum != v.payment_plan.minimum
                                    || plan.top_up != v.payment_plan.top_up
                            },
                        )
                    });
            let terms = self.vpsbg_reads.terms_changed
                || changed_top_up
                || self
                    .vpsbg_reads
                    .balance
                    .as_ref()
                    .is_some_and(|(b, _)| b.has_valid_card != v.approved_card);
            if terms {
                view["phase"] = json!("terms_changed");
            }
            view["image"] = json!({"state":self.vpsbg_reads.image_state.unwrap_or(
                if state.image.is_some() {"ready"} else if state.image_sent.is_some() {"asking"} else {"needed"})});
            view["introduction"] = Value::Null;
            view["deposit"] = self.vpsbg_deposit_view(&v.purchase, now);
        }
    }
    fn vpsbg_deposit_view(&self, purchase: &str, now: u64) -> Value {
        let Some(state) = self.vpsbg_purchases.get(purchase) else {
            return Value::Null;
        };
        let Some(p) = self.vpsbg_purchase(purchase) else {
            return Value::Null;
        };
        let release = self.vpsbg_fence(&p.account).ok().and_then(|(_, at)| at);
        let allowed = state.closed_at.is_none()
            && release.is_some_and(|at| now >= at)
            && self
                .vpsbg_reads
                .preflight_at
                .is_some_and(|at| at <= now && now - at <= 60 && release.is_none_or(|r| at >= r));
        let Some(attempt) = state.deposits.last() else {
            return json!({"state":"unknown","new_top_up_allowed":false,"covered_from_elsewhere":false});
        };
        let mut view = json!({"state":if attempt.transaction.is_some() {"settled"}
            else if let Some(i) = &attempt.invoice { if now < i.expires {"open"} else {"expired"} }
            else if now < attempt.started.saturating_add(3600) {"asking"} else {"unknown"},
            "new_top_up_allowed":allowed,"covered_from_elsewhere":attempt.suppressed});
        if let Some(invoice) = &attempt.invoice {
            view["order"] = json!(invoice.order);
            view["expires"] = json!(invoice.expires);
            let replaced = self
                .vpsbg_purchases
                .values()
                .flat_map(|s| &s.approvals)
                .flat_map(|a| &a.replaces_deposit)
                .any(|r| r.purchase == purchase && r.attempt == attempt.attempt);
            if state.closed_at.is_none()
                && !attempt.suppressed
                && self
                    .vpsbg_reads
                    .deposit_clear
                    .contains(&(purchase.into(), attempt.attempt))
                && attempt.transaction.is_none()
                && !replaced
                && now < invoice.expires
            {
                view["bolt11"] = json!(invoice.bolt11);
                view["amount_msat"] = json!(invoice.amount_msat);
            }
        }
        view
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
                self.vpsbg_cache_balance(
                    serde_json::from_value(balance).map_err(|_| protocol::REFUSED)?,
                    api.now(),
                );
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
        let deposit_clear = std::mem::take(&mut self.vpsbg_reads.deposit_clear);
        self.vpsbg_reads = ReadState {
            deposit_clear,
            ..ReadState::default()
        };
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
