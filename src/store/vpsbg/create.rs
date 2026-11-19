//! Run-once create and pay paths. No SSH contact or readiness transition lives here.
use super::*;

pub(in crate::store) struct HeldCreate {
    introduction: attest::AttestIntroduction,
    user_data: Zeroizing<String>,
}
impl HeldCreate {
    fn values(&self) -> [&[u8]; 2] {
        [
            self.introduction.ca_private_openssh.as_bytes(),
            self.user_data.as_bytes(),
        ]
    }
}

impl<S: Storage> Store<S> {
    pub(in crate::store) fn vpsbg_create_secrets(&self) -> Vec<Zeroizing<String>> {
        self.vpsbg_reads
            .create_held
            .upgrade()
            .map_or_else(Vec::new, |held| {
                vec![
                    Zeroizing::new(held.introduction.ca_private_openssh.to_string()),
                    Zeroizing::new(held.user_data.to_string()),
                ]
            })
    }
    pub(super) async fn vpsbg_approval_preflight(
        &mut self,
        api: &mut impl protocol::Api,
        order: Option<u64>,
    ) -> Result<wire::Balance, String> {
        let Some(order) = order else {
            return self.vpsbg_preflight(api, None).await;
        };
        let p = self.procurement.as_ref().ok_or(protocol::REFUSED)?;
        let id = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?.purchase.clone();
        if self.vpsbg_purchases[&id]
            .unpaid
            .is_none_or(|(saved, _, _)| saved != order)
            || self.vpsbg_purchases[&id].pay_sent.is_some()
        {
            return Err(protocol::REFUSED.into());
        }
        let balance = self.vpsbg_balance(api, Some(&id)).await?;
        self.vpsbg_reads.transactions = self
            .vpsbg_collect(
                api,
                Some(&id),
                "/v1/balance/transactions",
                |t: &wire::TransactionFact| t.id,
            )
            .await?;
        let orders: Vec<wire::OrderFact> = self
            .vpsbg_collect(api, Some(&id), "/v1/orders", |o: &wire::OrderFact| o.id)
            .await?;
        if !orders.iter().any(|o| o.id == order)
            || orders
                .iter()
                .any(|o| o.id != order && !wire::preflight_order_allowed(o))
        {
            return Err("Check this order at VPSBG".into());
        }
        self.vpsbg_reads.orders = orders;
        Ok(balance)
    }
    pub(super) fn vpsbg_create_pending(&self, purchase: &str) -> bool {
        let Some(p) = self
            .procurement
            .as_ref()
            .filter(|p| p.vendor == Vendor::Vpsbg)
        else {
            return false;
        };
        let Some(v) = &p.vpsbg else {
            return false;
        };
        let Some(s) = self.vpsbg_purchases.get(purchase) else {
            return false;
        };
        v.purchase == purchase
            && s.closed_at.is_none()
            && s.creates.is_empty()
            && s.unpaid.is_none()
            && s.associated.is_none()
            // Inspect the recorded interval, without making eligibility depend on
            // today's clock. Consumed/pinned/wrong-installation introductions refuse.
            && self.attest_deadline(&p.machine).is_none_or(|deadline|
                self.attest_introduction(&p.machine, deadline.saturating_sub(1)).is_some())
            && (v.payment_plan.top_up == 0
                || s.deposits.iter().any(|a| {
                    a.revision == v.approval_revision && (a.suppressed || a.transaction.is_some())
                }))
    }

    pub(super) async fn vpsbg_continue_create(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
    ) -> Result<(), String> {
        let p = self.vpsbg_purchase(purchase).ok_or(protocol::REFUSED)?;
        let revision = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?.approval_revision;
        let bound = self.bound_machine_relay(&p.machine)?;
        self.create_once(api, purchase, revision, bound).await
    }

    fn vpsbg_bound(
        &self,
        p: &provisioning::Purchase,
        bound: &BoundMachineRelay,
    ) -> Result<(), String> {
        let checked = self.bound_machine_relay(&p.machine)?;
        if checked.binding != bound.binding
            || p.vpsbg.as_ref().is_none_or(|v| v.binding != bound.binding)
        {
            return Err(protocol::REFUSED.into());
        }
        Ok(())
    }

    async fn vpsbg_response_held(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
        request: protocol::VendorRequest,
        held: &[&[u8]],
    ) -> Result<crate::poc::credit::ClearedValue, String> {
        self.vpsbg_api(api, Some(purchase))?;
        let url = Vendor::Vpsbg.request_url(wire::ORIGIN, &request.path)?;
        api.request(request.method, &url, request.body)
            .await
            .map_err(protocol::ReadError::message)?;
        self.vpsbg_api(api, Some(purchase))?;
        let raw = api.take_vpsbg_response().ok_or(protocol::REFUSED)?;
        let value = wire::reduce_response(
            request.method,
            &request.path,
            api.response_status(),
            &raw,
            |bytes| {
                self.check_output_bytes(bytes)?;
                if held
                    .iter()
                    .any(|secret| crate::redaction::contains(bytes, secret))
                {
                    return Err(protocol::REFUSED.into());
                }
                Ok(())
            },
            |value| {
                self.vpsbg_value_safe(value)
                    && self
                        .protect_output_with(value, held)
                        .is_ok_and(|safe| safe == *value)
            },
        )?;
        if !crate::poc::inference::safe(self, &value, held) {
            return Err(protocol::REFUSED.into());
        }
        Ok(crate::poc::credit::ClearedValue(value))
    }

    /// Fresh pre-create/pay gates. Lists are complete, and name reconciliation precedes any POST.
    async fn vpsbg_create_gates(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
        revision: u64,
        deadline: Option<u64>,
        paying: Option<u64>,
        name_list_already_read: bool,
    ) -> Result<wire::ImageFact, String> {
        self.vpsbg_api(api, Some(purchase))?;
        let p = self
            .vpsbg_purchase(purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        let v = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?;
        if v.approval_revision != revision {
            return Err("VPSBG approval revision changed.".into());
        }
        let plans = self
            .vpsbg_response(api, Some(purchase), wire::read("/v1/servers/plans"))
            .await?;
        let offer = protocol::array(&plans.0)?
            .iter()
            .find(|o| o["id"] == p.selected.offer["id"])
            .ok_or(protocol::REFUSED)?;
        let selected = protocol::Selection {
            offer: offer.clone(),
            image: wire::image(),
            resources: None,
            charge: Vendor::Vpsbg.offer_charge(offer)?,
        };
        let balance = self.vpsbg_balance(api, Some(purchase)).await?;
        if !Vendor::Vpsbg.same_terms(&p.selected, &selected)
            || selected.charge.amount != v.payment_plan.first_period
            || balance.has_valid_card != v.approved_card
        {
            self.vpsbg_reads.terms_changed = true;
            self.procurement_selection = Some(selected);
            return Err(
                "VPSBG terms_changed; approve the current terms and card flag again.".into(),
            );
        }
        if balance.amount < v.payment_plan.first_period {
            self.vpsbg_reads.pause = Some(json!({"kind":"balance_short"}));
            return Err("VPSBG balance_short; no create or pay was sent.".into());
        }
        self.vpsbg_reads.transactions = self
            .vpsbg_collect(
                api,
                Some(purchase),
                "/v1/balance/transactions",
                |t: &wire::TransactionFact| t.id,
            )
            .await?;
        let orders: Vec<wire::OrderFact> = self
            .vpsbg_collect(api, Some(purchase), "/v1/orders", |o: &wire::OrderFact| {
                o.id
            })
            .await
            .map_err(|_| "Check this order at VPSBG".to_string())?;
        if orders
            .iter()
            .any(|o| Some(o.id) != paying && !wire::preflight_order_allowed(o))
            || paying.is_some_and(|id| !orders.iter().any(|o| o.id == id))
        {
            self.vpsbg_reads.pause = Some(json!({"kind":"unpaid_order","pay_allowed":false}));
            return Err("Check this order at VPSBG".into());
        }
        self.vpsbg_reads.orders = orders;
        if !name_list_already_read {
            self.vpsbg_second_writer(api, Some(purchase)).await?;
        }
        let images: Vec<wire::ImageFact> = self
            .vpsbg_collect(
                api,
                Some(purchase),
                "/v1/custom-server-images",
                |i: &wire::ImageFact| i.id,
            )
            .await?;
        let image = images
            .into_iter()
            .find(|i| i.ready(wire::IMAGE_URL, api.now()) && i.size == wire::IMAGE_SIZE)
            .ok_or("The current VPSBG image is not ready for at least one hour.")?;
        if deadline.is_some_and(|end| !wire::budget_fits(api.now(), end)) {
            return Err("too close to the identity deadline to start the order".into());
        }
        self.vpsbg_reads.terms_changed = false;
        self.vpsbg_reads.pause = None;
        Ok(image)
    }

    fn vpsbg_matches(
        &self,
        p: &provisioning::Purchase,
        ack: &wire::CreateAck,
    ) -> Result<(), String> {
        wire::validate_create_ack(ack)?;
        let v = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?;
        if ack.hostname != v.name
            || ack.plan.id != protocol::id(&p.selected.offer)?
            || ack.plan.key != p.selected.offer["key"].as_str().ok_or(protocol::REFUSED)?
            || ack.plan.price_with_vat != p.selected.charge.amount
        {
            return Err("VPSBG server facts conflict with the approved purchase.".into());
        }
        Ok(())
    }

    async fn vpsbg_read_detail(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
        id: u64,
    ) -> Result<wire::Detail, String> {
        let mut response = self
            .vpsbg_response(
                api,
                Some(purchase),
                wire::read(&format!("/v1/servers/{id}")),
            )
            .await?;
        let server: wire::ServerFact =
            serde_json::from_value(response.0.take()).map_err(|_| protocol::REFUSED)?;
        let wire::ServerFact::Live(detail) = server else {
            return Err("The VPSBG server is terminated; check it in the console.".into());
        };
        if detail.server.id != id {
            return Err(protocol::REFUSED.into());
        }
        Ok(*detail)
    }

    /// Uses only a freshly completed name list. A zero result never clears an intent.
    async fn vpsbg_associate_by_name(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
    ) -> Result<bool, String> {
        let p = self
            .vpsbg_purchase(purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        let name = &p.vpsbg.as_ref().ok_or(protocol::REFUSED)?.name;
        let matches = self
            .vpsbg_reads
            .servers
            .iter()
            .filter(|s| match s {
                wire::ServerFact::Live(d) => &d.server.hostname == name,
                wire::ServerFact::Terminated(d) => &d.hostname == name,
            })
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err("Several VPSBG servers have the saved name; purchase paused.".into());
        }
        let Some(server) = matches.first() else {
            return Ok(false);
        };
        let id = server.id();
        let listed = match server {
            wire::ServerFact::Live(d) => d.server.clone(),
            _ => {
                return Err(
                    "The saved VPSBG name belongs to a terminated server; check the console."
                        .into(),
                );
            }
        };
        self.vpsbg_matches(&p, &listed)?;
        let detail = self.vpsbg_read_detail(api, purchase, id).await?;
        self.vpsbg_matches(&p, &detail.server)?;
        if !same_machine(&listed, &detail.server) {
            return Err(protocol::REFUSED.into());
        }
        if self.vpsbg_purchases[purchase].associated.is_none() {
            self.vpsbg_commit(
                purchase,
                Change::Associated {
                    server: AssociationFact::Read(detail.clone()),
                    charge: None,
                    checked_at: api.now(),
                },
            )
            .await?;
        }
        self.vpsbg_record_observed(purchase, detail, api.now())
            .await?;
        Ok(true)
    }

    pub(crate) async fn create_once(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
        revision: u64,
        mut bound: BoundMachineRelay,
    ) -> Result<(), String> {
        self.vpsbg_api(api, Some(purchase))?;
        if !self.vpsbg_create_pending(purchase) {
            return self.vpsbg_reconcile_create(api, purchase).await;
        }
        // Deposit/image preparation cannot consume this create invocation's budget.
        api.vpsbg_begin_window()?;
        // B739: the first provider read is always the complete exact-name inventory,
        // even with no intent tail, no usable image, or terms that now differ.
        self.vpsbg_second_writer(api, Some(purchase)).await?;
        if self.vpsbg_associate_by_name(api, purchase).await? {
            return Ok(());
        }
        let p = self
            .vpsbg_purchase(purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        self.vpsbg_bound(&p, &bound)?;
        if p.vpsbg
            .as_ref()
            .is_none_or(|v| v.approval_revision != revision)
        {
            return Err(protocol::REFUSED.into());
        }
        if self.attest_deadline(&p.machine).is_some() {
            // Private material from an earlier invocation is gone, irrespective of remaining time.
            self.replace_unused_machine(purchase, api.now()).await?;
            bound = self.bound_machine_relay(
                &self
                    .vpsbg_purchase(purchase)
                    .ok_or(protocol::REFUSED)?
                    .machine,
            )?;
        }
        let image = self
            .vpsbg_create_gates(api, purchase, revision, None, None, true)
            .await?;
        if self.vpsbg_associate_by_name(api, purchase).await? {
            return Ok(());
        }
        let p = self
            .vpsbg_purchase(purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        let entry = self
            .dispatch
            .approved_entries
            .get(&p.machine)
            .ok_or(protocol::REFUSED)?
            .approved
            .entry
            .clone();
        api.current()?;
        api.vpsbg_mutation_budget()?;
        let introduction = self.attest_introduction_begin(&entry).await?;
        let public = self.poc_identity_public_keys(&p.machine, &p.identity)?;
        let client = public["authorized_keys"]
            .as_str()
            .ok_or(protocol::REFUSED)?;
        let user_data = wire::compose_user_data(&introduction, client)?;
        let held = Rc::new(HeldCreate {
            introduction,
            user_data,
        });
        self.vpsbg_reads.create_held = Rc::downgrade(&held);
        let mut image = image;
        for attempt in 0..=1 {
            if attempt == 1 {
                // Retain this invocation's held authority and original introduction.
                // Only the request/time window restarts; every send fence still applies.
                api.vpsbg_begin_window()?;
                image = self
                    .vpsbg_create_gates(
                        api,
                        purchase,
                        revision,
                        Some(held.introduction.deadline_unix),
                        None,
                        false,
                    )
                    .await?;
                if self.vpsbg_associate_by_name(api, purchase).await? {
                    return Ok(());
                }
            }
            self.vpsbg_api(api, Some(purchase))?;
            self.vpsbg_bound(&p, &bound)?;
            if !wire::budget_fits(api.now(), held.introduction.deadline_unix) {
                return Err("too close to the identity deadline to start the order".into());
            }
            let state = &self.vpsbg_purchases[purchase];
            let ssh_key = if attempt == 0 {
                None
            } else {
                Some(state.key.as_ref().ok_or(protocol::REFUSED)?.0)
            };
            api.vpsbg_mutation_budget()?;
            let v = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?;
            self.vpsbg_commit(
                purchase,
                Change::CreateSent {
                    attempt,
                    name: v.name.clone(),
                    machine_identity: p.identity.clone(),
                    image: image.clone(),
                    approval_revision: revision,
                    started: api.now(),
                    ssh_key,
                },
            )
            .await?;
            self.vpsbg_api(api, Some(purchase))?;
            let mut body = json!({"name":v.name,"plan":p.selected.offer["key"],"billing_cycle":"1",
                "custom_server_image_id":image.id,"user_data":held.user_data.as_str()});
            if let Some(key) = ssh_key {
                body["ssh_keys"] = json!([key]);
            }
            let request = protocol::VendorRequest {
                method: "POST",
                path: "/v1/servers".into(),
                body: Some(body),
            };
            let mut response = self
                .vpsbg_response_held(api, purchase, request, &held.values())
                .await?;
            let reply: wire::CreateReply =
                serde_json::from_value(response.0.take()).map_err(|_| protocol::REFUSED)?;
            match reply {
                wire::CreateReply::Accepted(server) => {
                    self.vpsbg_matches(&p, &server)?;
                    self.vpsbg_commit(
                        purchase,
                        Change::Associated {
                            server: AssociationFact::Create(server),
                            charge: Some(ChargeEvidence::CreateAccepted {
                                status: api.response_status(),
                                first_period: v.payment_plan.first_period,
                            }),
                            checked_at: api.now(),
                        },
                    )
                    .await?;
                    // An observation is a separate read, never a create prerequisite.
                    return self.vpsbg_observe(api, purchase).await;
                }
                wire::CreateReply::Unpaid { order } => {
                    self.vpsbg_commit(
                        purchase,
                        Change::OrderUnpaid {
                            order,
                            create_attempt: attempt,
                            checked_at: api.now(),
                        },
                    )
                    .await?;
                    return Ok(());
                }
                wire::CreateReply::MissingLogin => {
                    self.vpsbg_commit(
                        purchase,
                        Change::CreateLoginRefused {
                            attempt,
                            reason: LoginReason::MissingLogin,
                            checked_at: api.now(),
                        },
                    )
                    .await?;
                    if attempt == 1 {
                        return Err(
                            "VPSBG refused login; approve a fresh purchase to close this one."
                                .into(),
                        );
                    }
                    self.vpsbg_register_key(api, purchase, client, &held)
                        .await?;
                }
            }
        }
        Err(protocol::REFUSED.into())
    }

    async fn vpsbg_register_key(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
        client: &str,
        held: &HeldCreate,
    ) -> Result<(), String> {
        api.vpsbg_mutation_budget()?;
        self.vpsbg_commit(purchase, Change::KeyRegistrationSent { started: api.now() })
            .await?;
        let request = protocol::VendorRequest {
            method: "POST",
            path: "/v1/ssh-keys".into(),
            body: Some(json!({"name":"tau-web-attest","key":client})),
        };
        let result = self
            .vpsbg_response_held(api, purchase, request, &held.values())
            .await;
        let parsed = ssh_key::PublicKey::from_openssh(client).map_err(|_| protocol::REFUSED)?;
        let fingerprint = parsed.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        let key: wire::SshKeyFact = match result {
            Ok(mut value) => {
                serde_json::from_value(value.0.take()).map_err(|_| protocol::REFUSED)?
            }
            Err(_) => {
                // Registration ambiguity permits reads only; no second registration.
                let keys: Vec<wire::SshKeyFact> = self
                    .vpsbg_collect(
                        api,
                        Some(purchase),
                        "/v1/ssh-keys",
                        |k: &wire::SshKeyFact| k.id,
                    )
                    .await?;
                let mut matching = keys.into_iter().filter(|k| k.key == client);
                let key = matching.next().ok_or(protocol::REFUSED)?;
                if matching.next().is_some() {
                    return Err(protocol::REFUSED.into());
                }
                key
            }
        };
        if key.key != client {
            return Err(protocol::REFUSED.into());
        }
        self.vpsbg_commit(
            purchase,
            Change::KeyRegistered {
                id: key.id,
                fingerprint,
            },
        )
        .await
    }

    async fn vpsbg_observe(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
    ) -> Result<(), String> {
        let id = self.vpsbg_purchases[purchase]
            .associated
            .as_ref()
            .ok_or(protocol::REFUSED)?
            .0
            .ack()
            .id;
        let detail = self.vpsbg_read_detail(api, purchase, id).await?;
        self.vpsbg_record_observed(purchase, detail, api.now())
            .await
    }

    async fn vpsbg_record_observed(
        &mut self,
        purchase: &str,
        detail: wire::Detail,
        checked_at: u64,
    ) -> Result<(), String> {
        if self.vpsbg_purchases[purchase].observed.as_ref() == Some(&detail) {
            return Ok(());
        }
        self.vpsbg_commit(
            purchase,
            Change::Observed {
                server: detail,
                checked_at,
            },
        )
        .await
    }

    pub(super) async fn vpsbg_reconcile_create(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
    ) -> Result<(), String> {
        self.vpsbg_api(api, Some(purchase))?;
        if self.vpsbg_purchases[purchase].closed_at.is_some() {
            return Err(protocol::REFUSED.into());
        }
        // Complete orders and transactions are required after any pay, irrespective of its response.
        if let Some((order, _, _)) = self.vpsbg_purchases[purchase].unpaid {
            let orders: Vec<wire::OrderFact> = self
                .vpsbg_collect(api, Some(purchase), "/v1/orders", |o: &wire::OrderFact| {
                    o.id
                })
                .await?;
            self.vpsbg_reads.transactions = self
                .vpsbg_collect(
                    api,
                    Some(purchase),
                    "/v1/balance/transactions",
                    |t: &wire::TransactionFact| t.id,
                )
                .await?;
            if let Some(paid) = orders.iter().find(|o| o.id == order && o.status == "paid")
                && self.vpsbg_purchases[purchase].pay_sent.is_some()
                && self.vpsbg_purchases[purchase].pay_resolved.is_none()
            {
                self.vpsbg_commit(
                    purchase,
                    Change::PayOrderResolved {
                        order,
                        outcome: PayOutcome::Paid(paid.clone()),
                    },
                )
                .await?;
            }
            self.vpsbg_reads.orders = orders;
        }
        if self.vpsbg_purchases[purchase].associated.is_some() {
            return self.vpsbg_observe(api, purchase).await;
        }
        self.vpsbg_second_writer(api, Some(purchase)).await?;
        if !self.vpsbg_associate_by_name(api, purchase).await? {
            self.vpsbg_reads.pause = Some(
                json!({"kind":"create_unknown","message":"The saved create outcome is unknown; no create will be repeated."}),
            );
        }
        // Orders expose no confirmed server reference yet. Never turn a name/debit into paid evidence.
        Ok(())
    }

    pub(crate) async fn vpsbg_pay_order(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
    ) -> Result<(), String> {
        self.vpsbg_api(api, Some(purchase))?;
        let p = self
            .vpsbg_purchase(purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        let v = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?;
        let state = &self.vpsbg_purchases[purchase];
        let (order, _, _) = state.unpaid.ok_or(protocol::REFUSED)?;
        if state.pay_sent.is_some() {
            return self.vpsbg_reconcile_create(api, purchase).await;
        }
        if state
            .approvals
            .last()
            .is_none_or(|a| a.pay_order != Some(order))
        {
            return Err("Approve payment of this saved VPSBG order first.".into());
        }
        let deadline = self.attest_deadline(&p.machine).ok_or(protocol::REFUSED)?;
        self.vpsbg_create_gates(
            api,
            purchase,
            v.approval_revision,
            Some(deadline),
            Some(order),
            false,
        )
        .await?;
        if self
            .vpsbg_reads
            .orders
            .iter()
            .any(|o| o.id == order && o.status == "paid")
        {
            return self.vpsbg_reconcile_create(api, purchase).await;
        }
        api.vpsbg_mutation_budget()?;
        self.bound_machine_relay(&p.machine)?;
        if !wire::budget_fits(api.now(), deadline) {
            return Err(protocol::REFUSED.into());
        }
        self.vpsbg_commit(
            purchase,
            Change::PayOrderSent {
                order,
                approval_revision: v.approval_revision,
                started: api.now(),
            },
        )
        .await?;
        let request = protocol::VendorRequest {
            method: "POST",
            path: "/v1/orders/pay".into(),
            body: Some(json!({"ids":[order]})),
        };
        // Exact private material is gone. Every composed authority/script contains
        // these markers. Scan their supersets through raw and decoded strings as
        // well as the held token, without reconstructing or retaining private bytes.
        let private_markers: [&[u8]; 2] = [
            b"-----BEGIN OPENSSH PRIVATE KEY-----",
            b"# tau-web CHN-R5a first-boot hook.",
        ];
        let _ = self
            .vpsbg_response_held(api, purchase, request, &private_markers)
            .await;
        self.vpsbg_reconcile_create(api, purchase).await
    }

    pub(super) async fn replace_unused_machine(
        &mut self,
        purchase: &str,
        now: u64,
    ) -> Result<(), String> {
        let p = self
            .vpsbg_purchase(purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        let identity = self
            .allocation()
            .issue(Family::Machines)
            .map_err(|e| e.to_string())?;
        let relay_identity = self
            .allocation()
            .issue(Family::Passes)
            .map_err(|e| e.to_string())?;
        let mut entry = self
            .dispatch
            .approved_entries
            .get(&p.machine)
            .ok_or(protocol::REFUSED)?
            .approved
            .entry
            .clone();
        entry.machine = format!("tau-vpsbg-{}", identity.index);
        let binding = MachinePassBinding {
            purchase: purchase.into(),
            machine: entry.machine.clone(),
            machine_identity: identity.clone(),
            pass_identity: relay_identity.clone(),
        };
        self.vpsbg_commit(
            purchase,
            Change::MachineReplaced {
                old_machine: p.machine,
                entry,
                identity,
                relay_identity,
                binding,
                replaced_at: now,
            },
        )
        .await
    }
}

fn same_machine(a: &wire::CreateAck, b: &wire::CreateAck) -> bool {
    a.id == b.id
        && a.hostname == b.hostname
        && a.plan == b.plan
        && a.billing_cycle == b.billing_cycle
        && a.created_at == b.created_at
}

impl<S: Storage> Store<S> {
    pub(super) fn vpsbg_project_create(&self, record: &Record) -> Result<Projection, String> {
        let refused = protocol::REFUSED;
        let mut p = self
            .vpsbg_purchase(&record.purchase)
            .ok_or(refused)?
            .clone();
        let mut state = self
            .vpsbg_purchases
            .get(&record.purchase)
            .ok_or(refused)?
            .clone();
        if state.closed_at.is_some() {
            return Err(refused.into());
        }
        let v = p.vpsbg.as_ref().ok_or(refused)?;
        let mut allocations = None;
        match &record.change {
            Change::CreateSent {
                attempt,
                name,
                machine_identity,
                image,
                approval_revision,
                started,
                ssh_key,
            } => {
                let admitted = match *attempt {
                    0 => {
                        state.creates.is_empty()
                            && self.vpsbg_create_pending(&record.purchase)
                            && ssh_key.is_none()
                    }
                    1 => {
                        state.creates.len() == 1
                            && state.creates[0].attempt == 0
                            && state.creates[0].refusal.is_some()
                            && state.key.as_ref().is_some_and(|k| Some(k.0) == *ssh_key)
                            && *started >= state.creates[0].started
                            && started.saturating_sub(state.creates[0].started) < 60
                    }
                    _ => false,
                };
                let intro = self
                    .attest_introduction(&p.machine, *started)
                    .ok_or(refused)?;
                if !admitted
                    || state.unpaid.is_some()
                    || state.associated.is_some()
                    || *name != v.name
                    || *machine_identity != p.identity
                    || *approval_revision != v.approval_revision
                    || *started < p.approved_at
                    || !image.ready(&image.url, *started)
                    || wire::validate_image_url(&image.url).is_err()
                    || !wire::budget_fits(*started, intro.deadline_unix)
                    || intro.installation_binding != self.attest_installation_binding(&p.machine)?
                {
                    return Err(refused.into());
                }
                self.bound_machine_relay(&p.machine)?;
                state.creates.push(CreateAttempt {
                    attempt: *attempt,
                    started: *started,
                    refusal: None,
                });
            }
            Change::CreateLoginRefused {
                attempt,
                checked_at,
                reason: LoginReason::MissingLogin,
            } => {
                let a = state.creates.last_mut().ok_or(refused)?;
                if a.attempt != *attempt
                    || a.refusal.is_some()
                    || *checked_at < a.started
                    || state.unpaid.is_some()
                    || state.associated.is_some()
                {
                    return Err(refused.into());
                }
                a.refusal = Some(0); // apply supplies this record's actual journal sequence.
            }
            Change::KeyRegistrationSent { started } => {
                let a = state.creates.last().ok_or(refused)?;
                if state.creates.len() != 1
                    || a.refusal.is_none()
                    || a.attempt != 0
                    || state.unpaid.is_some()
                    || state.associated.is_some()
                    || state.key_registration.is_some()
                    || *started < a.started
                    || started.saturating_sub(a.started) >= 60
                {
                    return Err(refused.into());
                }
                state.key_registration = Some(*started);
            }
            Change::KeyRegistered { id, fingerprint } => {
                if *id == 0
                    || state.key_registration.is_none()
                    || state.key.is_some()
                    || state.unpaid.is_some()
                    || state.creates.len() != 1
                    || state.creates[0].refusal.is_none()
                {
                    return Err(refused.into());
                }
                let public = self.poc_identity_public_keys(&p.machine, &p.identity)?;
                let key = ssh_key::PublicKey::from_openssh(
                    public["authorized_keys"].as_str().ok_or(refused)?,
                )
                .map_err(|_| refused)?;
                if *fingerprint != key.fingerprint(ssh_key::HashAlg::Sha256).to_string() {
                    return Err(refused.into());
                }
                state.key = Some((*id, fingerprint.clone()));
            }
            Change::OrderUnpaid {
                order,
                create_attempt,
                checked_at,
            } => {
                let a = state.creates.last().ok_or(refused)?;
                if *order == 0
                    || a.attempt != *create_attempt
                    || a.refusal.is_some()
                    || *checked_at < a.started
                    || state.unpaid.is_some()
                    || state.associated.is_some()
                    || self.vpsbg_purchases.iter().any(|(id, s)| {
                        id != &record.purchase
                            && s.unpaid.is_some_and(|(other, _, _)| other == *order)
                    })
                {
                    return Err(refused.into());
                }
                state.unpaid = Some((*order, *create_attempt, *checked_at));
            }
            Change::PayOrderSent {
                order,
                approval_revision,
                started,
            } => {
                let (_, _, unpaid_at) = state
                    .unpaid
                    .filter(|(id, _, _)| id == order)
                    .ok_or(refused)?;
                if state.pay_sent.is_some()
                    || state.associated.is_some()
                    || state
                        .approvals
                        .last()
                        .is_none_or(|a| a.pay_order != Some(*order))
                    || *approval_revision != v.approval_revision
                    || *started < unpaid_at
                    || *started < p.approved_at
                    || self
                        .attest_deadline(&p.machine)
                        .is_none_or(|end| !wire::budget_fits(*started, end))
                {
                    return Err(refused.into());
                }
                state.pay_sent = Some((*order, *approval_revision, *started));
            }
            Change::PayOrderResolved { order, outcome } => {
                if state.pay_sent.is_none_or(|(id, _, _)| id != *order)
                    || state.pay_resolved.is_some()
                {
                    return Err(refused.into());
                }
                match outcome {
                    PayOutcome::Paid(fact)
                        if fact.id == *order
                            && fact.status == "paid"
                            && fact.created_at <= crate::clock::MAX_UTC => {}
                    // No non-paid terminal meaning has been confirmed by the account check.
                    _ => return Err(refused.into()),
                }
                state.pay_resolved = Some(outcome.clone());
            }
            Change::Associated {
                server,
                charge,
                checked_at,
            } => {
                if let AssociationFact::Read(detail) = server {
                    wire::validate_detail(detail)?;
                }
                self.vpsbg_matches(&p, server.ack())?;
                let ack = server.ack();
                if state.associated.is_some()
                    || *checked_at < p.approved_at
                    || self.vpsbg_purchases.iter().any(|(id, s)| {
                        id != &record.purchase
                            && s.associated
                                .as_ref()
                                .is_some_and(|(old, _)| old.ack().id == ack.id)
                    })
                {
                    return Err(refused.into());
                }
                match (server, charge) {
                    (
                        AssociationFact::Create(_),
                        Some(ChargeEvidence::CreateAccepted {
                            status,
                            first_period,
                        }),
                    ) if (200..300).contains(status)
                        && *first_period == v.payment_plan.first_period
                        && state.creates.last().is_some_and(|a| a.refusal.is_none())
                        && state.unpaid.is_none() => {}
                    (AssociationFact::Read(_), None) => (),
                    _ => return Err(refused.into()),
                }
                state.associated = Some((server.clone(), charge.clone()));
            }
            Change::Observed { server, checked_at } => {
                wire::validate_detail(server)?;
                self.vpsbg_matches(&p, &server.server)?;
                let (associated, _) = state.associated.as_ref().ok_or(refused)?;
                if !same_machine(associated.ack(), &server.server) || *checked_at < p.approved_at {
                    return Err(refused.into());
                }
                state.observed = Some(server.clone());
            }
            Change::OrderPaid { .. } => {
                // The orders' server reference is unconfirmed. No invented association proof.
                return Err(refused.into());
            }
            Change::MachineReplaced {
                old_machine,
                entry,
                identity,
                relay_identity,
                binding,
                replaced_at,
            } => {
                if !state.creates.is_empty()
                    || state.unpaid.is_some()
                    || state.associated.is_some()
                    || *old_machine != p.machine
                    || *replaced_at < p.approved_at
                    || self.attest_deadline(old_machine).is_none()
                    || identity
                        != &self
                            .allocation()
                            .issue(Family::Machines)
                            .map_err(|e| e.to_string())?
                    || relay_identity
                        != &self
                            .allocation()
                            .issue(Family::Passes)
                            .map_err(|e| e.to_string())?
                    || self.vpsbg_machine_known(&entry.machine)
                    || self
                        .allocation()
                        .machine_pass_bindings()
                        .iter()
                        .any(|b| b.machine == entry.machine)
                    || self.dispatch.approved_entries.contains_key(&entry.machine)
                    || self.poc_targets.contains_key(&entry.machine)
                {
                    return Err(refused.into());
                }
                let mut expected = self
                    .dispatch
                    .approved_entries
                    .get(old_machine)
                    .ok_or(refused)?
                    .approved
                    .entry
                    .clone();
                expected.machine = entry.machine.clone();
                if expected != *entry {
                    return Err(refused.into());
                }
                let mut allocation = self.allocation().clone();
                for old in [&p.identity, &p.relay_identity] {
                    allocation
                        .apply(&allocation::Event::Failed(old.clone()))
                        .map_err(|e| e.to_string())?;
                }
                let mut dispatch = self.measured_dispatch_copy();
                dispatch.approved_entries.remove(old_machine);
                dispatch.associations.retain(|a| &a.entry != old_machine);
                dispatch.current_installations.remove(old_machine);
                dispatch.purchase_approvals.remove(old_machine);
                state.replaced.push(v.binding.clone());
                p.machine = entry.machine.clone();
                p.identity = identity.clone();
                p.relay_identity = relay_identity.clone();
                p.vpsbg.as_mut().ok_or(refused)?.binding = binding.clone();
                p.vpsbg.as_ref().ok_or(refused)?.validate(&p)?;
                // Use the same reservation/dispatch core as Approved, on the retired projection.
                use crate::dispatch::{Access, ApprovedEntry};
                dispatch.apply_poc_purchase(
                    &mut allocation,
                    ApprovedEntry {
                        entry: entry.clone(),
                        identity: identity.clone(),
                        access: Some(Access::ad_hoc()),
                    },
                    p.class_answer,
                )?;
                allocation
                    .apply(&allocation::Event::Reserve(relay_identity.clone()))
                    .map_err(|e| e.to_string())?;
                allocation
                    .bind_machine(binding.clone())
                    .map_err(|e| e.to_string())?;
                allocations = Some((allocation, dispatch));
            }
            _ => return Err(refused.into()),
        }
        p.vpsbg.as_ref().ok_or(refused)?.validate(&p)?;
        Ok(Projection {
            purchase: p,
            state,
            allocations,
        })
    }
}
