//! Delete once, then establish a terminal outcome from protected reads.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteIntent {
    pub machine: String,
    pub server_id: u64,
    pub hostname: String,
    pub reason: String,
    pub started: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteRefusal {
    pub server_id: u64,
    pub message: String,
    pub checked_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TerminationProof {
    Terminated(wire::Terminated),
    EvidencedGone { detail_status: u16, checked_at: u64 },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Retirement {
    pub machine: String,
    pub pass_identity: Identity,
    pub pin_retired: bool,
    pub revoke_requested_at: u64,
}

impl<S: Storage> Store<S> {
    pub(crate) fn vpsbg_machine_context(&self, machine: &str) -> Result<ActionContext, String> {
        let mut purchases = self
            .vpsbg_history()
            .filter(|p| p.vendor == Vendor::Vpsbg && p.machine == machine);
        let p = purchases.next().ok_or(protocol::REFUSED)?;
        if purchases.next().is_some() {
            return Err(protocol::REFUSED.into());
        }
        self.vpsbg_action_context(&p.vpsbg.as_ref().ok_or(protocol::REFUSED)?.purchase)
    }
    fn vpsbg_bound_delete(&self, purchase: &str) -> Result<(String, u64, String), String> {
        let p = self.vpsbg_purchase(purchase).ok_or(protocol::REFUSED)?;
        let v = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?;
        v.validate(p)?;
        let s = self
            .vpsbg_purchases
            .get(purchase)
            .ok_or(protocol::REFUSED)?;
        if s.closed_at.is_some() {
            return Err(protocol::REFUSED.into());
        }
        let ack = s.associated.as_ref().ok_or("No bound VPSBG server; cancel the saved order in the VPSBG console, then check again.")?.0.ack();
        if ack.id == 0 || ack.hostname != v.name {
            return Err(protocol::REFUSED.into());
        }
        wire::delete_server(ack.id, &v.name)?;
        Ok((p.machine.clone(), ack.id, v.name.clone()))
    }
    pub(crate) async fn vpsbg_delete_once(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
        confirmed: bool,
    ) -> Result<(), String> {
        self.vpsbg_api(api, Some(purchase))?;
        let (machine, server_id, hostname) = self.vpsbg_bound_delete(purchase)?;
        if self.vpsbg_purchases[purchase].delete_sent.is_some() {
            return self.vpsbg_delete_check(api, purchase).await;
        }
        let p = self.vpsbg_purchase(purchase).ok_or(protocol::REFUSED)?;
        if !self.vpsbg_is_ready(p) && !self.attest_expired(&machine, api.now()) {
            return Err(
                "Delete is available after certificate readiness or introduction expiry.".into(),
            );
        }
        let displayed_quote = self.vpsbg_reads.delete_quotes.get(purchase).cloned();
        let mut quote = self
            .vpsbg_response(
                api,
                Some(purchase),
                wire::read(&format!("/v1/servers/{server_id}/refund-quote")),
            )
            .await?;
        let quote: wire::Money =
            serde_json::from_value(quote.0.take()).map_err(|_| protocol::REFUSED)?;
        self.vpsbg_reads
            .delete_quotes
            .insert(purchase.into(), quote.clone());
        // A first request is a quote-only review. The page's plain confirm sends confirmed:true.
        if !confirmed {
            return Ok(());
        }
        if displayed_quote.as_ref() != Some(&quote) {
            return Err("Review the latest VPSBG refund quote and confirm deletion again.".into());
        }
        self.vpsbg_api(api, Some(purchase))?;
        api.vpsbg_mutation_budget()?;
        let request = wire::delete_server(server_id, &hostname)?;
        self.vpsbg_commit(
            purchase,
            Change::DeleteSent(DeleteIntent {
                machine,
                server_id,
                hostname,
                reason: wire::DELETE_REASON.into(),
                started: api.now(),
            }),
        )
        .await?;
        let response = self.vpsbg_response(api, Some(purchase), request).await?;
        if response.0["step_up_refused"] == true {
            self.vpsbg_commit(
                purchase,
                Change::DeleteRefused(DeleteRefusal {
                    server_id,
                    message: wire::DELETE_STEP_UP.into(),
                    checked_at: api.now(),
                }),
            )
            .await?;
            return Ok(());
        }
        if response.0["acknowledged"] != true {
            return Err(protocol::REFUSED.into());
        }
        self.vpsbg_reads.delete_acknowledged.insert(purchase.into());
        self.vpsbg_delete_check(api, purchase).await
    }
    pub(crate) async fn vpsbg_delete_check(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
    ) -> Result<(), String> {
        self.vpsbg_api(api, Some(purchase))?;
        let s = self
            .vpsbg_purchases
            .get(purchase)
            .ok_or(protocol::REFUSED)?;
        if s.closed_at.is_some() {
            if matches!(s.closure, Some(ClosureReason::Deleted { .. })) {
                self.vpsbg_retirement(purchase).await?;
                return self.vpsbg_observe_refund(api, purchase).await;
            }
            return Err(protocol::REFUSED.into());
        }
        if s.associated.is_none() {
            return self.vpsbg_check_unpaid_closure(api, purchase).await;
        }
        let (_, server_id, hostname) = self.vpsbg_bound_delete(purchase)?;
        let response = self
            .vpsbg_response(
                api,
                Some(purchase),
                wire::read(&format!("/v1/servers/{server_id}")),
            )
            .await;
        let proof = match response {
            Ok(mut value) => {
                if value.0["evidenced_gone"]["detail_status"] == 404 {
                    TerminationProof::EvidencedGone {
                        detail_status: 404,
                        checked_at: api.now(),
                    }
                } else {
                    let fact: wire::ServerFact =
                        serde_json::from_value(value.0.take()).map_err(|_| protocol::REFUSED)?;
                    match fact {
                        wire::ServerFact::Terminated(t)
                            if t.id == server_id && t.hostname == hostname =>
                        {
                            TerminationProof::Terminated(t)
                        }
                        _ => return Err(
                            "VPSBG deletion is not confirmed; only read-only checks are allowed."
                                .into(),
                        ),
                    }
                }
            }
            Err(_) => {
                // A failed detail read is never absence. Only a complete exact-name list can replace it.
                let rows: Vec<wire::ServerFact> = self
                    .vpsbg_collect(
                        api,
                        Some(purchase),
                        "/v1/servers",
                        |r: &wire::ServerFact| r.id(),
                    )
                    .await?;
                let matching = rows
                    .iter()
                    .filter(|r| r.hostname() == hostname)
                    .collect::<Vec<_>>();
                match matching.as_slice() {
                    [wire::ServerFact::Terminated(t)] if t.id == server_id => {
                        TerminationProof::Terminated(t.clone())
                    }
                    _ => return Err("VPSBG deletion has no unambiguous terminal evidence.".into()),
                }
            }
        };
        self.vpsbg_commit(
            purchase,
            Change::Closed {
                reason: ClosureReason::Deleted { server_id, proof },
                closed_at: api.now(),
            },
        )
        .await?;
        self.vpsbg_retirement(purchase).await?;
        self.vpsbg_observe_refund(api, purchase).await
    }
    async fn vpsbg_retirement(&mut self, purchase: &str) -> Result<(), String> {
        let s = &self.vpsbg_purchases[purchase];
        if s.retirement.is_some() {
            return Ok(());
        }
        let p = self.vpsbg_purchase(purchase).ok_or(protocol::REFUSED)?;
        self.vpsbg_commit(
            purchase,
            Change::Retirement(Retirement {
                machine: p.machine.clone(),
                pass_identity: p.relay_identity.clone(),
                pin_retired: true,
                revoke_requested_at: s.closed_at.ok_or(protocol::REFUSED)?,
            }),
        )
        .await
    }
    async fn vpsbg_observe_refund(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
    ) -> Result<(), String> {
        api.vpsbg_begin_window()?;
        self.vpsbg_balance(api, Some(purchase)).await?;
        let transactions: Vec<wire::TransactionFact> = self
            .vpsbg_collect(
                api,
                Some(purchase),
                "/v1/balance/transactions",
                |t: &wire::TransactionFact| t.id,
            )
            .await?;
        let s = &self.vpsbg_purchases[purchase];
        s.associated.as_ref().ok_or(protocol::REFUSED)?;
        // A server's quoted/total refund never establishes a credited transaction.
        // Only the saved create response's order and this purchase's bound association
        // tie a Refund to its server. B963 has confirmed no orders server-reference field.
        let order = s.unpaid.map(|(order, _, _)| order);
        let matching = transactions
            .iter()
            .filter(|t| {
                t.description == "Refund" && t.amount_with_vat > 0 && Some(t.order_id) == order
            })
            .collect::<Vec<_>>();
        self.vpsbg_reads.refunds.remove(purchase);
        if let [t] = matching.as_slice() {
            self.vpsbg_reads.refunds.insert(
                purchase.into(),
                wire::Money {
                    amount: u64::try_from(t.amount_with_vat).map_err(|_| protocol::REFUSED)?,
                    currency: wire::Currency::Eur,
                },
            );
        }
        self.vpsbg_reads.transactions = transactions;
        Ok(())
    }
    async fn vpsbg_check_unpaid_closure(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
    ) -> Result<(), String> {
        let reason = self
            .vpsbg_unpaid_closure_evidence(api, purchase, wire::CONFIRMED_CANCELLED_ORDER_STATUSES)
            .await?;
        self.vpsbg_commit(
            purchase,
            Change::Closed {
                reason,
                closed_at: api.now(),
            },
        )
        .await
    }
    pub(super) async fn vpsbg_unpaid_closure_evidence(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
        cancelled: &[&str],
    ) -> Result<ClosureReason, String> {
        self.vpsbg_api(api, Some(purchase))?;
        let s = self
            .vpsbg_purchases
            .get(purchase)
            .ok_or(protocol::REFUSED)?;
        if s.closed_at.is_some() || s.associated.is_some() {
            return Err(protocol::REFUSED.into());
        }
        let p = self.vpsbg_purchase(purchase).ok_or(protocol::REFUSED)?;
        let name = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?.name.clone();
        let (saved, _, _) = self.vpsbg_purchases[purchase]
            .unpaid
            .ok_or(protocol::REFUSED)?;
        let orders: Vec<wire::OrderFact> = self
            .vpsbg_collect(api, Some(purchase), "/v1/orders", |o: &wire::OrderFact| {
                o.id
            })
            .await?;
        let order = orders
            .into_iter()
            .find(|o| o.id == saved)
            .ok_or("Check this order at VPSBG")?;
        let transactions: Vec<wire::TransactionFact> = self
            .vpsbg_collect(
                api,
                Some(purchase),
                "/v1/balance/transactions",
                |t: &wire::TransactionFact| t.id,
            )
            .await?;
        let servers: Vec<wire::ServerFact> = self
            .vpsbg_collect(
                api,
                Some(purchase),
                "/v1/servers",
                |s: &wire::ServerFact| s.id(),
            )
            .await?;
        let rows = servers
            .iter()
            .filter(|s| s.hostname() == name)
            .collect::<Vec<_>>();
        let state = &self.vpsbg_purchases[purchase];
        let unresolved_pay = state.pay_sent.is_some() && state.pay_resolved.is_none();
        let reason = if rows.is_empty()
            && wire::order_cancelled(
                &order,
                cancelled,
                unresolved_pay,
                true,
                unpaid_resolves_create(state),
            ) {
            ClosureReason::OrderCancelled {
                order,
                checked_at: api.now(),
            }
        } else if let [wire::ServerFact::Terminated(server)] = rows.as_slice() {
            let debits = transactions
                .iter()
                .filter(|t| wire::order_debit(t, saved))
                .collect::<Vec<_>>();
            if debits.len() > 1
                || !wire::charged_server_gone(&order, debits.first().copied(), server, &name)
            {
                return Err("Check this order at VPSBG".into());
            }
            ClosureReason::ChargedServerGone {
                order,
                debit: debits.first().map(|t| (*t).clone()),
                server: server.clone(),
                checked_at: api.now(),
            }
        } else {
            return Err("Check this order at VPSBG".into());
        };
        Ok(reason)
    }
    pub(super) fn vpsbg_project_delete(&self, record: &Record) -> Result<Projection, String> {
        self.vpsbg_project_delete_with_statuses(record, wire::CONFIRMED_CANCELLED_ORDER_STATUSES)
    }
    pub(super) fn vpsbg_project_delete_with_statuses(
        &self,
        record: &Record,
        cancelled: &[&str],
    ) -> Result<Projection, String> {
        let p = self
            .vpsbg_purchase(&record.purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        let mut state = self
            .vpsbg_purchases
            .get(&record.purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        let v = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?;
        v.validate(&p)?;
        if state.closed_at.is_some() && !matches!(record.change, Change::Retirement(_)) {
            return Err(protocol::REFUSED.into());
        }
        match &record.change {
            Change::DeleteSent(sent) => {
                let (machine, server_id, hostname) = self.vpsbg_bound_delete(&record.purchase)?;
                if state.delete_sent.is_some()
                    || !(self.vpsbg_is_ready(&p) || self.attest_expired(&machine, sent.started))
                    || sent.machine != machine
                    || sent.server_id != server_id
                    || sent.hostname != hostname
                    || sent.reason != wire::DELETE_REASON
                    || sent.started < p.approved_at
                {
                    return Err(protocol::REFUSED.into());
                }
                state.delete_sent = Some(sent.clone());
            }
            Change::DeleteRefused(refusal) => {
                let sent = state.delete_sent.as_ref().ok_or(protocol::REFUSED)?;
                if state.delete_refused.is_some()
                    || refusal.server_id != sent.server_id
                    || refusal.message != wire::DELETE_STEP_UP
                    || refusal.checked_at < sent.started
                {
                    return Err(protocol::REFUSED.into());
                }
                state.delete_refused = Some(refusal.clone());
            }
            Change::Closed { reason, closed_at } => {
                if *closed_at < p.approved_at {
                    return Err(protocol::REFUSED.into());
                }
                match reason {
                    ClosureReason::Deleted { server_id, proof } => {
                        let (_, bound, hostname) = self.vpsbg_bound_delete(&record.purchase)?;
                        if *server_id != bound
                            || state
                                .delete_sent
                                .as_ref()
                                .is_some_and(|sent| *closed_at < sent.started)
                        {
                            return Err(protocol::REFUSED.into());
                        }
                        match proof {
                            TerminationProof::Terminated(t)
                                if t.id == bound && t.hostname == hostname => {}
                            TerminationProof::EvidencedGone {
                                detail_status: 404,
                                checked_at,
                            } if checked_at == closed_at => (),
                            _ => return Err(protocol::REFUSED.into()),
                        }
                    }
                    ClosureReason::OrderCancelled { order, checked_at } => {
                        if state.associated.is_some()
                            || order.created_at > *checked_at
                            || state
                                .unpaid
                                .is_none_or(|(id, _, at)| id != order.id || *checked_at < at)
                            || checked_at != closed_at
                            || !wire::order_cancelled(
                                order,
                                cancelled,
                                state.pay_sent.is_some() && state.pay_resolved.is_none(),
                                true,
                                unpaid_resolves_create(&state),
                            )
                        {
                            return Err(protocol::REFUSED.into());
                        }
                    }
                    ClosureReason::ChargedServerGone {
                        order,
                        debit,
                        server,
                        checked_at,
                    } => {
                        // d8 §16(1): an associated machine must take Deleted and request revocation.
                        if state.associated.is_some()
                            || order.created_at > *checked_at
                            || state
                                .unpaid
                                .is_none_or(|(id, _, at)| id != order.id || *checked_at < at)
                            || checked_at != closed_at
                            || !unpaid_resolves_create(&state)
                            || !wire::charged_server_gone(order, debit.as_ref(), server, &v.name)
                            || debit.as_ref().is_some_and(|t| t.created_at > *checked_at)
                        {
                            return Err(protocol::REFUSED.into());
                        }
                    }
                    _ => return Err(protocol::REFUSED.into()),
                }
                for identity in [&p.identity, &p.relay_identity] {
                    if self
                        .allocation()
                        .entries()
                        .iter()
                        .find(|e| &e.identity == identity)
                        .is_none_or(|e| {
                            !matches!(
                                e.status,
                                allocation::Status::Reserved | allocation::Status::Created
                            )
                        })
                    {
                        return Err(protocol::REFUSED.into());
                    }
                }
                state.closed_at = Some(*closed_at);
                state.closure = Some(reason.clone());
            }
            Change::Retirement(retirement) => {
                if !matches!(state.closure, Some(ClosureReason::Deleted { .. }))
                    || state.retirement.is_some()
                    || retirement.machine != p.machine
                    || retirement.pass_identity != p.relay_identity
                    || !retirement.pin_retired
                    || Some(retirement.revoke_requested_at) != state.closed_at
                    || self.poc_target(&p.machine).is_some()
                    || [&p.identity, &p.relay_identity].iter().any(|id| {
                        self.allocation()
                            .entries()
                            .iter()
                            .find(|e| &e.identity == *id)
                            .is_none_or(|e| {
                                !matches!(
                                    e.status,
                                    allocation::Status::Failed | allocation::Status::Destroyed
                                )
                            })
                    })
                {
                    return Err(protocol::REFUSED.into());
                }
                state.retirement = Some(retirement.clone());
            }
            _ => return Err(protocol::REFUSED.into()),
        }
        Ok(Projection {
            purchase: p,
            state,
            allocations: None,
        })
    }
    pub(super) fn vpsbg_apply_closure(&mut self, p: &provisioning::Purchase, purchase: &str) {
        let mut bindings = self.vpsbg_purchases[purchase].replaced.clone();
        bindings.push(
            p.vpsbg
                .as_ref()
                .expect("validated purchase")
                .binding
                .clone(),
        );
        for binding in bindings {
            let machine = &binding.machine;
            self.dispatch.approved_entries.remove(machine);
            self.dispatch.associations.retain(|a| &a.entry != machine);
            self.dispatch.current_installations.remove(machine);
            self.dispatch.purchase_approvals.remove(machine);
            self.poc_targets.remove(machine);
            self.vpsbg_fence_sessions(machine);
            for identity in [&binding.machine_identity, &binding.pass_identity] {
                let status = self
                    .allocation()
                    .entries()
                    .iter()
                    .find(|e| &e.identity == identity)
                    .expect("validated allocation")
                    .status;
                let event = match status {
                    allocation::Status::Reserved => {
                        Some(allocation::Event::Failed(identity.clone()))
                    }
                    allocation::Status::Created => {
                        Some(allocation::Event::Destroyed(identity.clone()))
                    }
                    _ => None,
                };
                if let Some(event) = event {
                    self.allocation
                        .as_mut()
                        .expect("validated allocation")
                        .apply(&event)
                        .expect("validated retirement");
                }
            }
        }
    }
    pub(super) fn vpsbg_fence_sessions(&mut self, machine: &str) {
        for exposure in &self.exposure_ledger {
            if exposure.bound_set.iter().any(|b| b.machine == machine) {
                self.ended_sessions.insert(exposure.session.clone());
            }
        }
        for session in &self.sessions {
            if session.bound_set.iter().any(|m| m == machine) {
                self.ended_sessions.insert(session.identity.clone());
                session.ended.set(true);
                session.given.borrow_mut().clear();
            }
        }
    }
    pub(super) fn vpsbg_delete_view(&self, view: &mut Value, p: &provisioning::Purchase) {
        let Some(v) = &p.vpsbg else { return };
        let Some(s) = self.vpsbg_purchases.get(&v.purchase) else {
            return;
        };
        view["delete"] = json!({"state":if matches!(s.closure, Some(ClosureReason::Deleted {..})) {"confirmed"} else if s.delete_refused.is_some() {"step_up_refused"} else if s.delete_sent.is_some() {if self.vpsbg_reads.delete_acknowledged.contains(&v.purchase) {"sent"} else {"unknown"}} else {"available"}});
        for (field, money) in [
            (
                "refund_quote",
                self.vpsbg_reads.delete_quotes.get(&v.purchase),
            ),
            ("refund", self.vpsbg_reads.refunds.get(&v.purchase)),
        ] {
            if let Some(m) = money {
                view["delete"][field] = json!({"amount":m.amount,"currency":"EUR"});
            }
        }
        if s.delete_refused.is_some() {
            view["delete"]["message"] = json!(wire::DELETE_STEP_UP);
        }
    }
}
fn unpaid_resolves_create(s: &PurchaseState) -> bool {
    let Some((_, attempt, _)) = s.unpaid else {
        return false;
    };
    s.creates.last().is_some_and(|a| a.attempt == attempt)
        && s.creates
            .iter()
            .all(|a| a.attempt == attempt || a.refusal.is_some())
}
