//! b2c: invented offline responses; no captured account material.
use super::*;
use crate::store::vpsbg::delete::{DeleteIntent, Retirement, TerminationProof};

struct DeleteApi {
    inner: CreateApi,
    context: ActionContext,
    status: u16,
    replies: std::collections::BTreeMap<String, (u16, Option<Vec<u8>>)>,
    deletes: usize,
    delete_status: u16,
    lost: bool,
    calls: Vec<(String, String)>,
}
impl DeleteApi {
    fn new(s: &Store<MemoryStorage>, id: &str, mut inner: CreateApi) -> Self {
        let p = s.vpsbg_purchase(id).unwrap();
        if !s.vpsbg_is_ready(p)
            && let Some(deadline) = s.attest_deadline(&p.machine)
        {
            inner.reads.time = inner.reads.time.max(deadline);
        }
        let mut api = Self {
            inner,
            context: s.vpsbg_action_context(id).unwrap(),
            status: 200,
            replies: Default::default(),
            deletes: 0,
            delete_status: 204,
            lost: false,
            calls: vec![],
        };
        api.reply(
            "/v1/servers/51/refund-quote",
            200,
            json!({"data":{"currency":"EUR","refund_gross":"38.79","services":[{"fake":true}]}}),
        );
        api
    }
    fn action(&mut self) -> &mut Self {
        self.inner.action();
        self
    }
    fn reply(&mut self, path: &str, status: u16, body: Value) {
        self.replies.insert(
            path.into(),
            (status, Some(serde_json::to_vec(&body).unwrap())),
        );
    }
    fn terminal(&mut self, name: &str) {
        self.reply("/v1/servers/51", 200, json!({"data":terminated(name,51)}));
    }
}
impl Api for DeleteApi {
    fn account(&self) -> String {
        self.inner.account()
    }
    fn now(&self) -> u64 {
        self.inner.now()
    }
    fn current(&self) -> Result<(), String> {
        self.inner.current()
    }
    fn vpsbg_context(&self) -> Option<&ActionContext> {
        Some(&self.context)
    }
    fn check_vendor(&self, vendor: Vendor) -> Result<(), String> {
        self.inner.check_vendor(vendor)
    }
    fn response_status(&self) -> u16 {
        self.status
    }
    fn take_vpsbg_response(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.inner.take_vpsbg_response()
    }
    fn vpsbg_begin_window(&mut self) -> Result<(), String> {
        self.inner.vpsbg_begin_window()
    }
    fn vpsbg_mutation_budget(&self) -> Result<(), String> {
        self.inner.vpsbg_mutation_budget()
    }
    async fn request(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Value>,
    ) -> Result<Value, ReadError> {
        let path = url.strip_prefix(wire::ORIGIN).ok_or(protocol::REFUSED)?;
        self.calls.push((method.into(), path.into()));
        assert!(Vendor::Vpsbg.request_method_allowed(wire::ORIGIN, method, url));
        if method == "DELETE" {
            assert!(body.is_none());
            self.inner.reads.vpsbg_mutation_budget()?;
            self.inner.reads.requests += 1;
            self.deletes += 1;
            self.status = self.delete_status;
            if self.lost {
                return Err("fake lost DELETE response".into());
            }
            self.inner.reads.raw = Some(Zeroizing::new(if self.status == 204 {
                vec![]
            } else {
                br#"{"message":"Fake step-up required"}"#.to_vec()
            }));
            return Ok(Value::Null);
        }
        assert_eq!(
            method, "GET",
            "closure never creates, pays or asks for money"
        );
        if let Some((status, bytes)) = self.replies.get(path) {
            self.inner.reads.vpsbg_mutation_budget()?;
            self.inner.reads.requests += 1;
            self.status = *status;
            self.inner.reads.raw = bytes.clone().map(Zeroizing::new);
            return if bytes.is_some() {
                Ok(Value::Null)
            } else {
                Err("fake failed detail read".into())
            };
        }
        let result = self.inner.request(method, url, body).await;
        self.status = self.inner.status;
        result
    }
}
fn terminated(name: &str, id: u64) -> Value {
    // 066/068 shapes: no live plan/address/state/script fields are required.
    json!({"id":id,"hostname":name,"status":"terminated","delete_refund_total":"38.79",
        "ip_addresses":[{"assigned_on":"2026-01-01 00:00:01"}],"discarded":"fake"})
}
fn hostname(s: &Store<MemoryStorage>, id: &str) -> String {
    s.vpsbg_purchase(id)
        .unwrap()
        .vpsbg
        .as_ref()
        .unwrap()
        .name
        .clone()
}
fn confirm_delete(
    s: &mut Store<MemoryStorage>,
    api: &mut DeleteApi,
    purchase: &str,
) -> Result<(), String> {
    block_on(s.vpsbg_delete_once(api.action(), purchase, false))?;
    block_on(s.vpsbg_delete_once(api.action(), purchase, true))
}
fn changes(s: &Store<MemoryStorage>, id: &str) -> Vec<Change> {
    let mut reader = Store::new(s.storage.clone(), DataKey(s.key.0), s.id.clone());
    s.records()
        .filter_map(|number| {
            let bytes = block_on(s.storage.read(&number.to_string())).unwrap();
            let (event, _) = reader.open_record(number, &bytes).unwrap();
            // Like unlock's replay, advance from the exact stored envelope bytes.
            reader.next = number + 1;
            reader.previous = Address(Sha256::digest(&bytes).into());
            match &event {
                Event::Vpsbg(r) if r.purchase == id => Some(r.change.clone()),
                _ => None,
            }
        })
        .collect()
}
fn approve_next(s: &mut Store<MemoryStorage>, api: &mut DeleteApi) -> String {
    s.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
    s.procurement_selection = Some(selected());
    api.inner.reads.balance(5000, false);
    let review = s
        .vpsbg_review(&selected(), &money_balance(5000), api.now())
        .unwrap();
    block_on(s.vpsbg_approve(
        api.inner.action(),
        money_approval("fake-after-delete"),
        review,
    ))
    .unwrap();
    s.procurement
        .as_ref()
        .unwrap()
        .vpsbg
        .as_ref()
        .unwrap()
        .purchase
        .clone()
}

#[test]
fn vpsbg_expired_delete_reload_fresh_approval() {
    for from_list in [false, true] {
        let (mut s, id, inner, probe) = pending(true);
        let old = s.vpsbg_purchase(&id).unwrap().clone();
        let name = hostname(&s, &id);
        assert!(s.poc_target(&old.machine).is_some());
        let context = s.vpsbg_poll_admit(&id, PollKind::Attest).unwrap();
        assert_eq!(
            (context.vendor, context.origin.as_str()),
            (Vendor::Vpsbg, wire::ORIGIN)
        );
        let deadline = s.attest_deadline(&old.machine).unwrap();
        let mut api = DeleteApi::new(&s, &id, inner);
        api.inner.reads.time = deadline;
        assert!(s.attest_expired(&old.machine, api.now()));
        assert_eq!(
            s.vpsbg_introduction_view(&id, api.now())["state"],
            "expired"
        );
        assert!(
            !s.vpsbg_poll_contexts_at(deadline)
                .iter()
                .any(|c| c.attest_pending)
        );
        let setup = s.dispatch.setup_approval;
        block_on(s.vpsbg_delete_once(api.action(), &id, false)).unwrap();
        assert_eq!(api.deletes, 0);
        assert_eq!(
            s.procurement_view()["delete"]["refund_quote"],
            json!({"amount":3879,"currency":"EUR"})
        );
        // A 204 followed by live detail never closes or releases the next purchase.
        assert!(confirm_delete(&mut s, &mut api, &id).is_err());
        assert_eq!(api.deletes, 1);
        assert!(s.vpsbg_purchases[&id].closed_at.is_none());
        assert!(!s.procurement_can_start());
        assert_eq!(s.procurement_view()["delete"]["state"], "sent");
        let mut s = money_reopen(&s);
        assert_eq!(s.procurement_view()["delete"]["state"], "unknown");
        if from_list {
            api.replies.insert("/v1/servers/51".into(), (0, None));
            api.inner.servers(vec![terminated(&name, 51)]);
        } else {
            api.terminal(&name);
        }
        block_on(s.vpsbg_delete_check(api.action(), &id)).unwrap();
        assert_eq!(api.deletes, 1);
        assert!(matches!(
            s.vpsbg_purchases[&id].closure,
            Some(ClosureReason::Deleted { .. })
        ));
        assert!(s.poc_target(&old.machine).is_none());
        assert!(s.attest_target(&old.machine).is_none());
        assert!(s.vpsbg_probe_admit(&probe, api.now()).is_err());
        assert!(block_on(s.poc_bind(&old.machine)).is_err());
        assert!(s.relay_key(&old.machine).is_none());
        assert!(s.procurement_can_start());
        assert_eq!(s.dispatch.setup_approval, setup);
        // A nonempty setup marker is also preserved by the same actual closure transition.
        let (mut live, live_id, inner, _) = pending(false);
        live.dispatch.setup_approval = Some(42);
        let mut check = DeleteApi::new(&live, &live_id, inner);
        check.terminal(&hostname(&live, &live_id));
        block_on(live.vpsbg_delete_check(check.action(), &live_id)).unwrap();
        assert_eq!(live.dispatch.setup_approval, Some(42));
        let before = s.records();
        block_on(s.vpsbg_delete_check(api.action(), &id)).unwrap();
        assert_eq!(
            s.records(),
            before,
            "terminal replay never appends a second close"
        );
        let mut s = money_reopen(&s);
        assert!(s.procurement_can_start());
        assert_eq!(s.dispatch.setup_approval, setup);
        assert!(s.attest_target(&old.machine).is_none());
        assert!(s.vpsbg_fence(&api.account()).unwrap().1.is_some());
        assert!(s.vpsbg_poll_admit(&id, PollKind::Deposit).is_ok());
        assert!(
            s.procurement_view()["archive"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["purchase"] == id)
        );
        assert_eq!(
            s.procurement_view()["closed"]["delete"]["state"],
            "confirmed"
        );
        let new_id = approve_next(&mut s, &mut api);
        let fresh = s.vpsbg_purchase(&new_id).unwrap();
        assert_ne!(fresh.identity, old.identity);
        assert_ne!(fresh.relay_identity, old.relay_identity);
        assert_ne!(new_id, id);
        let entry = s.dispatch.approved_entries[&fresh.machine]
            .approved
            .entry
            .clone();
        drop(block_on(s.attest_introduction_begin(&entry)).unwrap());
        assert!(block_on(s.attest_introduction_begin(&entry)).is_err());
        api.context = s.vpsbg_action_context(&id).unwrap();
        let mut row = money_row(101, "19.03", "bitcoin-ln", "Deposit");
        row["created_at"] = json!("2026-01-01T00:00:00Z");
        api.inner.reads.transactions(vec![row]);
        block_on(s.vpsbg_deposit_check(api.action(), &id)).unwrap();
        assert!(s.vpsbg_purchases[&id].deposits[0].transaction.is_some());
        assert!(s.vpsbg_fence(&api.account()).unwrap().0.is_empty());
        assert!(s.vpsbg_purchases[&new_id].deposits.is_empty());
        assert!(s.vpsbg_deposit_view(&id, api.now()).get("bolt11").is_none());
        assert_eq!(
            changes(&s, &id)
                .iter()
                .filter(|c| matches!(c, Change::DeleteSent(_)))
                .count(),
            1
        );
    }
}

#[test]
fn vpsbg_delete_sends_once_and_shows_step_up() {
    let (mut waiting, waiting_id, mut inner, _) = pending(false);
    let reads = inner.reads.calls.len();
    assert!(block_on(waiting.vpsbg_delete_once(inner.action(), &waiting_id, true)).is_err());
    assert_eq!(
        inner.reads.calls.len(),
        reads,
        "an unexpired pending machine cannot be deleted"
    );
    let (mut s, id, inner, _) = pending(false);
    let name = hostname(&s, &id);
    let mut api = DeleteApi::new(&s, &id, inner);
    assert!(block_on(s.vpsbg_delete_once(api.action(), &id, true)).is_err());
    assert_eq!(api.deletes, 0, "confirmation needs a published quote");
    api.reply(
        "/v1/servers/51/refund-quote",
        200,
        json!({"currency":"EUR","refund_gross":"38.78"}),
    );
    assert!(block_on(s.vpsbg_delete_once(api.action(), &id, true)).is_err());
    assert_eq!(api.deletes, 0, "a changed quote needs another confirmation");
    api.lost = true;
    assert!(confirm_delete(&mut s, &mut api, &id).is_err());
    assert_eq!(api.deletes, 1);
    let mut s = money_reopen(&s);
    assert!(confirm_delete(&mut s, &mut api, &id).is_err());
    assert!(block_on(s.vpsbg_delete_check(api.action(), &id)).is_err());
    assert_eq!(api.deletes, 1);
    assert!(s.vpsbg_purchases[&id].closed_at.is_none());
    api.reply("/v1/servers/51", 404, json!({"message":"Server not found"}));
    block_on(s.vpsbg_delete_check(api.action(), &id)).unwrap();
    assert!(matches!(
        s.vpsbg_purchases[&id].closure,
        Some(ClosureReason::Deleted {
            proof: TerminationProof::EvidencedGone {
                detail_status: 404,
                ..
            },
            ..
        })
    ));
    assert_eq!(api.deletes, 1);
    assert!(s.vpsbg_machine_context("wrong-machine").is_err());

    let (mut s, id, inner, _) = pending(false);
    let mut api = DeleteApi::new(&s, &id, inner);
    api.delete_status = 403;
    confirm_delete(&mut s, &mut api, &id).unwrap();
    assert_eq!(s.procurement_view()["delete"]["state"], "step_up_refused");
    assert!(
        s.procurement_view()["delete"]["message"]
            .as_str()
            .unwrap()
            .contains("VPSBG console")
    );
    assert!(s.vpsbg_purchases[&id].delete_refused.is_some());
    let mut s = money_reopen(&s);
    assert_eq!(s.procurement_view()["delete"]["state"], "step_up_refused");
    assert!(confirm_delete(&mut s, &mut api, &id).is_err());
    assert_eq!(api.deletes, 1);
    // Even an evidenced 404 is useful only for this purchase's bound server route.
    for path in ["/v1/servers/52/refund-quote", "/v1/servers?page=1"] {
        assert!(
            Vendor::Vpsbg
                .reduce_response(
                    "GET",
                    path,
                    404,
                    br#"{"message":"Server not found"}"#,
                    |_| Ok(()),
                    |_| true
                )
                .is_err()
        );
    }
    for wrong in ["id", "hostname"] {
        let (mut s, id, inner, _) = pending(false);
        let mut api = DeleteApi::new(&s, &id, inner);
        let mut intent = DeleteIntent {
            machine: "fake-create".into(),
            server_id: 51,
            hostname: hostname(&s, &id),
            reason: wire::DELETE_REASON.into(),
            started: api.now(),
        };
        if wrong == "id" {
            intent.server_id = 52;
        } else {
            intent.hostname.push('x');
        }
        let record = Record {
            purchase: id.clone(),
            change: Change::DeleteSent(intent),
        };
        let count = s.records();
        assert!(block_on(s.vpsbg_commit(&id, record.change.clone())).is_err());
        assert!(s.replay_vpsbg(s.next, &record).is_err());
        assert_eq!(s.records(), count);
        assert_eq!(api.deletes, 0);
        assert!(block_on(s.vpsbg_delete_once(api.action(), &id, false)).is_ok());
    }
    assert_eq!(name, format!("tau-web-{}", "c".repeat(32)));
}

#[test]
fn vpsbg_deleted_machine_publishes_revoke_request() {
    let (mut s, id, inner, probe) = pending(false);
    accept(&mut s, &probe);
    block_on(s.vpsbg_mark_ready(&id, inner.now())).unwrap();
    let session = block_on(s.poc_bind(&probe.machine)).unwrap();
    let origin = s
        .sessions
        .iter()
        .find(|entry| entry.identity == session)
        .unwrap()
        .clone();
    let key = hex::encode(s.relay_key(&probe.machine).unwrap().public_key());
    let capability = s.bound_machine_relay(&probe.machine).unwrap();
    s.vpsbg_reads
        .relay_admitted
        .insert((id.clone(), probe.machine.clone()));
    let mut api = DeleteApi::new(&s, &id, inner);
    api.terminal(&hostname(&s, &id));
    // An unconfirmed orders member cannot tie a refund to this server.
    api.inner.orders("refunded");
    let mut orders: Value =
        serde_json::from_slice(&api.inner.reads.responses["GET /v1/orders?page=1"]).unwrap();
    orders["data"][0]["server_id"] = json!(51);
    api.inner.reads.responses.insert(
        "GET /v1/orders?page=1".into(),
        serde_json::to_vec(&orders).unwrap(),
    );
    api.inner
        .reads
        .transactions(vec![money_row(71, "38.79", "balance", "Refund")]);
    block_on(s.vpsbg_delete_check(api.action(), &id)).unwrap();
    assert!(origin.ended.get());
    assert!(block_on(s.connection_session_for(&probe.machine, Some(&origin))).is_err());
    assert!(s.bound_relay_key(&capability).is_none());
    assert!(s.relay_key(&probe.machine).is_none());
    assert!(s.vpsbg_probe_admit(&probe, api.now()).is_err());
    assert!(block_on(s.poc_bind(&probe.machine)).is_err());
    assert!(s.attest_target(&probe.machine).is_none());
    assert!(
        s.procurement_view()["closed"]["delete"]
            .get("refund")
            .is_none()
    );
    for replay in [false, true] {
        if replay {
            s = money_reopen(&s);
        }
        let card = &s.procurement_view()["closed"];
        assert_eq!(card["relay_pass"]["state"], "revoke_requested");
        assert_eq!(card["relay_pass"]["key"], key);
        assert_eq!(card["relay_pass"]["host"], "8.8.8.8");
        assert_eq!(
            card["relay_pass"]["revoke_requested_at"],
            s.vpsbg_purchases[&id].closed_at.unwrap()
        );
        assert!(s.vpsbg_purchases[&id].retirement.is_some());
        assert!(s.relay_key(&probe.machine).is_none());
        assert!(s.attest_target(&probe.machine).is_none());
        assert!(s.ended_sessions.contains(&session));
    }
    let records = changes(&s, &id);
    assert_eq!(
        records
            .iter()
            .filter(|c| matches!(c, Change::Retirement(_)))
            .count(),
        1
    );
    let bad = Change::Retirement(Retirement {
        machine: probe.machine.clone(),
        pass_identity: probe.binding.pass_identity.clone(),
        pin_retired: true,
        revoke_requested_at: api.now(),
    });
    assert!(block_on(s.vpsbg_commit(&id, bad)).is_err());
}

fn unpaid(pay: bool) -> (Store<MemoryStorage>, String, DeleteApi) {
    let (mut s, id, mut inner) = fresh(false);
    issue_unexpired(&mut s, &id, inner.now());
    block_on(s.vpsbg_commit(
        &id,
        Change::DepositSuppressed {
            attempt: 0,
            order: Some(101),
            reason: SuppressionReason::CoveredFromElsewhere,
            balance: 5000,
            first_period: 3901,
            checked_at: inner.now(),
        },
    ))
    .unwrap();
    inner.reply = Reply::Unpaid;
    create(&mut s, &mut inner, &id).unwrap();
    if pay {
        inner.orders("unpaid");
        let selected = s.procurement.as_ref().unwrap().selected.clone();
        let review = s
            .vpsbg_review(&selected, &money_balance(5000), inner.now())
            .unwrap();
        block_on(s.vpsbg_approve(inner.action(), money_approval("fake-create"), review)).unwrap();
        // Keep the pay unresolved: neither the lost reply nor the reads prove application.
        inner.apply_pay = false;
        inner.lose_pay = true;
        block_on(s.vpsbg_pay_order(inner.action(), &id)).unwrap();
        assert!(s.vpsbg_purchases[&id].pay_sent.is_some());
        assert!(s.vpsbg_purchases[&id].pay_resolved.is_none());
    }
    let api = DeleteApi::new(&s, &id, inner);
    (s, id, api)
}

#[test]
fn vpsbg_unpaid_order_closures() {
    assert!(wire::CONFIRMED_CANCELLED_ORDER_STATUSES.is_empty());
    for status in ["paid", "cancelled", "refunded", "unpaid", "unknown"] {
        for pay in [false, true] {
            let (mut s, id, mut api) = unpaid(pay);
            api.inner.orders(status);
            let before = s.records();
            assert!(block_on(s.vpsbg_delete_check(api.action(), &id)).is_err());
            assert_eq!(s.records(), before);
            assert!(s.vpsbg_purchases[&id].closed_at.is_none());
            assert_eq!(api.deletes, 0);
            let evidence = block_on(s.vpsbg_unpaid_closure_evidence(
                api.action(),
                &id,
                &["cancelled", "paid"],
            ));
            assert_eq!(evidence.is_ok(), status == "cancelled" && !pay);
            let fact = wire::OrderFact {
                id: 71,
                created_at: MONEY_NOW,
                status: status.into(),
                server_id: None,
            };
            assert_eq!(
                wire::order_cancelled(&fact, &["cancelled"], pay, true, true),
                status == "cancelled" && !pay
            );
        }
    }
    // Missing and partial reads cannot manufacture a terminal order.
    for partial in [false, true] {
        let (mut s, id, mut api) = unpaid(false);
        if partial {
            api.reply("/v1/orders?page=1",200,json!({"data":[{"id":71,"created_at":"2026-01-01T00:00:00Z","status":"cancelled"}],"meta":{"current_page":1,"last_page":2,"total":11,"per_page":10}}));
        }
        let before = s.records();
        assert!(block_on(s.vpsbg_delete_check(api.action(), &id)).is_err());
        assert!(
            block_on(s.vpsbg_unpaid_closure_evidence(api.action(), &id, &["cancelled"])).is_err()
        );
        assert_eq!(s.records(), before);
    }
    // A test-only confirmed set exercises precisely the production replay predicate.
    let (mut s, id, mut api) = unpaid(false);
    let fence = s.vpsbg_fence(&api.account()).unwrap();
    api.inner.orders("cancelled");
    let reason =
        block_on(s.vpsbg_unpaid_closure_evidence(api.action(), &id, &["cancelled"])).unwrap();
    let record = Record {
        purchase: id.clone(),
        change: Change::Closed {
            reason,
            closed_at: api.now(),
        },
    };
    assert!(
        s.vpsbg_projection(&record).is_err(),
        "production admits no unconfirmed status"
    );
    let projected = s
        .vpsbg_project_delete_with_statuses(&record, &["cancelled"])
        .unwrap();
    let number = block_on(s.commit(&Event::Vpsbg(record.clone()))).unwrap();
    s.apply_vpsbg(number, &record, projected);
    assert!(s.procurement_can_start());
    assert_eq!(s.vpsbg_fence(&api.account()).unwrap(), fence);
    // Production's empty set intentionally refuses this test-only terminal on ordinary replay.
    api.inner
        .reads
        .responses
        .insert("GET /v1/orders?page=1".into(), EMPTY_PAGE.to_vec());
    let new_id = approve_next(&mut s, &mut api);
    assert_ne!(new_id, id);
    assert_eq!(s.vpsbg_fence(&api.account()).unwrap(), fence);

    for pay in [false, true] {
        for conflict in [
            "none",
            "paid",
            "two",
            "reference",
            "zero",
            "live",
            "no_charge",
        ] {
            let (mut s, id, mut api) = unpaid(pay);
            let name = hostname(&s, &id);
            api.inner.orders(if conflict == "paid" {
                "paid"
            } else {
                "refunded"
            });
            if conflict != "no_charge" && conflict != "paid" {
                api.inner.reads.transactions(vec![money_row(
                    71,
                    "-39.01",
                    "balance",
                    "Order Payment",
                )]);
            }
            let rows = match conflict {
                "two" => vec![terminated(&name, 51), terminated(&name, 52)],
                "zero" => vec![],
                "live" => vec![terminated(&name, 51), detail(&name)],
                _ => vec![terminated(&name, 51)],
            };
            api.inner.servers(rows);
            if conflict == "reference" {
                let mut rows: Value =
                    serde_json::from_slice(&api.inner.reads.responses["GET /v1/orders?page=1"])
                        .unwrap();
                rows["data"][0]["server_id"] = json!(52);
                api.inner.reads.responses.insert(
                    "GET /v1/orders?page=1".into(),
                    serde_json::to_vec(&rows).unwrap(),
                );
            }
            let before = s.records().count();
            let result = block_on(s.vpsbg_delete_check(api.action(), &id));
            if conflict == "none" || conflict == "paid" || conflict == "reference" {
                result.unwrap();
                assert_eq!(s.records().count(), before + 1);
                assert!(matches!(
                    s.vpsbg_purchases[&id].closure,
                    Some(ClosureReason::ChargedServerGone { .. })
                ));
                assert!(s.vpsbg_purchases[&id].associated.is_none());
                assert!(s.vpsbg_purchases[&id].pay_resolved.is_none());
                if let Some(ClosureReason::ChargedServerGone { order, .. }) =
                    &s.vpsbg_purchases[&id].closure
                {
                    assert_eq!(order.server_id, None, "unconfirmed wire reference ignored");
                }
                assert!(s.procurement_can_start());
                let reopened = money_reopen(&s);
                assert!(reopened.procurement_can_start());
                assert!(!reopened.vpsbg_fence(&api.account()).unwrap().0.is_empty());
            } else {
                assert!(result.is_err(), "{conflict}");
                assert_eq!(s.records().count(), before);
                assert!(!s.procurement_can_start());
            }
            assert_eq!(api.deletes, 0);
            assert!(api.calls.iter().all(|(method, _)| method == "GET"));
            assert_eq!(api.inner.creates, 1);
            assert_eq!(api.inner.pays, usize::from(pay));
        }
    }
    let (mut s, id, mut api) = unpaid(false);
    api.inner.servers(vec![detail(&hostname(&s, &id))]);
    block_on(s.vpsbg_reconcile_create(api.inner.action(), &id)).unwrap();
    assert!(s.vpsbg_purchases[&id].unpaid.is_some());
    assert!(s.vpsbg_purchases[&id].associated.is_some());
    let fact = wire::OrderFact {
        id: 71,
        created_at: MONEY_NOW,
        status: "paid".into(),
        server_id: Some(51),
    };
    let server = wire::Terminated {
        id: 51,
        hostname: hostname(&s, &id),
        status: wire::TerminatedStatus::Terminated,
        delete_refund_total: None,
    };
    let close = Change::Closed {
        reason: ClosureReason::ChargedServerGone {
            order: fact,
            debit: None,
            server,
            checked_at: api.now(),
        },
        closed_at: api.now(),
    };
    assert!(
        block_on(s.vpsbg_commit(&id, close)).is_err(),
        "d8 §16(1) forbids associated ChargedServerGone"
    );
    api.terminal(&hostname(&s, &id));
    block_on(s.vpsbg_delete_check(api.action(), &id)).unwrap();
    assert_eq!(
        s.procurement_view()["closed"]["relay_pass"]["state"],
        "revoke_requested"
    );
}

#[test]
fn vpsbg_completed_machine_delete_keeps_current() {
    let (mut s, id, inner, probe) = pending(false);
    accept(&mut s, &probe);
    block_on(s.vpsbg_mark_ready(&id, inner.now())).unwrap();
    let mut api = DeleteApi::new(&s, &id, inner);
    let current_id = approve_next(&mut s, &mut api);
    let current = s.procurement.clone();
    let allocations = s
        .vpsbg_purchase(&current_id)
        .unwrap()
        .vpsbg
        .as_ref()
        .unwrap()
        .binding
        .clone();
    let selected = s.procurement_selection.clone();
    let setup = s.dispatch.setup_approval;
    api.context = s.vpsbg_machine_context(&probe.machine).unwrap();
    api.terminal(&hostname(&s, &id));
    confirm_delete(&mut s, &mut api, &id).unwrap();
    assert_eq!(api.deletes, 1);
    assert_eq!(s.procurement, current);
    assert_eq!(s.procurement_selection, selected);
    assert_eq!(s.dispatch.setup_approval, setup);
    assert!(
        s.dispatch
            .approved_entries
            .contains_key("fake-after-delete")
    );
    assert!(s.completed_purchases.is_empty());
    assert!(s.bound_machine_relay(&allocations.machine).is_ok());
    let s = money_reopen(&s);
    assert_eq!(s.procurement, current);
    assert_eq!(
        s.vpsbg_purchases[&id].retirement.as_ref().unwrap().machine,
        probe.machine
    );
    assert!(s.relay_key(&probe.machine).is_none());
    assert!(s.relay_key(&allocations.machine).is_some());
}

#[test]
fn vpsbg_delete_protocol_is_exact_and_protected() {
    let name = format!("tau-web-{}", "a".repeat(32));
    let request = wire::delete_server(51, &name).unwrap();
    assert_eq!(request.method, "DELETE");
    assert!(request.body.is_none());
    assert_eq!(
        request.path,
        format!("/v1/servers/51?reason=No%20longer%20required&hostname={name}")
    );
    for path in [
        request.path.replace("%20", "+"),
        request.path.replace("51?", "051?"),
        format!("{}&extra=1", request.path),
        "/v1/servers/51/startup-script".into(),
    ] {
        assert!(!Vendor::Vpsbg.request_method_allowed(
            wire::ORIGIN,
            "DELETE",
            &format!("{}{path}", wire::ORIGIN)
        ));
    }
    assert!(!Vendor::Vpsbg.request_method_allowed(
        wire::ORIGIN,
        "GET",
        &format!("{}{}", wire::ORIGIN, request.path)
    ));
    let reduce = |method, path, status, bytes: &[u8]| {
        Vendor::Vpsbg.reduce_response(method, path, status, bytes, |_| Ok(()), |_| true)
    };
    assert_eq!(
        reduce("DELETE", &request.path, 204, b"").unwrap(),
        json!({"acknowledged":true})
    );
    assert!(reduce("DELETE", &request.path, 204, b"{}").is_err());
    assert!(reduce("DELETE", &request.path, 403, b"{").is_err());
    assert!(
        Vendor::Vpsbg
            .reduce_response(
                "DELETE",
                &request.path,
                204,
                b"",
                |_| Err("blocked".into()),
                |_| true
            )
            .is_err()
    );
    let quote = "/v1/servers/51/refund-quote";
    assert_eq!(
        reduce(
            "GET",
            quote,
            200,
            br#"{"currency":"EUR","refund_gross":"12.34"}"#
        )
        .unwrap()["amount"],
        1234
    );
    for amount in [
        json!(12.34),
        json!("12.345"),
        json!("-1.00"),
        json!("1e2"),
        json!("18446744073709551615.00"),
        Value::Null,
    ] {
        let body = serde_json::to_vec(&json!({"currency":"EUR","refund_gross":amount})).unwrap();
        assert!(reduce("GET", quote, 200, &body).is_err());
    }
    for bytes in [
        b"".as_slice(),
        b"{".as_slice(),
        br#"{"message":"different error"}"#.as_slice(),
    ] {
        assert!(reduce("GET", "/v1/servers/51", 404, bytes).is_err());
    }
    assert!(
        Vendor::Vpsbg
            .reduce_response(
                "GET",
                "/v1/servers/51",
                404,
                br#"{"message":"Server not found","discarded":["held fake secret"]}"#,
                |_| Ok(()),
                |_| false
            )
            .is_err()
    );
    for path in ["/v1/servers/51", "/v1/servers?page=1"] {
        let row = terminated(&name, 51);
        let bytes = if path.ends_with("page=1") {
            server_page(vec![row])
        } else {
            serde_json::to_vec(&json!({"data":row})).unwrap()
        };
        let fact = reduce("GET", path, 200, &bytes).unwrap();
        let fact = if path.ends_with("page=1") {
            fact["data"][0].clone()
        } else {
            fact
        };
        let fact: wire::ServerFact = serde_json::from_value(fact).unwrap();
        assert!(matches!(
            fact,
            wire::ServerFact::Terminated(wire::Terminated {
                delete_refund_total: Some(3879),
                ..
            })
        ));
    }
}

#[test]
fn vpsbg_closed_delete_is_atomic_before_retirement() {
    let (mut s, id, inner, probe) = pending(false);
    let terminal = wire::Terminated {
        id: 51,
        hostname: hostname(&s, &id),
        status: wire::TerminatedStatus::Terminated,
        delete_refund_total: None,
    };
    let close = Change::Closed {
        reason: ClosureReason::Deleted {
            server_id: 51,
            proof: TerminationProof::Terminated(terminal),
        },
        closed_at: inner.now(),
    };
    for bad in [
        Change::Closed {
            reason: ClosureReason::Deleted {
                server_id: 52,
                proof: TerminationProof::EvidencedGone {
                    detail_status: 404,
                    checked_at: inner.now(),
                },
            },
            closed_at: inner.now(),
        },
        Change::Closed {
            reason: ClosureReason::Deleted {
                server_id: 51,
                proof: TerminationProof::EvidencedGone {
                    detail_status: 204,
                    checked_at: inner.now(),
                },
            },
            closed_at: inner.now(),
        },
    ] {
        let before = s.records();
        assert!(block_on(s.vpsbg_commit(&id, bad.clone())).is_err());
        assert!(
            s.replay_vpsbg(
                s.next,
                &Record {
                    purchase: id.clone(),
                    change: bad
                }
            )
            .is_err()
        );
        assert_eq!(s.records(), before);
    }
    block_on(s.vpsbg_commit(&id, close.clone())).unwrap();
    let mut s = money_reopen(&s);
    assert!(s.vpsbg_purchases[&id].retirement.is_none());
    assert_eq!(
        s.procurement_view()["closed"]["relay_pass"]["state"],
        "revoke_requested"
    );
    assert!(s.procurement_can_start());
    assert!(s.relay_key(&probe.machine).is_none());
    assert!(s.vpsbg_probe_admit(&probe, inner.now()).is_err());
    assert!(s.attest_target(&probe.machine).is_none());
    assert!(block_on(s.vpsbg_commit(&id, close)).is_err());
    let mut api = DeleteApi::new(&s, &id, inner);
    block_on(s.vpsbg_delete_check(api.action(), &id)).unwrap();
    assert!(s.vpsbg_purchases[&id].retirement.is_some());
    assert_eq!(api.deletes, 0);
}

#[test]
fn vpsbg_delete_intent_append_fences_and_strict_records() {
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    enum BeforeDelete {
        Ready { accepted_at: u64 },
    }
    let BeforeDelete::Ready { accepted_at } =
        serde_json::from_value(json!({"ready":{"accepted_at":1}})).unwrap();
    assert_eq!(accepted_at, 1);
    for fault in [Fault::Fail(1), Fault::LandThenFail(3)] {
        let (mut s, id, inner, _) = pending(false);
        let mut api = DeleteApi::new(&s, &id, inner);
        let intent = Change::DeleteSent(DeleteIntent {
            machine: "fake-create".into(),
            server_id: 51,
            hostname: hostname(&s, &id),
            reason: wire::DELETE_REASON.into(),
            started: api.now(),
        });
        assert!(serde_json::from_value::<BeforeDelete>(json!(intent)).is_err());
        let mut malformed = json!(Record {
            purchase: id.clone(),
            change: intent
        });
        malformed["change"]["delete_sent"]["extra"] = json!(true);
        assert!(serde_json::from_value::<Record>(malformed.clone()).is_err());
        malformed["change"]["delete_sent"]
            .as_object_mut()
            .unwrap()
            .remove("extra");
        malformed["change"]["delete_sent"]
            .as_object_mut()
            .unwrap()
            .remove("hostname");
        assert!(serde_json::from_value::<Record>(malformed).is_err());
        s.storage.fault(fault);
        assert!(confirm_delete(&mut s, &mut api, &id).is_err());
        assert_eq!(
            api.deletes, 0,
            "a failed or ambiguous intent append sends nothing"
        );
        let mut s = money_reopen(&s);
        if matches!(fault, Fault::LandThenFail(3)) {
            assert!(s.vpsbg_purchases[&id].delete_sent.is_some());
            assert!(confirm_delete(&mut s, &mut api, &id).is_err());
            assert_eq!(api.deletes, 0, "a landed intent only reconciles");
        } else {
            assert!(s.vpsbg_purchases[&id].delete_sent.is_none());
        }
    }
}

#[test]
fn vpsbg_pending_delete_keeps_late_deposit_settlement() {
    for step_up in [false, true] {
        for automatic in [false, true] {
            for failed_detail in [false, true] {
                let (mut s, id, mut api) = if automatic {
                    // A 2xx CreateAck associates before the separate detail read fails.
                    // A deposit tick must stay independent of deletion in this state.
                    let (mut s, id, mut inner) = fresh(false);
                    issue_unexpired(&mut s, &id, inner.now());
                    block_on(s.vpsbg_commit(
                        &id,
                        Change::DepositSuppressed {
                            attempt: 0,
                            order: Some(101),
                            reason: SuppressionReason::CoveredFromElsewhere,
                            balance: 5000,
                            first_period: 3901,
                            checked_at: inner.now(),
                        },
                    ))
                    .unwrap();
                    let detail = inner.reads.responses.remove("GET /v1/servers/51").unwrap();
                    assert!(create(&mut s, &mut inner, &id).is_err());
                    assert_eq!(inner.creates, 1);
                    assert!(s.vpsbg_purchases[&id].associated.is_some());
                    assert!(s.vpsbg_purchases[&id].observed.is_none());
                    inner
                        .reads
                        .responses
                        .insert("GET /v1/servers/51".into(), detail);
                    let api = DeleteApi::new(&s, &id, inner);
                    (s, id, api)
                } else {
                    let (s, id, inner, _) = pending(true);
                    let api = DeleteApi::new(&s, &id, inner);
                    (s, id, api)
                };
                api.lost = !step_up;
                api.delete_status = if step_up { 403 } else { 204 };
                let result = confirm_delete(&mut s, &mut api, &id);
                assert_eq!(result.is_ok(), step_up);
                assert_eq!(api.deletes, 1);
                let mut s = money_reopen(&s);
                assert_eq!(s.vpsbg_purchases[&id].delete_refused.is_some(), step_up);
                assert!(s.vpsbg_purchases[&id].deposits[0].suppressed);
                assert!(s.vpsbg_purchases[&id].deposits[0].transaction.is_none());
                api.deletes = 0;
                api.calls.clear();
                // Failed detail plus an empty inventory is never deletion proof.
                // Readable live detail also cannot confirm deletion or starve credit.
                if failed_detail {
                    api.replies.insert("/v1/servers/51".into(), (0, None));
                }
                for tick in 0..3 {
                    if tick == 1 {
                        api.inner.reads.transactions(vec![money_row(
                            101,
                            "19.03",
                            "bitcoin-ln",
                            "Deposit",
                        )]);
                    }
                    if automatic {
                        assert!(s.vpsbg_poll_admit(&id, PollKind::Delete).is_ok());
                        assert!(block_on(s.vpsbg_delete_check(api.action(), &id)).is_err());
                        if s.vpsbg_purchases[&id].deposits[0].transaction.is_none() {
                            assert!(s.vpsbg_poll_admit(&id, PollKind::Deposit).is_ok());
                        }
                        block_on(s.vpsbg_poll_deposit(api.action(), &id)).unwrap();
                    } else {
                        // Resume and PaymentCheck share this entry point. Its deletion error
                        // must not prevent the earlier DepositSettled append.
                        assert!(block_on(s.vpsbg_progress(api.action(), &id, false)).is_err());
                    }
                    assert_eq!(
                        s.vpsbg_purchases[&id].deposits[0].transaction.is_some(),
                        tick > 0
                    );
                    let deposit = s.vpsbg_deposit_view(&id, api.now());
                    assert!(deposit.get("bolt11").is_none());
                    assert!(deposit.get("amount_msat").is_none());
                    assert!(s.vpsbg_purchases[&id].closed_at.is_none());
                    assert_eq!(api.deletes, 0, "polls never resend DELETE");
                }
                assert!(api.calls.iter().all(|(method, _)| method == "GET"));
                assert!(
                    api.calls
                        .iter()
                        .any(|(_, path)| path == "/v1/balance/transactions?page=1")
                );
                assert_eq!(
                    changes(&s, &id)
                        .iter()
                        .filter(|c| matches!(c, Change::DepositSettled { .. }))
                        .count(),
                    1
                );
                let s = money_reopen(&s);
                assert!(s.vpsbg_purchases[&id].deposits[0].transaction.is_some());
                assert!(s.vpsbg_poll_admit(&id, PollKind::Deposit).is_err());
                assert!(s.vpsbg_poll_admit(&id, PollKind::Delete).is_ok());
                assert!(s.vpsbg_deposit_view(&id, api.now()).get("bolt11").is_none());
            }
        }
    }
}

#[test]
fn vpsbg_closed_cards_preserve_mixed_lnvps_views() {
    for case in ["lnvps_current", "lnvps_closed_last", "vpsbg_closed_last"] {
        let (mut s, id, inner, _) = pending(false);
        let mut api = DeleteApi::new(&s, &id, inner);
        api.terminal(&hostname(&s, &id));
        block_on(s.vpsbg_delete_check(api.action(), &id)).unwrap();
        let card = s.procurement_view()["closed"].clone();
        assert_eq!(card["purchase"], id);
        let mut base = ready();
        match case {
            "lnvps_current" => {
                s.procurement = Some(lnvps_view_purchase());
                base.procurement = Some(lnvps_view_purchase());
            }
            "lnvps_closed_last" => {
                s.closed_purchases.push(lnvps_view_handoff());
                base.closed_purchases.push(lnvps_view_handoff());
            }
            _ => {
                s.closed_purchases.insert(0, lnvps_view_handoff());
                base.closed_purchases.push(lnvps_view_handoff());
            }
        }
        let mut expected = base.procurement_view();
        // The only allowed mixed-store addition is its VPSBG archive card, plus
        // replacing the base closed message when VPSBG really was the last closure.
        expected["archive"] = json!([card.clone()]);
        if case == "vpsbg_closed_last" {
            expected["closed"] = card;
        } else if case == "lnvps_current" {
            assert!(expected.get("closed").is_none());
        } else {
            assert!(expected["closed"].is_string());
        }
        assert_eq!(
            serde_json::to_vec(&s.procurement_view()).unwrap(),
            serde_json::to_vec(&expected).unwrap(),
            "{case}: all LNVPS fields retain the base view's exact bytes"
        );
    }
}

#[test]
fn vpsbg_orders_ignore_unconfirmed_server_reference_in_preflight() {
    let mut s = money_store();
    let id = money_save(&mut s, "fake-order-reference", 'a');
    let mut api = MoneyApi::new(&s);
    let rows = [
        json!("unconfirmed"),
        Value::Null,
        json!({"fake":51}),
        json!(52),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, reference)| {
        json!({
            "id":31 + index,
            "created_at":"2026-01-01T00:00:00Z",
            "status":"paid",
            "server_id":reference
        })
    })
    .collect();
    let body = server_page(rows);
    let reduced = Vendor::Vpsbg
        .reduce_response("GET", "/v1/orders?page=1", 200, &body, |_| Ok(()), |_| true)
        .unwrap();
    let page: wire::Page<wire::OrderFact> = serde_json::from_value(reduced).unwrap();
    assert_eq!(page.data.len(), 4);
    assert!(
        page.data
            .iter()
            .all(|o| o.server_id.is_none() && wire::preflight_order_allowed(o))
    );
    api.responses.insert("GET /v1/orders?page=1".into(), body);
    block_on(s.vpsbg_preflight(api.action(), Some(&id))).unwrap();
    assert_eq!(s.vpsbg_reads.orders, page.data);
    assert_eq!(api.posts("/v1/balance"), 0);
}

#[test]
fn vpsbg_deleted_refund_requires_saved_order_bound_to_server() {
    let (mut s, id, mut api) = unpaid(false);
    api.inner.servers(vec![detail(&hostname(&s, &id))]);
    block_on(s.vpsbg_reconcile_create(api.inner.action(), &id)).unwrap();
    assert_eq!(
        s.vpsbg_purchases[&id]
            .associated
            .as_ref()
            .unwrap()
            .0
            .ack()
            .id,
        51
    );
    api.terminal(&hostname(&s, &id));
    api.inner
        .reads
        .transactions(vec![money_row(72, "38.79", "balance", "Refund")]);
    block_on(s.vpsbg_delete_check(api.action(), &id)).unwrap();
    assert!(
        s.procurement_view()["closed"]["delete"]
            .get("refund")
            .is_none()
    );
    api.inner
        .reads
        .transactions(vec![money_row(71, "38.79", "balance", "Refund")]);
    block_on(s.vpsbg_delete_check(api.action(), &id)).unwrap();
    assert_eq!(
        s.procurement_view()["closed"]["delete"]["refund"],
        json!({"amount":3879,"currency":"EUR"})
    );
    let mut s = money_reopen(&s);
    block_on(s.vpsbg_delete_check(api.action(), &id)).unwrap();
    assert_eq!(
        s.procurement_view()["closed"]["delete"]["refund"],
        json!({"amount":3879,"currency":"EUR"})
    );
    assert_eq!(api.deletes, 0);
    assert!(api.calls.iter().all(|(method, _)| method == "GET"));
}
