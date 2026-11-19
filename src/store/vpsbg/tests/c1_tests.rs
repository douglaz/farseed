//! Invented, secret-free provider shapes. Never retain a create body in the fake call log.
use super::*;

#[derive(Clone, Copy)]
enum Reply {
    Accepted,
    Lost,
    Login,
    Unpaid,
    Echo(u8),
    Malformed(u8),
}
struct CreateApi {
    reads: MoneyApi,
    reply: Reply,
    status: u16,
    creates: usize,
    registrations: usize,
    pays: usize,
    lose_registration: bool,
    lose_pay: bool,
    refuse_key: bool,
    fallback: Vec<bool>,
    finished_windows: Vec<usize>,
}
fn ack(name: &str) -> Value {
    json!({"id":51,"hostname":name,"billing_cycle":1,
        "plan":{"id":7,"key":"fake-plan","price_with_vat":"39.01"},"status":"processing",
        "created_at":"2026-01-01T00:00:00Z","expiry_at":"2099-01-01T02:00:00+02:00",
        "ip_addresses":[],"server_image":null})
}
fn detail(name: &str) -> Value {
    let mut d = ack(name);
    d["ip_addresses"] = json!([{"version":4,"main":true,"ip_address":"8.8.8.8","assigned_on":"2026-01-01 00:00:01"}]);
    d["auto_renew"] = json!(true);
    d["state"] = json!({"running":true,"cloud_init_installing":true,"extra":"discarded"});
    d
}
fn fresh(covered: bool) -> (Store<MemoryStorage>, String, CreateApi) {
    let mut s = money_store();
    let id = "c".repeat(32);
    let mut p = money_purchase(&s, "fake-create", &id);
    if covered {
        p.vpsbg.as_mut().unwrap().payment_plan =
            wire::PaymentPlan::preview(&money_balance(5000), &p.selected, MONEY_NOW).unwrap();
    }
    block_on(s.vpsbg_commit(
        &id,
        Change::Approved {
            purchase: Box::new(p),
            replaces_deposit: vec![],
            late_credit_disclosed: false,
        },
    ))
    .unwrap();
    let mut reads = MoneyApi::new(&s);
    reads.time = crate::hostcert::now_unix().unwrap();
    reads.balance(5000, false);
    let image = json!({"id":41,"url":wire::IMAGE_URL,"name":"fake-image","status":"downloaded",
        "size":wire::IMAGE_SIZE,"created_at":"2026-01-01T00:00:00Z","deletion_at":"2099-01-01T00:00:00Z","deleted_at":null});
    reads.responses.insert(
        "GET /v1/custom-server-images?page=1".into(),
        server_page(vec![image]),
    );
    let name = s
        .vpsbg_purchase(&id)
        .unwrap()
        .vpsbg
        .as_ref()
        .unwrap()
        .name
        .clone();
    reads.responses.insert(
        "GET /v1/servers/51".into(),
        serde_json::to_vec(&json!({"data":detail(&name)})).unwrap(),
    );
    (
        s,
        id,
        CreateApi {
            reads,
            reply: Reply::Accepted,
            status: 200,
            creates: 0,
            registrations: 0,
            pays: 0,
            lose_registration: false,
            lose_pay: false,
            refuse_key: false,
            fallback: vec![],
            finished_windows: vec![],
        },
    )
}
impl CreateApi {
    fn action(&mut self) -> &mut Self {
        self.reads.action();
        self.finished_windows.clear();
        self
    }
    fn window_counts(&self) -> Vec<usize> {
        let mut counts = self.finished_windows.clone();
        counts.push(self.reads.requests);
        counts
    }
    fn servers(&mut self, values: Vec<Value>) {
        self.reads
            .responses
            .insert("GET /v1/servers?page=1".into(), server_page(values));
    }
    fn orders(&mut self, status: &str) {
        self.reads.responses.insert(
            "GET /v1/orders?page=1".into(),
            server_page(vec![json!({"id":71,
            "created_at":"2026-01-01T00:00:00Z","status":status})]),
        );
    }
}
impl Api for CreateApi {
    fn vpsbg_begin_window(&mut self) -> Result<(), String> {
        self.current()?;
        if self.reads.requests > 0 {
            self.finished_windows.push(self.reads.requests);
        }
        self.reads.requests = 0;
        self.reads.raw = None;
        self.status = 0;
        Ok(())
    }
    fn account(&self) -> String {
        self.reads.account()
    }
    fn now(&self) -> u64 {
        self.reads.now().max(crate::hostcert::now_unix().unwrap())
    }
    fn current(&self) -> Result<(), String> {
        self.reads.current()
    }
    fn check_vendor(&self, vendor: Vendor) -> Result<(), String> {
        self.reads.check_vendor(vendor)
    }
    fn response_status(&self) -> u16 {
        self.status
    }
    fn take_vpsbg_response(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.reads.raw.take()
    }
    fn vpsbg_mutation_budget(&self) -> Result<(), String> {
        if self.refuse_key && self.creates == 1 && self.status == 422 {
            return Err("Fake invocation ends after definitive refusal".into());
        }
        self.reads.vpsbg_mutation_budget()
    }
    async fn request(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Value>,
    ) -> Result<Value, ReadError> {
        self.status = 200;
        if method != "POST" {
            return self.reads.request(method, url, body).await;
        }
        self.reads.vpsbg_mutation_budget()?;
        self.reads.requests += 1;
        let path = url.strip_prefix(wire::ORIGIN).ok_or(protocol::REFUSED)?;
        assert!(Vendor::Vpsbg.request_method_allowed(wire::ORIGIN, method, url));
        let body = crate::poc::credit::ClearedValue(body.ok_or(protocol::REFUSED)?);
        let response = match path {
            "/v1/servers" => {
                self.creates += 1;
                self.fallback.push(body.0.get("ssh_keys").is_some());
                assert_eq!(body.0["billing_cycle"], "1");
                assert_eq!(body.0["plan"], "fake-plan");
                assert_eq!(body.0["custom_server_image_id"], 41);
                assert!(
                    body.0["user_data"]
                        .as_str()
                        .unwrap()
                        .contains(wire::HOOK_BODY)
                );
                let name = body.0["name"].as_str().unwrap();
                match self.reply {
                    Reply::Malformed(kind) => {
                        self.status = 422;
                        if kind >= 9 {
                            self.reads.raw = Some(Zeroizing::new(if kind == 9 {
                                b"{".to_vec()
                            } else {
                                vec![b'x'; protocol::BODY_LIMIT + 1]
                            }));
                            return Ok(Value::Null);
                        }
                        match kind {
                            0 => {
                                json!({"message":"Fake validation","errors":{"per_page":["Invalid"]}})
                            }
                            1 => json!({"errors":{"ssh_keys":["Missing"],"other":["Invalid"]}}),
                            2 => json!({"errors":{}}),
                            3 => json!({"message":"Missing keys"}),
                            4 => json!({"errors":{"ssh_keys":[]}}),
                            5 => json!({"errors":{"password":"Missing"}}),
                            6 => json!({"errors":{"ssh_keys":[null]}}),
                            7 => json!({"order_id":null,"errors":{"ssh_keys":["Missing"]}}),
                            _ => json!({"order_id":"71","errors":{"ssh_keys":["Missing"]}}),
                        }
                    }
                    Reply::Lost => return Err("Fake lost create reply".into()),
                    Reply::Unpaid => {
                        self.status = 400;
                        json!({"order_id":71,"message":"Fake unpaid order","errors":{"ssh_keys":["Missing"]}})
                    }
                    Reply::Login if self.creates == 1 => {
                        self.status = 422;
                        json!({"message":"Fake login required","errors":{"ssh_keys":["Missing"]}})
                    }
                    Reply::Echo(kind) => {
                        let script = body.0["user_data"].as_str().unwrap();
                        let ca = script
                            .split("<<'CAKEY'\n")
                            .nth(1)
                            .unwrap()
                            .split("CAKEY\n")
                            .next()
                            .unwrap();
                        let secret = if kind == 0 {
                            TOKEN
                        } else if kind == 1 {
                            ca
                        } else {
                            script
                        };
                        let value = crate::poc::credit::ClearedValue(
                            json!({"data":[ack(name)],"discarded":[{"nested":secret}]}),
                        );
                        let encoded = Zeroizing::new(serde_json::to_string(&value.0).unwrap());
                        let encoded = if kind == 3 {
                            Zeroizing::new(
                                encoded
                                    .chars()
                                    .map(|c| format!("\\u{:04x}", u32::from(c)))
                                    .collect::<String>(),
                            )
                        } else {
                            Zeroizing::new(encoded.replace('/', "\\/"))
                        };
                        if kind == 3 {
                            // Escape the held string, preserving the surrounding JSON syntax.
                            let escaped = Zeroizing::new(
                                secret
                                    .chars()
                                    .map(|c| format!("\\u{:04x}", u32::from(c)))
                                    .collect::<String>(),
                            );
                            self.reads.raw = Some(Zeroizing::new(
                                format!(
                                    "{{\"data\":[{}],\"ignored\":[\"{}\"]}}",
                                    ack(name),
                                    escaped.as_str()
                                )
                                .into_bytes(),
                            ));
                        } else if kind == 4 {
                            // An error's discarded nested string must also be scanned.
                            self.status = 422;
                            self.reads.raw = Some(Zeroizing::new(
                                format!(
                                    "{{\"errors\":{{\"ssh_keys\":[\"Missing\"]}},\"ignored\":{}}}",
                                    serde_json::to_string(secret).unwrap()
                                )
                                .into_bytes(),
                            ));
                        } else if kind == 5 {
                            self.reads.raw = Some(Zeroizing::new(secret.as_bytes().to_vec()));
                        } else {
                            self.reads.raw = Some(Zeroizing::new(encoded.as_bytes().to_vec()));
                        }
                        return Ok(Value::Null);
                    }
                    _ => json!({"data":[ack(name)]}),
                }
            }
            "/v1/ssh-keys" => {
                self.registrations += 1;
                let key = body.0["key"].as_str().unwrap();
                let fingerprint = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff";
                let value =
                    json!({"id":81,"name":"tau-web-attest","key":key,"fingerprint":fingerprint});
                if self.lose_registration {
                    self.reads
                        .responses
                        .insert("GET /v1/ssh-keys?page=1".into(), server_page(vec![value]));
                    return Err("Fake lost key registration reply".into());
                }
                json!({"data":value})
            }
            "/v1/orders/pay" => {
                self.pays += 1;
                assert_eq!(body.0, json!({"ids":[71]}));
                self.orders("paid");
                if self.lose_pay {
                    return Err("Fake lost pay response".into());
                }
                json!({"data":{"ids":[71]}})
            }
            _ => return Err(protocol::REFUSED.into()),
        };
        let response = crate::poc::credit::ClearedValue(response);
        self.reads.raw = Some(Zeroizing::new(serde_json::to_vec(&response.0).unwrap()));
        Ok(Value::Null)
    }
}
fn create(s: &mut Store<MemoryStorage>, api: &mut CreateApi, id: &str) -> Result<(), String> {
    let p = s.vpsbg_purchase(id).unwrap();
    let bound = s.bound_machine_relay(&p.machine)?;
    let revision = p.vpsbg.as_ref().unwrap().approval_revision;
    block_on(s.create_once(api.action(), id, revision, bound))
}

fn issue_unexpired(s: &mut Store<MemoryStorage>, id: &str, now: u64) {
    money_sent(s, id);
    let bolt11 = wire::bolt11::fake(101, now, "348860n", &[]);
    let decoded = wire::bolt11::decode(&bolt11).unwrap();
    block_on(s.vpsbg_commit(
        id,
        Change::DepositIssued {
            attempt: 0,
            invoice: wire::DepositInvoice {
                order: 101,
                amount: 1903,
                currency: wire::Currency::Eur,
                bolt11,
                payment_hash: decoded.payment_hash,
                amount_msat: decoded.amount_msat,
                provider_expiry: now + 720,
                bolt11_expiry: decoded.expires,
                expires: now + 720,
            },
        },
    ))
    .unwrap();
}

fn observations(s: &Store<MemoryStorage>, id: &str) -> usize {
    let mut count = 0;
    let mut reader = Store::new(s.storage.clone(), DataKey(s.key.0), s.id.clone());
    for number in s.records() {
        let bytes = block_on(s.storage.read(&number.to_string())).unwrap();
        let (event, _) = reader.open_record(number, &bytes).unwrap();
        if let Event::Vpsbg(ref record) = event
            && record.purchase == id
            && matches!(record.change, Change::Observed { .. })
        {
            count += 1;
        }
        reader.previous = Address(Sha256::digest(&bytes).into());
    }
    count
}

#[test]
fn vpsbg_progress_fallback_has_separate_bounded_windows() {
    // mode 0: T=0; mode 1: an exact settlement read by progress;
    // mode 2: a durably suppressed, still-unresolved invoice.
    for mode in 0..3 {
        for lost_registration in [false, true] {
            let (mut s, id, mut api) = fresh(mode == 0);
            if mode != 0 {
                issue_unexpired(&mut s, &id, api.now());
                if mode == 1 {
                    api.reads
                        .transactions(vec![money_row(101, "19.03", "bitcoin-ln", "Deposit")]);
                } else {
                    block_on(s.vpsbg_commit(
                        &id,
                        Change::DepositSuppressed {
                            attempt: 0,
                            order: Some(101),
                            reason: SuppressionReason::CoveredFromElsewhere,
                            balance: 5000,
                            first_period: 3901,
                            checked_at: api.now(),
                        },
                    ))
                    .unwrap();
                }
            }
            api.reply = Reply::Login;
            api.lose_registration = lost_registration;
            assert_eq!(api.reads.request_cap, 16);
            block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
            // Preparation, attempt 0 + registration (+ ambiguous-registration list),
            // then attempt 1's six gates, POST and observation, each separately capped.
            assert_eq!(
                api.window_counts(),
                vec![
                    if mode == 0 { 1 } else { 3 },
                    8 + usize::from(lost_registration),
                    8
                ]
            );
            assert!(api.window_counts().iter().all(|n| *n <= 16));
            assert_eq!(api.fallback, vec![false, true]);
            assert_eq!(api.registrations, 1);
            assert_eq!(api.creates, 2);
            assert_eq!(api.pays, 0);
            assert_eq!(s.vpsbg_purchases[&id].creates.len(), 2);
            let p = s.vpsbg_purchase(&id).unwrap();
            let public = s.poc_identity_public_keys(&p.machine, &p.identity).unwrap();
            let fingerprint =
                ssh_key::PublicKey::from_openssh(public["authorized_keys"].as_str().unwrap())
                    .unwrap()
                    .fingerprint(ssh_key::HashAlg::Sha256)
                    .to_string();
            assert_eq!(s.vpsbg_purchases[&id].key, Some((81, fingerprint)));
            assert!(s.vpsbg_reads.create_held.upgrade().is_none());
            let mut s = money_reopen(&s);
            for _ in 0..3 {
                block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
            }
            assert_eq!(api.creates, 2);
            assert_eq!(api.registrations, 1);
        }
    }
}

#[test]
fn vpsbg_budget_refusal_precedes_introduction_and_names_deadline() {
    let (mut s, id, mut api) = fresh(true);
    api.reads.request_cap = 6; // Name inventory plus all five initial gate reads fit.
    assert!(create(&mut s, &mut api, &id).is_err());
    assert!(s.attest_deadline("fake-create").is_none());
    assert_eq!(api.creates, 0);
    assert!(s.vpsbg_purchases[&id].creates.is_empty());

    let (mut s, id, mut api) = fresh(true);
    api.reads.time = crate::hostcert::now_unix().unwrap() + 1000;
    assert_eq!(
        create(&mut s, &mut api, &id).unwrap_err(),
        "too close to the identity deadline to start the order"
    );
    assert_eq!(api.creates, 0);
}

#[test]
fn vpsbg_late_suppressed_deposit_settles_after_create_and_association() {
    for associated in [false, true] {
        let (mut s, id, mut api) = fresh(false);
        issue_unexpired(&mut s, &id, api.now());
        // Suppress the unexpired invoice before allowing the first create.
        block_on(s.vpsbg_progress(api.action(), &id, true)).unwrap();
        assert!(s.vpsbg_purchases[&id].deposits[0].suppressed);
        assert!(s.procurement_view()["deposit"].get("bolt11").is_none());
        if !associated {
            api.reply = Reply::Lost;
        }
        let result = block_on(s.vpsbg_progress(api.action(), &id, false));
        assert_eq!(result.is_ok(), associated);
        assert_eq!(api.creates, 1);
        assert_eq!(s.vpsbg_purchases[&id].associated.is_some(), associated);
        api.reads.balance(0, false); // Creation spent F; the remaining balance is not a gate.
        let mut s = money_reopen(&s);
        for _ in 0..3 {
            block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
            block_on(s.vpsbg_poll_deposit(api.action(), &id)).unwrap();
            assert_ne!(s.procurement_view()["pause"]["kind"], "balance_short");
            assert!(
                s.vpsbg_reads
                    .pause
                    .as_ref()
                    .is_none_or(|p| p["kind"] != "balance_short")
            );
            assert!(s.vpsbg_purchases[&id].deposits[0].transaction.is_none());
            assert!(s.vpsbg_purchases[&id].deposits[0].suppressed);
            assert!(s.procurement_view()["deposit"].get("bolt11").is_none());
        }
        api.reads
            .transactions(vec![money_row(101, "19.03", "bitcoin-ln", "Deposit")]);
        api.reads.balance(1903, false); // A late credit, below F after the create charge.
        let mut s = money_reopen(&s);
        assert!(s.procurement_view()["deposit"].get("bolt11").is_none());
        block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
        assert!(s.vpsbg_purchases[&id].deposits[0].transaction.is_some());
        let mut s = money_reopen(&s);
        assert_eq!(s.procurement_view()["deposit"]["state"], "settled");
        assert!(s.procurement_view()["deposit"].get("bolt11").is_none());
        for _ in 0..3 {
            block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
            block_on(s.vpsbg_poll_deposit(api.action(), &id)).unwrap();
            assert_ne!(s.procurement_view()["pause"]["kind"], "balance_short");
            assert!(
                s.vpsbg_reads
                    .pause
                    .as_ref()
                    .is_none_or(|p| p["kind"] != "balance_short")
            );
            assert!(s.procurement_view()["deposit"].get("bolt11").is_none());
        }
        assert_eq!(api.creates, 1);
        assert_eq!(api.registrations, 0);
    }
}

#[test]
fn vpsbg_post_create_deposit_check_preserves_unpaid_order_and_pay() {
    let (mut s, id, mut api) = fresh(false);
    // This invoice still has two minutes left when the create gets its introduction.
    let issued_at = api.now() - 600;
    issue_unexpired(&mut s, &id, issued_at);
    block_on(s.vpsbg_progress(api.action(), &id, true)).unwrap();
    assert!(s.vpsbg_purchases[&id].deposits[0].suppressed);
    api.reply = Reply::Unpaid;
    block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
    api.orders("pending");
    api.reads.time = s.vpsbg_purchases[&id].deposits[0]
        .invoice
        .as_ref()
        .unwrap()
        .expires
        + 601;
    assert!(wire::budget_fits(
        api.now(),
        s.attest_deadline("fake-create").unwrap()
    ));
    let expected = json!({"kind":"unpaid_order","order":71,"pay_allowed":true});
    let mut s = money_reopen(&s);
    assert_eq!(s.procurement_view()["pause"], expected);
    for _ in 0..3 {
        s.vpsbg_reads.pause = Some(expected.clone());
        let before = api.reads.calls.len();
        block_on(s.vpsbg_deposit_check(api.action(), &id)).unwrap();
        assert_eq!(s.vpsbg_reads.pause, Some(expected.clone()));
        assert_eq!(s.procurement_view()["pause"], expected);
        assert_eq!(api.reads.calls[before..].len(), 2);
        assert!(
            api.reads.calls[before..]
                .iter()
                .all(|(_, path, _)| matches!(
                    path.as_str(),
                    "/v1/balance" | "/v1/balance/transactions?page=1"
                ))
        );
        block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
        assert_eq!(s.procurement_view()["pause"], expected);
        assert!(s.procurement_view()["deposit"].get("bolt11").is_none());
    }
    // A deposit read failure must also leave this purchase's own order pause intact.
    s.vpsbg_reads.pause = Some(expected.clone());
    api.reads
        .responses
        .remove("GET /v1/balance/transactions?page=1");
    assert!(block_on(s.vpsbg_deposit_check(api.action(), &id)).is_err());
    assert_eq!(s.vpsbg_reads.pause, Some(expected.clone()));
    assert_eq!(s.procurement_view()["pause"], expected);
    api.reads.transactions(vec![]);
    let selected = s.vpsbg_purchase(&id).unwrap().selected.clone();
    let review = s
        .vpsbg_review(&selected, &money_balance(5000), api.now())
        .unwrap();
    assert_eq!(review.pay_order, Some(71));
    block_on(s.vpsbg_approve(api.action(), money_approval("fake-create"), review)).unwrap();
    assert_eq!(s.vpsbg_purchase(&id).unwrap().selected, selected);
    let mut s = money_reopen(&s);
    block_on(s.vpsbg_pay_order(api.action(), &id)).unwrap();
    assert_eq!(api.pays, 1);
    assert_eq!(api.creates, 1);
    assert!(matches!(
        s.vpsbg_purchases[&id].pay_resolved,
        Some(PayOutcome::Paid(_))
    ));
}

#[test]
fn vpsbg_unresolved_create_refuses_selection_and_reapproval_across_reload() {
    for reload in [false, true] {
        let (mut s, id, mut api) = fresh(true);
        api.reply = Reply::Lost;
        assert!(create(&mut s, &mut api, &id).is_err());
        let mut s = if reload { money_reopen(&s) } else { s };
        let original = s.vpsbg_purchase(&id).unwrap().clone();
        let records = s.records().end;
        let mut plans: Value = serde_json::from_slice(PLANS).unwrap();
        let mut other = plans["data"][0].clone();
        other["id"] = json!(8);
        other["key"] = json!("fake-other-plan");
        other["price_with_vat"] = json!(40);
        plans["data"].as_array_mut().unwrap().push(other);
        let raw = serde_json::to_vec(&plans).unwrap();
        let offers = Vendor::Vpsbg
            .reduce_response("GET", "/v1/servers/plans", 200, &raw, |_| Ok(()), |_| true)
            .unwrap();
        let other = Selection {
            offer: offers[1].clone(),
            charge: Vendor::Vpsbg.offer_charge(&offers[1]).unwrap(),
            image: wire::image(),
            resources: None,
        };
        api.reads
            .responses
            .insert("GET /v1/servers/plans".into(), raw);
        assert!(
            block_on(s.procurement_select(
                api.action(),
                provisioning::Choice {
                    offer_id: 8,
                    image_id: 1,
                    resources: None,
                }
            ))
            .is_err()
        );
        assert_eq!(s.vpsbg_purchase(&id).unwrap(), &original);
        // Exercise approval's own admission independently of the selection-action guard.
        s.procurement_selection = Some(other.clone());
        let review = s
            .vpsbg_review(&other, &money_balance(5000), api.now())
            .unwrap();
        assert!(review.pay_order.is_none());
        assert!(
            block_on(s.vpsbg_approve(api.action(), money_approval("fake-create"), review)).is_err()
        );
        assert_eq!(s.records().end, records);
        assert_eq!(s.vpsbg_purchase(&id).unwrap(), &original);
        api.servers(vec![detail(&original.vpsbg.as_ref().unwrap().name)]);
        block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
        assert_eq!(s.vpsbg_purchase(&id).unwrap().selected, original.selected);
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
        let mut s = money_reopen(&s);
        block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
        assert_eq!(api.creates, 1);
        assert_eq!(api.registrations, 0);
    }
}

#[test]
fn vpsbg_sent_plan_revision_is_refused_on_write_and_replay() {
    for unpaid in [false, true] {
        let (mut s, id, mut api) = fresh(true);
        api.reply = if unpaid { Reply::Unpaid } else { Reply::Lost };
        let result = create(&mut s, &mut api, &id);
        assert_eq!(result.is_ok(), unpaid);
        let mut s = money_reopen(&s);
        let original = s.vpsbg_purchase(&id).unwrap().clone();
        let state = s.vpsbg_purchases[&id].clone();
        let records = s.records().end;
        for change in ["no_order", "wrong_order", "id", "key", "price", "cycle"] {
            let mut selected = original.selected.clone();
            match change {
                "id" => selected.offer["id"] = json!(8),
                "key" => selected.offer["key"] = json!("fake-other-plan"),
                "price" => {
                    selected.offer["price_with_vat"] = json!(4000);
                    selected.charge.amount = 4000;
                }
                "cycle" => selected.charge.interval_amount = 3,
                _ => {}
            }
            let review = s
                .vpsbg_review(&original.selected, &money_balance(5000), api.now())
                .unwrap();
            let mut payment_plan = review.payment_plan;
            if change == "price" {
                payment_plan.price = 4000;
                payment_plan.first_period = 4000;
                payment_plan.left_as_credit = 1000;
            }
            let record = Record {
                purchase: id.clone(),
                change: Change::ApprovalRevised {
                    revision: review.revision,
                    selected,
                    payment_plan,
                    approved_card: false,
                    approved_at: api.now(),
                    replaces_deposit: review.replaces_deposit,
                    late_credit_disclosed: review.late_credit_disclosed,
                    pay_order: match change {
                        "no_order" => None,
                        "wrong_order" => Some(72),
                        _ => review.pay_order,
                    },
                },
            };
            assert!(
                block_on(s.vpsbg_commit(&id, record.change.clone())).is_err(),
                "{unpaid}/{change}"
            );
            assert!(
                s.replay_vpsbg(records, &record).is_err(),
                "{unpaid}/{change}"
            );
            assert_eq!(s.records().end, records);
            assert_eq!(s.vpsbg_purchase(&id).unwrap(), &original);
            assert_eq!(s.vpsbg_purchases[&id], state);
        }
    }
}

#[test]
fn vpsbg_observations_change_only_with_detail_and_deposit_ticks_skip_detail() {
    let (mut s, id, mut api) = fresh(false);
    issue_unexpired(&mut s, &id, api.now());
    block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
    assert_eq!(observations(&s, &id), 1);
    let records = s.records().end;
    let mut s = money_reopen(&s);
    for _ in 0..32 {
        block_on(s.vpsbg_reconcile_create(api.action(), &id)).unwrap();
    }
    assert_eq!(observations(&s, &id), 1);
    assert_eq!(s.records().end, records);
    // Associated reconciliation only needs the bound detail, never another name list.
    let before = api.reads.calls.len();
    block_on(s.vpsbg_reconcile_create(api.action(), &id)).unwrap();
    assert_eq!(api.reads.calls[before..].len(), 1);
    assert_eq!(api.reads.calls[before].1, "/v1/servers/51");
    // The real automatic deposit entry point performs just settlement reads.
    let before = api.reads.calls.len();
    for _ in 0..32 {
        block_on(s.vpsbg_poll_deposit(api.action(), &id)).unwrap();
    }
    let calls = &api.reads.calls[before..];
    assert_eq!(calls.len(), 64);
    assert!(calls.iter().all(|(method, path, _)| method == "GET"
        && matches!(
            path.as_str(),
            "/v1/balance" | "/v1/balance/transactions?page=1"
        )));
    assert_eq!(s.records().end, records);
    let name = s
        .vpsbg_purchase(&id)
        .unwrap()
        .vpsbg
        .as_ref()
        .unwrap()
        .name
        .clone();
    let mut changed = detail(&name);
    changed["auto_renew"] = json!(false);
    api.reads.responses.insert(
        "GET /v1/servers/51".into(),
        serde_json::to_vec(&json!({"data":changed})).unwrap(),
    );
    block_on(s.vpsbg_reconcile_create(api.action(), &id)).unwrap();
    assert_eq!(observations(&s, &id), 2);
    assert_eq!(s.records().end, records + 1);
    let mut s = money_reopen(&s);
    for _ in 0..32 {
        block_on(s.vpsbg_reconcile_create(api.action(), &id)).unwrap();
    }
    assert_eq!(observations(&s, &id), 2);
    assert_eq!(api.creates, 1);
}

#[test]
fn vpsbg_image_relisted_before_create() {
    for invalid in 0..4 {
        let (mut s, id, mut api) = fresh(true);
        money_image(&mut s, &id); // A stale durable ready fact never authorizes creation.
        let key = "GET /v1/custom-server-images?page=1";
        let mut image: Value = serde_json::from_slice(&api.reads.responses[key]).unwrap();
        match invalid {
            0 => image["data"][0]["deletion_at"] = json!("2026-01-01T00:00:01Z"),
            1 => image = serde_json::from_slice(EMPTY_PAGE).unwrap(),
            2 => image["data"][0]["url"] = json!("https://images.invalid/fake-wrong.qcow2"),
            _ => image["data"][0]["size"] = json!(1234),
        }
        api.reads
            .responses
            .insert(key.into(), serde_json::to_vec(&image).unwrap());
        assert!(create(&mut s, &mut api, &id).is_err());
        assert_eq!(api.creates, 0);
    }
    let (mut s, id, mut api) = fresh(true);
    create(&mut s, &mut api, &id).unwrap();
    assert_eq!(api.creates, 1);
    assert_eq!(api.reads.calls.first().unwrap().1, "/v1/servers?page=1");
    assert_eq!(api.fallback, vec![false]);
    assert!(
        s.vpsbg_purchases[&id]
            .associated
            .as_ref()
            .unwrap()
            .1
            .is_some()
    );
    assert_eq!(
        s.vpsbg_purchases[&id]
            .observed
            .as_ref()
            .unwrap()
            .public_ipv4
            .unwrap()
            .to_string(),
        "8.8.8.8"
    );
    assert_eq!(s.procurement_view()["renewal"], "on");
    assert!(s.procurement_view()["paid_until"].as_u64().is_some());
    assert!(s.poc_targets.is_empty());
}

#[test]
fn vpsbg_create_echo_keeps_unknown() {
    for kind in 0..=5 {
        let (mut s, id, mut api) = fresh(true);
        api.reply = Reply::Echo(kind);
        assert!(create(&mut s, &mut api, &id).is_err());
        assert_eq!(api.creates, 1);
        assert_eq!(api.registrations, 0);
        assert!(s.vpsbg_reads.create_held.upgrade().is_none());
        assert!(s.vpsbg_purchases[&id].associated.is_none());
        assert_eq!(s.vpsbg_purchases[&id].creates.len(), 1);
        let mut s = money_reopen(&s);
        for _ in 0..3 {
            let _ = create(&mut s, &mut api, &id);
        }
        assert_eq!(api.creates, 1);
        let view = s.procurement_view().to_string();
        assert!(!view.contains("PRIVATE KEY"));
        assert!(!view.contains("CAKEY"));
        assert!(!view.contains(TOKEN));
        let mut reader = Store::new(s.storage.clone(), DataKey(s.key.0), s.id.clone());
        for number in s.records() {
            let bytes = block_on(s.storage.read(&number.to_string())).unwrap();
            let (event, _) = reader.open_record(number, &bytes).unwrap();
            if matches!(event, Event::Vpsbg(_)) {
                let text = serde_json::to_string(&event).unwrap();
                assert!(!text.contains("PRIVATE KEY"));
                assert!(!text.contains("CAKEY"));
            }
            reader.previous = Address(Sha256::digest(&bytes).into());
        }
    }
}

#[test]
fn vpsbg_create_checks_name_first() {
    for count in [1, 2] {
        let (mut s, id, mut api) = fresh(true);
        let name = s
            .vpsbg_purchase(&id)
            .unwrap()
            .vpsbg
            .as_ref()
            .unwrap()
            .name
            .clone();
        let mut rows = vec![detail(&name)];
        if count == 2 {
            let mut other = detail(&name);
            other["id"] = json!(52);
            rows.push(other);
        }
        api.servers(rows);
        assert_eq!(create(&mut s, &mut api, &id).is_ok(), count == 1);
        assert_eq!(api.creates, 0);
        assert_eq!(s.vpsbg_purchases[&id].associated.is_some(), count == 1);
        if count == 1 {
            assert_eq!(s.procurement_view()["pause"]["kind"], "payment_unproven");
        }
    }
    let (mut s, id, mut api) = fresh(true);
    api.reply = Reply::Lost;
    assert!(create(&mut s, &mut api, &id).is_err());
    let mut s = money_reopen(&s);
    for _ in 0..3 {
        create(&mut s, &mut api, &id).unwrap();
    }
    assert_eq!(api.creates, 1);
    assert!(!s.vpsbg_create_pending(&id));
    assert!(!s.vpsbg_close_allowed(&id));
}

#[test]
fn vpsbg_non_login_422_remains_unknown() {
    for kind in 0..=10 {
        let (mut s, id, mut api) = fresh(true);
        api.reply = Reply::Malformed(kind);
        assert!(create(&mut s, &mut api, &id).is_err());
        assert_eq!(api.creates, 1);
        assert_eq!(api.registrations, 0);
        assert!(s.vpsbg_purchases[&id].creates[0].refusal.is_none());
        assert!(s.vpsbg_purchases[&id].unpaid.is_none());
        let mut s = money_reopen(&s);
        create(&mut s, &mut api, &id).unwrap();
        assert_eq!(api.creates, 1);
        assert_eq!(api.registrations, 0);
    }
}

#[test]
fn vpsbg_unpaid_order_never_recreates() {
    let (mut s, id, mut api) = fresh(true);
    api.reply = Reply::Unpaid;
    create(&mut s, &mut api, &id).unwrap();
    api.orders("pending");
    assert_eq!(s.vpsbg_purchases[&id].unpaid.unwrap().0, 71);
    let mut s = money_reopen(&s);
    for _ in 0..3 {
        create(&mut s, &mut api, &id).unwrap();
    }
    assert_eq!(api.creates, 1);
    assert_eq!(api.registrations, 0);
    assert!(block_on(s.vpsbg_pay_order(api.action(), &id)).is_err());
    assert_eq!(api.pays, 0);
    let p = s.vpsbg_purchase(&id).unwrap().clone();
    let review = s
        .vpsbg_review(&p.selected, &money_balance(5000), api.now())
        .unwrap();
    assert_eq!(review.pay_order, Some(71));
    block_on(s.vpsbg_approve(api.action(), money_approval("fake-create"), review)).unwrap();
    api.lose_pay = true;
    block_on(s.vpsbg_pay_order(api.action(), &id)).unwrap();
    assert_eq!(api.pays, 1);
    assert!(matches!(
        s.vpsbg_purchases[&id].pay_resolved,
        Some(PayOutcome::Paid(_))
    ));
    let mut s = money_reopen(&s);
    block_on(s.vpsbg_pay_order(api.action(), &id)).unwrap();
    assert_eq!(api.pays, 1);
    assert_eq!(api.creates, 1);

    for lost_key in [false, true] {
        let (mut s, id, mut api) = fresh(true);
        api.reply = Reply::Login;
        api.lose_registration = lost_key;
        create(&mut s, &mut api, &id).unwrap();
        assert_eq!(api.creates, 2);
        assert_eq!(api.registrations, 1);
        if api.creates == 2 {
            assert_eq!(api.fallback, vec![false, true]);
        }
        let count = api.creates;
        let mut s = money_reopen(&s);
        let _ = create(&mut s, &mut api, &id);
        assert_eq!(api.creates, count);
        assert_eq!(api.registrations, 1);
    }
}

#[test]
fn vpsbg_settled_deposit_continues_to_one_create() {
    for mode in 0..4 {
        let (mut s, id, mut api) = fresh(mode == 0);
        if mode != 0 {
            money_issued(&mut s, &id);
            if mode == 1 {
                // Interrupt immediately after the settlement append, before introduction.
                let transaction: wire::TransactionFact = serde_json::from_value(
                    protocol::vpsbg::reduce_response(
                        "GET",
                        "/v1/balance/transactions?page=1",
                        200,
                        &server_page(vec![money_row(101, "19.03", "bitcoin-ln", "Deposit")]),
                        |_| Ok(()),
                        |_| true,
                    )
                    .unwrap()["data"][0]
                        .clone(),
                )
                .unwrap();
                block_on(s.vpsbg_commit(
                    &id,
                    Change::DepositSettled {
                        attempt: 0,
                        order: 101,
                        transaction,
                        checked_at: api.now(),
                    },
                ))
                .unwrap();
            } else {
                block_on(s.vpsbg_commit(
                    &id,
                    Change::DepositSuppressed {
                        attempt: 0,
                        order: Some(101),
                        reason: SuppressionReason::CoveredFromElsewhere,
                        balance: 5000,
                        first_period: 3901,
                        checked_at: api.now(),
                    },
                ))
                .unwrap();
            }
        }
        if mode == 3 {
            let entry = s.dispatch.approved_entries["fake-create"]
                .approved
                .entry
                .clone();
            drop(block_on(s.attest_introduction_begin(&entry)).unwrap());
        }
        let mut s = money_reopen(&s);
        assert!(
            s.vpsbg_poll_contexts()
                .iter()
                .any(|c| c.purchase == id && c.create_pending)
        );
        block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
        assert_eq!(api.creates, 1);
        assert_eq!(
            s.vpsbg_purchases[&id].replaced.len(),
            usize::from(mode == 3)
        );
        for _ in 0..3 {
            let _ = block_on(s.vpsbg_progress(api.action(), &id, false));
        }
        assert_eq!(api.creates, 1);
        assert!(!s.vpsbg_create_pending(&id));
        if mode == 3 {
            assert!(s.relay_key("fake-create").is_none());
            assert!(!s.procurement_can_start());
        }
    }
}

#[test]
fn vpsbg_card_flag_bound_to_money_approval_create_half() {
    let (mut s, id, mut api) = fresh(true);
    api.reads.balance(5000, true);
    assert!(create(&mut s, &mut api, &id).is_err());
    assert_eq!(api.creates, 0);
    assert_eq!(s.procurement_view()["phase"], "terms_changed");
    let p = s.vpsbg_purchase(&id).unwrap().clone();
    let mut balance = money_balance(5000);
    balance.has_valid_card = true;
    let review = s.vpsbg_review(&p.selected, &balance, api.now()).unwrap();
    block_on(s.vpsbg_approve(api.action(), money_approval("fake-create"), review)).unwrap();
    create(&mut s, &mut api, &id).unwrap();
    assert_eq!(api.creates, 1);
}

#[test]
fn vpsbg_refused_fallback_requires_explicit_fresh_approval() {
    let (mut s, id, mut api) = fresh(true);
    api.reply = Reply::Login;
    api.refuse_key = true;
    assert!(create(&mut s, &mut api, &id).is_err());
    assert_eq!(api.creates, 1);
    assert_eq!(api.registrations, 0);
    assert!(s.vpsbg_purchases[&id].creates[0].refusal.is_some());
    assert!(!s.vpsbg_close_allowed(&id));
    let mut s = money_reopen(&s);
    for _ in 0..3 {
        create(&mut s, &mut api, &id).unwrap();
    }
    assert_eq!(api.creates, 1);
    assert_eq!(api.registrations, 0);
    let old = s.vpsbg_purchase(&id).unwrap().clone();
    let review = s
        .vpsbg_review(&old.selected, &money_balance(5000), api.now())
        .unwrap();
    block_on(s.vpsbg_approve(api.action(), money_approval("fake-fresh-approval"), review)).unwrap();
    assert!(
        s.closed_purchases
            .iter()
            .any(|p| p.machine == "fake-create")
    );
    assert!(s.relay_key("fake-create").is_none());
    let next = s.procurement.as_ref().unwrap();
    assert!(next.identity.index > old.identity.index);
    assert!(next.relay_identity.index > old.relay_identity.index);
    let s = money_reopen(&s);
    assert!(s.relay_key("fake-fresh-approval").is_some());
    assert!(s.relay_key("fake-create").is_none());
    // An uncertain create has no refusal proof and cannot be closed by fresh approval.
    let (mut s, id, mut api) = fresh(true);
    api.reply = Reply::Lost;
    assert!(create(&mut s, &mut api, &id).is_err());
    let p = s.vpsbg_purchase(&id).unwrap().clone();
    let review = s
        .vpsbg_review(&p.selected, &money_balance(5000), api.now())
        .unwrap();
    assert!(
        block_on(s.vpsbg_approve(api.action(), money_approval("fake-no-authority"), review))
            .is_err()
    );
    assert!(s.closed_purchases.is_empty());
    assert_eq!(api.creates, 1);
}

#[test]
fn vpsbg_pay_budget_and_append_fences() {
    let (mut s, id, mut api) = fresh(true);
    api.reply = Reply::Unpaid;
    create(&mut s, &mut api, &id).unwrap();
    api.orders("pending");
    let p = s.vpsbg_purchase(&id).unwrap().clone();
    let review = s
        .vpsbg_review(&p.selected, &money_balance(5000), api.now())
        .unwrap();
    block_on(s.vpsbg_approve(api.action(), money_approval("fake-create"), review)).unwrap();
    api.reads.time =
        s.attest_deadline("fake-create").unwrap() - wire::BOOT_BUDGET - wire::RELAY_BUDGET;
    assert_eq!(
        block_on(s.vpsbg_pay_order(api.action(), &id)).unwrap_err(),
        "too close to the identity deadline to start the order"
    );
    assert_eq!(api.pays, 0);
    assert!(s.vpsbg_purchases[&id].pay_sent.is_none());
    for fault in [Fault::Fail(1), Fault::LandThenFail(3)] {
        let (mut s, id, mut api) = fresh(true);
        // Fail the public introduction append. No POST can precede it.
        s.storage.fault(fault);
        assert!(create(&mut s, &mut api, &id).is_err());
        assert_eq!(api.creates, 0);
        assert!(create(&mut s, &mut api, &id).is_err());
        assert_eq!(api.creates, 0);
        let mut replayed = money_reopen(&s);
        create(&mut replayed, &mut api, &id).unwrap();
        assert_eq!(api.creates, 1);
        assert_eq!(
            replayed.vpsbg_purchases[&id].replaced.len(),
            usize::from(matches!(fault, Fault::LandThenFail(3)))
        );
    }
}

#[test]
fn vpsbg_machine_pass_binding_survives_replay() {
    let (mut s, id, _api) = fresh(true);
    s.deployment_relay = crate::credential::RelayKey::from_deployment("12".repeat(32).as_bytes());
    let first = s.relay_key("fake-create").unwrap().public_key();
    assert_ne!(first, s.deployment_relay.as_ref().unwrap().public_key());
    assert_eq!(
        money_reopen(&s)
            .relay_key("fake-create")
            .unwrap()
            .public_key(),
        first
    );
    // Isolate a second simultaneously live binding in allocation metadata, as Restore must support.
    let mut exported = s.allocation().export();
    let machine = exported.issue(Family::Machines).unwrap();
    let pass = exported.issue(Family::Passes).unwrap();
    exported
        .apply(&allocation::Event::Reserve(machine.clone()))
        .unwrap();
    exported
        .apply(&allocation::Event::Reserve(pass.clone()))
        .unwrap();
    exported
        .bind_machine(MachinePassBinding {
            purchase: "d".repeat(32),
            machine: "fake-other".into(),
            machine_identity: machine.clone(),
            pass_identity: pass.clone(),
        })
        .unwrap();
    s.allocation = Some(exported.clone());
    let second = s.relay_key("fake-other").unwrap().public_key();
    assert_ne!(first, second);
    let mut restored = s.allocation().clone();
    restored
        .apply(&allocation::Event::Restore(exported.clone()))
        .unwrap();
    assert_eq!(
        restored.machine_pass_bindings(),
        exported.machine_pass_bindings()
    );
    s.allocation = Some(restored);
    assert_eq!(s.relay_key("fake-create").unwrap().public_key(), first);
    assert_eq!(s.relay_key("fake-other").unwrap().public_key(), second);
    block_on(s.commit(&Event::Allocation(allocation::Event::Restore(
        exported.clone(),
    ))))
    .unwrap();
    let replayed = money_reopen(&s);
    assert_eq!(
        replayed.relay_key("fake-create").unwrap().public_key(),
        first
    );
    assert_eq!(
        replayed.relay_key("fake-other").unwrap().public_key(),
        second
    );
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Old {
        seed: String,
        derivation_version: u32,
        next_unused: Value,
        entries: Vec<Value>,
        restored_from_import: bool,
        seed_backup: Option<Value>,
    }
    let old = serde_json::from_value::<Old>(json!(Metadata::new("fake".into()))).unwrap();
    assert_eq!(old.seed, "fake");
    assert_eq!(old.derivation_version, 1);
    assert!(old.entries.is_empty());
    assert!(old.next_unused.is_object());
    assert!(!old.restored_from_import);
    assert!(old.seed_backup.is_none());
    assert!(serde_json::from_value::<Old>(json!(exported.clone())).is_err());
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    enum OldEvent {
        Restore(Old),
    }
    assert!(
        serde_json::from_value::<OldEvent>(json!(allocation::Event::Restore(exported.clone())))
            .is_err()
    );
    let OldEvent::Restore(old) = serde_json::from_value::<OldEvent>(json!(
        allocation::Event::Restore(Metadata::new("fake".into()))
    ))
    .unwrap();
    assert_eq!(old.seed, "fake");
    assert_eq!(
        serde_json::to_string(&Metadata::new("fake".into())).unwrap(),
        r#"{"seed":"fake","derivation_version":1,"next_unused":{"machines":0,"passes":0,"handoffs":0},"entries":[],"restored_from_import":false,"seed_backup":null}"#
    );
    let mut missing = json!(exported.clone());
    missing
        .as_object_mut()
        .unwrap()
        .remove("machine_pass_bindings");
    let missing: Metadata = serde_json::from_value(missing).unwrap();
    let mut with_bindings = exported.clone();
    assert!(
        with_bindings
            .apply(&allocation::Event::Restore(missing.clone()))
            .is_err()
    );
    s.allocation = Some(missing);
    assert!(s.relay_key("fake-create").is_none());
    for field in ["seed", "derivation_version", "family", "index"] {
        let mut wrong = json!(exported.clone());
        wrong["machine_pass_bindings"][0]["pass_identity"][field] = match field {
            "seed" => json!("wrong"),
            "family" => json!("machines"),
            "index" => json!(100),
            _ => json!(2),
        };
        let wrong: Metadata = serde_json::from_value(wrong).unwrap();
        let mut m = exported.clone();
        assert!(m.apply(&allocation::Event::Restore(wrong)).is_err());
    }
    let mut duplicate = json!(exported.clone());
    let binding = duplicate["machine_pass_bindings"][0].clone();
    duplicate["machine_pass_bindings"]
        .as_array_mut()
        .unwrap()
        .push(binding);
    let mut m = exported.clone();
    assert!(
        m.apply(&allocation::Event::Restore(
            serde_json::from_value(duplicate).unwrap()
        ))
        .is_err()
    );
    let live = exported.clone();
    exported
        .apply(&allocation::Event::Failed(machine.clone()))
        .unwrap();
    exported
        .apply(&allocation::Event::Failed(pass.clone()))
        .unwrap();
    let mut m = exported.clone();
    assert!(m.apply(&allocation::Event::Restore(live)).is_err());
    m.apply(&allocation::Event::Restore(exported.clone()))
        .unwrap();
    s.allocation = Some(m);
    assert!(s.relay_key("fake-other").is_none());
    assert_eq!(s.vpsbg_purchase(&id).unwrap().machine, "fake-create");
}
