use super::*;

struct B947Api {
    inner: Fixture,
    duplicate_create: bool,
    list_status: u16,
    history_status: u16,
}
impl B947Api {
    fn new() -> Self {
        Self {
            inner: Fixture::new(false),
            duplicate_create: false,
            list_status: 200,
            history_status: 200,
        }
    }
}
impl Api for B947Api {
    fn account(&self) -> String {
        self.inner.account()
    }
    fn now(&self) -> u64 {
        self.inner.now()
    }
    fn current(&self) -> Result<(), String> {
        self.inner.current()
    }
    fn response_status(&self) -> u16 {
        self.inner.status
    }
    async fn request(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Value>,
    ) -> Result<Value, protocol::ReadError> {
        let path = format!("/api/v1/{}", url.split_once("/api/v1/").ok_or(REFUSED)?.1);
        let read = if method == "GET" && path == "/api/v1/vm" {
            self.inner.status = self.list_status;
            Some(Ok(json!(self.inner.machines)))
        } else if method == "GET" && path.ends_with("/payments?limit=100&offset=0") {
            self.inner.status = self.history_status;
            let vm = path.split('/').nth(4).unwrap().parse::<u64>().unwrap();
            Some(Ok(self.inner.history_response.clone().unwrap_or_else(
                || {
                    json!(
                        self.inner
                            .payments
                            .iter()
                            .filter(|pay| pay["vm_id"] == vm)
                            .collect::<Vec<_>>()
                    )
                },
            )))
        } else if method == "GET"
            && path
                .strip_prefix("/api/v1/vm/")
                .is_some_and(|tail| tail.parse::<u64>().is_ok())
        {
            let vm = path.rsplit('/').next().unwrap().parse::<u64>().unwrap();
            Some(
                self.inner
                    .machines
                    .iter()
                    .find(|row| row["id"] == vm)
                    .cloned()
                    .ok_or(protocol::ReadError::NotFound),
            )
        } else if method == "GET" && path.starts_with("/api/v1/payment/") {
            let id = path.rsplit('/').next().unwrap();
            Some(
                self.inner
                    .payments
                    .iter()
                    .find(|row| row["id"] == id)
                    .cloned()
                    .ok_or(protocol::ReadError::NotFound),
            )
        } else {
            None
        };
        if let Some(read) = read {
            self.inner.calls.push(format!("{method} {path}"));
            self.inner.urls.push(url.into());
            if let Some(error) = self.inner.read_errors.remove(&path) {
                return Err(error);
            }
            return self.inner.read_values.remove(&path).map_or(read, Ok);
        }
        let result = self.inner.request(method, url, body).await;
        if method == "POST" && path == "/api/v1/vm" {
            for vm in &mut self.inner.machines {
                vm["deleting_on"] = Value::Null;
            }
        }
        if self.duplicate_create && method == "POST" && path == "/api/v1/vm" {
            self.inner
                .machines
                .push(b947_vm(&self.inner.current_selection, 10));
        }
        result
    }
}
fn b947_vm(selected: &Selection, vm_id: u64) -> Value {
    let mut vm = fixtures::vm(selected, vm_id);
    vm["deleting_on"] = Value::Null;
    vm
}
fn b947_approved(entered: bool) -> (Store<MemoryStorage>, B947Api) {
    let mut s = ready();
    let mut api = B947Api::new();
    let secret = hex::encode([7; 32]);
    let account = protocol::Account::parse(secret.as_bytes()).unwrap();
    let source = if entered {
        protocol::AccountSource::Entered
    } else {
        protocol::AccountSource::Generated
    };
    block_on(s.provider_install(
        &account,
        secret.as_bytes(),
        "https://fixture.invalid",
        source,
    ))
    .unwrap();
    api.inner.account = account.public();
    // Historical approvals on entered accounts remain replayable.
    s.provider_account_source = Some(protocol::AccountSource::Generated);
    approve(&mut s, &mut api.inner);
    s.provider_account_source = Some(source);
    (s, api)
}
fn b947_intent(entered: bool) -> (Store<MemoryStorage>, B947Api) {
    let (mut s, mut api) = b947_approved(entered);
    block_on(s.procurement_commit(Record::RegistrationSent)).unwrap();
    block_on(s.procurement_commit(Record::Registered(
        json!({"id":7,"name":"tau-0","created":"2026-11-06T14:00:00Z"}),
    )))
    .unwrap();
    block_on(s.procurement_commit(Record::CreateSent(Create {
        before: Vec::new(),
        started: api.now(),
    })))
    .unwrap();
    api.inner.calls.clear();
    (s, api)
}
fn b947_invoice_intent(entered: bool) -> (Store<MemoryStorage>, B947Api) {
    let (mut s, mut api) = b947_intent(entered);
    api.inner
        .machines
        .push(b947_vm(&api.inner.current_selection, 11));
    if entered {
        block_on(s.procurement_choose(&mut api, 11)).unwrap();
    } else {
        block_on(s.associate_create(&mut api, None)).unwrap();
    }
    block_on(s.procurement_commit(Record::BillingQuoted(Billing {
        vm_id: 11,
        terms: fixtures::billing_terms(),
    })))
    .unwrap();
    block_on(s.procurement_commit(Record::InvoiceSent(Invoice {
        before: Vec::new(),
        started: api.now(),
    })))
    .unwrap();
    (s, api)
}
fn b947_stop(stage: StopStage, now: u64) -> Stopped {
    let mut row = fixtures::payment(11);
    row["is_upgrade"] = json!(true);
    Stopped {
        stage,
        checked_at: now,
        read_status: 200,
        failing_ids: if stage == StopStage::PaymentConflict {
            vec![json!("aabb")]
        } else {
            Vec::new()
        },
        history: if stage == StopStage::PaymentConflict {
            vec![row]
        } else {
            Vec::new()
        },
    }
}

#[test]
fn b947_candidate_key_filter_window_checks_and_cap() {
    let (mut s, mut api) = b947_intent(false);
    for id in 20..40 {
        let mut vm = b947_vm(&api.inner.current_selection, id);
        vm["ssh_key"]["id"] = json!(8);
        vm["template"] = json!(null);
        api.inner.machines.push(vm);
    }
    let before = b947_vm(&api.inner.current_selection, 9);
    s.procurement
        .as_mut()
        .unwrap()
        .create
        .as_mut()
        .unwrap()
        .before
        .push(before.clone());
    api.inner.machines.push(before);
    api.inner
        .machines
        .push(b947_vm(&api.inner.current_selection, 11));
    let result = block_on(s.reconcile_create(&mut api)).unwrap();
    assert_eq!(result.candidates.len(), 1);
    assert!(result.failing.is_empty());
    assert_eq!(api.inner.count("GET /api/v1/vm/9"), 0);
    assert_eq!(api.inner.count("GET /api/v1/vm/20"), 0);
    for (pointer, bad) in [
        ("/created", json!("2026-11-06T13:58:59Z")),
        ("/created", json!("2026-11-06T14:02:01Z")),
        ("/template/cpu", json!(99)),
        ("/expires", json!("2026-12-01T14:00:00Z")),
        ("/deleting_on", json!("2026-11-06T15:00:00Z")),
    ] {
        let mut vm = b947_vm(&api.inner.current_selection, 11);
        vm["deleting_on"] = Value::Null;
        *vm.pointer_mut(pointer).unwrap() = bad;
        api.inner.machines = vec![vm];
        let result = block_on(s.reconcile_create(&mut api)).unwrap();
        assert_eq!(result.failing, vec![11], "{pointer}");
        assert!(result.candidates.is_empty());
    }
    for field in ["expires", "deleting_on", "template"] {
        api.inner.machines = vec![b947_vm(&api.inner.current_selection, 11)];
        let mut detail = api.inner.machines[0].clone();
        detail[field] = json!("conflict");
        api.inner.read_values.insert("/api/v1/vm/11".into(), detail);
        assert_eq!(
            block_on(s.reconcile_create(&mut api)).unwrap().failing,
            vec![11]
        );
    }
    api.inner.machines = vec![b947_vm(&api.inner.current_selection, 11)];
    api.inner.payments.push(fixtures::payment(11));
    assert_eq!(
        block_on(s.reconcile_create(&mut api)).unwrap().failing,
        vec![11]
    );
    api.inner.payments.clear();
    api.inner.machines = (11..20)
        .map(|id| b947_vm(&api.inner.current_selection, id))
        .collect();
    assert_eq!(
        block_on(s.reconcile_create(&mut api))
            .unwrap()
            .failing
            .len(),
        9
    );
    assert!(s.procurement.as_ref().unwrap().vm.is_none());
}

#[test]
fn b947_lowest_id_duplicates_replay_and_immutable_association() {
    let (mut s, mut api) = b947_intent(false);
    api.inner.machines = vec![
        b947_vm(&api.inner.current_selection, 12),
        b947_vm(&api.inner.current_selection, 11),
    ];
    block_on(s.associate_create(&mut api, None)).unwrap();
    let p = s.procurement.as_ref().unwrap();
    assert_eq!(p.vm.as_ref().unwrap()["id"], 11);
    assert_eq!(p.duplicate_orders, vec![12]);
    let loaded = reopen(&s);
    assert_eq!(loaded.procurement, s.procurement);
    assert!(
        s.procurement_projection(&Record::Associated(api.inner.machines[0].clone()))
            .is_err()
    );
    api.inner.calls.clear();
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    assert_eq!(
        api.inner
            .count("GET /api/v1/vm/12/payments?limit=100&offset=0"),
        0
    );
    assert_eq!(
        api.inner
            .count("GET /api/v1/vm/12/renew?method=lightning&intervals=1"),
        0
    );
    let (mut s, mut api) = b947_intent(false);
    block_on(s.procurement_commit(Record::DuplicateOrders { vm_ids: vec![12] })).unwrap();
    let mut s = reopen(&s);
    api.inner.machines = vec![b947_vm(&api.inner.current_selection, 12)];
    assert!(block_on(s.associate_create(&mut api, None)).is_err());
    assert!(s.procurement.as_ref().unwrap().vm.is_none());
}

#[test]
fn b947_successful_create_reconciles_before_adoption() {
    let mut s = ready();
    let mut api = B947Api::new();
    approve(&mut s, &mut api.inner);
    api.duplicate_create = true;
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    let p = s.procurement.as_ref().unwrap();
    assert_eq!(p.vm.as_ref().unwrap()["id"], 10);
    assert_eq!(p.duplicate_orders, vec![11]);
    assert_eq!(api.inner.count("POST /api/v1/vm"), 1);
    assert_eq!(api.inner.count("GET /api/v1/vm"), 2);
    assert_eq!(reopen(&s).procurement, s.procurement);
}

#[test]
fn b947_entered_single_and_multiple_require_one_choice() {
    for count in [1, 2] {
        let (mut s, mut api) = b947_intent(true);
        api.inner.machines = (11..11 + count)
            .map(|id| b947_vm(&api.inner.current_selection, id))
            .collect();
        assert!(block_on(s.associate_create(&mut api, None)).is_err());
        assert!(s.procurement.as_ref().unwrap().vm.is_none());
        assert_eq!(
            s.procurement_view()["candidates"].as_array().unwrap().len(),
            count as usize
        );
        let chosen = 10 + count;
        block_on(s.procurement_choose(&mut api, chosen)).unwrap();
        assert_eq!(s.procurement_view()["vm_id"], chosen);
        assert!(s.procurement.as_ref().unwrap().duplicate_orders.is_empty());
        assert!(block_on(s.procurement_choose(&mut api, chosen)).is_err());
        assert_eq!(reopen(&s).procurement, s.procurement);
    }
}

#[test]
fn b947_before_machine_stop_fresh_read_cleanup_and_replay() {
    for failing in [false, true] {
        let (mut s, mut api) = b947_intent(false);
        let started = api.now();
        api.inner.clock = started + 299;
        assert!(block_on(s.procurement_stop(&mut api, StopStage::BeforeMachine)).is_err());
        assert_eq!(api.inner.count("GET /api/v1/vm"), 0);
        api.inner.clock += 1;
        if failing {
            let mut vm = b947_vm(&api.inner.current_selection, 11);
            vm["created"] = json!("2026-11-06T13:58:00Z");
            api.inner.machines.push(vm);
        }
        assert!(block_on(s.associate_create(&mut api, None)).is_err());
        let prompt = s.procurement_view()["stop"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(prompt.starts_with(if failing {
            "Machine 11 matches this order but can't be used here; it is left as it is."
        } else {
            "No machine has appeared for this order."
        }));
        let count = api.inner.count("GET /api/v1/vm");
        block_on(s.procurement_stop(&mut api, StopStage::BeforeMachine)).unwrap();
        assert_eq!(api.inner.count("GET /api/v1/vm"), count + 1);
        assert!(s.procurement_can_start());
        assert!(s.dispatch.approved_entries.is_empty());
        assert!(s.procurement.is_none());
        assert!(s.closed_purchases[0].vm.is_none());
        assert_eq!(
            s.procurement_view()["closed"],
            "Stopped: order abandoned; no machine adopted. Any late order will be ignored."
        );
        let mut loaded = reopen(&s);
        assert_eq!(loaded.closed_purchases, s.closed_purchases);
        assert!(loaded.procurement_can_start());
        assert!(block_on(loaded.procurement_resume(&mut api, false)).is_err());
        assert!(
            block_on(loaded.procurement_commit(Record::Associated(b947_vm(
                &api.inner.current_selection,
                11
            ))))
            .is_err()
        );
        assert!(api.inner.calls.iter().all(|call| call.starts_with("GET ")));
    }
}

#[test]
fn b947_before_machine_stop_refuses_invalid_records_and_changed_list() {
    let (mut s, mut api) = b947_intent(false);
    api.inner.clock += 300;
    let stop = b947_stop(StopStage::BeforeMachine, api.now());
    assert!(
        s.procurement_projection(&Record::PurchaseStopped(stop.clone()))
            .is_ok()
    );
    for status in [0, 404, 500] {
        let mut bad = stop.clone();
        bad.read_status = status;
        assert!(
            s.replay_procurement(s.next, &Record::PurchaseStopped(bad))
                .is_err()
        );
    }
    let mut bad = stop.clone();
    bad.checked_at -= 1;
    assert!(
        s.procurement_projection(&Record::PurchaseStopped(bad))
            .is_err()
    );
    let original = s.procurement.clone().unwrap();
    for mutation in 0..4 {
        let p = s.procurement.as_mut().unwrap();
        *p = original.clone();
        match mutation {
            0 => p.create = None,
            1 => p.vm = Some(b947_vm(&api.inner.current_selection, 11)),
            2 => {
                p.invoice = Some(Invoice {
                    before: Vec::new(),
                    started: api.now(),
                })
            }
            _ => {
                p.target = Some(TargetRecord {
                    machine: p.machine.clone(),
                    relay: p.relay.clone(),
                    profile: "v1".into(),
                    host: "192.0.2.10".into(),
                    port: 22,
                    user: "arch".into(),
                    elevation: crate::jobs::Elevation::SudoNoninteractive,
                    pin: "unused".into(),
                })
            }
        }
        assert!(
            s.replay_procurement(s.next, &Record::PurchaseStopped(stop.clone()))
                .is_err()
        );
    }
    s.procurement = Some(original);
    assert!(block_on(s.associate_create(&mut api, None)).is_err());
    api.inner
        .machines
        .push(b947_vm(&api.inner.current_selection, 11));
    assert!(block_on(s.procurement_stop(&mut api, StopStage::BeforeMachine)).is_err());
    assert!(s.procurement.is_some());
    api.list_status = 500;
    api.inner.machines.clear();
    assert!(block_on(s.procurement_stop(&mut api, StopStage::BeforeMachine)).is_err());
}

#[test]
fn b947_payment_conflict_stop_rechecks_history_and_replays_for_both_sources() {
    for entered in [false, true] {
        let (mut s, mut api) = b947_invoice_intent(entered);
        let mut conflict = fixtures::payment(11);
        conflict["is_upgrade"] = json!(true);
        api.inner.payments.push(conflict);
        assert!(block_on(s.associate_payment(&mut api, false)).is_err());
        assert_eq!(s.procurement_view()["stop"]["failing_ids"], json!(["aabb"]));
        assert!(s.procurement_view()["stop"].get("history").is_none());
        let stop = s.procurement_recovery.stop.clone().unwrap();
        assert!(
            s.procurement_projection(&Record::PurchaseStopped(stop.clone()))
                .is_ok()
        );
        let original = s.procurement.clone().unwrap();
        for mutation in 0..4 {
            let p = s.procurement.as_mut().unwrap();
            *p = original.clone();
            match mutation {
                0 => p.payment = Some(fixtures::payment(11)),
                1 => p.invoice = None,
                2 => p.vm = None,
                _ => p.billing = None,
            }
            assert!(
                s.replay_procurement(s.next, &Record::PurchaseStopped(stop.clone()))
                    .is_err()
            );
        }
        s.procurement = Some(original);
        for mutation in 0..4 {
            let mut bad = stop.clone();
            match mutation {
                0 => bad.read_status = 500,
                1 => bad.failing_ids.clear(),
                2 => bad.history[0]["is_upgrade"] = json!(false),
                _ => bad.checked_at = 0,
            }
            assert!(
                s.replay_procurement(s.next, &Record::PurchaseStopped(bad))
                    .is_err()
            );
        }
        let count = api
            .inner
            .count("GET /api/v1/vm/11/payments?limit=100&offset=0");
        block_on(s.procurement_stop(&mut api, StopStage::PaymentConflict)).unwrap();
        assert_eq!(
            api.inner
                .count("GET /api/v1/vm/11/payments?limit=100&offset=0"),
            count + 1
        );
        assert_eq!(
            s.closed_purchases[0].stopped.as_ref().unwrap().history,
            api.inner.payments
        );
        assert!(s.procurement_can_start());
        assert!(s.procurement_view()["closed"].as_str().unwrap().contains(if entered { "manage it there." } else { "This purchase will never use, invoice or pay for it; if it is unpaid, the provider deletes it within about an hour." }));
        assert_eq!(reopen(&s).closed_purchases, s.closed_purchases);
        assert!(block_on(s.procurement_resume(&mut api, true)).is_err());
        assert_eq!(
            api.inner
                .count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
            0
        );
    }
}

#[test]
fn b947_payment_conflict_stop_refuses_saved_payment_or_resolved_history() {
    let (mut s, mut api) = b947_invoice_intent(false);
    let mut bad = fixtures::payment(11);
    bad["is_upgrade"] = json!(true);
    api.inner.payments.push(bad);
    assert!(block_on(s.associate_payment(&mut api, false)).is_err());
    api.inner.payments[0]["is_upgrade"] = json!(false);
    assert!(block_on(s.procurement_stop(&mut api, StopStage::PaymentConflict)).is_err());
    api.history_status = 500;
    api.inner.payments[0]["is_upgrade"] = json!(true);
    assert!(block_on(s.procurement_stop(&mut api, StopStage::PaymentConflict)).is_err());
    api.history_status = 200;
    block_on(s.procurement_commit(s.payment_record(fixtures::payment(11), api.now()))).unwrap();
    let count = api.inner.calls.len();
    assert!(block_on(s.procurement_stop(&mut api, StopStage::PaymentConflict)).is_err());
    assert_eq!(api.inner.calls.len(), count);
}

#[test]
fn b947_lost_invoice_reply_selects_once_before_display() {
    for (rows, chosen, notice) in [
        (
            vec![("ccdd", false, "00"), ("aabb", true, "01")],
            "aabb",
            Some(SECOND_INVOICE),
        ),
        (vec![("ccdd", false, "00")], "ccdd", None),
        (vec![("ccdd", true, "00")], "ccdd", None),
        (
            vec![("CCDD", false, "00"), ("aabb", false, "00")],
            "aabb",
            Some(SECOND_INVOICE),
        ),
        (
            vec![("ccdd", true, "01"), ("aabb", true, "00")],
            "aabb",
            Some(PAID_TWICE),
        ),
        (
            vec![("aabb", false, "00.900"), ("ccdd", false, "00.100")],
            "ccdd",
            Some(SECOND_INVOICE),
        ),
    ] {
        let (mut s, mut api) = b947_invoice_intent(false);
        for (id, paid, seconds) in rows {
            let mut payment = fixtures::payment(11);
            payment["id"] = json!(id);
            payment["is_paid"] = json!(paid);
            payment["created"] = json!(format!("2026-11-06T14:00:{seconds}Z"));
            api.inner.payments.push(payment);
        }
        block_on(s.associate_payment(&mut api, true)).unwrap();
        assert_eq!(s.procurement_view()["payment"]["id"], chosen);
        assert_eq!(s.procurement_view()["payment_notice"], json!(notice));
        assert_eq!(reopen(&s).procurement, s.procurement);
        let mut replacement = fixtures::payment(11);
        replacement["id"] = json!("eeff");
        assert!(
            s.procurement_projection(&s.payment_record(replacement, api.now()))
                .is_err()
        );
        assert_eq!(
            api.inner
                .count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
            0
        );
    }
    let (mut s, mut api) = b947_invoice_intent(false);
    api.inner.payments = vec![fixtures::payment(11), fixtures::payment(11)];
    api.inner.payments[1]["id"] = json!("ccdd");
    api.inner.payments[1]["amount"] = json!(999);
    assert!(block_on(s.associate_payment(&mut api, false)).is_err());
    assert!(s.procurement_view()["payment"].is_null());
    assert_eq!(s.procurement_view()["stop"]["stage"], "payment_conflict");
    api.inner.payments[1] = fixtures::payment(99);
    api.inner.payments[1]["id"] = json!("ccdd");
    api.inner.history_response = Some(json!(api.inner.payments));
    assert!(block_on(s.associate_payment(&mut api, false)).is_err());
    assert_eq!(s.procurement_view()["stop"]["failing_ids"], json!(["ccdd"]));
    block_on(s.procurement_stop(&mut api, StopStage::PaymentConflict)).unwrap();
    assert!(s.procurement_can_start());
    assert_eq!(reopen(&s).closed_purchases, s.closed_purchases);
}

#[test]
fn b947_entered_account_core_refusals_and_existing_recovery() {
    let mut s = ready();
    let secret = hex::encode([7; 32]);
    let account = protocol::Account::parse(secret.as_bytes()).unwrap();
    assert_eq!(
        block_on(s.procurement_configure(&account, secret.as_bytes(), "https://fixture.invalid"))
            .unwrap_err(),
        ENTERED_REFUSED
    );
    assert!(s.provider_account().is_none());
    block_on(s.provider_install(
        &account,
        secret.as_bytes(),
        "https://fixture.invalid",
        protocol::AccountSource::Entered,
    ))
    .unwrap();
    let mut fresh_api = Fixture::new(false);
    fresh_api.account = account.public();
    let new_approval = Approval {
        origin: s.procurement_origin().into(),
        ..approval()
    };
    assert_eq!(
        block_on(s.procurement_approve(&mut fresh_api, new_approval)).unwrap_err(),
        ENTERED_REFUSED
    );
    assert!(s.procurement.is_none());
    assert!(fresh_api.calls.is_empty());
    let (mut s, mut api) = b947_intent(true);
    assert!(block_on(s.procurement_approve(&mut api, approval())).is_err());
    api.inner
        .machines
        .push(b947_vm(&api.inner.current_selection, 11));
    block_on(s.procurement_choose(&mut api, 11)).unwrap();
    assert_eq!(
        block_on(s.associate_payment(&mut api, true)).unwrap_err(),
        "This page can't pay for this purchase, because it no longer issues invoices on a provider account you entered yourself. Leave it with Stop this purchase or Close purchase below. Your existing machines keep working here."
    );
    assert_eq!(
        api.inner
            .count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        0
    );
    let (mut s, mut api) = b947_invoice_intent(true);
    api.inner.payments.push(fixtures::payment(11));
    block_on(s.associate_payment(&mut api, true)).unwrap();
    let mut loaded = reopen(&s);
    api.inner.payments[0]["is_paid"] = json!(true);
    block_on(loaded.procurement_payment_check(&mut api)).unwrap();
    assert_eq!(loaded.procurement_view()["payment"]["is_paid"], true);
}

#[test]
fn b947_account_source_is_retained_across_replay() {
    for entered in [false, true] {
        let (s, _) = b947_intent(entered);
        assert_eq!(s.provider_account_entered(), entered);
        assert_eq!(reopen(&s).provider_account_entered(), entered);
    }
}

#[test]
fn b947_missing_unpaid_fields_are_failing_rows_in_list_and_detail() {
    for field in ["expires", "deleting_on"] {
        for missing_in_detail in [false, true] {
            let (mut s, mut api) = b947_intent(false);
            let vm = b947_vm(&api.inner.current_selection, 11);
            let mut incomplete = vm.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            if missing_in_detail {
                api.inner.machines = vec![vm];
                api.inner
                    .read_values
                    .insert("/api/v1/vm/11".into(), incomplete);
            } else {
                api.inner.machines = vec![incomplete];
            }
            let result = block_on(s.reconcile_create(&mut api)).unwrap();
            assert_eq!(
                result.failing,
                vec![11],
                "{field}, detail: {missing_in_detail}"
            );
            assert!(result.candidates.is_empty());
        }
    }
}

#[test]
fn b947_lowest_id_is_enforced_on_append_and_replay_in_both_orders() {
    for duplicates_first in [false, true] {
        for duplicate_id in [11, 12, 13] {
            let (mut s, api) = b947_intent(false);
            let associated = Record::Associated(b947_vm(&api.inner.current_selection, 12));
            let duplicates = Record::DuplicateOrders {
                vm_ids: vec![duplicate_id],
            };
            let (first, second) = if duplicates_first {
                (duplicates, associated)
            } else {
                (associated, duplicates)
            };
            block_on(s.procurement_commit(first)).unwrap();
            let valid = duplicate_id > 12;
            if valid {
                block_on(s.procurement_commit(second)).unwrap();
                assert_eq!(reopen(&s).procurement, s.procurement);
            } else {
                let before = s.storage.files();
                assert!(block_on(s.procurement_commit(second.clone())).is_err());
                assert_eq!(s.storage.files(), before);
                // Write an authenticated record directly so unlock exercises replay validation.
                block_on(s.commit(&Event::Procurement(second))).unwrap();
                assert!(
                    block_on(unlock(
                        MemoryStorage::with_files(s.storage.files()),
                        &Fixed,
                        pass(),
                    ))
                    .is_err()
                );
            }
        }
    }
}

#[test]
fn b947_legacy_associated_machine_with_expiry_replays() {
    let (mut s, api) = b947_intent(true);
    let mut vm = fixtures::vm(&api.inner.current_selection, 11);
    vm["expires"] = json!("2026-12-06T14:00:00Z");
    // Older journals could associate an operator-paid machine before recovery.
    block_on(s.commit(&Event::Procurement(Record::Associated(vm.clone())))).unwrap();
    let loaded = reopen(&s);
    assert_eq!(loaded.procurement.as_ref().unwrap().vm.as_ref(), Some(&vm));
    assert!(loaded.provider_account_entered());
}

#[test]
fn b947_entered_account_reapproves_changed_terms_on_existing_purchase() {
    let (mut s, mut api) = b947_approved(true);
    let original = s.procurement.clone().unwrap();
    api.inner.current_selection.charge.amount *= 2;
    api.inner.current_selection.offer["cost_plan"]["amount"] =
        json!(api.inner.current_selection.charge.amount);
    block_on(s.procurement_select(
        &mut api,
        Choice {
            offer_id: 1,
            image_id: 3,
            resources: None,
        },
    ))
    .unwrap();
    let selected = s
        .procurement
        .as_ref()
        .unwrap()
        .pending_selection
        .clone()
        .unwrap();
    let mut s = reopen(&s);
    assert!(s.provider_account_entered());
    assert_eq!(s.procurement_view()["phase"], "terms_changed");
    let approval = Approval {
        origin: s.procurement_origin().into(),
        ..approval()
    };
    block_on(s.procurement_approve(&mut api, approval)).unwrap();
    let p = s.procurement.as_ref().unwrap();
    assert_eq!(p.identity, original.identity);
    assert_eq!(p.relay_identity, original.relay_identity);
    assert_eq!(p.account, original.account);
    assert_eq!(p.selected, selected);
    assert!(p.pending_selection.is_none());
    assert!(p.create.is_none());
    assert_eq!(api.inner.count("POST /api/v1/vm"), 0);
    assert_eq!(reopen(&s).procurement, s.procurement);
}
