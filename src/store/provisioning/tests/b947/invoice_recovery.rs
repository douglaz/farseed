use super::*;

fn duplicate_invoices() -> Vec<Value> {
    vec![
        fixtures::recovered_invoice(0xab, "8000n", Some(60)),
        fixtures::recovered_invoice(0xcd, "8000n", Some(120)),
    ]
}

fn payment_request(row: &Value) -> String {
    format!("GET /api/v1/payment/{}", row["id"].as_str().unwrap())
}

fn assert_invoice_pause(s: &Store<MemoryStorage>) {
    let view = s.procurement_view();
    assert_eq!(view["phase"], "invoice_uncertain");
    assert!(view["payment"].is_null());
    assert!(view["payment_notice"].is_null());
    assert!(view["recovered_invoice_deadline_ms"].is_null());
}

#[test]
fn recovered_invoice_uses_one_dispatch_one_saved_id_and_the_earlier_deadline() {
    let (mut s, mut api) = b947_approved(false);
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    assert_eq!(api.inner.count(ISSUE), 0);
    api.inner.lose_invoice = true;
    assert_eq!(
        block_on(s.procurement_resume(&mut api, true)).unwrap_err(),
        INVOICE_CONFIRMATION_MISSING
    );
    let issued = s.procurement.as_ref().unwrap().invoice.clone();
    assert!(issued.is_some());
    api.inner.payments = duplicate_invoices();
    api.inner.payments[0]["expires"] = json!("2026-11-06T14:00:30.900Z");
    let first = api.inner.payments[0].clone();
    let fractional_deadline = api.now_millis() + 30_900;
    api.set_millis(fractional_deadline - 800);
    let mut loaded = reopen(&s);
    block_on(loaded.procurement_resume(&mut api, false)).unwrap();
    assert_eq!(loaded.procurement_view()["payment"], first);
    assert_eq!(loaded.procurement_view()["recovered_invoice_deadline_ms"], fractional_deadline);
    assert_eq!(loaded.procurement.as_ref().unwrap().invoice, issued);
    assert_eq!(api.inner.count(ISSUE), 1);
    assert_eq!(api.inner.count(&payment_request(&first)), 1);

    // A second unlock sees the same data the page uses for its countdown and wallet controls.
    let mut second_tab = reopen(&loaded);
    assert_eq!(second_tab.procurement_view(), loaded.procurement_view());
    api.set_millis(fractional_deadline);
    api.inner.calls.clear();
    assert_eq!(
        block_on(second_tab.procurement_resume(&mut api, true)).unwrap_err(),
        "This invoice has expired. Press “Check now” if you already paid."
    );
    assert_eq!(api.inner.calls, [payment_request(&first)]);
    assert_eq!(reopen(&second_tab).procurement_view()["payment"], first);
    api.inner.payments[0]["is_paid"] = json!(true);
    api.inner.calls.clear();
    block_on(second_tab.procurement_payment_check(&mut api)).unwrap();
    assert_eq!(api.inner.calls, [payment_request(&first)]);
    assert_eq!(reopen(&second_tab).procurement_view()["payment"]["id"], first["id"]);
    assert_eq!(reopen(&second_tab).procurement_view()["payment"]["is_paid"], true);
}

#[test]
fn recovered_invoice_uses_encoded_deadline_and_excludes_expired_older_rows() {
    let (mut s, mut api) = b947_invoice_intent(false);
    api.inner.payments = duplicate_invoices();
    let start = api.now_millis();
    api.set_millis(start + 60_000);
    block_on(s.procurement_resume(&mut api, false)).unwrap();
    let view = reopen(&s).procurement_view();
    assert_eq!(view["payment"], api.inner.payments[1]);
    assert_eq!(view["recovered_invoice_deadline_ms"], start + 120_000);
    let recovery = s.procurement.as_ref().unwrap().invoice_recovery.as_ref().unwrap();
    assert_eq!(recovery.expired_unshown_ids, BTreeSet::from([hex::encode([0xab; 32])]));
    assert_eq!(api.inner.count(&payment_request(&api.inner.payments[0])), 0);
    assert_eq!(api.inner.count(ISSUE), 0);
}

#[test]
fn recovered_invoice_refuses_insufficient_evidence_for_the_wallet_amount() {
    for mode in ["different", "over approved", "hash", "unparseable", "upgrade"] {
        let (mut s, mut api) = b947_invoice_intent(false);
        api.inner.payments = duplicate_invoices();
        match mode {
            "different" => {
                api.inner.payments[1] = fixtures::recovered_invoice(0xcd, "12300n", None);
            }
            "over approved" => {
                api.inner.payments = [0xab, 0xcd]
                    .map(|id| fixtures::recovered_invoice(id, "12310n", None))
                    .to_vec();
            }
            "hash" => api.inner.payments[1]["id"] = json!(hex::encode([0xce; 32])),
            "unparseable" => api.inner.payments[1]["data"]["lightning"] = json!("lnbc1invalid"),
            _ => api.inner.payments[1]["is_upgrade"] = json!(true),
        }
        api.inner.calls.clear();
        assert_eq!(
            block_on(s.procurement_resume(&mut api, true)).unwrap_err(),
            INVOICE_TERMS_UNVERIFIED,
            "{mode}"
        );
        assert_invoice_pause(&reopen(&s));
        assert_eq!(api.inner.calls, [format!("GET {HISTORY}")], "{mode}");
    }
}

#[test]
fn recovered_invoice_rounds_approved_amount_up_to_the_next_whole_sat() {
    // A quote of 1,229,999 millisat authorizes at most 1,230 whole sats.
    let mut terms = fixtures::billing_terms();
    terms.tax -= 1;
    let (mut quoted, mut quote_api) = b947_approved(false);
    quote_api.inner.billing_terms = terms;
    assert!(block_on(quoted.procurement_resume(&mut quote_api, false)).is_err());
    quote_api.inner.lose_invoice = true;
    assert_eq!(
        block_on(quoted.procurement_resume(&mut quote_api, true)).unwrap_err(),
        INVOICE_CONFIRMATION_MISSING
    );
    quote_api.inner.payments = [0xab, 0xcd]
        .map(|id| {
            let mut row = fixtures::recovered_invoice(id, "12300n", None);
            row["tax"] = json!(229_999);
            row
        })
        .to_vec();
    block_on(quoted.procurement_resume(&mut quote_api, false)).unwrap();
    assert_eq!(quoted.procurement_view()["payment"], quote_api.inner.payments[0]);
    assert_eq!(quote_api.inner.count(ISSUE), 1);
}

#[test]
fn recovered_invoice_checks_selected_detail_and_the_closing_history() {
    for mode in [
        "reordered", "fraction changed", "detail changed", "detail missing",
        "detail paid", "sibling paid",
    ] {
        let (mut s, mut api) = b947_invoice_intent(false);
        api.inner.payments = duplicate_invoices();
        // Both invoices are in the same creation second. A fractional change in
        // the second read would reverse their ranking without changing seconds.
        api.inner.payments[0]["created"] = json!("2026-11-06T14:00:00.100Z");
        api.inner.payments[1]["created"] = json!("2026-11-06T14:00:00.200Z");
        let first = api.inner.payments[0].clone();
        let selected_path = payment_request(&first);
        let selected_path = selected_path.strip_prefix("GET ").unwrap();
        let mut latest = api.inner.payments.clone();
        match mode {
            "reordered" => latest.reverse(),
            "fraction changed" => latest[0]["created"] = json!("2026-11-06T14:00:00.300Z"),
            "detail changed" => {
                let mut detail = first.clone();
                detail["created"] = json!("2026-11-06T14:00:00.300Z");
                api.inner.read_values.insert(selected_path.into(), detail);
            }
            "detail missing" => {
                api.inner.read_errors.insert(selected_path.into(), protocol::ReadError::NotFound);
            }
            "detail paid" => {
                let mut detail = first.clone();
                detail["is_paid"] = json!(true);
                api.inner.read_values.insert(selected_path.into(), detail);
            }
            _ => latest[1]["is_paid"] = json!(true),
        }
        api.queue_read(HISTORY, json!(api.inner.payments));
        let closes_history = matches!(mode, "reordered" | "fraction changed" | "sibling paid");
        if closes_history {
            api.queue_read(HISTORY, json!(latest));
        }
        api.inner.calls.clear();
        let result = block_on(s.procurement_resume(&mut api, false));
        assert!(api.scripted_reads.is_empty(), "{mode}");
        let mut calls = vec![format!("GET {HISTORY}"), payment_request(&first)];
        if closes_history {
            calls.push(format!("GET {HISTORY}"));
        }
        assert_eq!(api.inner.calls, calls, "{mode}");
        let s = reopen(&s);
        if mode == "reordered" {
            result.unwrap();
            assert_eq!(s.procurement_view()["payment"], first);
        } else {
            assert_eq!(
                result.unwrap_err(),
                match mode {
                    "fraction changed" => INVOICE_TERMS_UNVERIFIED,
                    "detail changed" | "detail missing" => INVOICE_DETAIL_UNVERIFIED,
                    _ => INVOICE_ALREADY_PAID,
                },
                "{mode}"
            );
            assert_invoice_pause(&s);
            assert_eq!(
                s.procurement_view()["invoice_recovery_blocked"] == true,
                matches!(mode, "detail paid" | "sibling paid")
            );
        }
    }
}

#[test]
fn invoice_history_paid_and_bound_blocks_survive_a_later_smaller_history() {
    for count in [3, 100, 129] {
        let (mut s, mut api) = b947_invoice_intent(false);
        let mut rows = history_rows(count);
        if count == 3 {
            // The paid match is sufficient even when its siblings are malformed.
            rows[0] = json!({"is_paid":true,"vm_id":11});
            rows[1] = rows[2].clone();
        }
        api.inner.history_response = Some(json!(rows));
        api.inner.calls.clear();
        let (reason, block) = if count == 3 {
            (INVOICE_ALREADY_PAID, InvoiceRecoveryBlock::AlreadyPaid)
        } else {
            (INVOICE_HISTORY_INCOMPLETE, InvoiceRecoveryBlock::HistoryLimit)
        };
        assert_eq!(block_on(s.procurement_resume(&mut api, true)).unwrap_err(), reason);
        assert_eq!(api.inner.calls, [format!("GET {HISTORY}")]);
        assert!(matches!(purchase_events(&s).last().unwrap(),
            Event::Procurement(Record::InvoiceRecoveryBlocked(saved)) if *saved == block));
        let mut loaded = reopen(&s);
        api.inner.history_response = Some(json!([fixtures::payment(11)]));
        api.inner.calls.clear();
        assert_eq!(block_on(loaded.procurement_resume(&mut api, false)).unwrap_err(), reason);
        assert_eq!(
            block_on(loaded.procurement_stop(&mut api, StopStage::PaymentConflict)).unwrap_err(),
            reason
        );
        assert!(block_on(loaded.procurement_close(&mut api)).is_err());
        assert!(api.inner.calls.is_empty());
        assert_invoice_pause(&loaded);
        assert_eq!(loaded.procurement_view()["confirmation_message"], reason);
        assert!(loaded.procurement_view()["stop"].is_null());
        assert!(loaded.closed_purchases.is_empty());
        assert!(loaded.procurement_projection(&Record::Closed {
            vm_id: 11, inventory_status: 200, detail_status: 404, history_status: 404,
            checked_at: api.now() + 86_400,
        }).is_err());
    }
}

#[test]
fn invoice_stop_cannot_discard_a_newly_paid_row() {
    let (mut s, mut api) = b947_invoice_intent(false);
    api.inner.payments = duplicate_invoices();
    api.inner.payments[0]["is_upgrade"] = json!(true);
    assert_eq!(
        block_on(s.procurement_resume(&mut api, false)).unwrap_err(),
        INVOICE_TERMS_UNVERIFIED
    );
    assert_eq!(s.procurement_view()["stop"]["stage"], "payment_conflict");
    api.inner.payments[1]["is_paid"] = json!(true);
    assert_eq!(
        block_on(s.procurement_stop(&mut api, StopStage::PaymentConflict)).unwrap_err(),
        INVOICE_ALREADY_PAID
    );
    let mut loaded = reopen(&s);
    assert_invoice_pause(&loaded);
    assert!(loaded.procurement_view()["stop"].is_null());
    api.inner.payments.pop();
    api.inner.calls.clear();
    assert_eq!(
        block_on(loaded.procurement_stop(&mut api, StopStage::PaymentConflict)).unwrap_err(),
        INVOICE_ALREADY_PAID
    );
    assert!(api.inner.calls.is_empty());
    assert!(loaded.closed_purchases.is_empty());
}

#[derive(Clone, Copy)]
enum SavedInvoice {
    Adopted,
    Issued,
    LostReply,
}

fn saved_invoice_for_close(source: SavedInvoice) -> (Store<MemoryStorage>, B947Api) {
    let adopted = matches!(source, SavedInvoice::Adopted);
    let lost_reply = matches!(source, SavedInvoice::LostReply);
    let (mut s, mut api) = if adopted {
        b947_intent(false)
    } else {
        b947_approved(false)
    };
    if adopted {
        api.inner.machines = vec![b947_vm(&api.inner.current_selection, 11)];
        block_on(s.associate_create(&mut api, None)).unwrap();
        api.inner.payments.push(fixtures::payment(11));
        assert!(!block_on(s.associate_payment(&mut api, false)).unwrap());
    } else {
        assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
        api.inner.lose_invoice = lost_reply;
        let reply = block_on(s.procurement_resume(&mut api, true)).unwrap_err();
        if lost_reply {
            assert_eq!(reply, INVOICE_CONFIRMATION_MISSING);
            s = reopen(&s);
            assert!(!block_on(s.associate_payment(&mut api, false)).unwrap());
        } else {
            assert!(reply.contains("Waiting for external payment"));
        }
    }
    let purchase = s.procurement.as_ref().unwrap();
    assert_eq!(purchase.invoice.is_some(), !adopted);
    assert_eq!(api.inner.count(ISSUE), usize::from(!adopted));
    if lost_reply {
        assert_eq!(purchase.invoice_history_ids, BTreeSet::from(["aabb".into()]));
        assert!(purchase.invoice_history_at_ms.is_some());
    } else {
        assert!(purchase.invoice_history_ids.is_empty());
        assert!(purchase.invoice_history_at_ms.is_none());
    }
    assert_eq!(s.procurement_view()["payment"]["id"], "aabb");
    (s, api)
}

#[test]
fn invoice_close_cannot_discard_a_paid_history_for_a_saved_invoice() {
    for source in [SavedInvoice::Adopted, SavedInvoice::Issued, SavedInvoice::LostReply] {
        let (mut s, mut api) = saved_invoice_for_close(source);
        let original = s.procurement_view()["payment"].clone();
        api.inner.clock += 86_400;
        api.inner.machines.clear();
        api.inner.payments[0]["is_paid"] = json!(true);
        api.inner.calls.clear();
        assert_eq!(
            block_on(s.procurement_close(&mut api)).unwrap_err(),
            INVOICE_ALREADY_PAID
        );
        assert_eq!(
            api.inner.calls,
            ["GET /api/v1/vm", "GET /api/v1/vm/11", &format!("GET {HISTORY}")]
        );
        let mut loaded = reopen(&s);
        assert_invoice_pause(&loaded);
        assert_eq!(loaded.procurement.as_ref().unwrap().payment.as_ref(), Some(&original));
        assert_eq!(loaded.procurement_view()["confirmation_message"], INVOICE_ALREADY_PAID);
        api.inner.read_errors.insert(HISTORY.into(), protocol::ReadError::NotFound);
        api.inner.calls.clear();
        assert!(block_on(loaded.procurement_close(&mut api)).is_err());
        assert!(loaded.closed_purchases.is_empty());
        assert!(api.inner.calls.is_empty());
    }
}

#[test]
fn invoice_close_counts_the_saved_id_and_the_union_across_repeated_reads() {
    for (source, split) in [
        (SavedInvoice::Adopted, false),
        (SavedInvoice::Adopted, true),
        (SavedInvoice::Issued, false),
        (SavedInvoice::Issued, true),
    ] {
        let (mut s, mut api) = saved_invoice_for_close(source);
        api.inner.clock += 86_400;
        api.inner.machines.clear();
        let mut rows = history_rows(99);
        if split {
            let later = rows.pop().unwrap();
            api.inner.history_response = Some(json!(rows));
            assert!(block_on(s.procurement_close(&mut api)).is_err());
            s = reopen(&s);
            assert!(s.procurement_view()["invoice_recovery_blocked"].is_null());
            assert_eq!(s.procurement.as_ref().unwrap().invoice_history_ids.len(), 98);
            rows = vec![later];
        }
        api.inner.history_response = Some(json!(rows));
        assert_eq!(
            block_on(s.procurement_close(&mut api)).unwrap_err(),
            INVOICE_HISTORY_INCOMPLETE
        );
        let mut loaded = reopen(&s);
        assert_invoice_pause(&loaded);
        api.inner.calls.clear();
        api.inner.read_errors.insert(HISTORY.into(), protocol::ReadError::NotFound);
        assert!(block_on(loaded.procurement_close(&mut api)).is_err());
        assert_eq!(loaded.procurement_view()["confirmation_message"], INVOICE_HISTORY_INCOMPLETE);
        assert!(loaded.closed_purchases.is_empty());
        assert!(api.inner.calls.is_empty());
    }
}

#[test]
fn invoice_recovery_replay_keeps_unverified_siblings_and_the_latest_receipt_clock() {
    for known_ids in [false, true] {
        let (mut s, mut api) = b947_invoice_intent(false);
        let start = api.now_millis();
        let observed = start + 60_001;
        let rows = duplicate_invoices();
        api.inner.payments = rows.clone();
        let record_no = s.next;
        let step = api.queue_read(HISTORY, json!(rows));
        step.millis = Some(if known_ids { start } else { observed });
        step.fault = Some((s.storage.clone(), Fault::LandThenFail(3)));
        api.clock_after_append.push((s.storage.clone(), record_no, start));
        api.inner.calls.clear();
        assert_eq!(
            block_on(s.procurement_resume(&mut api, false)).unwrap_err(),
            INVOICE_REOPEN_TO_CHECK
        );
        assert_eq!(api.inner.calls, [format!("GET {HISTORY}")]);
        assert_invoice_pause(&s);
        assert_eq!(api.now_millis(), start);
        let mut loaded = reopen(&s);
        api.clock_after_append.clear();
        assert_eq!(
            loaded.procurement.as_ref().unwrap().invoice_history_at_ms,
            Some(if known_ids { start } else { observed })
        );
        assert!(loaded.procurement.as_ref().unwrap().invoice_recovery.is_none());
        if known_ids {
            api.set_millis(observed);
            api.inner.payments.truncate(1);
            api.inner.calls.clear();
            assert_eq!(
                block_on(loaded.procurement_resume(&mut api, false)).unwrap_err(),
                INVOICE_TERMS_UNVERIFIED
            );
            assert_eq!(api.inner.calls, [format!("GET {HISTORY}")]);
            assert_invoice_pause(&loaded);
            assert!(matches!(
                purchase_events(&loaded).last().unwrap(),
                Event::Procurement(Record::InvoiceHistoryObserved { ids, received_at_ms })
                    if ids.is_empty() && *received_at_ms == observed
            ));
            loaded = reopen(&loaded);
        }
        api.set_millis(start);
        api.inner.payments = rows.clone();
        block_on(loaded.procurement_resume(&mut api, false)).unwrap();
        assert_eq!(loaded.procurement_view()["payment"], rows[1]);
        let recovery = loaded
            .procurement
            .as_ref()
            .unwrap()
            .invoice_recovery
            .as_ref()
            .unwrap();
        assert_eq!(
            recovery.expired_unshown_ids,
            BTreeSet::from([rows[0]["id"].as_str().unwrap().into()])
        );
        assert_eq!(api.inner.count(ISSUE), 0);
    }
}

#[test]
fn invoice_recovery_saves_sibling_expiry_after_a_failed_detail_or_a_late_closing_read() {
    for detail_failed in [false, true] {
        let (mut s, mut api) = b947_invoice_intent(false);
        let start = api.now_millis();
        let mut rows = duplicate_invoices();
        // A is selected. Both A and B expire while the request is outstanding.
        rows[1] = fixtures::recovered_invoice(0xcd, "8000n", Some(60));
        api.inner.payments = rows.clone();
        if detail_failed {
            let detail = payment_request(&rows[0]).strip_prefix("GET ").unwrap().to_owned();
            api.inner.after_read_clock = Some((detail.clone(), (start + 60_000) / 1000));
            api.inner.read_errors.insert(detail, protocol::ReadError::NotFound);
        } else {
            api.queue_read(HISTORY, json!(rows));
            api.queue_read(HISTORY, json!(rows)).millis = Some(start + 60_000);
        }
        assert_eq!(
            block_on(s.procurement_resume(&mut api, false)).unwrap_err(),
            if detail_failed { INVOICE_DETAIL_UNVERIFIED } else { INVOICE_EXPIRED_BEFORE_DISPLAY }
        );
        assert!(api.scripted_reads.is_empty());
        assert_invoice_pause(&s);
        let mut loaded = reopen(&s);
        let proof = loaded.procurement.as_ref().unwrap().invoice_recovery.as_ref().unwrap();
        assert_eq!(proof.expired_unshown_ids, proof.observed_ids);
        assert_eq!(proof.expired_unshown_ids.len(), 2);
        api.set_millis(start);
        api.inner.payments.remove(0);
        api.inner.calls.clear();
        assert_eq!(
            block_on(loaded.procurement_resume(&mut api, false)).unwrap_err(),
            INVOICES_EXPIRED
        );
        assert_eq!(api.inner.calls, [format!("GET {HISTORY}")]);
        assert_invoice_pause(&loaded);
        assert_eq!(loaded.procurement_view()["confirmation_message"], INVOICES_EXPIRED);
    }

    let (mut s, mut api) = b947_invoice_intent(false);
    let start = api.now_millis();
    let rows = duplicate_invoices();
    api.inner.payments = rows.clone();
    let mut changed = rows.clone();
    changed.push(fixtures::recovered_invoice(0xef, "8000n", None));
    api.queue_read(HISTORY, json!(rows));
    api.queue_read(HISTORY, json!(changed)).millis = Some(start + 60_000);
    // The third append stores the newly seen ID from the changed closing
    // history. Force rollback before recovery can sample the clock again.
    api.clock_after_append.push((s.storage.clone(), s.next + 2, start));
    assert_eq!(
        block_on(s.procurement_resume(&mut api, false)).unwrap_err(),
        INVOICE_TERMS_UNVERIFIED
    );
    assert!(api.scripted_reads.is_empty());
    assert_eq!(api.now_millis(), start);
    assert_invoice_pause(&s);
    let mut loaded = reopen(&s);
    let purchase = loaded.procurement.as_ref().unwrap();
    assert_eq!(purchase.invoice_history_at_ms, Some(start + 60_000));
    assert_eq!(
        purchase.invoice_recovery.as_ref().unwrap().expired_unshown_ids,
        BTreeSet::from([rows[0]["id"].as_str().unwrap().into()])
    );
    api.clock_after_append.clear();
    api.set_millis(start);
    api.inner.payments = changed;
    block_on(loaded.procurement_resume(&mut api, false)).unwrap();
    assert_eq!(loaded.procurement_view()["payment"], rows[1]);
}

#[test]
fn invoice_recovery_accumulates_unverified_ids_before_validation_and_blocks_the_union() {
    let (mut s, mut api) = b947_invoice_intent(false);
    api.inner.history_response = Some(json!(history_rows(99)));
    api.inner.calls.clear();
    assert_eq!(
        block_on(s.procurement_resume(&mut api, false)).unwrap_err(),
        INVOICE_TERMS_UNVERIFIED
    );
    let mut loaded = reopen(&s);
    assert_eq!(loaded.procurement.as_ref().unwrap().invoice_history_ids.len(), 99);
    let mut bad = fixtures::payment(11);
    bad["is_upgrade"] = json!(true);
    api.inner.history_response = Some(json!([history_rows(1)[0], bad]));
    assert_eq!(
        block_on(loaded.procurement_resume(&mut api, false)).unwrap_err(),
        INVOICE_HISTORY_INCOMPLETE
    );
    let mut loaded = reopen(&loaded);
    api.inner.history_response = Some(json!(history_rows(1)));
    api.inner.calls.clear();
    assert_eq!(
        block_on(loaded.procurement_resume(&mut api, true)).unwrap_err(),
        INVOICE_HISTORY_INCOMPLETE
    );
    assert!(api.inner.calls.is_empty());
    assert_invoice_pause(&loaded);
}

#[test]
fn invoice_expiry_during_the_selection_append_never_exposes_that_invoice() {
    for (reject_before_write, fault, expiry_landed) in [
        (false, None, true),
        (true, None, false),
        (false, Some(Fault::Fail(6)), false),
        (false, Some(Fault::LandThenFail(6)), true),
    ] {
        let (mut s, mut api) = b947_invoice_intent(false);
        let start = api.now_millis();
        let rows = duplicate_invoices();
        api.inner.payments = rows.clone();
        // At a fixed receipt time the opening history writes raw IDs and their
        // verification. The next journal move is the provisional selection.
        let selection_number = s.next + 2;
        api.clock_after_append.push((s.storage.clone(), selection_number, start + 60_000));
        api.queue_read(HISTORY, json!(rows));
        api.queue_read(HISTORY, json!(rows)).fault = fault.map(|fault| (s.storage.clone(), fault));
        if reject_before_write {
            // This field appears in the expiry record only. Output protection
            // rejects it before storage, where the core append cannot fence writes.
            s.hold_test_credential(b"checked_at_ms");
            s.storage.memory().log.clear();
        }
        let result = block_on(s.procurement_resume(&mut api, false));
        assert!(api.scripted_reads.is_empty());
        let failed = reject_before_write || fault.is_some();
        assert_eq!(
            result.unwrap_err(),
            if failed { INVOICE_REOPEN_TO_CHECK } else { INVOICE_EXPIRED_BEFORE_DISPLAY }
        );
        assert_invoice_pause(&s);
        assert_eq!(api.now_millis(), start + 60_000);
        if reject_before_write {
            assert_eq!(s.failed.as_deref(), Some(crate::poc::wait::JOURNAL_REFUSED));
            assert_eq!(s.storage.memory().log, ["create", "close", "move"].repeat(3));
        }
        if failed {
            assert!(s.failed.is_some());
            let files = s.storage.files();
            let before = api.inner.calls.len();
            assert!(block_on(s.procurement_resume(&mut api, true)).is_err());
            assert_eq!(api.inner.calls.len(), before);
            assert_eq!(s.storage.files(), files);
        }
        let mut loaded = reopen(&s);
        let events = purchase_events(&loaded);
        let selected = events.iter().find_map(|event| match event {
            Event::Procurement(Record::RecoveredPayment { payment, .. }) => Some(payment),
            _ => None,
        });
        assert_eq!(selected, Some(&rows[0]));
        assert_eq!(
            matches!(events.last().unwrap(),
                Event::Procurement(Record::RecoveredPaymentExpiredBeforeDisplay { .. })),
            expiry_landed
        );

        api.clock_after_append.clear();
        api.set_millis(start);
        api.inner.payments.truncate(1);
        api.inner.calls.clear();
        if expiry_landed {
            assert_invoice_pause(&loaded);
            assert_eq!(
                block_on(loaded.procurement_resume(&mut api, true)).unwrap_err(),
                INVOICES_EXPIRED
            );
            assert_eq!(api.inner.calls, [format!("GET {HISTORY}")]);
            api.inner.payments = vec![rows[1].clone()];
            block_on(loaded.procurement_resume(&mut api, true)).unwrap();
            assert_eq!(loaded.procurement_view()["payment"], rows[1]);
        } else {
            // The selection landed but the proof it was never exposed did not.
            assert_eq!(loaded.procurement_view()["payment"], rows[0]);
            api.inner.payments = vec![rows[1].clone()];
            assert!(block_on(loaded.procurement_resume(&mut api, true)).is_err());
            assert_eq!(loaded.procurement_view()["payment"], rows[0]);
            assert_eq!(api.inner.calls, [payment_request(&rows[0])]);
        }
        assert_eq!(api.inner.count(ISSUE), 0);
    }
}

#[test]
fn invoice_recovery_remembers_multiple_unshown_expiries_amount_and_notice() {
    let (mut s, mut api) = b947_invoice_intent(false);
    let start = api.now_millis();
    let mut rows = duplicate_invoices();
    rows.push(fixtures::recovered_invoice(0xef, "8000n", Some(180)));
    api.inner.payments = rows.clone();

    // Raw IDs and verified terms precede the provisional selection of A.
    api.clock_after_append.push((s.storage.clone(), s.next + 2, start + 60_000));
    assert_eq!(
        block_on(s.procurement_resume(&mut api, false)).unwrap_err(),
        INVOICE_EXPIRED_BEFORE_DISPLAY
    );
    assert_invoice_pause(&s);
    let mut loaded = reopen(&s);

    // Reopen with a rolled-back clock, at the original receipt time. There
    // are no new IDs. B is selected and reaches its deadline during the append.
    api.clock_after_append.clear();
    api.set_millis(start);
    api.inner.payments.remove(0);
    api.clock_after_append.push((loaded.storage.clone(), loaded.next, start + 120_000));
    assert_eq!(
        block_on(loaded.procurement_resume(&mut api, false)).unwrap_err(),
        INVOICE_EXPIRED_BEFORE_DISPLAY
    );
    assert_invoice_pause(&loaded);
    let mut loaded = reopen(&loaded);
    let events = purchase_events(&loaded);
    let selections_and_expiries: Vec<_> = events.iter().filter(|event| {
        matches!(event, Event::Procurement(
            Record::RecoveredPayment { .. } | Record::RecoveredPaymentExpiredBeforeDisplay { .. }
        ))
    }).collect();
    assert!(matches!(
        selections_and_expiries.as_slice(),
        [
            Event::Procurement(Record::RecoveredPayment { payment: first, .. }),
            Event::Procurement(Record::RecoveredPaymentExpiredBeforeDisplay { expired_ids: first_expiry, .. }),
            Event::Procurement(Record::RecoveredPayment { payment: second, .. }),
            Event::Procurement(Record::RecoveredPaymentExpiredBeforeDisplay { expired_ids: second_expiry, .. }),
        ] if *first == rows[0] && *second == rows[1]
            && first_expiry.contains(first["id"].as_str().unwrap())
            && second_expiry.contains(second["id"].as_str().unwrap())
    ));
    let proof = loaded.procurement.as_ref().unwrap().invoice_recovery.as_ref().unwrap();
    assert_eq!(proof.expired_unshown_ids, [0xab, 0xcd].map(|id| hex::encode([id; 32])).into());
    assert_eq!(proof.observed_ids.len(), 3);
    assert_eq!(proof.wallet_amount_millisats, 800_000);

    api.clock_after_append.clear();
    api.set_millis(start);
    api.inner.payments = vec![rows[0].clone()];
    assert_eq!(
        block_on(loaded.procurement_resume(&mut api, true)).unwrap_err(),
        INVOICES_EXPIRED
    );
    api.inner.payments = vec![fixtures::recovered_invoice(0xef, "12300n", Some(180))];
    assert_eq!(
        block_on(loaded.procurement_resume(&mut api, true)).unwrap_err(),
        INVOICE_TERMS_UNVERIFIED
    );
    assert_invoice_pause(&loaded);
    api.inner.payments = vec![rows[2].clone()];
    block_on(loaded.procurement_resume(&mut api, true)).unwrap();
    let view = reopen(&loaded).procurement_view();
    assert_eq!(view["payment"], rows[2]);
    assert_eq!(
        view["payment_notice"],
        "The provider issued other unpaid invoices for the same price and period. This page uses only the invoice shown here and leaves the others unpaid."
    );
    assert_eq!(api.inner.count(ISSUE), 0);
}

#[test]
fn invoice_recovery_records_a_sibling_expiring_during_an_evidence_append() {
    for during_selection_expiry in [false, true] {
        let (mut s, mut api) = b947_invoice_intent(false);
        let start = api.now_millis();
        let rows = duplicate_invoices();
        api.inner.payments = rows.clone();
        if during_selection_expiry {
            // Raw IDs, verified set, provisional selection, then expiry of A.
            for (offset, delay) in [(2, 60_000), (3, 120_000)] {
                api.clock_after_append.push((s.storage.clone(), s.next + offset, start + delay));
            }
        } else {
            // The failed detail arrives just as A expires. The first expiry
            // evidence append lands when the next invoice expires.
            let path = payment_request(&rows[0]).strip_prefix("GET ").unwrap().to_owned();
            api.inner.after_read_clock = Some((path.clone(), (start + 60_000) / 1000));
            api.inner.read_errors.insert(path, protocol::ReadError::NotFound);
            api.clock_after_append.push((s.storage.clone(), s.next + 2, start + 120_000));
        }
        assert_eq!(
            block_on(s.procurement_resume(&mut api, false)).unwrap_err(),
            if during_selection_expiry {
                INVOICE_EXPIRED_BEFORE_DISPLAY
            } else {
                INVOICE_DETAIL_UNVERIFIED
            }
        );
        let mut loaded = reopen(&s);
        assert_invoice_pause(&loaded);
        let proof = loaded.procurement.as_ref().unwrap().invoice_recovery.as_ref().unwrap();
        assert_eq!(proof.expired_unshown_ids.len(), 2);
        api.clock_after_append.clear();
        api.set_millis(start);
        api.inner.payments.remove(0);
        assert_eq!(
            block_on(loaded.procurement_resume(&mut api, false)).unwrap_err(),
            INVOICES_EXPIRED
        );
        assert_invoice_pause(&loaded);
    }
}

#[test]
fn invoice_recovery_blocks_a_new_id_beyond_the_verified_history_bound() {
    let (mut s, mut api) = b947_invoice_intent(false);
    let start = api.now_millis();
    api.inner.payments = (128..=226)
        .map(|id| {
            fixtures::recovered_invoice(id, "8000n", Some(if id == 128 { 60 } else { 120 }))
        })
        .collect();
    api.queue_read(HISTORY, json!(api.inner.payments));
    api.queue_read(HISTORY, json!(api.inner.payments)).millis = Some(start + 60_000);
    assert_eq!(
        block_on(s.procurement_resume(&mut api, false)).unwrap_err(),
        INVOICE_EXPIRED_BEFORE_DISPLAY
    );
    assert!(api.scripted_reads.is_empty());
    let mut loaded = reopen(&s);
    let proof = loaded.procurement.as_ref().unwrap().invoice_recovery.as_ref().unwrap();
    assert_eq!(proof.observed_ids.len(), 99);
    assert_eq!(proof.expired_unshown_ids, BTreeSet::from([hex::encode([128; 32])]));
    let still_payable = api.inner.payments[1].clone();
    let mut new = fixtures::recovered_invoice(227, "8000n", None);
    new["is_upgrade"] = json!(true);
    api.inner.payments = vec![still_payable.clone(), new];
    assert_eq!(
        block_on(loaded.procurement_resume(&mut api, false)).unwrap_err(),
        INVOICE_HISTORY_INCOMPLETE
    );
    let mut loaded = reopen(&loaded);
    api.inner.payments = vec![still_payable];
    api.inner.calls.clear();
    assert_eq!(
        block_on(loaded.procurement_resume(&mut api, true)).unwrap_err(),
        INVOICE_HISTORY_INCOMPLETE
    );
    assert!(api.inner.calls.is_empty());
    assert_invoice_pause(&loaded);
}
