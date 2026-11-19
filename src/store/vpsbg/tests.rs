#![cfg(not(target_arch = "wasm32"))]

use super::*;
use crate::dispatch::ClassAnswer;
use crate::poc::provisioning::{Api, Charge, ReadError, Selection};
use std::cell::{Cell, RefCell};

const MONEY_NOW: u64 = 1_767_225_600;

#[test]
fn vpsbg_invoice_publication_requires_committed_issue() {
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    enum BeforeMoney {
        VpsbgTokenEntered(Value),
        Procurement(Value),
    }
    // Keep the old fields used: old readers can decode their own event variants.
    match serde_json::from_str::<BeforeMoney>(r#"{"procurement":null}"#).unwrap() {
        BeforeMoney::Procurement(value) => assert!(value.is_null()),
        BeforeMoney::VpsbgTokenEntered(value) => assert!(value.is_null()),
    }
    for fault in [Fault::Fail(1), Fault::LandThenFail(3)] {
        let mut s = money_store();
        let id = money_save(&mut s, "fake-commit-first", 'a');
        money_sent(&mut s, &id);
        let bolt11 = wire::bolt11::fake(101, MONEY_NOW, "348860n", &[]);
        let decoded = wire::bolt11::decode(&bolt11).unwrap();
        let change = Change::DepositIssued {
            attempt: 0,
            invoice: wire::DepositInvoice {
                order: 101,
                amount: 1903,
                currency: wire::Currency::Eur,
                bolt11: bolt11.clone(),
                payment_hash: decoded.payment_hash,
                amount_msat: decoded.amount_msat,
                provider_expiry: MONEY_NOW + 720,
                bolt11_expiry: decoded.expires,
                expires: MONEY_NOW + 720,
            },
        };
        let record = Record {
            purchase: id.clone(),
            change: change.clone(),
        };
        let bytes = serde_json::to_vec(&Event::Vpsbg(record.clone())).unwrap();
        assert!(serde_json::from_slice::<BeforeMoney>(&bytes).is_err());
        assert!(!format!("{record:?}").contains(&bolt11));
        s.storage.fault(fault);
        assert!(block_on(s.vpsbg_commit(&id, change.clone())).is_err());
        assert!(
            s.vpsbg_deposit_view(&id, MONEY_NOW + 1)
                .get("bolt11")
                .is_none()
        );
        assert!(block_on(s.vpsbg_commit(&id, change)).is_err());
        for bytes in s.storage.files().values() {
            assert!(!bytes.windows(bolt11.len()).any(|w| w == bolt11.as_bytes()));
            assert!(!bytes.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
        }
        let mut r = money_reopen(&s);
        assert!(
            r.vpsbg_deposit_view(&id, MONEY_NOW + 1)
                .get("bolt11")
                .is_none()
        );
        // Even a landed Issued needs complete reconciliation in the new session.
        let mut api = MoneyApi::new(&r);
        block_on(r.vpsbg_deposit_check(api.action(), &id)).unwrap();
        assert_eq!(
            r.vpsbg_deposit_view(&id, MONEY_NOW + 1)
                .get("bolt11")
                .is_some(),
            matches!(fault, Fault::LandThenFail(3))
        );
    }
    for fault in [Fault::Fail(1), Fault::LandThenFail(3)] {
        let mut s = money_store();
        let id = money_save(&mut s, "fake-intent-first", 'a');
        money_image(&mut s, &id);
        let mut api = MoneyApi::new(&s);
        s.storage.fault(fault);
        assert!(block_on(s.vpsbg_progress(api.action(), &id, true)).is_err());
        assert_eq!(api.posts("/v1/balance"), 0);
        assert!(s.vpsbg_purchases[&id].deposits.is_empty());
        let mut r = money_reopen(&s);
        assert_eq!(
            r.vpsbg_purchases[&id].deposits.len(),
            usize::from(matches!(fault, Fault::LandThenFail(3)))
        );
        if matches!(fault, Fault::LandThenFail(3)) {
            block_on(r.vpsbg_progress(api.action(), &id, false)).unwrap();
            assert_eq!(
                api.posts("/v1/balance"),
                0,
                "possibly committed intent never sends after restart"
            );
        }
    }
}

#[test]
fn vpsbg_revised_approval_names_every_fenced_attempt() {
    let mut s = money_store();
    let id = money_save(&mut s, "fake-replacement", 'a');
    money_issued(&mut s, &id);
    let mut api = MoneyApi::new(&s);
    api.time = MONEY_NOW + 1320;
    api.issue(102);
    let balance = wire::Balance {
        amount: 1998,
        minimum_deposit: 1000,
        balance_limit: 50_000,
        currency: wire::Currency::Eur,
        has_valid_card: false,
    };
    let review = s.vpsbg_review(&selected(), &balance, api.time).unwrap();
    assert_eq!(review.revision, 2);
    let approval = provisioning::Approval {
        origin: wire::ORIGIN.into(),
        machine: "fake-replacement".into(),
        relay: "wss://fake-relay.invalid/".into(),
        class_answer: ClassAnswer::No,
        approve_charge: true,
        approve_maintained_access: true,
    };
    block_on(s.vpsbg_approve(api.action(), approval, review)).unwrap();
    assert_eq!(
        api.calls
            .iter()
            .filter(|(_, path, _)| path.starts_with("/v1/balance/transactions?"))
            .count(),
        2,
        "one transactions read at approval and one in progress; no duplicate in progress"
    );
    assert_eq!(s.vpsbg_purchases[&id].approvals.len(), 2);
    assert_eq!(s.vpsbg_purchases[&id].deposits.len(), 2);
    assert_eq!(
        s.vpsbg_purchases[&id].deposits[1].replaces,
        vec![DepositRef {
            purchase: id.clone(),
            attempt: 0
        }]
    );
    assert_eq!(s.vpsbg_deposit_view(&id, api.time)["order"], 102);
    assert_eq!(
        s.vpsbg_fence(&api.account).unwrap().1,
        Some(api.time + 1500)
    );
    let mut r = money_reopen(&s);
    for _ in 0..2 {
        block_on(r.vpsbg_progress(api.action(), &id, false)).unwrap();
    }
    assert_eq!(api.posts("/v1/balance"), 1);
    assert!(r.vpsbg_purchases[&id].deposits[0].transaction.is_none());
    api.transactions(vec![money_row(101, "19.03", "bitcoin-ln", "Deposit")]);
    block_on(r.vpsbg_deposit_check(api.action(), &id)).unwrap();
    assert!(r.vpsbg_purchases[&id].deposits[0].transaction.is_some());
    assert!(r.vpsbg_purchases[&id].deposits[1].transaction.is_none());
}

#[test]
fn vpsbg_images_and_second_writer_gate_money() {
    for case in [
        "full",
        "wrong_url",
        "short_retention",
        "downloading_after_stale",
        "another_writer",
        "unknown_age",
    ] {
        let mut s = money_store();
        let id = money_save(&mut s, "fake-image-gate", 'a');
        let mut api = MoneyApi::new(&s);
        if case == "another_writer" || case == "unknown_age" {
            let row = if case == "another_writer" {
                let mut row = server_row();
                row["hostname"] = json!("tau-web-unowned");
                row["created_at"] = json!("2026-01-01T00:00:00Z");
                row
            } else {
                json!({"id":1,"hostname":"tau-web-unowned","status":"terminated"})
            };
            api.responses
                .insert("GET /v1/servers?page=1".into(), server_page(vec![row]));
        } else {
            let mut image: Value =
                serde_json::from_slice(&api.responses["POST /v1/custom-server-images"]).unwrap();
            let mut row = image["data"].take();
            if case == "short_retention" || case == "downloading_after_stale" {
                row["deletion_at"] = json!("2026-01-01T00:59:59Z");
            } else {
                row["url"] = json!("https://images.invalid/unrelated.qcow2");
            }
            let rows = if case == "downloading_after_stale" {
                let mut downloading = row.clone();
                downloading["id"] = json!(42);
                downloading["status"] = json!("downloading");
                vec![row, downloading]
            } else if case == "full" {
                let mut other = row.clone();
                other["id"] = json!(42);
                vec![row, other]
            } else {
                vec![row]
            };
            api.responses.insert(
                "GET /v1/custom-server-images?page=1".into(),
                server_page(rows),
            );
        }
        let _ = block_on(s.vpsbg_progress(
            api.action(),
            &id,
            case == "full" || case == "another_writer" || case == "unknown_age",
        ));
        assert_eq!(api.posts("/v1/balance"), 0, "money sent for {case}");
        assert!(s.vpsbg_purchases[&id].deposits.is_empty());
        if case == "downloading_after_stale" {
            assert_eq!(api.posts("/v1/custom-server-images"), 0);
            assert_eq!(s.vpsbg_reads.image_state, Some("downloading"));
        }
        if case == "full" {
            assert_eq!(
                s.vpsbg_reads.pause.as_ref().unwrap()["kind"],
                "image_list_full"
            );
        }
        if case == "another_writer" || case == "unknown_age" {
            assert_eq!(
                s.vpsbg_reads.pause.as_ref().unwrap()["kind"],
                "another_writer"
            );
        }
    }
}

#[test]
fn vpsbg_deposit_settlement_requires_its_transaction() {
    let mut s = money_store();
    let id = money_save(&mut s, "fake-settlement", 'a');
    money_issued(&mut s, &id);
    assert!(s.vpsbg_deposit_view(&id, MONEY_NOW + 10)["bolt11"].is_string());
    let mut api = MoneyApi::new(&s);
    api.time += 100;
    api.balance(5000, false);
    api.transactions(vec![money_row(999, "19.03", "bitcoin-ln", "Deposit")]);
    block_on(s.vpsbg_deposit_check(api.action(), &id)).unwrap();
    assert!(s.vpsbg_purchases[&id].deposits[0].transaction.is_none());
    assert!(s.vpsbg_purchases[&id].deposits[0].suppressed);
    assert_eq!(
        s.vpsbg_fence(&api.account).unwrap().1,
        Some(MONEY_NOW + 1320)
    );
    let mut s = money_reopen(&s);
    api.balance(0, false);
    assert_eq!(
        s.vpsbg_deposit_view(&id, api.time)["covered_from_elsewhere"],
        true
    );
    assert!(s.vpsbg_deposit_view(&id, api.time).get("bolt11").is_none());
    for row in [
        money_row(999, "19.03", "bitcoin-ln", "Deposit"),
        money_row(101, "-19.03", "bitcoin-ln", "Order Payment"),
        money_row(101, "19.03", "card", "Deposit"),
        money_row(101, "19.03", "bitcoin-ln", "Refund"),
        money_row(101, "19.02", "bitcoin-ln", "Deposit"),
    ] {
        api.transactions(vec![row]);
        let _ = block_on(s.vpsbg_deposit_check(api.action(), &id));
        assert!(s.vpsbg_purchases[&id].deposits[0].transaction.is_none());
    }
    block_on(s.vpsbg_close(api.time)).unwrap();
    let mut s = money_reopen(&s);
    s.procurement_choose_vendor(Vendor::Lnvps).unwrap();
    assert!(
        s.vpsbg_poll_contexts()
            .iter()
            .any(|context| context.purchase == id)
    );
    api.time = MONEY_NOW + 1500;
    let real = money_row(101, "19.03", "bitcoin-ln", "Deposit");
    api.responses.insert(
        "GET /v1/balance/transactions?page=1".into(),
        serde_json::to_vec(&json!({
        "data":[money_row(999,"19.03","bitcoin-ln","Deposit")],
        "meta":{"current_page":1,"last_page":2,"total":2,"per_page":1}}))
        .unwrap(),
    );
    let mut real = real;
    real["id"] = json!(902);
    api.responses.insert(
        "GET /v1/balance/transactions?page=2".into(),
        serde_json::to_vec(&json!({
        "data":[real.clone()],"meta":{"current_page":2,"last_page":2,"total":2,"per_page":1}}))
        .unwrap(),
    );
    block_on(s.vpsbg_deposit_check(api.action(), &id)).unwrap();
    assert!(s.vpsbg_purchases[&id].deposits[0].transaction.is_some());
    assert!(
        api.calls
            .iter()
            .any(|(_, p, _)| p.ends_with("transactions?page=2"))
    );
    assert_eq!(s.vpsbg_deposit_view(&id, api.time)["state"], "settled");
    assert!(s.vpsbg_deposit_view(&id, api.time).get("bolt11").is_none());
    assert!(s.vpsbg_fence(&api.account).unwrap().0.is_empty());
    let before = s.next;
    block_on(s.vpsbg_deposit_check(api.action(), &id)).unwrap();
    assert_eq!(s.next, before, "repeated exact row is idempotent");
    real["amount_with_vat"] = json!("19.04");
    api.responses.insert(
        "GET /v1/balance/transactions?page=2".into(),
        serde_json::to_vec(&json!({
        "data":[real],"meta":{"current_page":2,"last_page":2,"total":2,"per_page":1}}))
        .unwrap(),
    );
    assert!(block_on(s.vpsbg_deposit_check(api.action(), &id)).is_err());
    let r = money_reopen(&s);
    assert_eq!(r.vpsbg_purchases[&id], s.vpsbg_purchases[&id]);
    assert!(r.vpsbg_poll_contexts().is_empty());
    assert_eq!(api.posts("/v1/balance"), 0);

    // Both the received-invoice and never-received waits survive closure into a new purchase.
    for issued in [true, false] {
        let mut s = money_store();
        let old = money_save(&mut s, "fake-old", 'a');
        if issued {
            money_issued(&mut s, &old);
        } else {
            money_sent(&mut s, &old);
        }
        block_on(s.vpsbg_close(MONEY_NOW + 1)).unwrap();
        let mut s = money_reopen(&s);
        let mut api = MoneyApi::new(&s);
        let release = if issued {
            MONEY_NOW + 1320
        } else {
            MONEY_NOW + 3600
        };
        api.time = release - 1;
        s.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
        s.procurement_selection = Some(selected());
        let balance = wire::Balance {
            amount: 1998,
            minimum_deposit: 1000,
            balance_limit: 50_000,
            currency: wire::Currency::Eur,
            has_valid_card: false,
        };
        let approval = || provisioning::Approval {
            origin: wire::ORIGIN.into(),
            machine: "fake-successor".into(),
            relay: "wss://fake-relay.invalid/".into(),
            class_answer: ClassAnswer::No,
            approve_charge: true,
            approve_maintained_access: true,
        };
        let review = s.vpsbg_review(&selected(), &balance, api.time).unwrap();
        assert_eq!(
            review.replaces_deposit,
            vec![DepositRef {
                purchase: old.clone(),
                attempt: 0
            }]
        );
        assert!(block_on(s.vpsbg_approve(api.action(), approval(), review)).is_err());
        assert_eq!(api.posts("/v1/balance"), 0);
        api.time = release;
        let review = s.vpsbg_review(&selected(), &balance, api.time).unwrap();
        let mut undisclosed = review.clone();
        undisclosed.late_credit_disclosed = false;
        assert!(block_on(s.vpsbg_approve(api.action(), approval(), undisclosed)).is_err());
        assert_eq!(api.posts("/v1/balance"), 0);
        api.issue(102);
        block_on(s.vpsbg_approve(api.action(), approval(), review)).unwrap();
        let new_id = s
            .procurement
            .as_ref()
            .unwrap()
            .vpsbg
            .as_ref()
            .unwrap()
            .purchase
            .clone();
        assert_ne!(new_id, old);
        assert_eq!(api.posts("/v1/balance"), 1);
        assert_eq!(
            s.vpsbg_purchases[&new_id].deposits[0].replaces[0].purchase,
            old
        );
        assert_eq!(s.vpsbg_fence(&api.account).unwrap().1, Some(release + 1500));
        block_on(s.vpsbg_progress(api.action(), &new_id, false)).unwrap();
        assert_eq!(api.posts("/v1/balance"), 1);
        if issued {
            api.transactions(vec![money_row(101, "19.03", "bitcoin-ln", "Deposit")]);
            block_on(s.vpsbg_deposit_check(api.action(), &old)).unwrap();
            assert!(s.vpsbg_purchases[&old].deposits[0].transaction.is_some());
            assert!(s.vpsbg_purchases[&new_id].deposits[0].transaction.is_none());
        }
        assert!(s.vpsbg_deposit_view(&old, api.time).get("bolt11").is_none());
        assert_eq!(
            money_reopen(&s).vpsbg_fence(&api.account).unwrap(),
            s.vpsbg_fence(&api.account).unwrap()
        );
    }
}

#[test]
fn vpsbg_no_create_closure_preserves_history() {
    let mut s = money_store();
    let mut api = MoneyApi::new(&s);
    assert_eq!(
        block_on(s.procurement_close(api.action())),
        Err(wire::READ_ONLY.into())
    );
    assert!(api.calls.is_empty());
    let id = money_save(&mut s, "fake-give-up", 'a');
    money_issued(&mut s, &id);
    s.dispatch.setup_approval = Some(42); // Store-wide approval is independent of this purchase.
    assert!(s.vpsbg_close_allowed(&id));
    let bindings = s
        .procurement
        .as_ref()
        .unwrap()
        .vpsbg
        .as_ref()
        .unwrap()
        .binding
        .clone();
    api.time = MONEY_NOW + 1;
    block_on(s.procurement_close(api.action())).unwrap();
    assert!(api.calls.is_empty(), "give-up sends no provider request");
    assert_eq!(s.dispatch.setup_approval, Some(42));
    assert!(s.procurement.is_none());
    assert!(!s.dispatch.approved_entries.contains_key("fake-give-up"));
    assert!(s.procurement_can_start());
    assert!(!s.vpsbg_close_allowed(&id));
    assert!(block_on(s.vpsbg_close(MONEY_NOW + 2)).is_err());
    assert!(
        s.vpsbg_deposit_view(&id, MONEY_NOW + 2)
            .get("bolt11")
            .is_none()
    );
    let r = money_reopen(&s);
    assert_eq!(
        r.closed_purchases[0].vpsbg.as_ref().unwrap().binding,
        bindings
    );
    assert_eq!(
        r.vpsbg_fence(&r.vpsbg_token().unwrap().account).unwrap().1,
        Some(MONEY_NOW + 1320)
    );
    assert!(
        r.allocation()
            .entries()
            .iter()
            .filter(|entry| entry.identity == bindings.machine_identity
                || entry.identity == bindings.pass_identity)
            .all(|entry| entry.status == allocation::Status::Failed)
    );
    let mut reused = money_purchase(&r, "fake-give-up", &"b".repeat(32));
    reused.vpsbg.as_mut().unwrap().payment_plan = wire::PaymentPlan::preview(
        &wire::Balance {
            amount: 5000,
            minimum_deposit: 1000,
            balance_limit: 50_000,
            currency: wire::Currency::Eur,
            has_valid_card: false,
        },
        &selected(),
        MONEY_NOW,
    )
    .unwrap();
    let mut valid_new_name = reused.clone();
    valid_new_name.machine = "fake-unused-name".into();
    valid_new_name.vpsbg.as_mut().unwrap().binding.machine = valid_new_name.machine.clone();
    assert!(
        r.vpsbg_projection(&Record {
            purchase: "b".repeat(32),
            change: Change::Approved {
                purchase: Box::new(valid_new_name),
                replaces_deposit: vec![],
                late_credit_disclosed: false
            }
        })
        .is_ok()
    );
    assert!(
        r.vpsbg_projection(&Record {
            purchase: "b".repeat(32),
            change: Change::Approved {
                purchase: Box::new(reused),
                replaces_deposit: vec![],
                late_credit_disclosed: false
            }
        })
        .is_err()
    );
    let mut s = money_store();
    let id = money_save(&mut s, "fake-uncertain", 'c');
    s.procurement.as_mut().unwrap().create = Some(provisioning::Create {
        before: vec![],
        started: MONEY_NOW,
    });
    assert!(!s.vpsbg_close_allowed(&id));
    assert!(block_on(s.vpsbg_close(MONEY_NOW + 1)).is_err());
    let before = s.storage.files();
    s.authority.suspend();
    assert!(!s.vpsbg_close_allowed(&id));
    assert!(s.vpsbg_poll_contexts().is_empty());
    assert!(block_on(s.vpsbg_close(MONEY_NOW + 1)).is_err());
    assert_eq!(s.storage.files(), before);
}

#[test]
fn vpsbg_image_and_unknown_deposit_never_resend() {
    let mut s = money_store();
    let id = money_save(&mut s, "fake-once", 'a');
    let mut api = MoneyApi::new(&s);
    api.lose_deposit = true;
    assert!(block_on(s.vpsbg_progress(api.action(), &id, true)).is_err());
    assert_eq!(api.posts("/v1/balance"), 1);
    assert_eq!(s.vpsbg_deposit_view(&id, MONEY_NOW)["state"], "asking");
    let mut s = money_reopen(&s);
    api.lose_deposit = false;
    for _ in 0..2 {
        block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
    }
    assert_eq!(api.posts("/v1/balance"), 1);
    assert!(s.vpsbg_deposit_view(&id, MONEY_NOW).get("bolt11").is_none());
    for (method, path, _) in &api.calls {
        assert!(method == "GET" || path == "/v1/balance");
    }
    let mut s = money_store();
    let id = money_save(&mut s, "fake-image", 'b');
    let mut api = MoneyApi::new(&s);
    api.lose_image = true;
    api.responses.insert(
        "GET /v1/custom-server-images?page=1".into(),
        EMPTY_PAGE.to_vec(),
    );
    assert!(block_on(s.vpsbg_progress(api.action(), &id, true)).is_err());
    assert_eq!(api.posts("/v1/custom-server-images"), 1);
    assert_eq!(api.posts("/v1/balance"), 0);
    let mut s = money_reopen(&s);
    api.lose_image = false;
    block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
    assert_eq!(api.posts("/v1/custom-server-images"), 1);
    assert_eq!(api.posts("/v1/balance"), 0);
    api.time += 1800;
    assert!(block_on(s.vpsbg_progress(api.action(), &id, false)).is_err());
    assert_eq!(api.posts("/v1/custom-server-images"), 1);
}

fn money_approval(machine: &str) -> provisioning::Approval {
    provisioning::Approval {
        origin: wire::ORIGIN.into(),
        machine: machine.into(),
        relay: "wss://fake-relay.invalid/".into(),
        class_answer: ClassAnswer::No,
        approve_charge: true,
        approve_maintained_access: true,
    }
}
fn money_balance(amount: u64) -> wire::Balance {
    wire::Balance {
        amount,
        minimum_deposit: 1000,
        balance_limit: 50_000,
        currency: wire::Currency::Eur,
        has_valid_card: false,
    }
}

#[test]
fn vpsbg_unresolved_image_fence_survives_close_reload_and_approval() {
    let mut s = money_store();
    let old = money_save(&mut s, "fake-image-old", 'a');
    let mut api = MoneyApi::new(&s);
    api.responses.insert(
        "GET /v1/custom-server-images?page=1".into(),
        EMPTY_PAGE.to_vec(),
    );
    api.lose_image = true;
    assert!(block_on(s.vpsbg_progress(api.action(), &old, true)).is_err());
    assert_eq!(api.posts("/v1/custom-server-images"), 1);
    block_on(s.procurement_close(api.action())).unwrap();
    let mut s = money_reopen(&s);
    s.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
    s.procurement_selection = Some(selected());
    let review = s
        .vpsbg_review(&selected(), &money_balance(1998), api.time)
        .unwrap();
    api.lose_image = false;
    block_on(s.vpsbg_approve(api.action(), money_approval("fake-image-new"), review)).unwrap();
    let new = s
        .procurement
        .as_ref()
        .unwrap()
        .vpsbg
        .as_ref()
        .unwrap()
        .purchase
        .clone();
    assert_ne!(old, new);
    for _ in 0..2 {
        block_on(s.vpsbg_progress(api.action(), &new, false)).unwrap();
    }
    assert_eq!(api.posts("/v1/custom-server-images"), 1);
    assert_eq!(api.posts("/v1/balance"), 0);
    assert!(s.vpsbg_purchases[&new].image_sent.is_none());
    assert!(s.vpsbg_purchases[&old].image_sent.is_some());
    // Replay admission also refuses a second unresolved add across purchases.
    assert!(
        s.vpsbg_projection(&Record {
            purchase: new,
            change: Change::ImageSent {
                url: wire::IMAGE_URL.into(),
                name: "tau-web-attest".into(),
                started: api.time,
            }
        })
        .is_err()
    );
}

#[test]
fn vpsbg_coverage_waits_for_transactions_and_committed_suppression() {
    for failure in ["transactions", "append", "ambiguous_append", "catalogue"] {
        let mut s = money_store();
        let id = money_save(&mut s, "fake-coverage", 'a');
        money_issued(&mut s, &id);
        let mut api = MoneyApi::new(&s);
        assert!(s.vpsbg_deposit_view(&id, api.time).get("bolt11").is_some());
        api.balance(5000, false);
        if failure == "transactions" {
            api.responses.remove("GET /v1/balance/transactions?page=1");
        } else if failure == "append" {
            s.storage.fault(Fault::Fail(1));
        } else if failure == "ambiguous_append" {
            s.storage.fault(Fault::LandThenFail(3));
        }
        if failure == "catalogue" {
            block_on(s.procurement_catalogue(api.action())).unwrap();
        } else {
            assert!(block_on(s.vpsbg_deposit_check(api.action(), &id)).is_err());
        }
        assert!(!s.vpsbg_purchases[&id].deposits[0].suppressed);
        let deposit = s.vpsbg_deposit_view(&id, api.time);
        assert_eq!(deposit["covered_from_elsewhere"], false);
        assert!(deposit.get("bolt11").is_none(), "{failure}");
        assert!(deposit.get("amount_msat").is_none(), "{failure}");
        let view = s.procurement_view();
        assert_eq!(view["balance"]["amount"], 5000, "{failure}");
        assert!(view["payment_plan"].is_object(), "{failure}");
        assert!(view["money_review"].is_object(), "{failure}");
        assert_eq!(api.posts("/v1/balance"), 0);
        if failure == "append" || failure == "ambiguous_append" {
            let r = money_reopen(&s);
            assert_eq!(
                r.vpsbg_purchases[&id].deposits[0].suppressed,
                failure == "ambiguous_append"
            );
            if failure == "ambiguous_append" {
                assert!(r.vpsbg_deposit_view(&id, api.time).get("bolt11").is_none());
            }
        } else {
            // A failed subsequent balance read must not forget pending coverage.
            api.responses.remove("GET /v1/balance");
            assert!(block_on(s.vpsbg_read_account(api.action())).is_err());
            assert!(s.vpsbg_deposit_view(&id, api.time).get("bolt11").is_none());
            api.balance(5000, false);
            api.transactions(vec![]);
            block_on(s.vpsbg_deposit_check(api.action(), &id)).unwrap();
            assert_eq!(
                s.vpsbg_deposit_view(&id, api.time)["covered_from_elsewhere"],
                true
            );
            assert_eq!(s.procurement_view()["balance"]["amount"], 5000);
            api.balance(0, false);
            block_on(s.vpsbg_deposit_check(api.action(), &id)).unwrap();
            let r = money_reopen(&s);
            assert!(r.vpsbg_deposit_view(&id, api.time).get("bolt11").is_none());
        }
    }
}

#[test]
fn vpsbg_pending_coverage_keeps_page_shaped_reapproval_available() {
    for changed in ["price", "card"] {
        let mut s = money_store();
        let id = money_save(&mut s, "fake-covered-review", 'a');
        money_issued(&mut s, &id);
        let mut api = MoneyApi::new(&s);
        let old_review = s
            .vpsbg_review(&selected(), &money_balance(1998), api.time)
            .unwrap();
        api.balance(5000, changed == "card");
        if changed == "price" {
            let mut plans: Value = serde_json::from_slice(PLANS).unwrap();
            plans["data"][0]["price_with_vat"] = json!(40);
            api.responses.insert(
                "GET /v1/servers/plans".into(),
                serde_json::to_vec(&plans).unwrap(),
            );
        }
        // Discover the changed price during approve, so this does not fix B1701's
        // separate stale selection when the change is first found outside approve.
        assert!(
            block_on(s.vpsbg_approve(
                api.action(),
                money_approval("fake-covered-review"),
                old_review
            ))
            .is_err()
        );
        assert!(block_on(s.vpsbg_deposit_check(api.action(), &id)).is_err());
        assert!(!s.vpsbg_purchases[&id].deposits[0].suppressed);
        let view = s.procurement_view();
        assert_eq!(view["phase"], "terms_changed");
        assert_eq!(view["balance"]["amount"], 5000);
        assert!(view["payment_plan"].is_object());
        let selection: Selection = serde_json::from_value(view["selection"].clone()).unwrap();
        let review: MoneyReview = serde_json::from_value(view["money_review"].clone()).unwrap();
        assert_eq!(
            selection.charge.amount,
            if changed == "price" { 4000 } else { 3901 }
        );
        assert_eq!(review.approved_card, changed == "card");
        assert_eq!(review.payment_plan.top_up, 0);
        assert!(s.vpsbg_deposit_view(&id, api.time).get("bolt11").is_none());
        assert!(
            s.vpsbg_deposit_view(&id, api.time)
                .get("amount_msat")
                .is_none()
        );
        assert_eq!(
            s.vpsbg_deposit_view(&id, api.time)["covered_from_elsewhere"],
            false
        );

        block_on(s.vpsbg_approve(api.action(), money_approval("fake-covered-review"), review))
            .unwrap();
        assert_eq!(s.vpsbg_purchases[&id].approvals.len(), 2);
        assert_eq!(s.procurement.as_ref().unwrap().selected, selection);
        assert!(s.vpsbg_purchases[&id].deposits[0].suppressed);
        assert!(!s.vpsbg_reads.terms_changed);
        let deposit = s.vpsbg_deposit_view(&id, api.time);
        assert_eq!(deposit["covered_from_elsewhere"], true);
        assert!(deposit.get("bolt11").is_none());
        assert!(deposit.get("amount_msat").is_none());
        assert!(money_reopen(&s).vpsbg_purchases[&id].deposits[0].suppressed);
        assert_eq!(api.posts("/v1/balance"), 0);
    }
}

#[test]
fn vpsbg_current_terms_change_never_skips_later_attempt_settlement() {
    let mut s = money_store();
    let id = money_save(&mut s, "fake-current-attempts", 'a');
    money_issued(&mut s, &id);
    let mut api = MoneyApi::new(&s);
    api.time += 1320;
    api.issue(102);
    let review = s
        .vpsbg_review(&selected(), &money_balance(1998), api.time)
        .unwrap();
    block_on(s.vpsbg_approve(
        api.action(),
        money_approval("fake-current-attempts"),
        review,
    ))
    .unwrap();
    let mut plans: Value = serde_json::from_slice(PLANS).unwrap();
    plans["data"][0]["price_with_vat"] = json!(40);
    api.responses.insert(
        "GET /v1/servers/plans".into(),
        serde_json::to_vec(&plans).unwrap(),
    );
    api.balance(5000, false);
    let mut row = money_row(102, "19.03", "bitcoin-ln", "Deposit");
    row["created_at"] = json!("2026-01-01T00:22:00Z");
    api.transactions(vec![row]);
    assert!(block_on(s.vpsbg_deposit_check(api.action(), &id)).is_err());
    assert!(s.vpsbg_reads.terms_changed);
    assert!(s.vpsbg_purchases[&id].deposits[0].transaction.is_none());
    assert!(!s.vpsbg_purchases[&id].deposits[0].suppressed);
    assert!(s.vpsbg_purchases[&id].deposits[1].transaction.is_some());
    assert_eq!(s.vpsbg_deposit_view(&id, api.time)["state"], "settled");
    assert!(
        money_reopen(&s).vpsbg_purchases[&id].deposits[1]
            .transaction
            .is_some()
    );
    assert_eq!(api.posts("/v1/balance"), 1);
}

#[test]
fn vpsbg_unlanded_suppression_reload_requires_complete_reconciliation() {
    for amount in [1998, 5000] {
        for failure in ["balance", "transactions", "incomplete"] {
            let mut s = money_store();
            let id = money_save(&mut s, "fake-reload-coverage", 'a');
            money_issued(&mut s, &id);
            let mut api = MoneyApi::new(&s);
            api.time += 100;
            api.balance(5000, false);
            s.storage.fault(Fault::Fail(1));
            assert!(block_on(s.vpsbg_deposit_check(api.action(), &id)).is_err());
            assert!(!s.vpsbg_purchases[&id].deposits[0].suppressed);
            let mut s = money_reopen(&s);
            assert!(s.vpsbg_deposit_view(&id, api.time).get("bolt11").is_none());
            assert!(
                s.vpsbg_deposit_view(&id, api.time)
                    .get("amount_msat")
                    .is_none()
            );
            api.balance(amount, false);
            if failure == "balance" {
                api.responses.remove("GET /v1/balance");
            } else if failure == "transactions" {
                api.responses.remove("GET /v1/balance/transactions?page=1");
            } else {
                api.responses.insert(
                    "GET /v1/balance/transactions?page=1".into(),
                    serde_json::to_vec(&json!({
                        "data":[money_row(999,"19.03","bitcoin-ln","Deposit")],
                        "meta":{"current_page":1,"last_page":2,"total":2,"per_page":1}
                    }))
                    .unwrap(),
                );
                api.responses.remove("GET /v1/balance/transactions?page=2");
            }
            assert!(block_on(s.vpsbg_deposit_check(api.action(), &id)).is_err());
            let deposit = s.vpsbg_deposit_view(&id, api.time);
            assert!(deposit.get("bolt11").is_none(), "{failure}");
            assert!(deposit.get("amount_msat").is_none(), "{failure}");
            assert_eq!(deposit["covered_from_elsewhere"], false);
            assert_eq!(s.procurement_view()["pause"]["kind"], "reconciliation");
            assert!(s.procurement_view()["pause"]["message"].is_string());
            assert!(!s.vpsbg_purchases[&id].deposits[0].suppressed);

            // A successful balance-only catalogue read still cannot publish the invoice.
            api.balance(amount, false);
            block_on(s.procurement_catalogue(api.action())).unwrap();
            assert!(s.vpsbg_deposit_view(&id, api.time).get("bolt11").is_none());
            // Both pages must complete before either clearing or suppressing the attempt.
            api.responses.insert(
                "GET /v1/balance/transactions?page=1".into(),
                serde_json::to_vec(&json!({
                    "data":[money_row(999,"19.03","bitcoin-ln","Deposit")],
                    "meta":{"current_page":1,"last_page":2,"total":2,"per_page":1}
                }))
                .unwrap(),
            );
            let mut second = money_row(998, "19.03", "bitcoin-ln", "Deposit");
            second["id"] = json!(902);
            api.responses.insert(
                "GET /v1/balance/transactions?page=2".into(),
                serde_json::to_vec(&json!({
                    "data":[second],
                    "meta":{"current_page":2,"last_page":2,"total":2,"per_page":1}
                }))
                .unwrap(),
            );
            let calls = api.calls.len();
            block_on(s.vpsbg_deposit_check(api.action(), &id)).unwrap();
            assert!(
                api.calls[calls..]
                    .iter()
                    .any(|(_, path, _)| path.ends_with("transactions?page=2"))
            );
            let covered = amount >= 3901;
            let deposit = s.vpsbg_deposit_view(&id, api.time);
            assert_eq!(deposit.get("bolt11").is_some(), !covered);
            assert_eq!(deposit.get("amount_msat").is_some(), !covered);
            assert_eq!(deposit["covered_from_elsewhere"], covered);
            assert_eq!(s.vpsbg_purchases[&id].deposits[0].suppressed, covered);
            assert!(s.vpsbg_purchases[&id].deposits[0].transaction.is_none());
            assert!(s.procurement_view()["pause"].is_null());
            let r = money_reopen(&s);
            assert_eq!(r.vpsbg_purchases[&id].deposits[0].suppressed, covered);
            assert!(r.vpsbg_deposit_view(&id, api.time).get("bolt11").is_none());
            assert_eq!(api.posts("/v1/balance"), 0);
        }
    }
}

#[test]
fn vpsbg_old_coverage_does_not_hide_a_disclosed_later_invoice() {
    let mut s = money_store();
    let id = money_save(&mut s, "fake-later-invoice", 'a');
    money_issued(&mut s, &id);
    let mut api = MoneyApi::new(&s);
    api.balance(5000, false);
    block_on(s.vpsbg_deposit_check(api.action(), &id)).unwrap();
    assert!(s.vpsbg_purchases[&id].deposits[0].suppressed);
    api.balance(1998, false);
    block_on(s.vpsbg_deposit_check(api.action(), &id)).unwrap();
    assert_eq!(s.procurement_view()["pause"]["kind"], "balance_short");
    api.time += 1320;
    block_on(s.vpsbg_deposit_check(api.action(), &id)).unwrap();
    assert_eq!(
        s.vpsbg_deposit_view(&id, api.time)["new_top_up_allowed"],
        true
    );
    let view = s.procurement_view();
    let review: MoneyReview = serde_json::from_value(view["money_review"].clone()).unwrap();
    assert!(review.late_credit_disclosed);
    assert_eq!(
        review.replaces_deposit,
        vec![DepositRef {
            purchase: id.clone(),
            attempt: 0
        }]
    );
    api.issue(102);
    block_on(s.vpsbg_approve(api.action(), money_approval("fake-later-invoice"), review)).unwrap();
    let state = &s.vpsbg_purchases[&id];
    assert_eq!(state.deposits.len(), 2);
    assert!(state.deposits[0].suppressed);
    assert!(!state.deposits[1].suppressed);
    assert!(state.deposits[1].invoice.is_some());
    let deposit = s.vpsbg_deposit_view(&id, api.time);
    assert_eq!(deposit["order"], 102);
    assert_eq!(deposit["covered_from_elsewhere"], false);
    assert!(deposit["bolt11"].is_string());
    assert!(deposit["amount_msat"].is_u64());
    assert_eq!(api.posts("/v1/balance"), 1);
    block_on(s.vpsbg_progress(api.action(), &id, false)).unwrap();
    assert!(s.vpsbg_deposit_view(&id, api.time)["bolt11"].is_string());
    assert_eq!(api.posts("/v1/balance"), 1);
}

#[test]
fn vpsbg_sent_requires_request_and_time_budget() {
    for image in [false, true] {
        // The image needs one list then one POST; deposit needs seven reads then one POST.
        let reads = if image { 1 } else { 7 };
        for (used, remaining_ms, allowed) in [
            (16 - reads, 60_000.0, false),
            (15 - reads, 14_999.0, false),
            (15 - reads, 15_000.0, true),
        ] {
            let mut s = money_store();
            let id = money_save(&mut s, "fake-budget", 'a');
            if !image {
                money_image(&mut s, &id);
            }
            let mut api = MoneyApi::new(&s);
            api.requests = used;
            api.remaining_ms = remaining_ms;
            if image {
                api.responses.insert(
                    "GET /v1/custom-server-images?page=1".into(),
                    EMPTY_PAGE.to_vec(),
                );
            }
            let before = s.next;
            assert_eq!(
                block_on(s.vpsbg_progress(&mut api, &id, true)).is_ok(),
                allowed
            );
            let state = &s.vpsbg_purchases[&id];
            assert_eq!(state.image_sent.is_some(), image && allowed);
            assert_eq!(!state.deposits.is_empty(), !image && allowed);
            assert_eq!(
                api.posts(if image {
                    "/v1/custom-server-images"
                } else {
                    "/v1/balance"
                }),
                usize::from(allowed)
            );
            assert!(api.requests <= api.request_cap);
            if !allowed {
                assert_eq!(s.next, before, "no intent when exchange budget is missing");
            }
        }
    }
}

#[test]
fn vpsbg_invoice_and_settlement_allow_bounded_browser_clock_skew() {
    for (skew, allowed) in [(60, true), (301, false)] {
        let mut s = money_store();
        let id = money_save(&mut s, "fake-clock", 'a');
        let mut api = MoneyApi::new(&s);
        api.time += skew;
        assert_eq!(
            block_on(s.vpsbg_progress(api.action(), &id, true)).is_ok(),
            allowed
        );
        assert_eq!(api.posts("/v1/balance"), 1);
        let view = s.vpsbg_deposit_view(&id, api.time);
        assert_eq!(view.get("bolt11").is_some(), allowed);
        if allowed {
            assert!(
                s.vpsbg_deposit_view(&id, MONEY_NOW + 720)
                    .get("bolt11")
                    .is_none()
            );
            let mut row = money_row(101, "19.03", "bitcoin-ln", "Deposit");
            row["created_at"] = json!("2026-01-01T00:00:00Z");
            api.transactions(vec![row]);
            block_on(s.vpsbg_deposit_check(api.action(), &id)).unwrap();
            assert_eq!(s.vpsbg_deposit_view(&id, api.time)["state"], "settled");
            assert!(
                money_reopen(&s).vpsbg_purchases[&id].deposits[0]
                    .transaction
                    .is_some()
            );
        }
    }
}

#[test]
fn vpsbg_historical_image_replays_and_new_purchase_uses_current_constant() {
    let mut s = money_store();
    let old = money_save(&mut s, "fake-old-image", 'a');
    let old_url = "https://images.invalid/fake-older-image.qcow2";
    assert!(
        s.vpsbg_projection(&Record {
            purchase: old.clone(),
            change: Change::ImageSent {
                url: "http://images.invalid/fake.qcow2".into(),
                name: "tau-web-attest".into(),
                started: MONEY_NOW,
            },
        })
        .is_err()
    );
    block_on(s.vpsbg_commit(
        &old,
        Change::ImageSent {
            url: old_url.into(),
            name: "tau-web-attest".into(),
            started: MONEY_NOW,
        },
    ))
    .unwrap();
    let mut s = money_reopen(&s); // ImageSent alone must replay with an older URL.
    let image = wire::ImageFact {
        id: 40,
        url: old_url.into(),
        name: "fake-old-image".into(),
        status: "downloaded".into(),
        size: 1234,
        created_at: MONEY_NOW - 60,
        deletion_at: MONEY_NOW + 86_400,
        deleted_at: None,
    };
    let mut mismatch = image.clone();
    mismatch.url = wire::IMAGE_URL.into();
    assert!(
        s.vpsbg_projection(&Record {
            purchase: old.clone(),
            change: Change::ImageReady {
                image: mismatch,
                checked_at: MONEY_NOW,
            }
        })
        .is_err()
    );
    block_on(s.vpsbg_commit(
        &old,
        Change::ImageReady {
            image: image.clone(),
            checked_at: MONEY_NOW,
        },
    ))
    .unwrap();
    let mut s = money_reopen(&s);
    let mut api = MoneyApi::new(&s);
    assert!(block_on(s.vpsbg_progress(api.action(), &old, false)).is_err());
    assert_eq!(api.posts("/v1/balance"), 0);
    block_on(s.procurement_close(api.action())).unwrap();
    let mut s = money_reopen(&s);
    s.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
    s.procurement_selection = Some(selected());
    api.responses.insert(
        "GET /v1/custom-server-images?page=1".into(),
        EMPTY_PAGE.to_vec(),
    );
    let review = s
        .vpsbg_review(&selected(), &money_balance(1998), api.time)
        .unwrap();
    block_on(s.vpsbg_approve(api.action(), money_approval("fake-current-image"), review)).unwrap();
    let new = s
        .procurement
        .as_ref()
        .unwrap()
        .vpsbg
        .as_ref()
        .unwrap()
        .purchase
        .clone();
    assert_eq!(
        s.vpsbg_purchases[&new].image_sent.as_ref().unwrap().0,
        wire::IMAGE_URL
    );
    assert_eq!(api.posts("/v1/custom-server-images"), 1);
    assert_eq!(
        api.calls
            .iter()
            .find(|(m, p, _)| m == "POST" && p == "/v1/custom-server-images")
            .unwrap()
            .2
            .as_ref()
            .unwrap()["url"],
        wire::IMAGE_URL
    );
}

#[test]
fn vpsbg_price_change_reapproval_uses_the_published_selection() {
    let mut s = money_store();
    let id = money_save(&mut s, "fake-price", 'a');
    let mut api = MoneyApi::new(&s);
    let mut plans: Value = serde_json::from_slice(PLANS).unwrap();
    plans["data"][0]["price_with_vat"] = json!(40);
    api.responses.insert(
        "GET /v1/servers/plans".into(),
        serde_json::to_vec(&plans).unwrap(),
    );
    let old = selected();
    let review = s
        .vpsbg_review(&old, &money_balance(1998), api.time)
        .unwrap();
    assert!(block_on(s.vpsbg_approve(api.action(), money_approval("fake-price"), review)).is_err());
    let view = s.procurement_view();
    assert_eq!(view["phase"], "terms_changed");
    assert_eq!(view["approved_selection"], json!(old));
    let echoed: Selection = serde_json::from_value(view["selection"].clone()).unwrap();
    assert_eq!(echoed.charge.amount, 4000);
    assert!(Vendor::Vpsbg.same_terms(s.procurement_review_selection().unwrap(), &echoed));
    let review: MoneyReview = serde_json::from_value(view["money_review"].clone()).unwrap();
    // Keep this regression at approval: the image is still downloading, so no deposit is sent.
    let mut image: Value =
        serde_json::from_slice(&api.responses["POST /v1/custom-server-images"]).unwrap();
    image["data"]["status"] = json!("downloading");
    api.responses.insert(
        "GET /v1/custom-server-images?page=1".into(),
        server_page(vec![image["data"].take()]),
    );
    block_on(s.vpsbg_approve(api.action(), money_approval("fake-price"), review)).unwrap();
    assert_eq!(s.procurement.as_ref().unwrap().selected, echoed);
    assert_eq!(s.vpsbg_purchases[&id].approvals.len(), 2);
    assert_eq!(api.posts("/v1/balance"), 0);
    assert_eq!(
        money_reopen(&s).procurement.as_ref().unwrap().selected,
        echoed
    );
}

#[test]
fn vpsbg_close_dispatch_accepts_its_captured_terminal_purchase() {
    let mut s = money_store();
    let id = money_save(&mut s, "fake-dispatch-close", 'a');
    let vendor = s.procurement_vendor();
    let mut api = MoneyApi::new(&s);
    assert!(!s.vpsbg_closed_dispatch(vendor, &id));
    block_on(s.procurement_close(api.action())).unwrap();
    assert_ne!(vendor, s.procurement_vendor());
    assert!(s.vpsbg_closed_dispatch(vendor, &id));
    assert!(!s.vpsbg_closed_dispatch(Vendor::Lnvps, &id));
    assert!(!s.vpsbg_closed_dispatch(vendor, &"b".repeat(32)));
    assert!(money_reopen(&s).vpsbg_closed_dispatch(vendor, &id));
    assert!(api.calls.is_empty());
}

#[test]
fn vpsbg_archived_attempt_does_not_block_later_settlement_or_current_terms() {
    let mut s = money_store();
    let old = money_save(&mut s, "fake-archived", 'a');
    money_issued(&mut s, &old);
    let mut api = MoneyApi::new(&s);
    api.time += 1320;
    api.issue(102);
    let review = s
        .vpsbg_review(&selected(), &money_balance(1998), api.time)
        .unwrap();
    block_on(s.vpsbg_approve(api.action(), money_approval("fake-archived"), review)).unwrap();
    block_on(s.procurement_close(api.action())).unwrap();
    let mut s = money_reopen(&s);
    s.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
    s.procurement_selection = Some(selected());
    api.balance(5000, false);
    let review = s
        .vpsbg_review(&selected(), &money_balance(5000), api.time)
        .unwrap();
    block_on(s.vpsbg_approve(api.action(), money_approval("fake-current"), review)).unwrap();
    let current = s
        .procurement
        .as_ref()
        .unwrap()
        .vpsbg
        .as_ref()
        .unwrap()
        .purchase
        .clone();
    assert!(!s.vpsbg_reads.terms_changed);
    // The old plan is gone. It must not block the next attempt's settlement.
    api.responses
        .insert("GET /v1/servers/plans".into(), br#"{"data":[]}"#.to_vec());
    api.balance(5000, false);
    let mut row = money_row(102, "19.03", "bitcoin-ln", "Deposit");
    row["created_at"] = json!("2026-01-01T00:22:00Z");
    api.transactions(vec![row]);
    let calls = api.calls.len();
    block_on(s.vpsbg_deposit_check(api.action(), &old)).unwrap();
    assert!(!s.vpsbg_purchases[&old].deposits[0].suppressed);
    assert!(s.vpsbg_purchases[&old].deposits[0].transaction.is_none());
    assert!(s.vpsbg_purchases[&old].deposits[1].transaction.is_some());
    assert!(!s.vpsbg_reads.terms_changed);
    assert_ne!(s.procurement_view()["phase"], "terms_changed");
    assert!(s.vpsbg_purchases[&current].deposits.is_empty());
    assert!(
        !api.calls[calls..]
            .iter()
            .any(|(_, p, _)| p == "/v1/servers/plans")
    );
    assert!(
        money_reopen(&s).vpsbg_purchases[&old].deposits[1]
            .transaction
            .is_some()
    );
}

struct MoneyApi {
    account: String,
    time: u64,
    responses: std::collections::BTreeMap<String, Vec<u8>>,
    raw: Option<Zeroizing<Vec<u8>>>,
    calls: Vec<(String, String, Option<Value>)>,
    lose_deposit: bool,
    lose_image: bool,
    requests: usize,
    request_cap: usize,
    remaining_ms: f64,
}
impl MoneyApi {
    fn action(&mut self) -> &mut Self {
        self.requests = 0;
        self
    }
    fn new(s: &Store<MemoryStorage>) -> Self {
        let mut responses = std::collections::BTreeMap::new();
        for path in [
            "/v1/orders?page=1",
            "/v1/servers?page=1",
            "/v1/balance/transactions?page=1",
        ] {
            responses.insert(format!("GET {path}"), EMPTY_PAGE.to_vec());
        }
        responses.insert("GET /v1/servers/plans".into(), PLANS.to_vec());
        responses.insert("GET /v1/balance".into(), BALANCE.to_vec());
        let image = json!({"id":41,"url":wire::IMAGE_URL,"name":"fake-image",
            "status":"downloaded","size":wire::IMAGE_SIZE,"downloaded":wire::IMAGE_SIZE,
            "created_at":"2025-12-31T23:59:00Z","deletion_at":"2026-01-02T00:00:00Z","deleted_at":null});
        responses.insert(
            "GET /v1/custom-server-images?page=1".into(),
            server_page(vec![image.clone()]),
        );
        responses.insert(
            "POST /v1/custom-server-images".into(),
            serde_json::to_vec(&json!({"data":image})).unwrap(),
        );
        let invoice = wire::bolt11::fake(101, MONEY_NOW, "348860n", &[]);
        responses.insert(
            "POST /v1/balance".into(),
            serde_json::to_vec(&json!({"data":{
            "amount":"19.03","currency":"EUR","payment_method":"bitcoin-ln",
            "payment_information":{"payment_request":invoice,"expiry_at":"2026-01-01T00:12:00Z"}}}))
            .unwrap(),
        );
        Self {
            account: s.vpsbg_token().unwrap().account.clone(),
            time: MONEY_NOW,
            responses,
            raw: None,
            calls: Vec::new(),
            lose_deposit: false,
            lose_image: false,
            requests: 0,
            request_cap: 16,
            remaining_ms: 60_000.0,
        }
    }
    fn balance(&mut self, amount: u64, card: bool) {
        self.responses.insert(
            "GET /v1/balance".into(),
            serde_json::to_vec(&json!({"data":{
            "balance":format!("{}.{:02}", amount/100, amount%100),"minimum_deposit":"10.00",
            "balance_limit":"500.00","currency":"EUR","has_valid_card":card}}))
            .unwrap(),
        );
    }
    fn posts(&self, path: &str) -> usize {
        self.calls
            .iter()
            .filter(|(m, p, _)| m == "POST" && p == path)
            .count()
    }
    fn issue(&mut self, order: u64) {
        let invoice = wire::bolt11::fake(order, self.time, "348860n", &[]);
        self.responses.insert(
            "POST /v1/balance".into(),
            serde_json::to_vec(&json!({"data":{
            "amount":"19.03","currency":"EUR","payment_method":"bitcoin-ln",
            "payment_information":{"payment_request":invoice,"expiry_at":"2026-01-01T02:00:00Z"}}}))
            .unwrap(),
        );
    }
    fn transactions(&mut self, rows: Vec<Value>) {
        self.responses.insert(
            "GET /v1/balance/transactions?page=1".into(),
            server_page(rows),
        );
    }
}
impl Api for MoneyApi {
    fn vpsbg_mutation_budget(&self) -> Result<(), String> {
        if self.requests >= self.request_cap {
            return Err("fake request budget exhausted".into());
        }
        wire::mutation_budget(self.requests, self.remaining_ms)
    }
    async fn request(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Value>,
    ) -> Result<Value, ReadError> {
        if self.requests >= self.request_cap || self.remaining_ms <= 0.0 {
            return Err("fake exchange budget exhausted".into());
        }
        self.requests += 1;
        let path = url.strip_prefix(wire::ORIGIN).ok_or(protocol::REFUSED)?;
        assert!(Vendor::Vpsbg.request_method_allowed(wire::ORIGIN, method, url));
        self.calls.push((method.into(), path.into(), body));
        if method == "POST"
            && ((path == "/v1/balance" && self.lose_deposit)
                || (path == "/v1/custom-server-images" && self.lose_image))
        {
            return Err("fake lost response".into());
        }
        self.raw = Some(Zeroizing::new(
            self.responses
                .get(&format!("{method} {path}"))
                .ok_or(protocol::REFUSED)?
                .clone(),
        ));
        Ok(Value::Null)
    }
    fn account(&self) -> String {
        self.account.clone()
    }
    fn now(&self) -> u64 {
        self.time
    }
    fn current(&self) -> Result<(), String> {
        Ok(())
    }
    fn response_status(&self) -> u16 {
        200
    }
    fn check_vendor(&self, vendor: Vendor) -> Result<(), String> {
        if vendor == Vendor::Vpsbg {
            Ok(())
        } else {
            Err(protocol::REFUSED.into())
        }
    }
    fn take_vpsbg_response(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.raw.take()
    }
}
fn money_store() -> Store<MemoryStorage> {
    let mut s = ready();
    block_on(s.vpsbg_token_install(TOKEN.as_bytes())).unwrap();
    s.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
    s.procurement_selection = Some(selected());
    s
}
fn money_reopen(s: &Store<MemoryStorage>) -> Store<MemoryStorage> {
    block_on(unlock(
        MemoryStorage::with_files(s.storage.files()),
        &Fixed,
        pass(),
    ))
    .unwrap()
}
fn money_purchase(
    s: &Store<MemoryStorage>,
    machine: &str,
    purchase_id: &str,
) -> provisioning::Purchase {
    let mut p = purchase();
    p.machine = machine.into();
    p.relay = "wss://fake-relay.invalid/".into();
    p.account = s.vpsbg_token().unwrap().account.clone();
    p.identity = s.allocation().issue(Family::Machines).unwrap();
    p.relay_identity = s.allocation().issue(Family::Passes).unwrap();
    p.approved_at = MONEY_NOW;
    let v = p.vpsbg.as_mut().unwrap();
    v.purchase = purchase_id.into();
    v.name = format!("tau-web-{purchase_id}");
    v.binding = MachinePassBinding {
        purchase: purchase_id.into(),
        machine: machine.into(),
        machine_identity: p.identity.clone(),
        pass_identity: p.relay_identity.clone(),
    };
    v.payment_plan.read_at = MONEY_NOW;
    p
}
fn money_save(s: &mut Store<MemoryStorage>, machine: &str, c: char) -> String {
    let id = c.to_string().repeat(32);
    let p = money_purchase(s, machine, &id);
    block_on(s.vpsbg_commit(
        &id,
        Change::Approved {
            purchase: Box::new(p),
            replaces_deposit: vec![],
            late_credit_disclosed: false,
        },
    ))
    .unwrap();
    id
}
fn money_image(s: &mut Store<MemoryStorage>, id: &str) {
    block_on(s.vpsbg_commit(
        id,
        Change::ImageReady {
            image: wire::ImageFact {
                id: 41,
                status: "downloaded".into(),
                name: "fake-image".into(),
                url: wire::IMAGE_URL.into(),
                size: wire::IMAGE_SIZE,
                created_at: MONEY_NOW - 60,
                deletion_at: MONEY_NOW + 86_400,
                deleted_at: None,
            },
            checked_at: MONEY_NOW,
        },
    ))
    .unwrap();
}
fn money_sent(s: &mut Store<MemoryStorage>, id: &str) {
    money_image(s, id);
    block_on(s.vpsbg_commit(
        id,
        Change::DepositSent {
            attempt: 0,
            approval_revision: 1,
            amount: 1903,
            started: MONEY_NOW,
            replaces: vec![],
        },
    ))
    .unwrap();
}
fn money_issued(s: &mut Store<MemoryStorage>, id: &str) {
    money_sent(s, id);
    let bolt11 = wire::bolt11::fake(101, MONEY_NOW, "348860n", &[]);
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
                provider_expiry: MONEY_NOW + 720,
                bolt11_expiry: decoded.expires,
                expires: MONEY_NOW + 720,
            },
        },
    ))
    .unwrap();
    // Model a reconciled live invoice; replay deliberately does not retain this eligibility.
    let mut api = MoneyApi::new(s);
    block_on(s.vpsbg_deposit_check(api.action(), id)).unwrap();
}
fn money_row(order: u64, amount: &str, method: &str, description: &str) -> Value {
    json!({"id":901,"created_at":"2026-01-01T00:01:00Z","amount_with_vat":amount,
        "order_id":order,"payment_method":method,"description":description})
}

#[test]
fn vpsbg_preflight_fails_closed_on_orders() {
    let mut s = money_store();
    let id = money_save(&mut s, "fake-first", 'a');
    let mut api = MoneyApi::new(&s);
    block_on(s.vpsbg_preflight(api.action(), Some(&id))).unwrap();
    for status in [
        json!("pending"),
        json!("refunded"),
        json!("cancelled"),
        json!("unpaid"),
        json!("UNKNOWN"),
        Value::Null,
    ] {
        // Only exact paid passes; no other terminal meaning has been confirmed.
        api.responses.insert(
            "GET /v1/orders?page=1".into(),
            server_page(vec![
                json!({"id":31,"created_at":"2026-01-01T00:00:00Z","status":status}),
            ]),
        );
        assert_eq!(
            block_on(s.vpsbg_progress(api.action(), &id, true)).unwrap_err(),
            "Check this order at VPSBG"
        );
        assert_eq!(api.posts("/v1/balance"), 0);
        assert!(s.vpsbg_purchases[&id].deposits.is_empty());
    }
    for status in ["paid", "refunded", "cancelled", "unpaid", ""] {
        assert_eq!(
            wire::preflight_order_allowed(&wire::OrderFact {
                id: 1,
                created_at: MONEY_NOW,
                status: status.into()
            }),
            status == "paid"
        );
    }
    api.responses.insert(
        "GET /v1/orders?page=1".into(),
        br#"{"data":[],"meta":{"current_page":1,"last_page":2,"total":11,"per_page":10}}"#.to_vec(),
    );
    assert!(block_on(s.vpsbg_progress(api.action(), &id, true)).is_err());
    assert_eq!(api.posts("/v1/balance"), 0);
    api.responses.remove("GET /v1/orders?page=1");
    assert!(block_on(s.vpsbg_progress(api.action(), &id, true)).is_err());
    assert_eq!(api.posts("/v1/balance"), 0);
    api.responses.insert(
        "GET /v1/orders?page=1".into(),
        server_page(vec![json!({"id":101,"created_at":"2026-01-01T00:00:00Z"})]),
    );
    assert_eq!(
        block_on(s.vpsbg_preflight(api.action(), Some(&id))).unwrap_err(),
        "Check this order at VPSBG"
    );
    api.responses.insert(
        "GET /v1/orders?page=1".into(),
        server_page(vec![
            json!({"id":101,"created_at":"2026-01-01T00:00:00Z","status":"paid"}),
        ]),
    );
    block_on(s.vpsbg_progress(api.action(), &id, true)).unwrap();
    assert_eq!(
        api.posts("/v1/balance"),
        1,
        "a paid deposit order permits later preflight"
    );
}

#[test]
fn vpsbg_card_flag_bound_to_money_approval() {
    let mut s = money_store();
    let mut api = MoneyApi::new(&s);
    let balance: wire::Balance = serde_json::from_value(
        Vendor::Vpsbg
            .reduce_response("GET", "/v1/balance", 200, BALANCE, |_| Ok(()), |_| true)
            .unwrap(),
    )
    .unwrap();
    let displayed = s.vpsbg_review(&selected(), &balance, MONEY_NOW).unwrap();
    assert_eq!(displayed.payment_plan.top_up, 1903);
    assert!(!displayed.approved_card);
    let approval = || provisioning::Approval {
        origin: wire::ORIGIN.into(),
        machine: "fake-card".into(),
        relay: "wss://fake-relay.invalid/".into(),
        class_answer: ClassAnswer::No,
        approve_charge: true,
        approve_maintained_access: true,
    };
    api.balance(1998, true);
    assert!(block_on(s.vpsbg_approve(api.action(), approval(), displayed.clone())).is_err());
    assert!(s.vpsbg_purchases.is_empty());
    assert_eq!(s.procurement_view()["phase"], "terms_changed");
    assert_eq!(api.posts("/v1/balance"), 0);
    api.balance(1998, false);
    block_on(s.vpsbg_approve(api.action(), approval(), displayed)).unwrap();
    assert_eq!(api.posts("/v1/balance"), 1);
    let id = s
        .procurement
        .as_ref()
        .unwrap()
        .vpsbg
        .as_ref()
        .unwrap()
        .purchase
        .clone();
    let approved = s.procurement.as_ref().unwrap().vpsbg.clone().unwrap();
    let mut r = money_reopen(&s);
    assert_eq!(
        r.procurement.as_ref().unwrap().vpsbg.as_ref(),
        Some(&approved)
    );
    assert_eq!(
        r.vpsbg_purchases[&id].approvals[0].payment_plan,
        approved.payment_plan
    );
    api.balance(1998, true);
    block_on(r.vpsbg_progress(api.action(), &id, false)).unwrap();
    assert_eq!(r.procurement_view()["phase"], "terms_changed");
    assert_eq!(api.posts("/v1/balance"), 1);
    for action in ["resume", "pay_order", "create", "first_contact"] {
        assert!(r.procurement_admit_action(action).is_err());
    }
    for action in ["read", "approve", "close"] {
        r.procurement_admit_action(action).unwrap();
    }
    assert!(block_on(r.procurement_resume(api.action(), false)).is_err());
    for route in ["/v1/servers", "/v1/orders/pay"] {
        assert!(!Vendor::Vpsbg.request_method_allowed(
            wire::ORIGIN,
            "POST",
            &format!("{}{route}", wire::ORIGIN)
        ));
    }
    assert!(
        !api.calls
            .iter()
            .any(|(m, p, _)| m == "POST" && (p == "/v1/servers" || p == "/v1/orders/pay"))
    );
}

#[test]
fn vpsbg_approved_name_and_binding() {
    let mut s = money_store();
    let id = "a".repeat(32);
    let mut p = money_purchase(&s, "fake-binding", &id);
    p.vpsbg.as_mut().unwrap().name = "tau-web-wrong".into();
    let before = s.storage.files();
    assert!(
        block_on(s.vpsbg_commit(
            &id,
            Change::Approved {
                purchase: Box::new(p),
                replaces_deposit: vec![],
                late_credit_disclosed: false
            }
        ))
        .is_err()
    );
    assert_eq!(s.storage.files(), before);
    // Consume an unrelated pass: approval must reserve the *next* one, never eligible_pass.
    let pass_identity = s.allocation().issue(Family::Passes).unwrap();
    block_on(s.record(allocation::Event::Reserve(pass_identity.clone()))).unwrap();
    let valid = money_purchase(&s, "fake-bad-pass", &"c".repeat(32));
    let mut invalid = valid.clone();
    invalid.relay_identity = pass_identity.clone();
    invalid.vpsbg.as_mut().unwrap().binding.pass_identity = pass_identity.clone();
    for (purchase, accepted) in [(valid, true), (invalid, false)] {
        assert_eq!(
            s.vpsbg_projection(&Record {
                purchase: "c".repeat(32),
                change: Change::Approved {
                    purchase: Box::new(purchase),
                    replaces_deposit: vec![],
                    late_credit_disclosed: false
                }
            })
            .is_ok(),
            accepted
        );
    }
    let mut api = MoneyApi::new(&s);
    api.balance(5000, false);
    let approve = |machine: &str| provisioning::Approval {
        origin: wire::ORIGIN.into(),
        machine: machine.into(),
        relay: "wss://fake-relay.invalid/".into(),
        class_answer: ClassAnswer::No,
        approve_charge: true,
        approve_maintained_access: true,
    };
    let balance = wire::Balance {
        amount: 5000,
        minimum_deposit: 1000,
        balance_limit: 50_000,
        currency: wire::Currency::Eur,
        has_valid_card: false,
    };
    let review = s.vpsbg_review(&selected(), &balance, api.time).unwrap();
    block_on(s.vpsbg_approve(api.action(), approve("fake-binding"), review)).unwrap();
    let p = s.procurement.clone().unwrap();
    let v = p.vpsbg.as_ref().unwrap();
    assert_eq!(v.purchase.len(), 32);
    assert_eq!(v.name, format!("tau-web-{}", v.purchase));
    assert_ne!(v.binding.pass_identity, pass_identity);
    assert_eq!(v.binding.pass_identity.index, 1);
    assert_eq!(s.allocation().next_unused().machines, p.identity.index + 1);
    let mut r = money_reopen(&s);
    assert_eq!(r.procurement.as_ref(), Some(&p));
    block_on(r.vpsbg_close(api.time)).unwrap();
    api.time += 1;
    r.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
    r.procurement_selection = Some(selected());
    let review = r.vpsbg_review(&selected(), &balance, api.time).unwrap();
    block_on(r.vpsbg_approve(api.action(), approve("fake-binding-two"), review)).unwrap();
    let fresh = r.procurement.as_ref().unwrap();
    let fresh_v = fresh.vpsbg.as_ref().unwrap();
    assert_ne!(fresh_v.purchase, v.purchase);
    assert_ne!(fresh_v.name, v.name);
    assert_ne!(fresh.identity, p.identity);
    assert_ne!(fresh.relay_identity, p.relay_identity);
    assert_eq!(api.posts("/v1/balance"), 0);
}

// All identifiers, responses and custody values below are invented test data.
const TOKEN: &str = "FAKE-VPSBG-UNIT-TEST-TOKEN-NEVER-A-REAL-CREDENTIAL";
const PLANS: &[u8] = br#"{"data":[{"id":7,"key":"fake-plan","name":"Fake plan","type":"vps","vcpus":2,"dedicated_cpu":false,"memory":2048,"disk":20,"bandwidth":1000,"network_speed":100,"minimum_billing_cycle":1,"available":true,"price_with_vat":39.01}]}"#;
const BALANCE: &[u8] = br#"{"data":{"balance":19.98,"minimum_deposit":10,"balance_limit":500,"currency":"EUR","has_valid_card":false}}"#;
const EMPTY_PAGE: &[u8] =
    br#"{"data":[],"meta":{"current_page":1,"last_page":1,"total":0,"per_page":10}}"#;

fn server_row() -> Value {
    json!({"id":21,"hostname":"fake-existing-server","billing_cycle":"3",
        "plan":{"id":7,"key":"fake-plan","price_with_vat":39.01},
        "status":"active","created_at":"2026-01-01T00:00:00Z",
        "expiry_at":"2026-12-01T00:00:00Z",
        "state":{"running":true,"cloud_init_installing":true}})
}

fn server_page(rows: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({"meta":{"current_page":1,"last_page":1,
        "total":rows.len(),"per_page":10},"data":rows}))
    .unwrap()
}

struct Fixed;
impl Kdf for Fixed {
    async fn derive(&self, _: LocalPassphrase, _: &Salt) -> Result<WrappingKey, String> {
        Ok(WrappingKey([9; 32]))
    }
}
fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"fake vpsbg unit test passphrase".to_vec())
}
fn ready() -> Store<MemoryStorage> {
    let mut store = block_on(create(MemoryStorage::default(), &Fixed, pass())).unwrap();
    block_on(store.seed_backup(allocation::Completion::Skipped)).unwrap();
    store
}
fn selected() -> Selection {
    let offers = Vendor::Vpsbg
        .reduce_response("GET", "/v1/servers/plans", 200, PLANS, |_| Ok(()), |_| true)
        .unwrap();
    let offer = offers[0].clone();
    Selection {
        charge: Vendor::Vpsbg.offer_charge(&offer).unwrap(),
        offer,
        image: wire::image(),
        resources: None,
    }
}
fn purchase() -> provisioning::Purchase {
    let identity = Identity {
        seed: "fake-unit-test-seed".into(),
        derivation_version: 1,
        family: Family::Machines,
        index: 0,
    };
    let relay_identity = Identity {
        family: Family::Passes,
        ..identity.clone()
    };
    let selected = selected();
    let payment_plan = wire::PaymentPlan::preview(
        &wire::Balance {
            amount: 1998,
            minimum_deposit: 1000,
            balance_limit: 50_000,
            currency: wire::Currency::Eur,
            has_valid_card: false,
        },
        &selected,
        1234,
    )
    .unwrap();
    let purchase = "a".repeat(32);
    provisioning::Purchase {
        vendor: Vendor::Vpsbg,
        vpsbg: Some(VpsbgPurchase {
            name: format!("tau-web-{purchase}"),
            binding: MachinePassBinding {
                purchase: purchase.clone(),
                machine: "fake-machine".into(),
                machine_identity: identity.clone(),
                pass_identity: relay_identity.clone(),
            },
            purchase,
            payment_plan,
            approved_card: false,
            approval_revision: 1,
        }),
        origin: wire::ORIGIN.into(),
        machine: "fake-machine".into(),
        identity,
        relay_identity,
        class_answer: ClassAnswer::No,
        account: "b".repeat(64),
        relay: "wss://fake-relay.invalid".into(),
        selected,
        user: "nixos".into(),
        approved_at: 1234,
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
    }
}

fn lnvps_view_purchase() -> provisioning::Purchase {
    let mut p = purchase();
    p.vendor = Vendor::Lnvps;
    p.vpsbg = None;
    p.origin = "https://fake-lnvps.invalid".into();
    p.machine = "fake-lnvps-machine".into();
    p.account = "fake-lnvps-account".into();
    p.user = "arch".into();
    p.selected = Selection {
        offer: json!({"id":17,"name":"Fake LNVPS plan"}),
        image: json!({"id":1}),
        resources: None,
        charge: Charge {
            currency: "BTC".into(),
            amount: 1000,
            interval_amount: 1,
            interval_type: "month".into(),
        },
    };
    p
}

fn lnvps_view_handoff() -> provisioning::Purchase {
    let mut p = lnvps_view_purchase();
    p.vm = Some(json!({"id":17,"status":{"state":"running"},"auto_renewal_enabled":false}));
    p.payment = Some(json!({"id":"fake-lnvps-payment","is_paid":true}));
    p.paid_at = Some(1238);
    p.publication = Some(json!({"origin":"https://fake-lnvps.invalid","vm_id":17}));
    p.target = Some(crate::poc::targets::TargetRecord {
        machine: p.machine.clone(),
        relay: p.relay.clone(),
        profile: "v1".into(),
        host: "fake-host.invalid".into(),
        port: 22,
        user: p.user.clone(),
        elevation: crate::jobs::Elevation::SudoNoninteractive,
        pin: "fake-host-pin".into(),
    });
    p
}

struct Reads {
    account: String,
    calls: Vec<(String, String)>,
    current_calls: Cell<usize>,
    vendors: RefCell<Vec<Vendor>>,
    raw: Option<Zeroizing<Vec<u8>>>,
    plans: Vec<u8>,
    balance: Vec<u8>,
    servers: Vec<u8>,
}
impl Reads {
    fn new(account: String) -> Self {
        Self {
            account,
            calls: Vec::new(),
            current_calls: Cell::new(0),
            vendors: RefCell::new(Vec::new()),
            raw: None,
            plans: PLANS.to_vec(),
            balance: BALANCE.to_vec(),
            servers: EMPTY_PAGE.to_vec(),
        }
    }
}
impl Api for Reads {
    async fn request(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Value>,
    ) -> Result<Value, ReadError> {
        self.calls.push((method.into(), url.into()));
        assert_eq!(method, "GET", "read-only fixture received a mutation");
        assert!(body.is_none());
        let path = url.strip_prefix(wire::ORIGIN).ok_or(protocol::REFUSED)?;
        let bytes = match path {
            "/v1/servers/plans" => &self.plans,
            "/v1/balance" => &self.balance,
            "/v1/servers?page=1" => &self.servers,
            "/v1/balance/transactions?page=1" | "/v1/orders?page=1" => {
                self.raw = Some(Zeroizing::new(EMPTY_PAGE.to_vec()));
                return Ok(json!({"unreduced_sentinel":true}));
            }
            _ => return Err(protocol::REFUSED.into()),
        };
        self.raw = Some(Zeroizing::new(bytes.clone()));
        // Only the VPSBG response custody/reducer path can produce valid read facts.
        Ok(json!({"unreduced_sentinel":true}))
    }
    fn check_vendor(&self, vendor: Vendor) -> Result<(), String> {
        self.vendors.borrow_mut().push(vendor);
        if vendor != Vendor::Vpsbg {
            return Err(protocol::REFUSED.into());
        }
        Ok(())
    }
    fn take_vpsbg_response(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.raw.take()
    }
    fn account(&self) -> String {
        self.account.clone()
    }
    fn now(&self) -> u64 {
        1234
    }
    fn current(&self) -> Result<(), String> {
        self.current_calls.set(self.current_calls.get() + 1);
        Ok(())
    }
}

#[test]
fn vpsbg_lnvps_view_is_unchanged() {
    // Frozen base projection: b1's, plus the six fields poc/u2c dab8e84 (B947) adds to every LNVPS view
    // (archive, candidates, duplicate_orders, payment_notice, stop, stop_after). No current
    // Vendor/describe/selection helper builds this oracle.
    let approved: Value = serde_json::from_str(r#"{
        "archive":[],"candidates":[],"duplicate_orders":[],"payment_notice":null,"stop":null,
        "stop_after":null,
        "origin":"https://fake-lnvps.invalid","phase":"approved",
        "machine":"fake-lnvps-machine","account":"fake-lnvps-account",
        "selection":{"offer":{"id":17,"name":"Fake LNVPS plan"},"image":{"id":1},
            "resources":null,"charge":{"currency":"BTC","amount":1000,
                "interval_amount":1,"interval_type":"month"}},
        "approved_selection":{"offer":{"id":17,"name":"Fake LNVPS plan"},"image":{"id":1},
            "resources":null,"charge":{"currency":"BTC","amount":1000,
                "interval_amount":1,"interval_type":"month"}},
        "relay":"wss://fake-relay.invalid","class_answer":"no",
        "identity":{"seed":"fake-unit-test-seed","derivation_version":1,"family":"machines","index":0},
        "ssh_key_id":null,"vm_id":null,"billing":null,"payment":null,"paid_at":null,
        "readiness_poll_seconds":60,"readiness_wait_seconds":10800,"readiness_state":null,
        "auto_renewal_enabled":null,"target":null,"publication":null,"public_keys":null
    }"#).unwrap();
    let invoice: Value = serde_json::from_str(
        r#"{
        "phase":"invoice_uncertain","vm_id":17,"readiness_state":"running",
        "auto_renewal_enabled":false
    }"#,
    )
    .unwrap();
    let handed_off: Value = serde_json::from_str(
        r#"{
        "phase":"handed_off","vm_id":17,"readiness_state":"running",
        "auto_renewal_enabled":false,"selection":null,
        "payment":{"id":"fake-lnvps-payment","is_paid":true},"paid_at":1238,
        "publication":{"origin":"https://fake-lnvps.invalid","vm_id":17},
        "target":{"machine":"fake-lnvps-machine","relay":"wss://fake-relay.invalid",
            "profile":"v1","host":"fake-host.invalid","port":22,"user":"arch",
            "elevation":"sudo -n","pin":"fake-host-pin"}
    }"#,
    )
    .unwrap();
    let completed: Value = serde_json::from_str(
        r#"{
        "machine":"fake-lnvps-machine","origin":"https://fake-lnvps.invalid",
        "vm_id":17,"payment_id":"fake-lnvps-payment","is_paid":true,"target_saved":true
    }"#,
    )
    .unwrap();

    for phase in ["approved", "invoice_uncertain", "handed_off"] {
        let mut store = ready();
        let p = match phase {
            "approved" => lnvps_view_purchase(),
            "invoice_uncertain" => {
                let mut p = lnvps_view_purchase();
                p.vm = lnvps_view_handoff().vm;
                p.invoice = Some(provisioning::Invoice {
                    before: vec![],
                    started: 1237,
                });
                p
            }
            _ => lnvps_view_handoff(),
        };
        store.procurement = Some(p);
        store.completed_purchases.push(lnvps_view_handoff());
        let mut expected = approved.clone();
        if phase != "approved" {
            let overrides = if phase == "handed_off" {
                &handed_off
            } else {
                &invoice
            };
            expected
                .as_object_mut()
                .unwrap()
                .extend(overrides.as_object().unwrap().clone());
        }
        expected["completed"] = json!([completed]);
        // Value serialization compares every byte, including absent fields and completed entries.
        assert_eq!(
            serde_json::to_vec(&store.procurement_view()).unwrap(),
            serde_json::to_vec(&expected).unwrap(),
            "{phase}"
        );
    }
    let mut store = ready();
    store.completed_purchases.push(lnvps_view_handoff());
    assert_eq!(
        serde_json::to_vec(&store.procurement_view()["completed"][0]).unwrap(),
        serde_json::to_vec(&completed).unwrap()
    );
    assert!(store.procurement_view().get("vendor").is_none());
    store.completed_purchases.push(purchase());
    assert_eq!(
        store.procurement_view()["completed"][1]["vendor"]["id"],
        "vpsbg"
    );
}

#[test]
fn vpsbg_read_dispatch_keeps_vendor() {
    let mut store = ready();
    block_on(store.vpsbg_token_install(TOKEN.as_bytes())).unwrap();
    store.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
    // A stale LNVPS default must not determine the draft's transport or predicates.
    store.provider_origin = "https://fake-lnvps.invalid".into();
    let mut api = Reads::new(store.vpsbg_token().unwrap().account.clone());
    let quarterly = server_row();
    let mut yearly = quarterly.clone();
    yearly["id"] = json!(22);
    yearly["billing_cycle"] = json!(12);
    let mut unknown = quarterly.clone();
    unknown["id"] = json!(23);
    unknown["billing_cycle"] = json!(1);
    unknown["status"] = json!("fake-new-provider-status");
    unknown["state"] = json!({});
    api.servers = server_page(vec![quarterly.clone(), yearly, unknown]);
    let files = store.storage.files();
    let next = store.next;
    let catalogue = block_on(store.procurement_catalogue(&mut api)).unwrap();
    assert_eq!(catalogue["offers"][0]["price_with_vat"], 3901);
    assert_eq!(catalogue["images"], json!([wire::image()]));
    assert!(catalogue.get("unreduced_sentinel").is_none());
    block_on(store.procurement_select(
        &mut api,
        provisioning::Choice {
            offer_id: 7,
            image_id: 1,
            resources: None,
        },
    ))
    .unwrap();
    let candidate = store.procurement_selection.as_ref().unwrap();
    Vendor::Vpsbg.validate_selection(candidate).unwrap();
    assert!(Vendor::Lnvps.validate_selection(candidate).is_err());
    assert_eq!(Vendor::Vpsbg.region(candidate).unwrap(), "Bulgaria");
    assert!(Vendor::Vpsbg.owns_read("/v1/servers", 7, None));
    assert!(!Vendor::Vpsbg.owns_read("/api/v1/vm/7", 7, None));
    let missing = br#"{"error":"fake missing machine"}"#;
    let old_url = "https://fake-lnvps.invalid/api/v1/vm/7";
    assert!(Vendor::Lnvps.decoded_missing("GET", old_url, 404, missing));
    assert!(!Vendor::Vpsbg.decoded_missing("GET", old_url, 404, missing));
    assert!(!Vendor::Vpsbg.decoded_email_required(
        "POST",
        "https://fake-lnvps.invalid/api/v1/vm",
        403,
        &serde_json::to_vec(&json!({"error":protocol::EMAIL_REQUIRED})).unwrap()
    ));
    let view = store.procurement_view();
    assert_eq!(view["vendor"]["id"], "vpsbg");
    assert_eq!(view["vendor"]["billing"], "PrepaidBalance");
    assert_eq!(view["vendor"]["host_key_route"], "AttestCertificate");
    assert_eq!(view["origin"], wire::ORIGIN);
    assert_eq!(view["balance"]["amount"], 1998);
    assert_eq!(view["balance"]["currency"], "EUR");
    assert_eq!(view["payment_plan"]["top_up"], 1903);
    assert_eq!(view["payment_plan"]["top_up_allowed_from"], Value::Null);
    assert_eq!(view["close_allowed"], false);
    assert!(store.procurement.is_none());
    block_on(store.vpsbg_read_account(&mut api)).unwrap();
    let facts: Vec<_> = store
        .vpsbg_reads
        .servers
        .iter()
        .map(|fact| {
            let wire::ServerFact::Live(detail) = fact else {
                panic!("expected live inventory fact")
            };
            (detail.server.billing_cycle, detail.server.status.clone())
        })
        .collect();
    assert_eq!(
        facts,
        vec![
            (3, wire::ServerStatus::Active),
            (12, wire::ServerStatus::Active),
            (
                1,
                wire::ServerStatus::Unknown("fake-new-provider-status".into())
            )
        ]
    );
    let wire::ServerFact::Live(detail) = &store.vpsbg_reads.servers[0] else {
        panic!("expected live fact")
    };
    assert_eq!(
        detail.state,
        Some(wire::BootState {
            running: Some(true),
            cloud_init_installing: Some(true),
            cloud_init_failed: None
        })
    );
    let wire::ServerFact::Live(detail) = &store.vpsbg_reads.servers[2] else {
        panic!("expected live fact")
    };
    assert_eq!(
        detail.state,
        Some(wire::BootState {
            running: None,
            cloud_init_installing: None,
            cloud_init_failed: None
        })
    );
    assert_eq!(store.procurement_view()["vendor_account"]["check"], "works");
    assert_eq!(
        api.calls,
        [
            "/v1/servers/plans",
            "/v1/balance",
            "/v1/servers/plans",
            "/v1/balance",
            "/v1/balance",
            "/v1/balance/transactions?page=1",
            "/v1/servers?page=1",
            "/v1/orders?page=1",
        ]
        .map(|path| ("GET".to_string(), format!("{}{path}", wire::ORIGIN)))
    );
    assert!(!api.vendors.borrow().is_empty());
    assert!(api.vendors.borrow().iter().all(|v| *v == Vendor::Vpsbg));

    // LNVPS's generic JSON decoder accepts this; the VPSBG reduction must refuse it.
    api.plans = br#"{"data":{"templates":[]}}"#.to_vec();
    assert!(Vendor::Lnvps.decode_response(&api.plans).is_ok());
    assert!(block_on(store.procurement_catalogue(&mut api)).is_err());
    api.plans = PLANS.to_vec();
    api.balance =
        br#"{"balance":"19.98","minimum_deposit":"10","balance_limit":"500","currency":"EUR"}"#
            .to_vec();
    assert!(block_on(store.vpsbg_read_account(&mut api)).is_err());
    assert_eq!(
        store.procurement_view()["vendor_account"]["check"],
        "refused"
    );
    assert!(store.vpsbg_reads.balance.is_none());
    assert_eq!(store.storage.files(), files);
    assert_eq!(store.next, next);

    // Inventory terms are observations; they never broaden the new-purchase selection.
    api.balance = BALANCE.to_vec();
    block_on(store.vpsbg_read_account(&mut api)).unwrap();
    let mut nonmonthly = selected();
    nonmonthly.offer["billing_cycle"] = json!("3");
    assert!(Vendor::Vpsbg.validate_selection(&nonmonthly).is_err());
    assert!(
        wire::PaymentPlan::preview(
            &store.vpsbg_reads.balance.as_ref().unwrap().0,
            &nonmonthly,
            1234
        )
        .is_err()
    );
    let mut plans: Value = serde_json::from_slice(PLANS).unwrap();
    plans["data"][0]["minimum_billing_cycle"] = json!(3);
    api.plans = serde_json::to_vec(&plans).unwrap();
    assert!(
        block_on(store.procurement_select(
            &mut api,
            provisioning::Choice {
                offer_id: 7,
                image_id: 1,
                resources: None,
            }
        ))
        .is_err()
    );
    api.plans = PLANS.to_vec();

    for invalid in [
        json!(""),
        json!("x".repeat(65)),
        json!("bad\nstatus"),
        Value::Null,
        json!(1),
    ] {
        let mut row = quarterly.clone();
        row["status"] = invalid;
        api.servers = server_page(vec![row]);
        assert!(block_on(store.vpsbg_read_account(&mut api)).is_err());
    }
    for invalid in [
        json!(0),
        json!("0"),
        json!(-1),
        json!(u64::from(u32::MAX) + 1),
    ] {
        let mut row = quarterly.clone();
        row["billing_cycle"] = invalid;
        api.servers = server_page(vec![row]);
        assert!(block_on(store.vpsbg_read_account(&mut api)).is_err());
    }
    for flag in ["running", "cloud_init_installing", "cloud_init_failed"] {
        for invalid in [Value::Null, json!(0), json!("false"), json!([]), json!({})] {
            let mut row = quarterly.clone();
            row["state"][flag] = invalid;
            api.servers = server_page(vec![row]);
            assert!(
                block_on(store.vpsbg_read_account(&mut api)).is_err(),
                "{flag}"
            );
            assert!(store.vpsbg_reads.servers.is_empty());
        }
    }
    assert_eq!(store.storage.files(), files);
    assert_eq!(store.next, next);

    // The previous LNVPS purchase remains intact, but is projected only as completed.
    let mut store = ready();
    block_on(store.vpsbg_token_install(TOKEN.as_bytes())).unwrap();
    let previous = lnvps_view_handoff();
    store.provider_origin = previous.origin.clone();
    store.procurement = Some(previous.clone());
    store.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
    let mut api = Reads::new(store.vpsbg_token().unwrap().account.clone());
    let before = store.storage.files();
    let next = store.next;
    for selected in [false, true] {
        if selected {
            block_on(store.procurement_catalogue(&mut api)).unwrap();
            block_on(store.procurement_select(
                &mut api,
                provisioning::Choice {
                    offer_id: 7,
                    image_id: 1,
                    resources: None,
                },
            ))
            .unwrap();
            block_on(store.vpsbg_read_account(&mut api)).unwrap();
        }
        let view = store.procurement_view();
        assert_eq!(view["origin"], wire::ORIGIN);
        assert_eq!(view["vendor"]["id"], "vpsbg");
        assert_eq!(view["vendor_choice"], "vpsbg");
        assert_eq!(view["selection"], json!(store.procurement_selection));
        for field in [
            "phase",
            "machine",
            "account",
            "approved_selection",
            "relay",
            "class_answer",
            "identity",
            "ssh_key_id",
            "vm_id",
            "billing",
            "payment",
            "paid_at",
            "target",
            "publication",
            "public_keys",
            "readiness_state",
            "auto_renewal_enabled",
        ] {
            assert!(view.get(field).is_none(), "inherited LNVPS {field}");
        }
        assert_eq!(
            view["completed"],
            json!([{"machine":"fake-lnvps-machine",
            "origin":"https://fake-lnvps.invalid","vm_id":17,"payment_id":"fake-lnvps-payment",
            "is_paid":true,"target_saved":true}])
        );
        assert_eq!(store.procurement, Some(previous.clone()));
        assert_eq!(store.storage.files(), before);
        assert_eq!(store.next, next);
    }
    assert!(
        api.calls
            .iter()
            .all(|(method, url)| method == "GET" && url.starts_with(wire::ORIGIN))
    );
    assert!(api.vendors.borrow().iter().all(|v| *v == Vendor::Vpsbg));
}

fn money_action(
    store: &mut Store<MemoryStorage>,
    api: &mut Reads,
    action: &str,
) -> Result<(), String> {
    match action {
        "approve" => block_on(store.procurement_approve(
            api,
            provisioning::Approval {
                origin: wire::ORIGIN.into(),
                machine: "fake-machine".into(),
                relay: "wss://fake-relay.invalid".into(),
                class_answer: ClassAnswer::No,
                approve_charge: true,
                approve_maintained_access: true,
            },
        )),
        "resume" | "email_check" => block_on(store.procurement_resume(api, false)),
        "initial_invoice" => block_on(store.procurement_resume(api, true)),
        "payment_check" => block_on(store.procurement_payment_check(api)),
        "close" => block_on(store.procurement_close(api)),
        "email_send" => {
            block_on(store.procurement_email_send(api, Some("fake@example.invalid".into())))
        }
        "email_reissue" => block_on(store.procurement_email_send(api, None)),
        _ => panic!("unknown test action"),
    }
}

#[test]
fn vpsbg_b2a_refuses_money_actions() {
    let mut store = ready();
    store.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
    store.deployment_origin = Some("https://fake-lnvps.invalid".into());
    store.procurement_selection = Some(selected());
    let mut api = Reads::new("fake-unused-account".into());
    let before = store.storage.files();
    let next = store.next;
    let previous = store.previous.0;
    let allocation = serde_json::to_value(store.allocation()).unwrap();
    for action in [
        "approve",
        "resume",
        "payment_check",
        "email_check",
        "initial_invoice",
        "close",
        "email_send",
        "email_reissue",
    ] {
        assert!(Vendor::Lnvps.admit_action(action).is_ok());
        let generation_reached = Cell::new(false);
        let dispatch_reached = Cell::new(false);
        // Exercise the same native guard called by provider_request before either step.
        let result = block_on(async {
            store.procurement_vendor().admit_action(action)?;
            generation_reached.set(true);
            store.provider_generate().await?;
            dispatch_reached.set(true);
            money_action(&mut store, &mut api, action)
        });
        assert_eq!(result, Err(wire::READ_ONLY.into()), "{action}");
        assert!(!generation_reached.get(), "{action} reached generation");
        assert!(!dispatch_reached.get(), "{action} reached store dispatch");
        // Also exercise every public store mutation entry point without the browser guard.
        assert_eq!(
            money_action(&mut store, &mut api, action),
            Err(wire::READ_ONLY.into())
        );
        assert_eq!(api.current_calls.get(), 0, "{action} reached API admission");
        assert!(api.calls.is_empty());
        assert!(store.provider_account().is_none());
        assert!(store.procurement.is_none());
        assert_eq!(store.storage.files(), before);
        assert_eq!(store.next, next);
        assert_eq!(store.previous.0, previous);
        assert_eq!(
            serde_json::to_value(store.allocation()).unwrap(),
            allocation
        );
        assert_eq!(store.procurement_selection, Some(selected()));
    }
    assert!(Vendor::Vpsbg.admit_action("read").is_ok());
}

fn token_record(account: String) -> TokenRecord {
    TokenRecord {
        account,
        generation: 1,
        token: crate::poc::credit::SecretText(Zeroizing::new(TOKEN.into())),
    }
}

#[test]
fn vpsbg_token_custody() {
    let mut store = ready();
    let before = store.storage.files();
    for bad in [
        Vec::new(),
        vec![0xff],
        b"fake token".to_vec(),
        b"fake\ntoken".to_vec(),
        b"fake\0token".to_vec(),
        "fake\u{a0}token".as_bytes().to_vec(),
        vec![b'x'; 4097],
    ] {
        assert!(block_on(store.vpsbg_token_install(&bad)).is_err());
        assert!(store.vpsbg_token().is_none());
        assert_eq!(store.storage.files(), before);
    }
    block_on(store.vpsbg_token_install(TOKEN.as_bytes())).unwrap();
    store.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
    let account = store.vpsbg_token().unwrap().account.clone();
    assert_eq!(account.len(), 64);
    assert_eq!(store.vpsbg_token().unwrap().generation, 1);
    assert_eq!(
        format!("{:?}", store.vpsbg_token().unwrap()),
        "VpsbgTokenEntered(<redacted>)"
    );
    let event = Event::VpsbgTokenEntered(token_record(account.clone()));
    let plaintext = serde_json::to_vec(&journal(&event)).unwrap();
    assert!(std::str::from_utf8(&plaintext).unwrap().contains(TOKEN));
    let (public, held) = super::super::journal::public_bytes(&event, &plaintext).unwrap();
    assert!(!std::str::from_utf8(&public).unwrap().contains(TOKEN));
    assert_eq!(held, vec![TOKEN.as_bytes()]);
    assert_eq!(
        serde_json::from_slice::<Value>(&public).unwrap(),
        json!({"journal_version":4,"event":{"vpsbg_token_entered":{
            "account":account,"generation":1,"token":""
        }}})
    );
    let files = store.storage.files();
    assert_ne!(files, before);
    for bytes in files.values() {
        assert!(!bytes.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
    }
    assert!(store.check_output_bytes(TOKEN.as_bytes()).is_err());
    assert!(block_on(store.vpsbg_token_install(b"FAKE-SECOND-UNIT-TOKEN")).is_err());
    assert_eq!(store.storage.files(), files);

    let storage = store.storage.clone();
    let mut local = Local::new(storage, Fixed);
    local.state = State::Unlocked(Box::new(store));
    for replayed in [false, true] {
        if replayed {
            let report = block_on(local.unlock(pass()));
            assert_eq!(report["state"], "unlocked");
        }
        let store = local.store().unwrap();
        assert_eq!(store.vpsbg_token().unwrap().account, account);
        assert_eq!(store.vpsbg_token().unwrap().token.0.as_str(), TOKEN);
        assert!(store.check_output_bytes(TOKEN.as_bytes()).is_err());
        assert!(
            !store
                .protect_output(&json!({"echo":TOKEN}))
                .unwrap()
                .to_string()
                .contains(TOKEN)
        );
        store.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
        let report = local.report(Some(TOKEN));
        assert_eq!(report["procurement"]["vendor_account"]["key_set"], true);
        assert!(!report.to_string().contains(TOKEN));
        assert!(!report.to_string().contains(&account));
        // Native coverage ends at Local retirement: browser thread-local custody is wasm-only.
        local.retire();
        assert!(local.store().is_none());
        assert_eq!(local.report(None)["state"], "locked");
        assert_eq!(local.storage.files(), files);
    }

    // History is injected only into the projection: b2a correctly cannot create these records.
    for history in 0..3 {
        let mut store = ready();
        match history {
            0 => store.procurement = Some(purchase()),
            1 => store.completed_purchases.push(purchase()),
            _ => store.closed_purchases.push(purchase()),
        }
        let files = store.storage.files();
        assert!(store.vpsbg_token_entry_ready().is_err());
        assert!(block_on(store.vpsbg_token_install(TOKEN.as_bytes())).is_err());
        assert!(
            store
                .replay_vpsbg_token(&token_record("c".repeat(64)))
                .is_err()
        );
        assert!(store.vpsbg_token().is_none());
        assert_eq!(store.storage.files(), files);
    }
}

// Frozen pre-b2a purchase layout and closed vendor grammar. Reusing today's Purchase
// or Vendor here would make a compatibility regression invisible to the assertions.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OldVendor {
    #[default]
    Lnvps,
}
impl OldVendor {
    fn is_lnvps(&self) -> bool {
        matches!(self, Self::Lnvps)
    }
}
fn old_user() -> String {
    "arch".into()
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OldPurchase {
    #[serde(default, skip_serializing_if = "OldVendor::is_lnvps")]
    vendor: OldVendor,
    origin: String,
    machine: String,
    identity: Identity,
    relay_identity: Identity,
    class_answer: ClassAnswer,
    account: String,
    relay: String,
    selected: Selection,
    #[serde(default = "old_user")]
    user: String,
    approved_at: u64,
    #[serde(default)]
    pending_selection: Option<Selection>,
    registration_sent: bool,
    ssh_key: Option<Value>,
    create: Option<provisioning::Create>,
    vm: Option<Value>,
    invoice: Option<provisioning::Invoice>,
    #[serde(default)]
    billing: Option<provisioning::Billing>,
    payment: Option<Value>,
    paid_at: Option<u64>,
    publication: Option<Value>,
    target: Option<crate::poc::targets::TargetRecord>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum OldRecord {
    Approved(Box<OldPurchase>),
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
    CreateSent(provisioning::Create),
    EmailRequired,
    EmailEntered {
        email: String,
    },
    EmailVerified,
    CreateEmailRefused,
    Associated(Value),
    BillingQuoted(provisioning::Billing),
    InvoiceSent(provisioning::Invoice),
    Payment {
        payment: Value,
        paid_at: Option<u64>,
    },
    Observation(Value),
    Handoff {
        target: crate::poc::targets::TargetRecord,
        publication: Value,
    },
}

// The complete old event tag set, with its old procurement payload.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum OldEvent {
    Seed { mnemonic: String },
    Command { machine: String, command: String },
    Intent(Intent),
    LaunchPrepared(crate::dispatch::PreparedLaunch),
    LaunchTransmission(crate::dispatch::LaunchAttempt),
    Resend(crate::dispatch::LaunchAttempt),
    OperationIntent(crate::dispatch::OperationIntent),
    OperationObservation(crate::dispatch::Observation),
    OperationReceipt(crate::dispatch::StoredReceipt),
    Association(crate::dispatch::StoredAssociation),
    OperationResponse { call: u64, body: String },
    Terminal(Terminal),
    JobTerminal(crate::jobs::Evidence),
    JobObservation(crate::jobs::Evidence),
    Disposition(Disposition),
    PocCommandDisposition(Disposition),
    Allocation(allocation::Event),
    Setup(crate::dispatch::SetupRecord),
    Delivery(super::super::delivery::Record),
    Exposure(Exposure),
    End(crate::binding::End),
    ModeAcceptance(Acceptance),
    Goal(crate::goals::Goal),
    Poc(super::super::poc::Record),
    SignatureRefusal(SignatureRefusal),
    ConnectionRefusal(ConnectionRefusal),
    InferenceAccount { credential: String },
    InferenceIntent(crate::inference::Intent),
    InferenceTerminal(crate::inference::Terminal),
    DedicatedReinstall(super::super::reinstall::Record),
    PocTarget(super::super::poc_targets::Record),
    Procurement(OldRecord),
    ProviderProtection(crate::poc::inference::EchoFingerprints),
    PocProviderAccount(protocol::AccountRecord),
    PocCreditAccount(crate::poc::credit::AccountRecord),
    PocCredit(super::super::credit::Record),
    PocAiKey(super::super::ai_keys::Record),
    PocCreditExposure(Exposure),
}

#[test]
fn vpsbg_purchase_shape_keeps_stop_and_duplicate_orders() {
    // A purchase as the LNVPS order reconciliation writes it, with a duplicate order and a Stop,
    // must replay through the strict PurchaseShape and serialize back to the same bytes; a
    // missing field would refuse it.
    let mut p = purchase();
    p.vendor = Vendor::Lnvps;
    p.vpsbg = None;
    p.origin = protocol::ORIGIN.into();
    p.duplicate_orders = vec![7, 11];
    p.stopped = Some(provisioning::Stopped {
        checked_at: 1300,
        stage: provisioning::StopStage::PaymentConflict,
        read_status: 200,
        failing_ids: vec![json!("fake-payment")],
        history: vec![json!({"id": "fake-payment"})],
    });
    let bytes = serde_json::to_vec(&p).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(text.contains("\"duplicate_orders\":[7,11]"));
    assert!(text.contains("\"stopped\":{\"checked_at\":1300"));
    let back: provisioning::Purchase = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back, p);
    assert_eq!(serde_json::to_vec(&back).unwrap(), bytes);
    // Both omitted when empty, as before: a purchase without them still round-trips byte for byte.
    p.duplicate_orders.clear();
    p.stopped = None;
    let plain = serde_json::to_vec(&p).unwrap();
    let text = String::from_utf8(plain.clone()).unwrap();
    assert!(!text.contains("duplicate_orders") && !text.contains("stopped"));
    let back: provisioning::Purchase = serde_json::from_slice(&plain).unwrap();
    assert_eq!(serde_json::to_vec(&back).unwrap(), plain);
}

#[test]
fn vpsbg_records_refused_by_old_shape() {
    let mut lnvps = purchase();
    lnvps.vendor = Vendor::Lnvps;
    lnvps.vpsbg = None;
    lnvps.origin = protocol::ORIGIN.into();
    lnvps.user = "arch".into();
    lnvps.selected = Selection {
        offer: json!({"id":7,"name":"Fake LNVPS plan","cpu":2,"memory":2147483648u64,
            "disk_size":21474836480u64,"disk_type":"ssd","disk_interface":"scsi",
            "region":{"id":1,"name":"Fake region","company_id":1},"limits":{},
            "cost_plan":{"currency":"BTC","amount":1000,"interval_amount":1,"interval_type":"month"}}),
        image: json!({"id":1,"distribution":"archlinux","encrypted":false,"flavour":"fake","version":"fake"}),
        resources: None,
        charge: Charge {
            currency: "BTC".into(),
            amount: 1000,
            interval_amount: 1,
            interval_type: "month".into(),
        },
    };
    Vendor::Lnvps.validate_selection(&lnvps.selected).unwrap();
    let bytes = serde_json::to_vec(&lnvps).unwrap();
    let old: OldPurchase = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&old).unwrap(), bytes);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value.get("vendor").is_none());
    assert!(value.get("vpsbg").is_none());
    let restored: provisioning::Purchase = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored, lnvps);
    let mut explicit_vendor = value.clone();
    explicit_vendor["vendor"] = json!("lnvps");
    assert_eq!(
        serde_json::from_value::<provisioning::Purchase>(explicit_vendor).unwrap(),
        lnvps
    );
    for record in [
        provisioning::Record::Approved(Box::new(lnvps.clone())),
        provisioning::Record::TermsChanged(lnvps.selected.clone()),
        provisioning::Record::Reapproved {
            selected: lnvps.selected.clone(),
            approved_at: 1235,
        },
        provisioning::Record::RegistrationSent,
        provisioning::Record::Registered(json!({"id":7})),
        provisioning::Record::CreateSent(provisioning::Create {
            before: vec![],
            started: 1235,
        }),
        provisioning::Record::EmailRequired,
        provisioning::Record::EmailEntered {
            email: "fake@example.invalid".into(),
        },
        provisioning::Record::EmailVerified,
        provisioning::Record::CreateEmailRefused,
        provisioning::Record::Associated(json!({"id":7})),
        provisioning::Record::BillingQuoted(provisioning::Billing {
            vm_id: 7,
            terms: protocol::BillingTerms {
                amount: 1000,
                tax: 0,
                processing_fee: 0,
                currency: "BTC".into(),
                time: 1235,
            },
        }),
        provisioning::Record::InvoiceSent(provisioning::Invoice {
            before: vec![],
            started: 1235,
        }),
        provisioning::Record::Payment {
            payment: json!({"id":"fake-payment"}),
            paid_at: None,
        },
        provisioning::Record::Observation(json!({"id":7})),
        provisioning::Record::Closed {
            vm_id: 7,
            inventory_status: 200,
            detail_status: 404,
            history_status: 404,
            checked_at: 1235,
        },
    ] {
        let record_bytes = serde_json::to_vec(&record).unwrap();
        let old: OldRecord = serde_json::from_slice(&record_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&old).unwrap(), record_bytes);
        let event = Event::Procurement(record);
        let event_bytes = serde_json::to_vec(&journal(&event)).unwrap();
        let old: super::super::journal::Journal<OldEvent> =
            serde_json::from_slice(&event_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&old).unwrap(), event_bytes);
    }

    let p = purchase();
    let value = serde_json::to_value(&p).unwrap();
    assert_eq!(
        serde_json::from_value::<provisioning::Purchase>(value.clone()).unwrap(),
        p
    );
    assert!(serde_json::from_value::<OldPurchase>(value.clone()).is_err());
    let mut vendor_only = value.clone();
    vendor_only.as_object_mut().unwrap().remove("vpsbg");
    assert!(serde_json::from_value::<OldPurchase>(vendor_only.clone()).is_err());
    assert!(serde_json::from_value::<provisioning::Purchase>(vendor_only).is_err());
    let mut extension_only = serde_json::to_value(&lnvps).unwrap();
    extension_only["vpsbg"] = value["vpsbg"].clone();
    assert!(serde_json::from_value::<OldPurchase>(extension_only.clone()).is_err());
    assert!(serde_json::from_value::<provisioning::Purchase>(extension_only).is_err());
    let event = Event::VpsbgTokenEntered(token_record("b".repeat(64)));
    let event_bytes = serde_json::to_vec(&journal(&event)).unwrap();
    assert!(
        serde_json::from_slice::<super::super::journal::Journal<OldEvent>>(&event_bytes).is_err()
    );
    assert!(serde_json::from_slice::<super::super::journal::Journal<Event>>(&event_bytes).is_ok());
    let approved = Event::Procurement(provisioning::Record::Approved(Box::new(p.clone())));
    let approved_bytes = serde_json::to_vec(&journal(&approved)).unwrap();
    assert!(
        serde_json::from_slice::<super::super::journal::Journal<OldEvent>>(&approved_bytes)
            .is_err()
    );
    assert!(
        serde_json::from_slice::<super::super::journal::Journal<Event>>(&approved_bytes).is_ok()
    );
    let mut store = ready();
    let files = store.storage.files();
    assert_eq!(
        store.replay_procurement(store.next, &provisioning::Record::Approved(Box::new(p))),
        Err(wire::READ_ONLY.into())
    );
    assert_eq!(store.storage.files(), files);
    assert!(store.procurement.is_none());

    for (pointer, invalid) in [
        ("/vendor", json!("unknown-vendor")),
        ("/vpsbg", Value::Null),
        ("/origin", json!("https://fake-wrong-origin.invalid")),
        ("/vpsbg/name", json!("tau-web-wrong-name")),
        ("/vpsbg/purchase", json!("bad")),
        ("/vpsbg/binding/purchase", json!("d".repeat(32))),
        ("/vpsbg/binding/machine", json!("fake-other-machine")),
        ("/vpsbg/binding/machine_identity/index", json!(1)),
        ("/vpsbg/binding/pass_identity/index", json!(1)),
        ("/identity/family", json!("passes")),
        ("/relay_identity/family", json!("machines")),
        ("/relay_identity/seed", json!("fake-other-seed")),
        ("/relay_identity/derivation_version", json!(2)),
        ("/vpsbg/payment_plan/price", json!(3900)),
        ("/vpsbg/payment_plan/first_period", json!(3900)),
        ("/vpsbg/payment_plan/top_up", json!(1902)),
        ("/vpsbg/payment_plan/left_as_credit", json!(1)),
        ("/vpsbg/approval_revision", json!(0)),
        ("/vpsbg/approved_card", json!("false")),
        ("/selected/offer/billing_cycle", json!("3")),
        ("/selected/offer/billing_cycle", json!("6")),
        ("/selected/offer/billing_cycle", json!("12")),
        ("/selected/offer/billing_cycle", json!("24")),
        ("/selected/offer/minimum_billing_cycle", json!(0)),
        ("/selected/offer/minimum_billing_cycle", json!(2)),
        ("/selected/charge/interval_amount", json!(3)),
    ] {
        let mut inconsistent = value.clone();
        *inconsistent.pointer_mut(pointer).unwrap() = invalid;
        assert!(
            serde_json::from_value::<provisioning::Purchase>(inconsistent).is_err(),
            "{pointer}"
        );
    }
    for pointer in ["", "/vpsbg", "/vpsbg/binding", "/vpsbg/payment_plan"] {
        let mut unknown = value.clone();
        unknown.pointer_mut(pointer).unwrap()["unexpected"] = json!(true);
        assert!(
            serde_json::from_value::<provisioning::Purchase>(unknown).is_err(),
            "{pointer}"
        );
    }
}
