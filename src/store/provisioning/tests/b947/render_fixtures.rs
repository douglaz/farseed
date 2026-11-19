//! LNVPS states use the same fake provider and real store transitions as the B947 tests.
use super::*;
use crate::store::poc::tests::render_fixtures::{dump, fixed, report};

fn configured() -> (Store<MemoryStorage>, B947Api) {
    let mut store = ready();
    configure_origin(&mut store, "https://fake-lnvps.invalid");
    let mut api = B947Api::new();
    api.inner.account = protocol::Account::parse(hex::encode([7; 32]).as_bytes())
        .unwrap()
        .public();
    assert_eq!(
        store.provider_account().unwrap().public(),
        api.inner.account
    );
    assert!(!store.provider_account_entered());
    (store, api)
}

fn approved() -> (Store<MemoryStorage>, B947Api) {
    let (mut store, mut api) = configured();
    approve(&mut store, &mut api.inner);
    (store, api)
}

fn intent() -> (Store<MemoryStorage>, B947Api) {
    let (mut store, api) = approved();
    block_on(store.procurement_commit(Record::RegistrationSent)).unwrap();
    block_on(store.procurement_commit(Record::Registered(
        json!({"id":7,"name":"tau-0","created":"2026-11-06T14:00:00Z"}),
    )))
    .unwrap();
    block_on(store.procurement_commit(Record::CreateSent(Create {
        before: vec![],
        started: api.now(),
    })))
    .unwrap();
    (store, api)
}

fn associated() -> (Store<MemoryStorage>, B947Api) {
    let (mut store, mut api) = intent();
    api.inner.machines = vec![b947_vm(&api.inner.current_selection, 11)];
    block_on(store.associate_create(&mut api, None)).unwrap();
    (store, api)
}

fn invoice() -> (Store<MemoryStorage>, B947Api, String) {
    let (mut store, mut api) = associated();
    let error = issue_invoice(&mut store, &mut api.inner).unwrap_err();
    assert!(store.procurement.as_ref().unwrap().payment.is_some());
    (store, api, error)
}

fn invoice_intent() -> (Store<MemoryStorage>, B947Api) {
    let (mut store, api) = associated();
    block_on(store.procurement_commit(Record::BillingQuoted(Billing {
        vm_id: 11,
        terms: fixtures::billing_terms(),
    })))
    .unwrap();
    block_on(store.procurement_commit(Record::InvoiceSent(Invoice {
        before: vec![],
        started: api.now(),
    })))
    .unwrap();
    (store, api)
}

fn save(state: &str, store: Store<MemoryStorage>, error: Option<&str>) {
    assert!(store.provider_account().is_some());
    dump("lnvps", state, report(store, Fixed, error, None));
}

#[test]
fn render_fixture_lnvps_catalogue() {
    fixed(|| {
        let (mut store, mut api) = configured();
        let catalogue = block_on(store.procurement_catalogue(&mut api)).unwrap();
        assert!(store.procurement.is_none());
        dump(
            "lnvps",
            "catalogue",
            report(store, Fixed, None, Some(catalogue)),
        );
    });
}

#[test]
fn render_fixture_lnvps_approved() {
    fixed(|| {
        let (store, _) = approved();
        assert_eq!(store.procurement_view()["phase"], "approved");
        save("approved", store, None);
    });
}

#[test]
fn render_fixture_lnvps_order_placed() {
    fixed(|| {
        let (store, _) = associated();
        assert_eq!(store.procurement_view()["vm_id"], 11);
        assert!(store.procurement.as_ref().unwrap().payment.is_none());
        save("order_placed", store, None);
    });
}

#[test]
fn render_fixture_lnvps_invoice_shown() {
    fixed(|| {
        let (store, _, error) = invoice();
        assert_eq!(store.procurement_view()["payment"]["is_paid"], false);
        save("invoice_shown", store, Some(&error));
    });
}

#[test]
fn render_fixture_lnvps_invoice_expired() {
    fixed(|| {
        let (mut store, mut api, _) = invoice();
        api.inner.clock = timestamp("2026-11-07T14:00:00Z").unwrap();
        let error = block_on(store.procurement_resume(&mut api, false)).unwrap_err();
        assert!(error.contains("Initial invoice expired"));
        save("invoice_expired", store, Some(&error));
    });
}

// Paid and machine_starting reach the native store states, but their worker messages
// require browser::readiness_report (wasm-only, with an unfixable Date::now read).
// They are intentionally omitted rather than sending incomplete worker messages.

#[test]
fn render_fixture_lnvps_duplicate_orders() {
    fixed(|| {
        let (mut store, mut api) = intent();
        api.inner.machines = vec![
            b947_vm(&api.inner.current_selection, 12),
            b947_vm(&api.inner.current_selection, 11),
        ];
        block_on(store.associate_create(&mut api, None)).unwrap();
        assert_eq!(store.procurement_view()["duplicate_orders"], json!([12]));
        save("duplicate_orders", store, None);
    });
}

#[test]
fn render_fixture_lnvps_stop_offered() {
    fixed(|| {
        let (mut store, mut api) = intent();
        api.inner.clock += 300;
        let error = block_on(store.associate_create(&mut api, None)).unwrap_err();
        assert_eq!(store.procurement_view()["stop"]["stage"], "before_machine");
        save("stop_offered", store, Some(&error));
    });
}

#[test]
fn render_fixture_lnvps_stopped_before_machine() {
    fixed(|| {
        let (mut store, mut api) = intent();
        api.inner.clock += 300;
        assert!(block_on(store.associate_create(&mut api, None)).is_err());
        block_on(store.procurement_stop(&mut api, StopStage::BeforeMachine)).unwrap();
        assert!(store.procurement.is_none());
        assert!(
            store.procurement_view()["closed"]
                .as_str()
                .unwrap()
                .starts_with("Stopped:")
        );
        save("stopped_before_machine", store, None);
    });
}

fn conflict() -> (Store<MemoryStorage>, B947Api, String) {
    let (mut store, mut api) = invoice_intent();
    let mut payment = fixtures::payment(11);
    payment["is_upgrade"] = json!(true);
    api.inner.payments.push(payment);
    let error = block_on(store.associate_payment(&mut api, false)).unwrap_err();
    assert_eq!(
        store.procurement_view()["stop"]["stage"],
        "payment_conflict"
    );
    (store, api, error)
}

#[test]
fn render_fixture_lnvps_payment_conflict() {
    fixed(|| {
        let (store, _, error) = conflict();
        save("payment_conflict", store, Some(&error));
    });
}

#[test]
fn render_fixture_lnvps_stopped_payment_conflict() {
    fixed(|| {
        let (mut store, mut api, _) = conflict();
        block_on(store.procurement_stop(&mut api, StopStage::PaymentConflict)).unwrap();
        assert!(store.procurement.is_none());
        assert!(store.closed_purchases[0].stopped.is_some());
        save("stopped_payment_conflict", store, None);
    });
}

#[test]
fn render_fixture_lnvps_ready() {
    fixed(|| {
        let (mut store, mut api, _) = invoice();
        api.inner.payments[0]["is_paid"] = json!(true);
        block_on(store.procurement_payment_check(&mut api)).unwrap();
        block_on(store.procurement_readiness_check(&mut api)).unwrap();
        assert_eq!(store.procurement_view()["phase"], "handed_off");
        assert!(store.poc_target("machine-a").is_some());
        save("ready", store, None);
    });
}

#[test]
fn render_fixture_lnvps_closed() {
    fixed(|| {
        let (mut store, mut api) = associated();
        disappear(&mut api.inner);
        block_on(store.procurement_close(&mut api)).unwrap();
        assert!(store.procurement.is_none());
        assert!(store.procurement_view()["closed"].is_string());
        save("closed", store, None);
    });
}
