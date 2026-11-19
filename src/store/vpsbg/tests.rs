#![cfg(not(target_arch = "wasm32"))]

use super::*;
use crate::dispatch::ClassAnswer;
use crate::poc::provisioning::{Api, Charge, ReadError, Selection};
use std::cell::{Cell, RefCell};

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
