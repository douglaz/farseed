//! Stable full reports through the existing b2a/b2b journal fixtures.
//! Open/waiting fixtures hold until 2100; expired fixtures use fixed past deadlines.
use super::*;
use crate::store::poc::tests::render_fixtures::{dump, fixed, report};

// The open/waiting fixtures hold until 2100-01-01T00:00:00Z.
const RENDER_FAR_FUTURE: u64 = 4102444800;

fn covered() -> (Store<MemoryStorage>, String) {
    let mut store = money_store();
    let id = "c".repeat(32);
    let mut purchase = money_purchase(&store, "fake-render-machine", &id);
    purchase.vpsbg.as_mut().unwrap().payment_plan =
        wire::PaymentPlan::preview(&money_balance(5000), &purchase.selected, MONEY_NOW).unwrap();
    block_on(store.vpsbg_commit(
        &id,
        Change::Approved {
            purchase: Box::new(purchase),
            replaces_deposit: vec![],
            late_credit_disclosed: false,
        },
    ))
    .unwrap();
    money_image(&mut store, &id);
    (store, id)
}

/// Exercise the journal replay seam with a fixed public introduction, without calling the
/// wall-clock-writing attest_introduction_begin. Never construct a replacement report field.
fn sent() -> (Store<MemoryStorage>, String) {
    sent_until(MONEY_NOW + crate::hostcert::ATTEST_CERTIFICATE_DEADLINE_SECONDS)
}

fn sent_until(deadline: u64) -> (Store<MemoryStorage>, String) {
    use ssh_key::private::Ed25519Keypair;
    let (mut store, id) = covered();
    let purchase = store.vpsbg_purchase(&id).unwrap().clone();
    let seed = store
        .seed()
        .unwrap()
        .attest_certificate_authority(
            purchase.identity.derivation_version,
            purchase.identity.index,
        )
        .unwrap();
    let public = ssh_key::PublicKey::new(
        ssh_key::public::KeyData::Ed25519(Ed25519Keypair::from_seed(&seed).public),
        "",
    );
    let introduction = crate::store::attest::Introduction {
        machine: purchase.machine.clone(),
        route: crate::store::attest::Route::AttestCertificate,
        ca_public: public.to_openssh().unwrap(),
        principal: crate::store::attest::attest_principal(&public).unwrap(),
        begun_unix: MONEY_NOW,
        deadline_unix: deadline,
        installation_binding: store
            .attest_installation_binding(&purchase.machine)
            .unwrap(),
    };
    block_on(store.commit(&Event::AttestIntroduction(introduction.clone()))).unwrap();
    store.replay_attest_introduction(&introduction).unwrap();
    block_on(store.vpsbg_commit(
        &id,
        Change::CreateSent {
            attempt: 0,
            name: purchase.vpsbg.as_ref().unwrap().name.clone(),
            machine_identity: purchase.identity,
            image: store.vpsbg_purchases[&id].image.clone().unwrap(),
            approval_revision: 1,
            started: MONEY_NOW,
            ssh_key: None,
        },
    ))
    .unwrap();
    (store, id)
}

fn read_association() -> Store<MemoryStorage> {
    let (mut store, id) = covered();
    // Name reconciliation is a real supported path before any local create or introduction.
    let mut row = server_row();
    row["id"] = json!(51);
    row["hostname"] = json!(
        store
            .vpsbg_purchase(&id)
            .unwrap()
            .vpsbg
            .as_ref()
            .unwrap()
            .name
    );
    row["billing_cycle"] = json!("1");
    let mut api = MoneyApi::new(&store);
    api.responses.insert(
        "GET /v1/servers?page=1".into(),
        server_page(vec![row.clone()]),
    );
    api.responses.insert(
        "GET /v1/servers/51".into(),
        serde_json::to_vec(&json!({"data":row})).unwrap(),
    );
    block_on(store.vpsbg_reconcile_create(api.action(), &id)).unwrap();
    assert!(api.calls.iter().all(|(method, _, _)| method == "GET"));
    assert!(store.attest.is_empty());
    assert_eq!(
        store.procurement_view()["provisioning"]["state"],
        "associated"
    );
    assert_eq!(
        store.procurement_view()["pause"]["kind"],
        "payment_unproven"
    );
    store
}

fn introduced(deadline: u64, unpaid: bool) -> (Store<MemoryStorage>, String, MoneyApi) {
    let (mut store, id) = sent_until(deadline);
    if unpaid {
        block_on(store.vpsbg_commit(
            &id,
            Change::OrderUnpaid {
                order: 71,
                create_attempt: 0,
                checked_at: MONEY_NOW,
            },
        ))
        .unwrap();
    }
    let mut row = server_row();
    row["id"] = json!(51);
    row["hostname"] = json!(
        store
            .vpsbg_purchase(&id)
            .unwrap()
            .vpsbg
            .as_ref()
            .unwrap()
            .name
    );
    row["billing_cycle"] = json!("1");
    let mut api = MoneyApi::new(&store);
    api.responses.insert(
        "GET /v1/servers?page=1".into(),
        server_page(vec![row.clone()]),
    );
    api.responses.insert(
        "GET /v1/servers/51".into(),
        serde_json::to_vec(&json!({"data":row})).unwrap(),
    );
    block_on(store.vpsbg_reconcile_create(api.action(), &id)).unwrap();
    assert!(api.calls.iter().all(|(method, _, _)| method == "GET"));
    assert!(store.vpsbg_purchases[&id].associated.is_some());
    (store, id, api)
}

/// MoneyApi's invented GETs plus a bodyless 204; every response uses the real reducer.
struct RenderDeleteApi {
    reads: MoneyApi,
    context: ActionContext,
    status: u16,
    deletes: usize,
    delete_path: String,
}

impl RenderDeleteApi {
    fn action(&mut self) -> &mut Self {
        self.reads.action();
        self
    }
}

impl Api for RenderDeleteApi {
    fn account(&self) -> String {
        self.reads.account()
    }
    fn now(&self) -> u64 {
        self.reads.now()
    }
    fn current(&self) -> Result<(), String> {
        self.reads.current()
    }
    fn check_vendor(&self, vendor: Vendor) -> Result<(), String> {
        self.reads.check_vendor(vendor)
    }
    fn vpsbg_context(&self) -> Option<&ActionContext> {
        Some(&self.context)
    }
    fn response_status(&self) -> u16 {
        self.status
    }
    fn take_vpsbg_response(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.reads.take_vpsbg_response()
    }
    fn vpsbg_mutation_budget(&self) -> Result<(), String> {
        self.reads.vpsbg_mutation_budget()
    }
    fn vpsbg_begin_window(&mut self) -> Result<(), String> {
        self.reads.requests = 0;
        self.reads.raw = None;
        Ok(())
    }
    async fn request(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Value>,
    ) -> Result<Value, ReadError> {
        if method == "DELETE" {
            let path = url.strip_prefix(wire::ORIGIN).ok_or(protocol::REFUSED)?;
            assert_eq!(path, self.delete_path);
            assert!(Vendor::Vpsbg.request_method_allowed(wire::ORIGIN, method, url));
            assert!(body.is_none());
            self.reads.vpsbg_mutation_budget()?;
            self.reads.requests += 1;
            self.deletes += 1;
            assert_eq!(self.deletes, 1, "never issue a second DELETE");
            self.reads.calls.push((method.into(), path.into(), None));
            self.status = 204;
            self.reads.raw = Some(Zeroizing::new(vec![]));
            return Ok(Value::Null);
        }
        assert_eq!(method, "GET");
        self.status = 200;
        self.reads.request(method, url, body).await
    }
}

fn locally_delete_sent() -> (Store<MemoryStorage>, String, RenderDeleteApi) {
    let deadline = MONEY_NOW + crate::hostcert::ATTEST_CERTIFICATE_DEADLINE_SECONDS;
    let (mut store, id, mut reads) = introduced(deadline, true);
    reads.time = deadline;
    reads.calls.clear();
    reads.responses.insert(
        "GET /v1/servers/51/refund-quote".into(),
        serde_json::to_vec(&json!({"data":{"currency":"EUR","refund_gross":"38.79"}})).unwrap(),
    );
    let name = &store
        .vpsbg_purchase(&id)
        .unwrap()
        .vpsbg
        .as_ref()
        .unwrap()
        .name;
    let request = wire::delete_server(51, name).unwrap();
    let mut api = RenderDeleteApi {
        reads,
        context: store.vpsbg_action_context(&id).unwrap(),
        status: 200,
        deletes: 0,
        delete_path: request.path,
    };
    block_on(store.vpsbg_delete_once(api.action(), &id, false)).unwrap();
    assert_eq!(api.deletes, 0);
    // The 204 is acknowledged; the automatic live detail check cannot confirm deletion.
    let error = block_on(store.vpsbg_delete_once(api.action(), &id, true)).unwrap_err();
    assert_eq!(
        error,
        "VPSBG deletion is not confirmed; only read-only checks are allowed."
    );
    assert_eq!(api.deletes, 1);
    assert!(store.vpsbg_purchases[&id].delete_sent.is_some());
    assert!(store.vpsbg_purchases[&id].closed_at.is_none());
    assert_eq!(
        api.reads
            .calls
            .iter()
            .map(|(m, p, _)| (m.as_str(), p.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("GET", "/v1/servers/51/refund-quote"),
            ("GET", "/v1/servers/51/refund-quote"),
            ("DELETE", api.delete_path.as_str()),
            ("GET", "/v1/servers/51"),
        ]
    );
    assert_eq!(store.procurement_view()["delete"]["state"], "sent");
    (store, id, api)
}

fn save(state: &str, store: Store<MemoryStorage>) {
    assert!(store.provider_account().is_none());
    let value = report(store, Fixed, None, None);
    assert_eq!(value["store"]["provider_configuration"]["key_set"], false);
    assert!(!value.to_string().contains(TOKEN));
    dump("vpsbg", state, value);
}

#[test]
fn vpsbg_render_fixture_fresh_choice() {
    fixed(|| {
        let store = ready();
        assert!(store.procurement_vendor_choice_open());
        save("fresh_choice", store);
    });
}

#[test]
fn vpsbg_render_fixture_token_entered() {
    fixed(|| {
        let mut store = ready();
        store.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
        block_on(store.vpsbg_token_install(TOKEN.as_bytes())).unwrap();
        assert!(store.procurement_selection.is_none());
        assert_eq!(store.procurement_view()["vendor_account"]["key_set"], true);
        save("token_entered", store);
    });
}

#[test]
fn vpsbg_render_fixture_offers_fetched() {
    fixed(|| {
        let mut store = money_store();
        store.procurement_selection = None;
        let mut api = MoneyApi::new(&store);
        let catalogue = block_on(store.procurement_catalogue(api.action())).unwrap();
        assert!(store.procurement_selection.is_none());
        assert!(store.procurement.is_none());
        assert!(store.procurement_view().get("money_review").is_none());
        assert_eq!(catalogue["offers"][0]["price_with_vat"], 3901);
        assert_eq!(catalogue["images"], json!([wire::image()]));
        let value = report(store, Fixed, None, Some(catalogue));
        assert_eq!(value["store"]["provider_configuration"]["key_set"], false);
        assert!(!value.to_string().contains(TOKEN));
        dump("vpsbg", "offers_fetched", value);
    });
}

#[test]
fn vpsbg_render_fixture_money_review() {
    fixed(|| {
        let mut store = money_store();
        store.procurement_selection = None;
        let mut api = MoneyApi::new(&store);
        // Selection fetches the catalogue and balance before publishing the selected plan.
        block_on(store.procurement_select(
            api.action(),
            provisioning::Choice {
                offer_id: 7,
                image_id: 1,
                resources: None,
            },
        ))
        .unwrap();
        assert!(store.procurement.is_none());
        assert!(store.procurement_view()["money_review"].is_object());
        assert!(store.provider_account().is_none());
        let mut value = report(store, Fixed, None, None);
        // The message posted right after a successful Select: www/worker.js:696 adds this flag
        // and src/harness/inference.rs:160-161 keeps it; without it the page disables Approve.
        value["store"]["provider_selection_reviewed"] = true.into();
        assert_eq!(value["store"]["provider_configuration"]["key_set"], false);
        assert!(!value.to_string().contains(TOKEN));
        dump("vpsbg", "money_review", value);
    });
}

#[test]
fn vpsbg_render_fixture_approved() {
    fixed(|| {
        let mut store = money_store();
        money_save(&mut store, "fake-render-machine", 'a');
        assert_eq!(store.procurement_view()["image"]["state"], "needed");
        assert_eq!(store.procurement_view()["provisioning"]["state"], "deposit");
        save("approved", store);
    });
}

#[test]
fn vpsbg_render_fixture_deposit_pending() {
    fixed(|| {
        let mut store = money_store();
        let id = money_save(&mut store, "fake-render-machine", 'a');
        let mut api = MoneyApi::new(&store);
        // The real validator accepts this future-dated fake invoice: it rejects timestamps
        // older than the intent by >300s, with no upper timestamp bound (vpsbg.rs:1945).
        // Its provider expiry and the durable replacement fence remain beyond the report clock.
        let bolt11 = wire::bolt11::fake(101, RENDER_FAR_FUTURE - 720, "348860n", &[]);
        api.responses.insert(
            "POST /v1/balance".into(),
            serde_json::to_vec(&json!({"data":{
                "amount":"19.03","currency":"EUR","payment_method":"bitcoin-ln",
                "payment_information":{"payment_request":bolt11,"expiry_at":"2100-01-01T00:00:00Z"}
            }}))
            .unwrap(),
        );
        block_on(store.vpsbg_progress(api.action(), &id, true)).unwrap();
        assert_eq!(api.posts("/v1/balance"), 1);
        assert_eq!(store.vpsbg_purchases[&id].deposits.len(), 1);
        let view = store.procurement_view();
        assert_eq!(view["deposit"]["state"], "open");
        assert_eq!(view["deposit"]["bolt11"], bolt11);
        assert_eq!(view["deposit"]["amount_msat"], 34_886_000);
        assert_eq!(view["deposit"]["expires"], RENDER_FAR_FUTURE);
        assert_eq!(view["deposit"]["new_top_up_allowed"], false);
        for now in [MONEY_NOW, RENDER_FAR_FUTURE - 1] {
            assert_eq!(store.vpsbg_deposit_view(&id, now), view["deposit"]);
        }
        assert!(
            view["payment_plan"]["top_up_allowed_from"]
                .as_u64()
                .unwrap()
                > RENDER_FAR_FUTURE
        );
        save("deposit_pending", store);
    });
}

#[test]
fn vpsbg_render_fixture_deposit_settled() {
    fixed(|| {
        let mut store = money_store();
        let id = money_save(&mut store, "fake-render-machine", 'a');
        money_issued(&mut store, &id);
        let mut api = MoneyApi::new(&store);
        api.time = MONEY_NOW + 60;
        api.transactions(vec![money_row(101, "19.03", "bitcoin-ln", "Fake deposit")]);
        block_on(store.vpsbg_deposit_check(api.action(), &id)).unwrap();
        assert_eq!(store.procurement_view()["deposit"]["state"], "settled");
        assert!(store.vpsbg_purchases[&id].creates.is_empty());
        save("deposit_settled", store);
    });
}

#[test]
fn vpsbg_render_fixture_create_pending() {
    fixed(|| {
        let (store, _) = covered();
        assert_eq!(store.procurement_view()["create_pending"], true);
        assert!(store.attest.is_empty());
        save("create_pending", store);
    });
}

#[test]
fn vpsbg_render_fixture_create_unknown() {
    fixed(|| {
        let (store, id) = sent();
        assert_eq!(store.vpsbg_purchases[&id].creates.len(), 1);
        assert_eq!(store.procurement_view()["pause"]["kind"], "create_unknown");
        assert!(store.procurement_view()["introduction"].is_null());
        save("create_unknown", store);
    });
}

#[test]
fn vpsbg_render_fixture_refused_login() {
    fixed(|| {
        let (mut store, id) = sent();
        block_on(store.vpsbg_commit(
            &id,
            Change::CreateLoginRefused {
                attempt: 0,
                checked_at: MONEY_NOW,
                reason: LoginReason::MissingLogin,
            },
        ))
        .unwrap();
        assert_eq!(store.procurement_view()["pause"]["kind"], "login_refused");
        save("refused_login", store);
    });
}

#[test]
fn vpsbg_render_fixture_unpaid_order() {
    fixed(|| {
        let (mut store, id) = sent();
        block_on(store.vpsbg_commit(
            &id,
            Change::OrderUnpaid {
                order: 71,
                create_attempt: 0,
                checked_at: MONEY_NOW,
            },
        ))
        .unwrap();
        let purchase = store.vpsbg_purchase(&id).unwrap().clone();
        let extension = purchase.vpsbg.as_ref().unwrap();
        block_on(store.vpsbg_commit(
            &id,
            Change::ApprovalRevised {
                revision: 2,
                selected: purchase.selected.clone(),
                payment_plan: extension.payment_plan.clone(),
                approved_card: false,
                approved_at: MONEY_NOW,
                replaces_deposit: vec![],
                late_credit_disclosed: false,
                pay_order: Some(71),
            },
        ))
        .unwrap();
        block_on(store.vpsbg_commit(
            &id,
            Change::PayOrderSent {
                order: 71,
                approval_revision: 2,
                started: MONEY_NOW,
            },
        ))
        .unwrap();
        // An unresolved pay is a supported unpaid-order state. Its pay_allowed is
        // unconditionally false, so the report never compares the wall clock to a deadline.
        assert!(store.vpsbg_purchases[&id].pay_resolved.is_none());
        let view = store.procurement_view();
        assert_eq!(view["provisioning"]["state"], "unpaid_order");
        assert_eq!(
            view["pause"],
            json!({"kind":"unpaid_order","order":71,"pay_allowed":false})
        );
        assert!(view["introduction"].is_null());
        save("unpaid_order", store);
    });
}

#[test]
fn vpsbg_render_fixture_associated() {
    fixed(|| save("associated", read_association()));
}

#[test]
fn vpsbg_render_fixture_payment_not_proven() {
    fixed(|| save("payment_not_proven", read_association()));
}

#[test]
fn vpsbg_render_fixture_introduction_waiting() {
    fixed(|| {
        let (store, id, _) = introduced(RENDER_FAR_FUTURE, false);
        assert_eq!(
            store.procurement_view()["introduction"],
            json!({"state":"waiting","deadline":RENDER_FAR_FUTURE})
        );
        assert_eq!(
            store.vpsbg_introduction_view(&id, MONEY_NOW),
            store.vpsbg_introduction_view(&id, RENDER_FAR_FUTURE - 1)
        );
        save("introduction_waiting", store);
    });
}

#[test]
fn vpsbg_render_fixture_introduction_expired() {
    fixed(|| {
        let deadline = MONEY_NOW + crate::hostcert::ATTEST_CERTIFICATE_DEADLINE_SECONDS;
        let (store, id, _) = introduced(deadline, false);
        assert_eq!(
            store.procurement_view()["introduction"],
            json!({"state":"expired","deadline":deadline})
        );
        assert_eq!(
            store.vpsbg_introduction_view(&id, deadline),
            store.vpsbg_introduction_view(&id, RENDER_FAR_FUTURE)
        );
        save("introduction_expired", store);
    });
}

#[test]
fn vpsbg_render_fixture_delete_sent() {
    fixed(|| {
        let (store, _, _) = locally_delete_sent();
        save("delete_sent", store);
    });
}

#[test]
fn vpsbg_render_fixture_deleted() {
    fixed(|| {
        let (mut store, id, mut api) = locally_delete_sent();
        let name = &store
            .vpsbg_purchase(&id)
            .unwrap()
            .vpsbg
            .as_ref()
            .unwrap()
            .name;
        api.reads.responses.insert(
            "GET /v1/servers/51".into(),
            serde_json::to_vec(&json!({"data":{
                "id":51,"hostname":name,"status":"terminated","delete_refund_total":"38.79"
            }}))
            .unwrap(),
        );
        api.reads
            .transactions(vec![money_row(71, "38.79", "balance", "Refund")]);
        block_on(store.vpsbg_delete_check(api.action(), &id)).unwrap();
        assert_eq!(api.deletes, 1);
        assert!(store.procurement.is_none());
        let view = store.procurement_view();
        assert!(view["closed"].is_string());
        assert_eq!(
            view["closed_card"]["delete"],
            json!({
                "state":"confirmed",
                "refund_quote":{"amount":3879,"currency":"EUR"},
                "refund":{"amount":3879,"currency":"EUR"}
            })
        );
        assert_eq!(view["closed_card"]["introduction"]["state"], "expired");
        assert_eq!(
            view["closed_card"]["relay_pass"]["state"],
            "revoke_requested"
        );
        assert_eq!(view["archive"][0], view["closed_card"]);
        save("deleted", store);
    });
}

#[test]
fn vpsbg_render_fixture_deleted_external() {
    fixed(|| {
        // A read-associated machine can be deleted externally, before any introduction.
        // delete_check establishes that outcome without a local DELETE or a report clock.
        let mut store = read_association();
        let id = store
            .procurement
            .as_ref()
            .unwrap()
            .vpsbg
            .as_ref()
            .unwrap()
            .purchase
            .clone();
        let name = store
            .procurement
            .as_ref()
            .unwrap()
            .vpsbg
            .as_ref()
            .unwrap()
            .name
            .clone();
        let mut api = MoneyApi::new(&store);
        api.responses.insert(
            "GET /v1/servers/51".into(),
            serde_json::to_vec(&json!({"data":{
                "id":51,"hostname":name,"status":"terminated","delete_refund_total":"38.79"
            }}))
            .unwrap(),
        );
        block_on(store.vpsbg_delete_check(api.action(), &id)).unwrap();
        assert!(store.procurement.is_none());
        assert!(store.attest.is_empty());
        let view = store.procurement_view();
        assert!(view["closed"].is_string());
        assert_eq!(view["closed_card"]["delete"]["state"], "confirmed");
        assert_eq!(
            view["closed_card"]["relay_pass"]["state"],
            "revoke_requested"
        );
        assert_eq!(view["archive"][0], view["closed_card"]);
        assert!(api.calls.iter().all(|(method, _, _)| method == "GET"));
        save("deleted_external", store);
    });
}

#[test]
fn vpsbg_render_fixture_ready() {
    use ssh_key::{
        PrivateKey,
        certificate::{Builder, CertType},
        private::{Ed25519Keypair, KeypairData},
    };
    fixed(|| {
        let (mut store, id) = sent();
        let purchase = store.vpsbg_purchase(&id).unwrap().clone();
        let mut row = server_row();
        row["id"] = json!(51);
        row["hostname"] = json!(purchase.vpsbg.as_ref().unwrap().name);
        row["billing_cycle"] = json!("1");
        // The same invented public IPv4 used by the existing readiness fixtures. Never contacted.
        row["ip_addresses"] = json!([{"version":4,"main":true,"ip_address":"8.8.8.8","assigned_on":"2026-01-01 00:00:01"}]);
        let bytes = serde_json::to_vec(&json!({"data":row})).unwrap();
        let reduced = Vendor::Vpsbg
            .reduce_response("GET", "/v1/servers/51", 200, &bytes, |_| Ok(()), |_| true)
            .unwrap();
        let wire::ServerFact::Live(detail) = serde_json::from_value(reduced).unwrap() else {
            panic!("fake live detail");
        };
        block_on(store.vpsbg_commit(
            &id,
            Change::Associated {
                server: AssociationFact::Create(detail.server.clone()),
                charge: Some(ChargeEvidence::CreateAccepted {
                    status: 201,
                    first_period: purchase.selected.charge.amount,
                }),
                checked_at: MONEY_NOW,
            },
        ))
        .unwrap();
        let mut api = MoneyApi::new(&store);
        api.responses.insert("GET /v1/servers/51".into(), bytes);
        let probe = block_on(store.vpsbg_prepare_attest(api.action(), &id))
            .unwrap()
            .unwrap();
        let intro = store
            .attest_introduction(&purchase.machine, MONEY_NOW)
            .unwrap()
            .clone();
        let seed = store
            .seed()
            .unwrap()
            .attest_certificate_authority(
                purchase.identity.derivation_version,
                purchase.identity.index,
            )
            .unwrap();
        let ca =
            PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&seed)), "").unwrap();
        let host = Ed25519Keypair::from_seed(&[31; 32]);
        let mut builder = Builder::new(
            vec![17; 32],
            ssh_key::public::KeyData::Ed25519(host.public),
            intro.begun_unix,
            intro.deadline_unix,
        )
        .unwrap();
        builder.cert_type(CertType::Host).unwrap();
        builder.valid_principal(&intro.principal).unwrap();
        let cert = builder.sign(&ca).unwrap();
        store.vpsbg_probe_admit(&probe, MONEY_NOW).unwrap();
        let fingerprint = crate::hostcert::verify(Some(&cert), &intro, MONEY_NOW).unwrap();
        // Persist the same acceptance as attest_accept, through its replay validation seam,
        // so accepted_unix never comes from that method's wall clock.
        let acceptance = crate::store::attest::Acceptance {
            machine: purchase.machine.clone(),
            route: crate::store::attest::Route::AttestCertificate,
            inner_key_fingerprint: fingerprint,
            installation_binding: intro.installation_binding,
            accepted_unix: MONEY_NOW,
            consumed: true,
        };
        block_on(store.commit(&Event::AttestAcceptance(acceptance.clone()))).unwrap();
        store.replay_attest_acceptance(&acceptance).unwrap();
        block_on(store.vpsbg_mark_ready(&id, MONEY_NOW)).unwrap();
        assert!(store.vpsbg_is_ready(store.vpsbg_purchase(&id).unwrap()));
        assert_eq!(
            store.procurement_view()["completed"][0]["introduction"]["state"],
            "accepted"
        );
        save("ready", store);
    });
}
