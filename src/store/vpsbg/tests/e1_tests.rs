//! Offline readiness fixtures: generated test authorities and invented provider responses only.
use super::*;
#[path = "g1_tests.rs"]
mod g1_tests;
use crate::harness::{AttestProbe, PinSource};
use crate::store::vpsbg::readiness::{AttestPace, probe_budget_ms};
use ssh_key::{
    PrivateKey,
    certificate::{Builder, CertType},
    private::{Ed25519Keypair, KeypairData},
};

fn live_detail(s: &Store<MemoryStorage>, id: &str, ip: bool) -> Value {
    let name = &s.vpsbg_purchase(id).unwrap().vpsbg.as_ref().unwrap().name;
    let mut d = detail(name);
    d["status"] = json!("active");
    d["locked"] = json!(true);
    d["lock_reason"] = json!("activation");
    d["state"] = json!({"running":true,"cloud_init_installing":true,"cloud_init_failed":false});
    if !ip {
        d["ip_addresses"] = json!([]);
    }
    d
}
fn supply_detail(api: &mut CreateApi, d: Value) {
    api.reads.responses.insert(
        "GET /v1/servers/51".into(),
        serde_json::to_vec(&json!({"data":d})).unwrap(),
    );
}
fn pending(late_deposit: bool) -> (Store<MemoryStorage>, String, CreateApi, AttestProbe) {
    let (mut s, id, mut api) = fresh(!late_deposit);
    if late_deposit {
        issue_unexpired(&mut s, &id, api.now());
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
    create(&mut s, &mut api, &id).unwrap();
    let d = live_detail(&s, &id, true);
    supply_detail(&mut api, d);
    let probe = block_on(s.vpsbg_prepare_attest(api.action(), &id))
        .unwrap()
        .unwrap();
    (s, id, api, probe)
}
fn test_certificate(s: &Store<MemoryStorage>, probe: &AttestProbe) -> ssh_key::Certificate {
    let intro = s
        .attest_introduction(&probe.machine, crate::hostcert::now_unix().unwrap())
        .unwrap();
    let identity = &probe.binding.machine_identity;
    // Only a fake unit-test seed is used; production never reconstructs a lost private half.
    let seed = s
        .seed()
        .unwrap()
        .attest_certificate_authority(identity.derivation_version, identity.index)
        .unwrap();
    let ca = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&seed)), "").unwrap();
    let host = Ed25519Keypair::from_seed(&[31; 32]);
    let subject = ssh_key::public::KeyData::Ed25519(host.public);
    let mut builder =
        Builder::new(vec![17; 32], subject, intro.begun_unix, intro.deadline_unix).unwrap();
    builder.cert_type(CertType::Host).unwrap();
    builder.valid_principal(&intro.principal).unwrap();
    builder.sign(&ca).unwrap()
}
fn accept(s: &mut Store<MemoryStorage>, probe: &AttestProbe) {
    let cert = test_certificate(s, probe);
    let now = crate::hostcert::now_unix().unwrap();
    s.vpsbg_probe_admit(probe, now).unwrap();
    let intro = s.attest_introduction(&probe.machine, now).unwrap();
    let fingerprint = crate::hostcert::verify(Some(&cert), intro, now).unwrap();
    block_on(s.attest_accept(&probe.machine, &fingerprint, &probe.installation_binding)).unwrap();
}

#[test]
fn vpsbg_attest_target_needs_ipv4_and_introduction() {
    let (mut s, id, mut api) = fresh(true);
    create(&mut s, &mut api, &id).unwrap();
    assert!(s.poc_target("fake-create").is_none());
    supply_detail(&mut api, live_detail(&s, &id, false));
    assert!(block_on(s.vpsbg_prepare_attest(api.action(), &id)).is_err());
    assert!(s.poc_target("fake-create").is_none());
    supply_detail(&mut api, live_detail(&s, &id, true));
    let probe = block_on(s.vpsbg_prepare_attest(api.action(), &id))
        .unwrap()
        .unwrap();
    let target = s.poc_target(&probe.machine).unwrap().clone();
    let boot = s.vpsbg_purchases[&id]
        .observed
        .as_ref()
        .unwrap()
        .state
        .as_ref()
        .unwrap();
    assert_eq!(
        (boot.running, boot.cloud_init_installing),
        (Some(true), Some(true))
    );
    assert!(target.pin.is_empty());
    assert_eq!(target.host, "8.8.8.8");
    assert_eq!(
        (target.user.as_str(), target.port, target.elevation),
        ("nixos", 22, crate::jobs::Elevation::SudoNoninteractive)
    );
    assert!(
        target.validate().is_err(),
        "ordinary enrollment still refuses an empty pin"
    );
    assert!(
        s.procurement.as_ref().unwrap().target.is_none(),
        "pending access is not handoff"
    );
    assert!(block_on(s.poc_bind(&probe.machine)).is_err());
    let before = s.records().count();
    block_on(s.vpsbg_prepare_attest(api.action(), &id)).unwrap();
    assert_eq!(
        s.records().count(),
        before,
        "unchanged reads commit no second target"
    );
    let reopened = money_reopen(&s);
    assert_eq!(reopened.poc_target(&probe.machine), Some(&target));
    assert!(!reopened.procurement_can_start());

    // Replay admission is also the write projection. Strip only the later target projection
    // from a clone, preserving its real association, observation and introduction predecessors.
    let mut prior = money_reopen(&s);
    prior.vpsbg_purchases.get_mut(&id).unwrap().attest_target = None;
    prior.poc_targets.remove(&probe.machine);
    let good = Change::AttestTarget {
        target: target.clone(),
        server_id: 51,
        introduction_binding: probe.installation_binding.clone(),
        checked_at: api.now(),
    };
    for case in 0..11 {
        let mut bad = good.clone();
        if let Change::AttestTarget {
            target,
            server_id,
            introduction_binding,
            checked_at,
        } = &mut bad
        {
            match case {
                0 => *introduction_binding = "wrong-installation".into(),
                1 => *server_id = 52,
                2 => target.host = "8.8.4.4".into(),
                3 => target.user = "root".into(),
                4 => target.port = 2222,
                5 => target.elevation = crate::jobs::Elevation::None,
                6 => target.relay = "wss://other.invalid/".into(),
                7 => target.pin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                8 => target.machine = "other-machine".into(),
                9 => target.profile = "other".into(),
                _ => *checked_at = prior.attest_deadline(&probe.machine).unwrap(),
            }
        }
        let record = Record {
            purchase: id.clone(),
            change: bad.clone(),
        };
        let next = prior.next;
        assert!(
            block_on(prior.vpsbg_commit(&id, bad)).is_err(),
            "write case {case}"
        );
        assert!(
            prior.replay_vpsbg(next, &record).is_err(),
            "replay case {case}"
        );
        assert_eq!(prior.next, next);
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    enum BeforeReadiness {
        Observed {},
    }
    for change in [
        good.clone(),
        Change::Ready {
            accepted_at: api.now(),
        },
    ] {
        let encoded = serde_json::to_value(change).unwrap();
        assert!(serde_json::from_value::<BeforeReadiness>(encoded.clone()).is_err());
        let kind = encoded.as_object().unwrap().keys().next().unwrap().clone();
        let mut unknown = encoded.clone();
        unknown[&kind]["unknown"] = json!(true);
        assert!(serde_json::from_value::<Change>(unknown).is_err());
        let mut missing = encoded;
        missing[&kind].as_object_mut().unwrap().clear();
        assert!(serde_json::from_value::<Change>(missing).is_err());
    }
    let mut wrong_intro = money_reopen(&s);
    wrong_intro
        .vpsbg_purchases
        .get_mut(&id)
        .unwrap()
        .attest_target = None;
    wrong_intro.poc_targets.remove(&probe.machine);
    wrong_intro.attest.remove(&probe.machine);
    assert!(block_on(wrong_intro.vpsbg_commit(&id, good.clone())).is_err());
    let n = wrong_intro.next;
    assert!(
        wrong_intro
            .replay_vpsbg(
                n,
                &Record {
                    purchase: id.clone(),
                    change: good.clone()
                }
            )
            .is_err()
    );
    let mut wrong_pair = prior;
    wrong_pair
        .procurement
        .as_mut()
        .unwrap()
        .vpsbg
        .as_mut()
        .unwrap()
        .binding
        .pass_identity
        .index += 1;
    assert!(block_on(wrong_pair.vpsbg_commit(&id, good.clone())).is_err());
    let n = wrong_pair.next;
    assert!(
        wrong_pair
            .replay_vpsbg(
                n,
                &Record {
                    purchase: id,
                    change: good
                }
            )
            .is_err()
    );
}

#[test]
fn vpsbg_attest_probe_is_identity_only() {
    let (mut s, id, api, probe) = pending(false);
    assert!(s.sessions.is_empty());
    for case in 0..4 {
        let mut stale = probe.clone();
        match case {
            0 => stale.installation_binding.push_str("-stale"),
            1 => stale.binding.pass_identity.index += 1,
            2 => stale.token_generation += 1,
            _ => stale.machine.push_str("-other"),
        }
        assert!(s.vpsbg_probe_admit(&stale, api.now()).is_err());
    }
    let selected = s.relay_key(&probe.machine).unwrap().public_key();
    let published = s.procurement_view()["relay_pass"]["key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(published, hex::encode(selected));
    assert_eq!(
        s.procurement_view()["relay_pass"]["expiry"],
        MONEY_NOW + 31 * 86400
    );
    assert_eq!(s.procurement_view()["relay_pass"]["state"], "needed");
    let cert = test_certificate(&s, &probe);
    let calls = RefCell::new(Vec::new());
    let before = s.next;
    let handshake = async {
        s.vpsbg_probe_admit(&probe, api.now())?;
        assert_eq!(s.relay_key(&probe.machine).unwrap().public_key(), selected);
        s.vpsbg_relay_admitted(&probe, api.now())?;
        calls.borrow_mut().push("shared-handshake");
        let intro = s.attest_introduction(&probe.machine, api.now()).unwrap();
        assert!(
            crate::hostcert::verify(None, intro, api.now()).is_err(),
            "no bare-key bypass"
        );
        let fingerprint = crate::hostcert::verify(Some(&cert), intro, api.now())?;
        block_on(s.attest_accept(&probe.machine, &fingerprint, &probe.installation_binding))?;
        Ok::<_, String>(())
    };
    block_on(crate::harness::identity_only(handshake, |()| async {
        calls.borrow_mut().push("disconnect");
        Ok(())
    }))
    .unwrap();
    assert_eq!(*calls.borrow(), ["shared-handshake", "disconnect"]);
    assert_eq!(s.next, before + 1, "exactly the existing acceptance append");
    assert!(s.sessions.is_empty());
    assert!(s.commands().is_empty());
    assert!(s.dispatch.calls.is_empty());
    assert!(!s.attest_target(&probe.machine).unwrap().pin.is_empty());
    let (_, pins) = crate::poc::targets::resolve(&s, &probe.machine).unwrap();
    assert_eq!(
        pins.pin(&probe.machine).unwrap().0,
        s.attest_target(&probe.machine).unwrap().pin
    );
    assert!(s.poc_target(&probe.machine).unwrap().pin.is_empty());
    assert_eq!(s.procurement_view()["relay_pass"]["state"], "admitted");
    let source = include_str!("../../../harness/probe.rs");
    assert!(source.contains("crate::harness::identity_only"));
    assert!(source.contains("handshake("));
    for forbidden in [
        ".authenticate_",
        ".channel_open",
        ".exec(",
        ".client_key(",
        "Session::new",
        "hostcert::verify",
    ] {
        assert!(!source.contains(forbidden), "probe acquired {forbidden}");
    }
    block_on(s.vpsbg_mark_ready(&id, api.now())).unwrap();
    assert!(money_reopen(&s).vpsbg_accepted(&id));
}

#[test]
fn vpsbg_attest_retries_until_deadline() {
    let (mut s, id, api, probe) = pending(false);
    let end = s.attest_deadline(&probe.machine).unwrap();
    let now = crate::hostcert::now_unix().unwrap();
    let mut pace = AttestPace::default();
    assert_eq!(pace.begin(now * 1000, end), Some(15_000));
    assert_eq!(pace.begin((now + 5) * 1000, end), None, "no overlap");
    let refusal = crate::hostcert::verify(
        None,
        s.attest_introduction(&probe.machine, now).unwrap(),
        now,
    );
    assert!(
        refusal.is_err(),
        "a bare host key has no certificate authority"
    );
    assert!(!s.vpsbg_accepted(&id));
    pace.finish();
    assert_eq!(pace.begin(now * 1000 + 4999, end), None);
    assert_eq!(pace.begin((now + 5) * 1000, end), Some(15_000));
    pace.finish();
    assert_eq!(pace.begin((end - 2) * 1000, end), Some(2000));
    pace.finish();
    assert_eq!(pace.begin(end * 1000, end), None);
    assert_eq!(pace.begin((end + 1) * 1000, end), None);
    assert_eq!(probe_budget_ms(end * 1000, end), None);
    assert_eq!(probe_budget_ms(end * 1000 - 700, end), Some(700));
    assert_eq!(
        s.vpsbg_introduction_view(&id, end),
        json!({"state":"expired","deadline":end})
    );
    assert!(!s.vpsbg_accepted(&id));
    assert!(s.vpsbg_probe_admit(&probe, end).is_err());
    let entry = s.dispatch.approved_entries[&probe.machine]
        .approved
        .entry
        .clone();
    assert!(block_on(s.attest_introduction_begin(&entry)).is_err());
    assert_eq!(s.attest_deadline(&probe.machine), Some(end));

    // A later transport failure cannot undo an acceptance; reload discovers it without a dial.
    let outcome = block_on(crate::harness::identity_only(
        async {
            accept(&mut s, &probe);
            Ok::<_, String>(())
        },
        |()| async { Err("fake response lost after certificate acceptance".into()) },
    ));
    assert!(outcome.is_err());
    let mut reopened = money_reopen(&s);
    assert!(
        reopened
            .vpsbg_poll_contexts()
            .iter()
            .any(|c| c.purchase == id && c.accepted && c.attest_pending)
    );
    let mut api = api;
    let creates = api.creates;
    let requests = api.reads.calls.len();
    assert!(
        block_on(reopened.vpsbg_prepare_attest(api.action(), &id))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        api.reads.calls.len(),
        requests,
        "accepted pin projects Ready without another exchange"
    );
    assert_eq!(api.creates, creates);
    assert!(reopened.vpsbg_is_ready(reopened.vpsbg_purchase(&id).unwrap()));
    assert!(
        !reopened
            .vpsbg_poll_contexts()
            .iter()
            .any(|c| c.purchase == id && c.attest_pending)
    );
    assert_eq!(reopened.attest_deadline(&probe.machine), Some(end));
}

struct ContextApi {
    inner: CreateApi,
    context: ActionContext,
}
impl Api for ContextApi {
    fn vpsbg_context(&self) -> Option<&ActionContext> {
        Some(&self.context)
    }
    fn account(&self) -> String {
        self.inner.account()
    }
    fn now(&self) -> u64 {
        self.inner.now()
    }
    fn current(&self) -> Result<(), String> {
        self.inner.current()
    }
    fn check_vendor(&self, v: Vendor) -> Result<(), String> {
        self.inner.check_vendor(v)
    }
    fn vpsbg_begin_window(&mut self) -> Result<(), String> {
        self.inner.vpsbg_begin_window()
    }
    fn take_vpsbg_response(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.inner.take_vpsbg_response()
    }
    fn response_status(&self) -> u16 {
        self.inner.response_status()
    }
    async fn request(&mut self, m: &str, u: &str, b: Option<Value>) -> Result<Value, ReadError> {
        self.inner.request(m, u, b).await
    }
}

#[test]
fn vpsbg_poll_contexts_survive_handoff() {
    let (mut s, id, api, probe) = pending(true);
    assert!(s.poc_target(&probe.machine).is_some());
    assert!(s.procurement.as_ref().unwrap().target.is_none());
    let context = s.vpsbg_poll_admit(&id, PollKind::Attest).unwrap();
    assert_eq!(context.vendor, Vendor::Vpsbg);
    assert_eq!(context.origin, wire::ORIGIN);
    assert_eq!(context.account, api.account());
    let mut api = ContextApi {
        inner: api,
        context,
    };
    block_on(s.vpsbg_prepare_attest(&mut api, &id)).unwrap();
    s.vpsbg_context_current(&api.context).unwrap();
    for action in ["attest", "pay_order"] {
        s.vpsbg_admit_addressed(action).unwrap();
    }
    for action in ["delete", "delete_check"] {
        assert!(s.vpsbg_admit_addressed(action).is_ok());
    }
    assert!(
        block_on(s.vpsbg_pay_order(&mut api, &id)).is_err(),
        "the context cannot invent pay authority"
    );
    accept(&mut s, &probe);
    block_on(s.vpsbg_mark_ready(&id, api.now())).unwrap();
    s.procurement_choose_vendor(Vendor::Lnvps).unwrap();
    assert!(s.procurement_view().get("vendor").is_none());
    assert!(s.vpsbg_poll_admit(&id, PollKind::Deposit).is_ok());
    assert!(s.vpsbg_poll_admit(&id, PollKind::Attest).is_err());
    s.vpsbg_context_current(&api.context).unwrap();
    api.inner.action();
    block_on(s.vpsbg_poll_deposit(&mut api, &id)).unwrap();
    for (visible, online, unlocked, current) in [
        (false, true, true, true),
        (true, false, true, true),
        (true, true, false, true),
        (true, true, true, false),
    ] {
        assert!(poll_authority(visible, online, unlocked, current).is_err());
    }
    poll_authority(true, true, true, true).unwrap();
    s.authority.suspend();
    assert!(s.vpsbg_poll_admit(&id, PollKind::Deposit).is_err());
    assert!(s.vpsbg_poll_contexts().is_empty());
}

#[test]
fn vpsbg_completed_purchase_keeps_its_vendor() {
    let (mut s, id, api, probe) = pending(true);
    accept(&mut s, &probe);
    block_on(s.vpsbg_mark_ready(&id, api.now())).unwrap();
    s.procurement_choose_vendor(Vendor::Lnvps).unwrap();
    let mut context = s.vpsbg_action_context(&id).unwrap();
    let completed = s.procurement_view()["completed"][0].clone();
    assert_eq!(completed["vendor"]["id"], "vpsbg");
    assert_eq!(completed["origin"], wire::ORIGIN);
    assert_eq!(completed["vm_id"], 51);
    assert_eq!(completed["introduction"]["state"], "accepted");
    assert_eq!(completed["trust"]["route"], "AttestCertificate");
    assert_eq!(
        completed["relay_pass"]["key"],
        hex::encode(s.relay_key(&probe.machine).unwrap().public_key())
    );
    let mut api = ContextApi {
        inner: api,
        context: context.clone(),
    };
    // The actual shared provider_response/check_api path honors the bound purchase over the draft.
    api.inner.action();
    let result = block_on(s.provider_read(&mut api, wire::read("/v1/balance"))).unwrap();
    assert_eq!(result["currency"], "eur");
    s.vpsbg_context_current(&context).unwrap();
    context.vendor = Vendor::Lnvps;
    assert!(s.vpsbg_context_current(&context).is_err());
    context = api.context.clone();
    context.origin = "https://other.invalid".into();
    assert!(s.vpsbg_context_current(&context).is_err());
    context = api.context.clone();
    context.generation += 1;
    assert!(s.vpsbg_context_current(&context).is_err());
    let mut r = money_reopen(&s);
    r.procurement_choose_vendor(Vendor::Lnvps).unwrap();
    assert_eq!(r.procurement_view()["completed"][0], completed);
    api.inner.action();
    block_on(r.vpsbg_poll_deposit(&mut api, &id)).unwrap();
    assert_eq!(api.inner.creates, 1);
    assert_eq!(api.inner.pays, 0);
    // A current LNVPS purchase is independent of the addressed completed VPSBG one.
    let previous = r.procurement.take().unwrap();
    r.completed_purchases.push(previous);
    r.procurement = Some(lnvps_view_purchase());
    assert_eq!(r.procurement_vendor(), Vendor::Lnvps);
    assert_eq!(r.procurement_view()["completed"][0], completed);
    r.vpsbg_context_current(&api.context).unwrap();
    assert!(r.vpsbg_poll_admit(&id, PollKind::Deposit).is_ok());
    api.inner.action();
    block_on(r.vpsbg_poll_deposit(&mut api, &id)).unwrap();
    api.inner.reads.responses.insert(
        "GET /v1/balance".into(),
        serde_json::to_vec(&json!({"id":1,"balance":"fake LNVPS shape"})).unwrap(),
    );
    api.inner.action();
    assert!(block_on(r.provider_read(&mut api, wire::read("/v1/balance"))).is_err());
    assert_eq!((api.inner.creates, api.inner.pays), (1, 0));
}

#[test]
fn vpsbg_ready_gates_can_start() {
    let (mut s, id, mut api, probe) = pending(false);
    assert!(!s.procurement_can_start());
    assert!(s.procurement_choose_vendor(Vendor::Lnvps).is_err());
    let ready = Record {
        purchase: id.clone(),
        change: Change::Ready {
            accepted_at: api.now(),
        },
    };
    let n = s.next;
    assert!(block_on(s.vpsbg_commit(&id, ready.change.clone())).is_err());
    assert!(s.replay_vpsbg(n, &ready).is_err());
    accept(&mut s, &probe);
    block_on(s.vpsbg_mark_ready(&id, api.now())).unwrap();
    assert!(s.procurement_can_start());
    let mut s = money_reopen(&s);
    assert!(s.procurement_can_start());
    s.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
    api.action();
    block_on(s.procurement_select(
        &mut api,
        provisioning::Choice {
            offer_id: 7,
            image_id: 1,
            resources: None,
        },
    ))
    .unwrap();
    let selected = s.procurement_review_selection().unwrap().clone();
    let review = s
        .vpsbg_review(&selected, &money_balance(5000), api.now())
        .unwrap();
    block_on(s.vpsbg_approve(
        api.action(),
        provisioning::Approval {
            origin: wire::ORIGIN.into(),
            machine: "fake-next-machine".into(),
            relay: "wss://fake-relay.invalid/".into(),
            class_answer: ClassAnswer::No,
            approve_charge: true,
            approve_maintained_access: true,
        },
        review,
    ))
    .unwrap();
    assert_ne!(s.procurement.as_ref().unwrap().machine, probe.machine);
    assert_eq!(s.completed_purchases.len(), 1);
    assert!(
        !s.procurement_can_start(),
        "the successor blocks until its own Ready or Closed"
    );
    block_on(s.vpsbg_close(api.now())).unwrap();
    assert!(
        s.procurement_can_start(),
        "Closed releases only its own live entry"
    );
    assert!(money_reopen(&s).procurement_can_start());

    // A real replacement retires its previous entry, and cannot release its live successor.
    let (mut s, id, mut api) = fresh(true);
    let old = s.dispatch.approved_entries["fake-create"].clone();
    drop(block_on(s.attest_introduction_begin(&old.approved.entry)).unwrap());
    create(&mut s, &mut api, &id).unwrap();
    let machine = s.vpsbg_purchase(&id).unwrap().machine.clone();
    assert_ne!(machine, "fake-create");
    assert!(!s.procurement_can_start());
    supply_detail(&mut api, live_detail(&s, &id, true));
    let probe = block_on(s.vpsbg_prepare_attest(api.action(), &id))
        .unwrap()
        .unwrap();
    // Preserve the old approved entry to exercise the explicit provenance-based skip.
    s.dispatch
        .approved_entries
        .insert("fake-create".into(), old);
    assert!(!s.procurement_can_start());
    accept(&mut s, &probe);
    block_on(s.vpsbg_mark_ready(&id, api.now())).unwrap();
    assert!(s.procurement_can_start());
}

fn completed_card(s: &Store<MemoryStorage>, id: &str) -> Value {
    s.procurement_view()["completed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|card| card["purchase"] == id)
        .unwrap()
        .clone()
}

struct LnvpsReads {
    account: String,
    calls: Vec<String>,
}
impl Api for LnvpsReads {
    fn account(&self) -> String {
        self.account.clone()
    }
    fn now(&self) -> u64 {
        crate::hostcert::now_unix().unwrap()
    }
    fn current(&self) -> Result<(), String> {
        Ok(())
    }
    fn check_vendor(&self, vendor: Vendor) -> Result<(), String> {
        assert_eq!(vendor, Vendor::Lnvps);
        Ok(())
    }
    async fn request(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Value>,
    ) -> Result<Value, ReadError> {
        use crate::poc::provisioning::tests as fixtures;
        assert_eq!(method, "GET");
        assert!(body.is_none());
        let path = url.strip_prefix("https://fake-lnvps.invalid").unwrap();
        self.calls.push(path.into());
        match path {
            "/api/v1/vm/templates" => {
                Ok(json!({"templates":[fixtures::offer()],"custom_template":[fixtures::custom()]}))
            }
            "/api/v1/image" => Ok(json!([fixtures::image()])),
            _ => Err(protocol::REFUSED.into()),
        }
    }
}

#[test]
fn vpsbg_ready_allows_real_lnvps_account_and_approval() {
    let (mut s, id, api, probe) = pending(false);
    assert!(s.provider_account().is_none());
    accept(&mut s, &probe);
    block_on(s.vpsbg_mark_ready(&id, api.now())).unwrap();
    let card = completed_card(&s, &id);
    s.procurement_choose_vendor(Vendor::Lnvps).unwrap();
    assert_eq!(completed_card(&s, &id), card);
    s.deployment_origin = Some("https://fake-lnvps.invalid".into());
    block_on(s.provider_generate()).unwrap();
    let account = s.provider_account().unwrap().copy();
    assert_ne!(account.public(), s.vpsbg_purchase(&id).unwrap().account);
    assert_eq!(
        money_reopen(&s).provider_account().unwrap().public(),
        account.public()
    );
    assert_eq!(completed_card(&s, &id), card);
    let mut api = LnvpsReads {
        account: account.public(),
        calls: Vec::new(),
    };
    let catalogue = block_on(s.procurement_catalogue(&mut api)).unwrap();
    assert_eq!(catalogue["offers"]["templates"][0]["id"], 1);
    assert_eq!(completed_card(&s, &id), card);
    block_on(s.procurement_select(
        &mut api,
        provisioning::Choice {
            offer_id: 1,
            image_id: 3,
            resources: None,
        },
    ))
    .unwrap();
    assert_eq!(completed_card(&s, &id), card);
    block_on(s.procurement_approve(
        &mut api,
        provisioning::Approval {
            origin: "https://fake-lnvps.invalid".into(),
            machine: "fake-next-lnvps".into(),
            relay: "wss://fake-relay.invalid/".into(),
            class_answer: ClassAnswer::No,
            approve_charge: true,
            approve_maintained_access: true,
        },
    ))
    .unwrap();
    assert_eq!(
        api.calls,
        ["/api/v1/vm/templates", "/api/v1/image"].repeat(3)
    );
    let purchase = s.procurement.as_ref().unwrap();
    assert_eq!(purchase.vendor, Vendor::Lnvps);
    assert_eq!(purchase.account, account.public());
    assert_eq!(purchase.machine, "fake-next-lnvps");
    assert_eq!(s.completed_purchases.len(), 1);
    assert_eq!(completed_card(&s, &id), card);
    assert!(s.procurement_account(&"b".repeat(64)).is_err());
    let reopened = money_reopen(&s);
    assert_eq!(completed_card(&reopened, &id), card);
    assert_eq!(
        reopened.procurement.as_ref().unwrap().account,
        account.public()
    );
    assert!(reopened.procurement_account(&"b".repeat(64)).is_err());
}

#[test]
fn vpsbg_ready_card_survives_same_vendor_draft_and_reload() {
    let (mut s, id, mut api, probe) = pending(false);
    accept(&mut s, &probe);
    block_on(s.vpsbg_mark_ready(&id, api.now())).unwrap();
    let card = completed_card(&s, &id);
    for field in [
        "introduction",
        "trust",
        "relay_pass",
        "vm_id",
        "paid_until",
        "renewal",
        "effective_pin",
    ] {
        assert!(!card[field].is_null(), "missing completed {field}");
    }
    for reload in [false, true] {
        if reload {
            s = money_reopen(&s);
        }
        s.procurement_choose_vendor(Vendor::Vpsbg).unwrap();
        assert_eq!(completed_card(&s, &id), card);
        assert!(s.procurement_review_selection().is_none());
        block_on(s.procurement_select(
            api.action(),
            provisioning::Choice {
                offer_id: 7,
                image_id: 1,
                resources: None,
            },
        ))
        .unwrap();
        assert!(s.procurement_review_selection().is_some());
        assert_eq!(completed_card(&s, &id), card);
        let draft = s.procurement_view();
        assert_eq!(draft["vendor"]["id"], "vpsbg");
        for field in [
            "machine",
            "purchase",
            "identity",
            "target",
            "publication",
            "vm_id",
            "effective_pin",
            "relay_pass",
            "approved_selection",
        ] {
            assert!(
                draft.get(field).is_none(),
                "draft inherited {field} after reload={reload}"
            );
        }
        assert!(draft["introduction"].is_null());
        assert!(draft["paid_until"].is_null());
        assert_eq!(draft["renewal"], "unknown");
        assert!(
            s.completed_purchases.is_empty(),
            "still before the next approval"
        );
    }
}

#[test]
fn vpsbg_expired_view_survives_dropped_poll_context() {
    let (s, id, _api, probe) = pending(false);
    let end = s.attest_deadline(&probe.machine).unwrap();
    let reopened = money_reopen(&s);
    for s in [&s, &reopened] {
        assert!(
            s.vpsbg_poll_contexts_at(end - 1)
                .iter()
                .any(|c| c.purchase == id && c.attest_pending)
        );
        for now in [end, end + 60] {
            // A deposit-poll context remains: this fixture approves directly and skips the image
            // step, which the production flow never does. Only the attest context must drop.
            assert!(
                !s.vpsbg_poll_contexts_at(now)
                    .iter()
                    .any(|c| c.purchase == id && c.attest_pending)
            );
            let mut view = json!({});
            s.vpsbg_machine_view(&mut view, s.vpsbg_purchase(&id).unwrap(), now);
            assert_eq!(
                view["introduction"],
                json!({"state":"expired","deadline":end})
            );
            assert!(view.get("effective_pin").is_none());
            assert_eq!(s.attest_deadline(&probe.machine), Some(end));
        }
    }
}

#[test]
fn vpsbg_catalogue_checks_token_before_purchase() {
    let mut s = money_store();
    let mut api = Reads::new(s.vpsbg_token().unwrap().account.clone());
    assert!(s.procurement.is_none());
    assert_eq!(s.procurement_view()["vendor_account"]["check"], "unchecked");
    block_on(s.procurement_catalogue(&mut api)).unwrap();
    assert_eq!(s.procurement_view()["vendor_account"]["check"], "works");
    api.balance =
        br#"{"balance":"19.98","minimum_deposit":"10","balance_limit":"500","currency":"EUR"}"#
            .to_vec();
    assert!(block_on(s.procurement_catalogue(&mut api)).is_err());
    assert_eq!(s.procurement_view()["vendor_account"]["check"], "refused");
    assert!(s.procurement.is_none());
    assert_eq!(
        api.calls,
        ["/v1/servers/plans", "/v1/balance"]
            .repeat(2)
            .into_iter()
            .map(|path| ("GET".into(), format!("{}{path}", wire::ORIGIN)))
            .collect::<Vec<_>>()
    );
}
