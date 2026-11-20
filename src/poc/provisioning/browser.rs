//! Actual browser fetch of the exact absolute URL supplied by Purchase authority.
use super::*;
use serde_json::json;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use tokio::sync::Notify;
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroize;

const UNKNOWN_MUTATION: &str = "Provider mutation outcome unknown or browser access unavailable; the saved intent is retained. Use read-only Refresh/Resume to reconcile or remain paused; never retry the mutation.";

thread_local! {
    static VPSBG_TOKEN: RefCell<Option<crate::store::vpsbg::TokenRecord>> = const {RefCell::new(None)};
    static ACCOUNT: RefCell<Option<Account>> = const {RefCell::new(None)};
    static ACTIVE: Cell<bool> = const {Cell::new(false)};
    static PENDING: RefCell<Option<Rc<Pending>>> = const {RefCell::new(None)};
    static READINESS_CHECKED: RefCell<Option<(Value, u64, &'static str)>> = const {RefCell::new(None)};
    static VISIBLE: Cell<bool> = const {Cell::new(true)};
    static VPSBG_ONLINE: Cell<bool> = const {Cell::new(true)};
    static VPSBG_VISIBLE: Cell<bool> = const {Cell::new(true)};
    static VPSBG_EPOCH: Cell<u64> = const {Cell::new(0)};
    static VISIBILITY: Cell<u64> = const {Cell::new(0)};
    static LAST: Cell<Option<f64>> = const {Cell::new(None)};
    static ATTEST_PACE: RefCell<std::collections::BTreeMap<String, crate::store::vpsbg::readiness::AttestPace>> = const { RefCell::new(std::collections::BTreeMap::new()) };
    #[cfg(feature="tracer")]
    static TEST_ORIGIN: RefCell<Option<String>> = const {RefCell::new(None)};
}
pub(crate) fn freeze() {
    crate::harness::stop_probe();
    PENDING.with_borrow(|p| {
        if let Some(p) = p {
            p.stop();
        }
    });
}
pub(crate) fn end() {
    freeze();
    ACCOUNT.with_borrow_mut(|a| *a = None);
    VPSBG_TOKEN.with_borrow_mut(|a| *a = None);
}
pub(crate) fn restore(account: Option<&Account>) {
    ACCOUNT.with_borrow_mut(|a| *a = account.map(Account::copy));
}
pub(crate) fn restore_vpsbg(record: Option<&crate::store::vpsbg::TokenRecord>) {
    VPSBG_TOKEN.with_borrow_mut(|a| *a = record.map(|r| r.copy()));
}
pub(crate) fn key_is_set() -> bool {
    ACCOUNT.with_borrow(Option::is_some)
}
#[wasm_bindgen]
pub fn provider_key_is_set() -> bool {
    key_is_set()
}

#[wasm_bindgen]
pub fn provider_visibility(visible: bool) {
    if VISIBLE.replace(visible) != visible {
        VISIBILITY.set(VISIBILITY.get().wrapping_add(1));
    }
    if !visible {
        crate::harness::stop_probe();
    }
}

#[wasm_bindgen]
pub fn vpsbg_presence(visible: bool, online: bool) {
    let was_visible = VPSBG_VISIBLE.replace(visible);
    if VPSBG_ONLINE.replace(online) != online || was_visible != visible {
        VPSBG_EPOCH.set(VPSBG_EPOCH.get().wrapping_add(1));
    }
    if !online || !visible {
        crate::harness::stop_probe();
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ProbeEpoch {
    visibility: u64,
    online: u64,
    lifecycle: u64,
}
impl ProbeEpoch {
    pub(crate) fn capture() -> Result<Self, String> {
        let epoch = Self {
            visibility: VISIBILITY.get(),
            online: VPSBG_EPOCH.get(),
            lifecycle: crate::lifecycle::owner().generation(),
        };
        epoch.check()?;
        Ok(epoch)
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        let owner = crate::lifecycle::owner();
        crate::store::vpsbg::poll_authority(
            VISIBLE.get() && VPSBG_VISIBLE.get(),
            VPSBG_ONLINE.get(),
            owner.ordinary().is_ok(),
            self.visibility == VISIBILITY.get()
                && self.online == VPSBG_EPOCH.get()
                && self.lifecycle == owner.generation(),
        )
    }
}

#[wasm_bindgen]
pub fn provider_action_delay() -> u32 {
    let Ok(now) = monotonic_ms() else {
        return 0;
    };
    LAST.get().map_or(0, |last| {
        if now < last {
            1000
        } else {
            (1000.0 - (now - last)).clamp(0.0, 1000.0).ceil() as u32
        }
    })
}

pub(crate) fn readiness_report(purchase: &Value) -> Value {
    let inactive = if !VISIBLE.get() {
        Some("the page is hidden")
    } else if !key_is_set() {
        Some("the provider key is missing")
    } else if crate::poc::inference::response_pending() {
        Some("a command response is pending")
    } else if crate::lifecycle::owner().ordinary().is_err() {
        Some("local lifecycle authority is unavailable")
    } else {
        None
    };
    let checked = READINESS_CHECKED.with_borrow(|saved| {
        saved
            .as_ref()
            .filter(|(identity, _, _)| identity == &purchase["identity"])
            .map(|(_, at, kind)| (at * 1000, *kind))
    });
    let now = (js_sys::Date::now() / 1000.0) as u64;
    json!({"checked_at":checked.map(|(at,_)|at),"kind":checked.map(|(_,kind)|kind).unwrap_or("checking"),"inactive":inactive,"expired":purchase["paid_at"].as_u64().is_some_and(|paid|now >= paid.saturating_add(readiness_wait_seconds()))})
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub fn test_provider_clear() {
    end();
}

#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub fn test_procurement_origin(origin: String) -> Result<(), JsValue> {
    let port = origin
        .strip_prefix("https://127.0.0.1:")
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|p| *p != 0)
        .ok_or("loopback HTTPS origin required")?;
    TEST_ORIGIN.with_borrow_mut(|o| *o = Some(format!("https://127.0.0.1:{port}")));
    Ok(())
}
struct Active;
impl Active {
    fn acquire() -> Result<Self, String> {
        if ACTIVE.replace(true) {
            return Err("Provisioning is already working; wait for its report.".into());
        }
        Ok(Self)
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        ACTIVE.set(false);
    }
}

#[wasm_bindgen]
pub async fn provider_configure(bytes: js_sys::Uint8Array, origin: String) -> String {
    let mut secret = Zeroizing::new(bytes.to_vec());
    bytes.fill(0, 0, bytes.length());
    let result = async {
        let _active = Active::acquire()?;
        if crate::poc::inference::response_pending() {return Err("Provider account entry refused: command response pending; retry after it completes.".into());}
        let continuation = crate::lifecycle::owner().continuation()?;
        let account = Account::parse(&secret)?;
        let local = crate::worker::local();
        let mut local = local.lock().await;
        continuation.check()?;
        if crate::poc::inference::response_pending() {return Err("Provider account entry refused: command response pending; retry after it completes.".into());}
        if local.dispatch_refusal().is_some() {
            return Err("Unlock before setting the provider account.".into());
        }
        let store = local
            .store()
            .ok_or("Unlock before setting the provider account.")?;
        #[cfg(feature = "tracer")]
        let origin = TEST_ORIGIN.with_borrow(Clone::clone).unwrap_or(origin);
        store.procurement_configure(&account, &secret, &origin).await?;
        continuation.check()?;
        ACCOUNT.with_borrow_mut(|a| *a = Some(account));
        Ok::<(), String>(())
    }
    .await;
    secret.zeroize();
    crate::worker::local()
        .lock()
        .await
        .report(result.as_ref().err().map(String::as_str))
        .to_string()
}

#[wasm_bindgen]
pub async fn provider_token_configure(bytes: js_sys::Uint8Array) -> String {
    let mut input = Zeroizing::new(bytes.to_vec());
    bytes.fill(0, 0, bytes.length());
    let result = async {
        let _active = Active::acquire()?;
        let continuation = crate::lifecycle::owner().continuation()?;
        let local = crate::worker::local();
        let mut local = local.lock().await;
        continuation.check()?;
        if local.dispatch_refusal().is_some() {
            return Err("Unlock before setting the VPSBG token.".into());
        }
        let store = local
            .store()
            .ok_or("Unlock before setting the VPSBG token.")?;
        store.vpsbg_token_install(&input).await?;
        continuation.check()?;
        restore_vpsbg(store.vpsbg_token());
        Ok::<(), String>(())
    }
    .await;
    input.zeroize();
    let local = crate::worker::local();
    let local = local.lock().await;
    local.encode_report(local.report(result.as_ref().err().map(String::as_str)))
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Vendor {
        vendor: Vendor,
    },
    Catalogue,
    Select {
        choice: crate::store::provisioning::Choice,
    },
    Approve {
        approval: crate::store::provisioning::Approval,
        selection: Selection,
        #[serde(default, deserialize_with = "money_review_input")]
        vpsbg: Option<crate::store::vpsbg::MoneyReview>,
    },
    Resume {
        #[serde(default)]
        purchase: Option<String>,
    },
    PaymentCheck {
        #[serde(default)]
        purchase: Option<String>,
    },
    PayOrder {
        #[serde(default)]
        purchase: Option<String>,
    },
    ReadinessCheck {
        #[serde(default)]
        purchase: Option<String>,
    },
    EmailCheck,
    EmailSend {
        email: String,
    },
    EmailReissue,
    Close,
    Stop {
        stage: crate::store::provisioning::StopStage,
    },
    Choose {
        vm_id: u64,
    },
    Delete {
        machine: String,
        #[serde(default)]
        confirmed: bool,
    },
    DeleteCheck {
        machine: String,
    },
    InitialInvoice {
        billing: crate::store::provisioning::Billing,
    },
}
fn money_review_input<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<crate::store::vpsbg::MoneyReview>, D::Error> {
    crate::store::vpsbg::MoneyReview::deserialize(d).map(Some)
}

#[wasm_bindgen]
pub async fn provider_request(request: String) -> String {
    let request = Zeroizing::new(request);
    let result = async {
        let _active = Active::acquire()?;
        if crate::poc::inference::response_pending() {
            return Err(
                "Provider reads refused: command response pending; retry after it completes."
                    .into(),
            );
        }
        // Each action remains bounded and paced.
        let now = monotonic_ms()?;
        if LAST.get().is_some_and(|last| now < last || now - last < 1000.0) {
            return Err("Provider reads paused briefly; Refresh after one second.".into());
        }
        LAST.set(Some(now));
        let continuation = crate::lifecycle::owner().continuation()?;
        let action: Action =
            serde_json::from_str(&request).map_err(|_| "Invalid provisioning request.")?;
        let local = crate::worker::local();
        let mut local = local.lock().await;
        continuation.check()?;
        if crate::poc::inference::response_pending() {
            return Err(
                "Provider reads refused: command response pending; retry after it completes."
                    .into(),
            );
        }
        if local.dispatch_refusal().is_some() {
            return Err("Unlock before provisioning.".into());
        }
        let store = local.store().ok_or("Unlock before provisioning.")?;
        if matches!(&action, Action::Approve { vpsbg: Some(_), .. }) && store.procurement_vendor() != Vendor::Vpsbg {
            return Err("Invalid provisioning request.".into());
        }
        if let Action::Vendor { vendor } = &action {
            store.procurement_choose_vendor(*vendor)?;
            return Ok(None);
        }
        let action_name = match &action {
            Action::Approve { .. } => "approve", Action::Resume { .. } => "resume", Action::PaymentCheck { .. } => "payment_check", Action::PayOrder { .. } => "pay_order",
            Action::EmailCheck => "email_check", Action::InitialInvoice { .. } => "initial_invoice",
            Action::Close => "close", Action::EmailSend { .. } => "email_send", Action::EmailReissue => "email_reissue",
            Action::Delete {..} => "delete", Action::DeleteCheck {..} => "delete_check",
            _ => "read",
        };
        let addressed = match &action {
            Action::Resume { purchase } | Action::PaymentCheck { purchase }
                | Action::PayOrder { purchase } | Action::ReadinessCheck { purchase } => purchase.as_deref(),
            _ => None,
        };
        let addressed_context = match &action {
            Action::Delete {machine,..} | Action::DeleteCheck {machine} => Some(store.vpsbg_machine_context(machine)?),
            _ => addressed.map(|id| store.vpsbg_action_context(id)).transpose()?,
        };
        let vendor = addressed_context.as_ref().map_or(store.procurement_vendor(), |c| c.vendor);
        if addressed_context.is_some() {
            store.vpsbg_admit_addressed(action_name)?;
        } else {
            store.procurement_admit_action(action_name)?;
        }
        let automatic = matches!(action, Action::ReadinessCheck { .. } | Action::EmailCheck);
        let context = if addressed_context.is_some() { addressed_context } else if vendor == Vendor::Vpsbg {
            store.procurement_view()["purchase"].as_str().map(|id| store.vpsbg_action_context(id)).transpose()?
        } else { None };
        if automatic && vendor == Vendor::Vpsbg {
            if !VISIBLE.get() || !VPSBG_VISIBLE.get() || !VPSBG_ONLINE.get() {
                return Ok(None);
            }
            let Some(context) = &context else { return Ok(None) };
            store.vpsbg_poll_admit(&context.purchase, crate::store::vpsbg::PollKind::Attest)?;
        }
        let eligible = if matches!(action, Action::EmailCheck) {
            store.procurement_email_eligible()
        } else {
            store.procurement_readiness_eligible()
        };
        if automatic && (!VISIBLE.get() || if vendor == Vendor::Vpsbg { store.vpsbg_token().is_none() } else { !key_is_set() || !eligible }) {
            return Ok(None);
        }
        if !automatic && vendor == Vendor::Lnvps { store.provider_generate().await?; }
        continuation.check()?;
        restore(store.provider_account());
        restore_vpsbg(store.vpsbg_token());
        let credential = match vendor {
            Vendor::Lnvps => Credential::Lnvps(store.provider_account().ok_or("Provider account unavailable.")?.copy()),
            Vendor::Vpsbg => Credential::VpsbgToken(store.vpsbg_token().ok_or("Enter the VPSBG token first.")?.copy()),
        };
        let mut api = Browser {
            context,
            vendor,
            origin: if vendor == Vendor::Vpsbg { vpsbg::ORIGIN.into() } else { store.procurement_origin().into() },
            credential,
            raw_response: None,
            continuation,
            automatic_visibility: (automatic || vendor == Vendor::Vpsbg).then(|| VISIBILITY.get()),
            vpsbg_epoch: VPSBG_EPOCH.get(),
            started: now,
            requests: 0,
            response_status: 0,
        };
        api.current()?;
        let observe_readiness = matches!(action, Action::ReadinessCheck { .. } | Action::Resume { .. } | Action::InitialInvoice { .. });
        let identity = store.procurement_view()["identity"].clone();
        let closing_purchase = if matches!(action, Action::Close) && api.vendor == Vendor::Vpsbg {
            store.procurement_view()["purchase"].as_str().map(str::to_string)
        } else { None };
        let result = match action {
            Action::Vendor { .. } => unreachable!(),
            Action::Catalogue => store.procurement_catalogue(&mut api).await.map(Some),
            Action::Select { choice } => store
                .procurement_select(&mut api, choice)
                .await
                .map(|_| None),
            Action::Approve { approval, selection, vpsbg } => {
                if !store.procurement_review_selection().is_some_and(|current| store.procurement_vendor().same_terms(current, &selection)) {
                    return Err("The displayed configuration is stale or missing; review the current selection and approve it again.".into());
                }
                if api.vendor == Vendor::Vpsbg {
                    store.vpsbg_approve(&mut api, approval, vpsbg.ok_or("Review and explicitly approve the VPSBG money plan first.")?).await?;
                    return Ok(None);
                }
                let fresh = matches!(store.procurement_view()["phase"].as_str(), None | Some("handed_off"));
                store.procurement_approve(&mut api, approval).await?;
                if fresh {
                    // Give ordering its own budget without renewing lifecycle authority.
                    api.started = monotonic_ms()?;
                    api.requests = 0;
                    api.response_status = 0;
                    store.procurement_resume(&mut api, false).await.map(|_| None)
                } else {
                    Ok(None)
                }
            }
            // The addressed attest continuation below owns the one detail refresh and probe.
            Action::ReadinessCheck { .. } if api.vendor == Vendor::Vpsbg => Ok(None),
            Action::ReadinessCheck { .. } => store.procurement_readiness_check(&mut api).await.map(|_| None),
            Action::EmailCheck => store.procurement_resume(&mut api, false).await.map(|_| None),
            Action::EmailSend { email } => store.procurement_email_send(&mut api, Some(email)).await.map(|_| None),
            Action::EmailReissue => store.procurement_email_send(&mut api, None).await.map(|_| None),
            Action::PaymentCheck { .. } if api.vendor == Vendor::Vpsbg => {
                let purchase = api.context.as_ref().ok_or(REFUSED)?.purchase.clone();
                store.vpsbg_progress(&mut api, &purchase, false).await.map(|_| None)
            }
            Action::PaymentCheck { .. } => store.procurement_payment_check(&mut api).await.map(|_| None),
            Action::PayOrder { .. } => {
                let purchase = api.context.as_ref().ok_or(REFUSED)?.purchase.clone();
                store.vpsbg_pay_order(&mut api, &purchase).await.map(|_| None)
            }
            Action::Close => store.procurement_close(&mut api).await.map(|_| None),
            Action::Stop { stage } => store.procurement_stop(&mut api, stage).await.map(|_| None),
            Action::Choose { vm_id } => store.procurement_choose(&mut api, vm_id).await.map(|_| None),
            Action::Delete {confirmed,..} => {
                let purchase = api.context.as_ref().ok_or(REFUSED)?.purchase.clone();
                store.vpsbg_delete_once(&mut api, &purchase, confirmed).await.map(|_| None)
            }
            Action::DeleteCheck {..} => {
                let purchase = api.context.as_ref().ok_or(REFUSED)?.purchase.clone();
                store.vpsbg_delete_check(&mut api, &purchase).await.map(|_| None)
            }
            Action::Resume { .. } if api.vendor == Vendor::Vpsbg => {
                let purchase = api.context.as_ref().ok_or(REFUSED)?.purchase.clone();
                store.vpsbg_progress(&mut api, &purchase, false).await.map(|_| None)
            }
            Action::Resume { .. } => store
                .procurement_resume(&mut api, false)
                .await
                .map(|_| None),
            Action::InitialInvoice { billing } => {
                if store.procurement_billing() != Some(&billing) {
                    return Err("The displayed initial quote is stale or missing; review the saved quote and approve it again.".into());
                }
                store.procurement_resume(&mut api, true).await.map(|_| None)
            }
        };
        if let Some(context) = &api.context { store.vpsbg_context_current(context)?; }
        if api.context.is_none() && api.vendor != store.procurement_vendor()
            && !(result.is_ok() && closing_purchase.as_deref().is_some_and(|purchase|
                store.vpsbg_closed_dispatch(api.vendor, purchase))) {
            return Err(REFUSED.into());
        }
        if observe_readiness && api.requests > 0 && api.current().is_ok() && store.procurement_readiness_eligible() && store.procurement_view()["identity"] == identity {
            let outcome = result.as_ref().map(|_| ()).map_err(Clone::clone);
            READINESS_CHECKED.with_borrow_mut(|saved| *saved = Some((identity, api.now(), api.vendor.readiness_kind(&outcome))));
        }
        if observe_readiness && result.is_ok() && api.vendor == Vendor::Vpsbg
            && let Some(context) = &api.context
        {
            let purchase = context.purchase.clone();
            if store.vpsbg_poll_admit(&purchase, crate::store::vpsbg::PollKind::Attest).is_ok() {
                let probe = store.vpsbg_prepare_attest(&mut api, &purchase).await?;
                drop(local);
                finish_attest(&api, &purchase, probe).await?;
                return Ok(None);
            }
        }
        result
    }
    .await;
    let local = crate::worker::local();
    let local = local.lock().await;
    let mut report = local.report(result.as_ref().err().map(String::as_str));
    if let Ok(Some(catalogue)) = result {
        report["provider_catalogue"] = catalogue;
    }
    local.encode_report(report)
}

/// Worker-only deposit contexts come from retained journal projections, including closed ones.
#[wasm_bindgen]
pub async fn vpsbg_poll_contexts() -> String {
    if !VISIBLE.get()
        || !VPSBG_VISIBLE.get()
        || !VPSBG_ONLINE.get()
        || crate::lifecycle::owner().ordinary().is_err()
    {
        return "[]".into();
    }
    let shared = crate::worker::local();
    let mut local = shared.lock().await;
    if local.dispatch_refusal().is_some() {
        return "[]".into();
    }
    local.store().map_or_else(
        || "[]".into(),
        |store| json!(store.vpsbg_poll_contexts()).to_string(),
    )
}

#[wasm_bindgen]
pub async fn vpsbg_poll(purchase: String, kind: String) -> String {
    let result = async {
        let _active = Active::acquire()?;
        if !VISIBLE.get()
            || !VPSBG_VISIBLE.get()
            || !VPSBG_ONLINE.get()
            || crate::poc::inference::response_pending()
        {
            return Err(REFUSED.into());
        }
        let now = monotonic_ms()?;
        if provider_action_delay() > 0 {
            return Err("Provider reads paused briefly; Refresh after one second.".into());
        }
        LAST.set(Some(now));
        let continuation = crate::lifecycle::owner().continuation()?;
        let shared = crate::worker::local();
        let mut local = shared.lock().await;
        continuation.check()?;
        if local.dispatch_refusal().is_some() {
            return Err(REFUSED.into());
        }
        let store = local.store().ok_or(REFUSED)?;
        let kind: crate::store::vpsbg::PollKind =
            serde_json::from_value(json!(kind)).map_err(|_| REFUSED)?;
        let context = store.vpsbg_poll_admit(&purchase, kind)?;
        // Resolve the addressed purchase before constructing the transport. Draft vendor is irrelevant.
        let p = store.vpsbg_purchase(&purchase).ok_or(REFUSED)?;
        let record = store
            .vpsbg_token()
            .filter(|r| r.account == p.account)
            .ok_or(REFUSED)?
            .copy();
        let mut api = Browser {
            context: Some(context),
            vendor: Vendor::Vpsbg,
            origin: vpsbg::ORIGIN.into(),
            credential: Credential::VpsbgToken(record),
            raw_response: None,
            continuation,
            automatic_visibility: Some(VISIBILITY.get()),
            vpsbg_epoch: VPSBG_EPOCH.get(),
            started: now,
            requests: 0,
            response_status: 0,
        };
        if kind == crate::store::vpsbg::PollKind::Deposit {
            store.vpsbg_poll_deposit(&mut api, &purchase).await?;
            api.current()?;
            store.vpsbg_context_current(api.context.as_ref().ok_or(REFUSED)?)
        } else if kind == crate::store::vpsbg::PollKind::Delete {
            store.vpsbg_delete_check(&mut api, &purchase).await?;
            api.current()?;
            store.vpsbg_context_current(api.context.as_ref().ok_or(REFUSED)?)
        } else {
            let probe = store.vpsbg_prepare_attest(&mut api, &purchase).await?;
            drop(local);
            finish_attest(&api, &purchase, probe).await
        }
    }
    .await;
    let shared = crate::worker::local();
    let local = shared.lock().await;
    local.encode_report(local.report(result.as_ref().err().map(String::as_str)))
}

async fn finish_attest(
    api: &Browser,
    purchase: &str,
    probe: Option<crate::harness::AttestProbe>,
) -> Result<(), String> {
    let Some(probe) = probe else { return Ok(()) };
    api.current()?;
    let key = format!("{purchase}/{}", probe.installation_binding);
    let shared = crate::worker::local();
    let deadline = {
        let mut local = shared.lock().await;
        api.current()?;
        local
            .store()
            .ok_or(REFUSED)?
            .attest_deadline(&probe.machine)
            .ok_or(REFUSED)?
    };
    let began = ATTEST_PACE.with_borrow_mut(|p| {
        p.entry(key.clone())
            .or_default()
            .begin(js_sys::Date::now() as u64, deadline)
            .is_some()
    });
    if !began {
        return Ok(());
    }
    struct PaceGuard(String);
    impl Drop for PaceGuard {
        fn drop(&mut self) {
            ATTEST_PACE.with_borrow_mut(|p| {
                if let Some(p) = p.get_mut(&self.0) {
                    p.finish();
                }
            });
        }
    }
    let _pace = PaceGuard(key);
    let stop = crate::harness::Stop::new(&probe.machine);
    let outcome =
        crate::harness::probe_attest(purchase, &probe.machine, &probe.installation_binding, &stop)
            .await;
    let shared = crate::worker::local();
    let mut local = shared.lock().await;
    api.current()?;
    let store = local.store().ok_or(REFUSED)?;
    store.vpsbg_context_current(api.context.as_ref().ok_or(REFUSED)?)?;
    store.vpsbg_probe_current(&probe)?;
    // An acceptance is durable even when the later response or disconnect was lost.
    if store.vpsbg_accepted(purchase) {
        return store.vpsbg_mark_ready(purchase, api.now()).await;
    }
    match outcome {
        Err(why) => Err(store.poc_refusal(&why.to_json())),
        Ok(()) => Err("The machine has not yet proved its identity.".into()),
    }
}

struct Pending {
    controller: web_sys::AbortController,
    stopped: Cell<bool>,
    notify: Notify,
}
impl Pending {
    fn stop(&self) {
        self.stopped.set(true);
        self.controller.abort();
        self.notify.notify_waiters();
    }
}
struct Wait {
    pending: Rc<Pending>,
    worker: web_sys::WorkerGlobalScope,
    timer: i32,
    _callback: Closure<dyn FnMut()>,
}
impl Drop for Wait {
    fn drop(&mut self) {
        self.pending.stop();
        self.worker.clear_timeout_with_handle(self.timer);
        PENDING.with_borrow_mut(|p| *p = None);
    }
}

enum Credential {
    Lnvps(Account),
    VpsbgToken(crate::store::vpsbg::TokenRecord),
}
impl Credential {
    fn account(&self) -> String {
        match self {
            Self::Lnvps(a) => a.public(),
            Self::VpsbgToken(r) => r.account.clone(),
        }
    }
    fn current(&self) -> bool {
        match self {
            Self::Lnvps(account) => {
                ACCOUNT.with_borrow(|a| a.as_ref().is_some_and(|a| a.public() == account.public()))
            }
            Self::VpsbgToken(record) => VPSBG_TOKEN.with_borrow(|a| {
                a.as_ref().is_some_and(|a| {
                    a.account == record.account && a.generation == record.generation
                })
            }),
        }
    }
}
struct Browser {
    context: Option<crate::store::vpsbg::ActionContext>,
    vendor: Vendor,
    origin: String,
    automatic_visibility: Option<u64>,
    vpsbg_epoch: u64,
    credential: Credential,
    raw_response: Option<Zeroizing<Vec<u8>>>,
    continuation: crate::lifecycle::Continuation,
    started: f64,
    requests: u8,
    response_status: u16,
}
impl Browser {
    fn remaining_ms(&self) -> Result<f64, String> {
        let elapsed = monotonic_ms()? - self.started;
        if elapsed < 0.0 {
            return Err(INCOMPLETE.into());
        }
        if elapsed >= 60000.0 {
            return Err(
                "Provider work paused at the local time bound; Refresh the saved purchase.".into(),
            );
        }
        Ok(60000.0 - elapsed)
    }
}
impl Api for Browser {
    fn vpsbg_begin_window(&mut self) -> Result<(), String> {
        self.check_vendor(Vendor::Vpsbg)?;
        self.current()?;
        self.started = monotonic_ms()?;
        self.requests = 0;
        self.response_status = 0;
        self.raw_response = None;
        Ok(())
    }
    fn vpsbg_context(&self) -> Option<&crate::store::vpsbg::ActionContext> {
        self.context.as_ref()
    }
    fn vpsbg_mutation_budget(&self) -> Result<(), String> {
        self.current()?;
        vpsbg::mutation_budget(usize::from(self.requests), self.remaining_ms()?)
    }
    fn take_vpsbg_response(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.raw_response.take()
    }
    fn check_vendor(&self, vendor: Vendor) -> Result<(), String> {
        if self.vendor != vendor {
            return Err(REFUSED.into());
        }
        Ok(())
    }
    fn response_status(&self) -> u16 {
        self.response_status
    }
    fn account(&self) -> String {
        self.credential.account()
    }
    fn now(&self) -> u64 {
        (js_sys::Date::now() / 1000.0) as u64
    }
    fn current(&self) -> Result<(), String> {
        self.continuation.check()?;
        if self.vendor == Vendor::Vpsbg
            && (!VPSBG_VISIBLE.get()
                || !VPSBG_ONLINE.get()
                || self.vpsbg_epoch != VPSBG_EPOCH.get())
        {
            return Err("VPSBG work paused while offline; only reconcile on the next wake.".into());
        }
        if self
            .automatic_visibility
            .is_some_and(|epoch| !VISIBLE.get() || VISIBILITY.get() != epoch)
        {
            return Err("Readiness reads are not running while the page is hidden.".into());
        }
        self.remaining_ms()?;
        if !self.credential.current() {
            return Err(INCOMPLETE.into());
        }
        Ok(())
    }
    async fn request(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Value>,
    ) -> Result<Value, ReadError> {
        self.current()?;
        self.response_status = 0;
        self.raw_response = None;
        self.requests += 1;
        if self.requests > 16 {
            return Err("Provider work paused at the local read bound; Refresh later.".into());
        }
        if !self
            .vendor
            .request_method_allowed(&self.origin, method, url)
        {
            return Err(REFUSED.into());
        }
        let pending = Rc::new(Pending {
            controller: web_sys::AbortController::new().map_err(|_| INCOMPLETE)?,
            stopped: Cell::new(false),
            notify: Notify::new(),
        });
        let worker: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
        let weak = Rc::downgrade(&pending);
        let callback = Closure::<dyn FnMut()>::new(move || {
            if let Some(p) = weak.upgrade() {
                p.stop();
            }
        });
        let timer = worker
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.as_ref().unchecked_ref(),
                // The same timer cancels pending headers and body reads before the
                // explicit action can consume another full exchange budget.
                self.remaining_ms()?.min(15000.0).ceil() as i32,
            )
            .map_err(|_| INCOMPLETE)?;
        PENDING.with_borrow_mut(|p| *p = Some(pending.clone()));
        let registration = Wait {
            pending: pending.clone(),
            worker: worker.clone(),
            timer,
            _callback: callback,
        };
        let cancelled = pending.notify.notified();
        let body = if self.vendor == Vendor::Vpsbg {
            body.map(crate::poc::credit::ClearedValue)
                .map(|b| Zeroizing::new(b.0.to_string()))
        } else {
            body.map(|b| Zeroizing::new(b.to_string()))
        };
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| REFUSED)?;
        let auth = match &self.credential {
            Credential::Lnvps(account) if self.vendor == Vendor::Lnvps => {
                self.vendor.authorization(
                    account,
                    url,
                    method,
                    body.as_ref().map(|b| b.as_bytes()),
                    self.now(),
                    &nonce,
                )?
            }
            Credential::VpsbgToken(record) if self.vendor == Vendor::Vpsbg => {
                vpsbg::token_text(record.token.0.as_bytes())?;
                Zeroizing::new(format!("Bearer {}", record.token.0.as_str()))
            }
            _ => return Err(REFUSED.into()),
        };
        let init = web_sys::RequestInit::new();
        init.set_method(method);
        init.set_mode(web_sys::RequestMode::Cors);
        init.set_credentials(web_sys::RequestCredentials::Omit);
        init.set_cache(web_sys::RequestCache::NoStore);
        init.set_redirect(web_sys::RequestRedirect::Error);
        init.set_signal(Some(&pending.controller.signal()));
        let headers = web_sys::Headers::new().map_err(|_| INCOMPLETE)?;
        headers
            .set("Authorization", &auth)
            .map_err(|_| INCOMPLETE)?;
        if body.is_some() {
            headers
                .set("Content-Type", "application/json")
                .map_err(|_| INCOMPLETE)?;
        }
        init.set_headers(&headers);
        if let Some(body) = &body {
            init.set_body(&JsValue::from_str(body));
        }
        let request =
            web_sys::Request::new_with_str_and_init(url, &init).map_err(|_| INCOMPLETE)?;
        let _ = headers.delete("Authorization");
        self.current()?;
        let policy = self.vendor.request_policy(method, url);
        let mutation = policy.mutation;
        let email_refusal = policy.email_refusal;
        let exchange = async {
            let response: web_sys::Response = JsFuture::from(worker.fetch_with_request(&request))
                .await
                .map_err(|_| INCOMPLETE)?
                .dyn_into()
                .map_err(|_| INCOMPLETE)?;
            self.current()?;
            let status = response.status();
            self.response_status = status;
            let refused = || {
                ReadError::from(if mutation {
                    UNKNOWN_MUTATION
                } else {
                    READ_REFUSED
                })
            };
            if self.vendor == Vendor::Vpsbg
                && !(200..300).contains(&status)
                && !matches!(status, 400 | 403)
                && !(status == 404
                    && method == "GET"
                    && url
                        .strip_prefix(vpsbg::ORIGIN)
                        .is_some_and(vpsbg::server_detail_path))
                && !(status == 422
                    && method == "POST"
                    && url == format!("{}/v1/servers", vpsbg::ORIGIN))
            {
                return Err(refused());
            }
            if self.vendor == Vendor::Vpsbg && method == "DELETE" && status == 204 {
                // Fetch exposes a null body for 204. It is only an acknowledgment.
                self.raw_response = Some(Zeroizing::new(Vec::new()));
                return Ok(Value::Null);
            }
            if self.vendor != Vendor::Vpsbg
                && (!(200..300).contains(&status)
                    && !(status == 404 && policy.missing_read && !mutation)
                    && !(status == 403 && email_refusal))
            {
                return Err(refused());
            }
            let stream = js_sys::Reflect::get(&response, &"body".into()).map_err(|_| INCOMPLETE)?;
            let reader = function(&stream, "getReader")?
                .call0(&stream)
                .map_err(|_| INCOMPLETE)?;
            let read = function(&reader, "read")?;
            let mut output = Zeroizing::new(Vec::new());
            loop {
                let promise: js_sys::Promise = read
                    .call0(&reader)
                    .map_err(|_| INCOMPLETE)?
                    .dyn_into()
                    .map_err(|_| INCOMPLETE)?;
                let chunk = JsFuture::from(promise).await.map_err(|_| INCOMPLETE)?;
                self.current()?;
                if pending.stopped.get() {
                    return Err(INCOMPLETE.into());
                }
                if js_sys::Reflect::get(&chunk, &"done".into())
                    .map_err(|_| INCOMPLETE)?
                    .as_bool()
                    == Some(true)
                {
                    break;
                }
                let bytes = js_sys::Uint8Array::new(
                    &js_sys::Reflect::get(&chunk, &"value".into()).map_err(|_| INCOMPLETE)?,
                );
                let size = bytes.length() as usize;
                if output.len().saturating_add(size) > BODY_LIMIT {
                    bytes.fill(0, 0, bytes.length());
                    return Err(if status == 404 {
                        refused()
                    } else {
                        "Provider response exceeded the local body bound.".into()
                    });
                }
                let part = Zeroizing::new(bytes.to_vec());
                output.extend_from_slice(&part);
                bytes.fill(0, 0, bytes.length());
            }
            if self.vendor == Vendor::Vpsbg {
                self.current()?;
                self.raw_response = Some(output);
                return Ok(Value::Null);
            }
            if status == 404 {
                return Err(
                    if self.vendor.decoded_missing(method, url, status, &output) {
                        ReadError::NotFound
                    } else {
                        refused()
                    },
                );
            }
            if status == 403 {
                return Err(
                    if self
                        .vendor
                        .decoded_email_required(method, url, status, &output)
                    {
                        ReadError::EmailRequired
                    } else {
                        refused()
                    },
                );
            }
            let data = self.vendor.decode_response(&output)?;
            self.current()?;
            Ok(data)
        };
        let result: Result<Value, ReadError> =
            match futures_util::future::select(Box::pin(exchange), Box::pin(cancelled)).await {
                futures_util::future::Either::Left((result, _)) => result,
                _ => Err(INCOMPLETE.into()),
            };
        drop(registration);
        result.map_err(|error| {
            if mutation && error != ReadError::EmailRequired {
                UNKNOWN_MUTATION.into()
            } else if self.response_status == 404
                && policy.missing_read
                && error != ReadError::NotFound
            {
                READ_REFUSED.into()
            } else {
                error
            }
        })
    }
}
fn monotonic_ms() -> Result<f64, String> {
    let performance =
        js_sys::Reflect::get(&js_sys::global(), &"performance".into()).map_err(|_| INCOMPLETE)?;
    function(&performance, "now")?
        .call0(&performance)
        .ok()
        .and_then(|v| v.as_f64())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .ok_or_else(|| INCOMPLETE.into())
}
fn function(value: &JsValue, name: &str) -> Result<js_sys::Function, String> {
    js_sys::Reflect::get(value, &name.into())
        .ok()
        .and_then(|v| v.dyn_into().ok())
        .ok_or_else(|| INCOMPLETE.into())
}
