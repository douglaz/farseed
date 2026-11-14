//! Actual browser fetch of the exact absolute URL supplied by Purchase authority.
use super::*;
use crate::poc::inference::EchoFilter;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use tokio::sync::Notify;
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroize;

const UNKNOWN_MUTATION: &str = "Provider mutation outcome unknown or browser access unavailable; the saved intent is retained. Use read-only Refresh/Resume to reconcile or remain paused; never retry the mutation.";

thread_local! {
    static ACCOUNT: RefCell<Option<Account>> = const {RefCell::new(None)};
    static ACTIVE: Cell<bool> = const {Cell::new(false)};
    static PENDING: RefCell<Option<Rc<Pending>>> = const {RefCell::new(None)};
    static READINESS_CHECKED: RefCell<Option<(Value, u64, &'static str)>> = const {RefCell::new(None)};
    static VISIBLE: Cell<bool> = const {Cell::new(true)};
    static VISIBILITY: Cell<u64> = const {Cell::new(0)};
    static LAST: Cell<Option<f64>> = const {Cell::new(None)};
    #[cfg(feature="tracer")]
    static TEST_ORIGIN: RefCell<Option<String>> = const {RefCell::new(None)};
}
pub(crate) fn freeze() {
    PENDING.with_borrow(|p| {
        if let Some(p) = p {
            p.stop();
        }
    });
}
pub(crate) fn end() {
    freeze();
    ACCOUNT.with_borrow_mut(|a| *a = None);
}
pub(crate) fn restore(account: Option<&Account>) {
    ACCOUNT.with_borrow_mut(|a| *a = account.map(Account::copy));
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

fn readiness_kind(result: &Result<(), String>) -> &'static str {
    match result {
        Ok(()) => "ready",
        Err(why) if why.starts_with("Waiting for provider boot readiness") => "starting",
        Err(why) if why.starts_with("Waiting for an unambiguous supported published host key") => {
            "published_key"
        }
        Err(why) if why == "Waiting for one allocated IPv4 address." => "address",
        Err(_) => "refused",
    }
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

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Catalogue,
    Select {
        choice: crate::store::provisioning::Choice,
    },
    Approve {
        approval: crate::store::provisioning::Approval,
        selection: Selection,
    },
    Resume,
    PaymentCheck,
    ReadinessCheck,
    Close,
    InitialInvoice {
        billing: crate::store::provisioning::Billing,
    },
}

#[wasm_bindgen]
pub async fn provider_request(request: String) -> String {
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
        let automatic = matches!(action, Action::ReadinessCheck);
        if automatic && (!VISIBLE.get() || !key_is_set() || !store.procurement_readiness_eligible()) {
            return Ok(None);
        }
        if !automatic { store.provider_generate().await?; }
        continuation.check()?;
        restore(store.provider_account());
        let mut api = Browser {
            account: store.provider_account().ok_or("Provider account unavailable.")?.copy(),
            continuation,
            filter: None,
            prepared: None,
            automatic_visibility: automatic.then(|| VISIBILITY.get()),
            started: now,
            requests: 0,
            response_status: 0,
        };
        api.current()?;
        let observe_readiness = matches!(action, Action::ReadinessCheck | Action::Resume | Action::InitialInvoice { .. });
        let identity = store.procurement_view()["identity"].clone();
        let result = match action {
            Action::Catalogue => store.procurement_catalogue(&mut api).await.map(Some),
            Action::Select { choice } => store
                .procurement_select(&mut api, choice)
                .await
                .map(|_| None),
            Action::Approve { approval, selection } => {
                if !store.procurement_review_selection().is_some_and(|current| current.same_terms(&selection)) {
                    return Err("The displayed configuration is stale or missing; review the current selection and approve it again.".into());
                }
                store.procurement_approve(&mut api, approval).await.map(|_| None)
            }
            Action::ReadinessCheck => store.procurement_readiness_check(&mut api).await.map(|_| None),
            Action::PaymentCheck => store.procurement_payment_check(&mut api).await.map(|_| None),
            Action::Close => store.procurement_close(&mut api).await.map(|_| None),
            Action::Resume => store
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
        if observe_readiness && api.requests > 0 && api.current().is_ok() && store.procurement_readiness_eligible() && store.procurement_view()["identity"] == identity {
            let outcome = result.as_ref().map(|_| ()).map_err(Clone::clone);
            READINESS_CHECKED.with_borrow_mut(|saved| *saved = Some((identity, api.now(), readiness_kind(&outcome))));
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
    report.to_string()
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
struct Prepared {
    url: String,
    method: String,
    body: Option<Zeroizing<String>>,
    auth: Zeroizing<String>,
}
struct Browser {
    automatic_visibility: Option<u64>,
    account: Account,
    continuation: crate::lifecycle::Continuation,
    filter: Option<EchoFilter>,
    prepared: Option<Prepared>,
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
    fn response_status(&self) -> u16 {
        self.response_status
    }
    fn prepare(
        &mut self,
        method: &str,
        url: &str,
        body: Option<&Value>,
    ) -> Result<Option<crate::poc::inference::EchoFingerprints>, String> {
        self.current()?;
        if self.prepared.is_some() || !matches!(method, "GET" | "POST") {
            return Err(REFUSED.into());
        }
        let url = url.to_string();
        let body = body.map(|b| Zeroizing::new(b.to_string()));
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| REFUSED)?;
        let auth = self.account.authorization(
            &url,
            method,
            body.as_ref().map(|b| b.as_bytes()),
            self.now(),
            &nonce,
        )?;
        let filter = request_filter(&auth)?;
        let fingerprints = filter.fingerprints();
        self.filter = Some(filter);
        self.prepared = Some(Prepared {
            url,
            method: method.into(),
            body,
            auth,
        });
        Ok(Some(fingerprints))
    }
    fn account(&self) -> String {
        self.account.public()
    }
    fn now(&self) -> u64 {
        (js_sys::Date::now() / 1000.0) as u64
    }
    fn current(&self) -> Result<(), String> {
        self.continuation.check()?;
        if self
            .automatic_visibility
            .is_some_and(|epoch| !VISIBLE.get() || VISIBILITY.get() != epoch)
        {
            return Err("Readiness reads are not running while the page is hidden.".into());
        }
        self.remaining_ms()?;
        if ACCOUNT.with_borrow(|a| {
            a.as_ref()
                .is_none_or(|a| a.public() != self.account.public())
        }) {
            return Err(INCOMPLETE.into());
        }
        Ok(())
    }
    fn take_filter(&mut self) -> Option<EchoFilter> {
        self.filter.take()
    }
    async fn request(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Value>,
    ) -> Result<Value, ReadError> {
        self.current()?;
        self.response_status = 0;
        self.requests += 1;
        if self.requests > 16 {
            return Err("Provider work paused at the local read bound; Refresh later.".into());
        }
        if !matches!(method, "GET" | "POST") {
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
        let Prepared {
            url: prepared_url,
            method: prepared_method,
            body: prepared_body,
            auth,
        } = self.prepared.take().ok_or(REFUSED)?;
        if prepared_url != url
            || prepared_method != method
            || prepared_body.as_deref().map(String::as_str)
                != body.as_ref().map(Value::to_string).as_deref()
        {
            return Err(REFUSED.into());
        }
        let body = prepared_body;
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
        let mutation = method == "POST" && !url.ends_with("/api/v1/vm/custom-template/price")
            || url.contains("/renew?");
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
            if !(200..300).contains(&status)
                && !(status == 404 && missing_read(method, url) && !mutation)
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
                output.extend_from_slice(&bytes.to_vec());
                bytes.fill(0, 0, bytes.length());
            }
            if status == 404 {
                return Err(if decoded_missing(method, url, status, &output) {
                    ReadError::NotFound
                } else {
                    refused()
                });
            }
            let value: Value = serde_json::from_slice(&output).map_err(|_| REFUSED)?;
            let data = value.get("data").ok_or(REFUSED)?.clone();
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
            if mutation {
                UNKNOWN_MUTATION.into()
            } else if self.response_status == 404
                && missing_read(method, url)
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
