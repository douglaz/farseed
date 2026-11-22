use super::*;
use crate::credential::InferenceAccountCredential;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use tokio::sync::Notify;
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;

// Preserve the old one-minute busy limit independently of the reply token cap.
const BUSY_WINDOW_MS: i32 = 60_000;

thread_local! {
    static CONFIG: RefCell<Option<Configuration>> = const { RefCell::new(None) };
    static KEY: RefCell<Option<InferenceAccountCredential>> = const { RefCell::new(None) };
    static REQUESTS: RefCell<Vec<std::rc::Weak<Pending>>> = const { RefCell::new(Vec::new()) };
    static REVISION: Cell<u64> = const { Cell::new(0) };
}

struct Pending {
    session: String,
    task: String,
    retry: Cell<Option<(u32, u32)>>,
    controller: web_sys::AbortController,
    stopped: Cell<bool>,
    ready: Notify,
}
impl Pending {
    fn stop(&self) {
        self.stopped.set(true);
        self.retry.set(None);
        self.controller.abort();
        self.ready.notify_waiters();
    }

    async fn until<T>(&self, work: impl std::future::Future<Output = T>) -> Result<T, String> {
        let ready = self.ready.notified();
        if self.stopped.get() {
            return Err(INCOMPLETE.into());
        }
        match futures_util::future::select(Box::pin(work), Box::pin(ready)).await {
            futures_util::future::Either::Left((result, _)) if !self.stopped.get() => Ok(result),
            _ => Err(INCOMPLETE.into()),
        }
    }
}

/// Add only live, in-memory wait status to the page projection.
pub(crate) fn retry_progress(report: &mut Value) {
    let Some(tasks) = report.get_mut("tasks").and_then(Value::as_array_mut) else {
        return;
    };
    REQUESTS.with_borrow(|requests| {
        for pending in requests.iter().filter_map(std::rc::Weak::upgrade) {
            if let Some((retry, limit)) = pending.retry.get()
                && !pending.stopped.get()
                && let Some(task) = tasks.iter_mut().find(|task| {
                    task["id"] == pending.task && task["start_session"] == pending.session
                })
            {
                task["inference_retry"] =
                    format!("Provider busy, retrying ({retry} of {limit}).").into();
            }
        }
    });
}

pub(crate) fn freeze() {
    crate::poc::credit::browser::freeze();
    REQUESTS.with_borrow_mut(|requests| {
        requests.retain(|pending| {
            if let Some(pending) = pending.upgrade() {
                pending.stop();
                true
            } else {
                false
            }
        });
    });
}
pub(crate) fn stop_session(session: &str) {
    crate::poc::credit::browser::stop_session(session);
    REQUESTS.with_borrow(|requests| {
        for pending in requests.iter().filter_map(std::rc::Weak::upgrade) {
            if pending.session == session {
                pending.stop();
            }
        }
    });
}
pub(crate) fn stop_task(task: &str) {
    REQUESTS.with_borrow(|requests| {
        for pending in requests.iter().filter_map(std::rc::Weak::upgrade) {
            if pending.task == task {
                pending.stop();
            }
        }
    });
}
pub(crate) fn configuration() -> Option<Configuration> {
    CONFIG.with_borrow(Clone::clone)
}
pub(crate) fn end() {
    crate::poc::credit::browser::retire();
    freeze();
    KEY.with_borrow_mut(|key| *key = None);
    CONFIG.with_borrow_mut(|config| *config = None);
    REVISION.set(REVISION.get().wrapping_add(1));
}
pub(crate) fn approval() -> Result<crate::binding::InferenceApproval, String> {
    let configuration = CONFIG.with_borrow(Clone::clone);
    #[cfg(feature = "tracer")]
    if configuration.is_none() {
        return Ok(crate::binding::InferenceApproval::synthetic());
    }
    Ok(crate::binding::InferenceApproval {
        approved: true,
        configuration: configuration.ok_or("configure inference before Start session")?,
    })
}

pub(crate) fn restore_credit(configuration: Configuration) {
    REQUESTS.with_borrow(|requests| {
        for pending in requests.iter().filter_map(std::rc::Weak::upgrade) {
            pending.stop();
        }
    });
    KEY.with_borrow_mut(|key| *key = None);
    REVISION.set(REVISION.get().wrapping_add(1));
    restore(configuration);
}
pub(crate) fn restore(configuration: Configuration) {
    CONFIG.with_borrow_mut(|current| *current = Some(configuration));
}

pub(crate) fn key_is_set() -> bool {
    KEY.with_borrow(Option::is_some) || crate::poc::credit::browser::key_present()
}
pub(crate) async fn configure(
    endpoint: String,
    model: String,
    key: Zeroizing<Vec<u8>>,
    expected_sessions: Vec<String>,
) -> Result<(), String> {
    let continuation = crate::lifecycle::owner().continuation()?;
    let local = crate::worker::local();
    let mut local = local.lock().await;
    continuation.check()?;
    if let Some(why) = local.dispatch_refusal() {
        return Err(why.into());
    }
    let store = local.store().ok_or("locked")?;
    let sessions = store.sessions();
    let mut current_sessions = sessions
        .iter()
        .filter(|session| session["session_state"] != "ended")
        .map(|session| {
            session["identity"]
                .as_str()
                .map(str::to_owned)
                .ok_or("session identity")
        })
        .collect::<Result<Vec<_>, _>>()?;
    current_sessions.sort();
    // End and Start hold this same writer. No session can change between this
    // comparison and installing the key below, even if admission waited on it.
    if current_sessions != expected_sessions {
        return Err("inference configuration refused: session changed; enter the key again".into());
    }
    if response_pending() {
        return Err(
            "inference configuration refused: command response pending; retry after it completes"
                .into(),
        );
    }
    let config = Configuration::new(endpoint, model)?;
    valid_key(&key)?;
    store.poc_configuration_ready()?;
    for session in sessions.iter().filter(|s| s["session_state"] != "ended") {
        if store
            .session_configuration(session["identity"].as_str().ok_or("session identity")?)?
            .model
            != config.model
        {
            return Err("restore the admitted inference model for this session".into());
        }
    }

    if !safe(
        store,
        &json!({"endpoint":config.endpoint,"model":config.model}),
        &[&key],
    ) {
        return Err("inference configuration contains protected material".into());
    }

    crate::poc::credit::browser::select_byo();
    freeze();
    REVISION.set(REVISION.get().wrapping_add(1));
    KEY.with_borrow_mut(|held| *held = Some(InferenceAccountCredential::new(key.to_vec())));
    CONFIG.with_borrow_mut(|held| *held = Some(config));
    Ok(())
}

pub(crate) fn held_key() -> Option<InferenceAccountCredential> {
    KEY.with_borrow(|key| {
        key.as_ref()
            .map(|key| InferenceAccountCredential::new(key.0.to_vec()))
    })
}

fn with_request_key<T>(
    session: &str,
    credit: bool,
    use_key: impl FnOnce(&[u8]) -> Result<T, String>,
) -> Result<T, String> {
    if credit {
        crate::poc::credit::browser::with_key(session, use_key)
    } else {
        KEY.with_borrow(|key| use_key(&key.as_ref().ok_or("inference key missing")?.0))
    }
}

struct Registration {
    pending: Rc<Pending>,
    worker: web_sys::WorkerGlobalScope,
    timer: i32,
    total_timer: Option<i32>,
    _callback: Closure<dyn FnMut()>,
}
impl Registration {
    async fn retry_wait(&mut self, retry: u32, limit: u32) -> Result<(), String> {
        self.worker.clear_timeout_with_handle(self.timer);
        self.pending.retry.set(Some((retry, limit)));
        let result = async {
            let (send, receive) = tokio::sync::oneshot::channel();
            let mut send = Some(send);
            let callback = Closure::<dyn FnMut()>::new(move || {
                if let Some(send) = send.take() {
                    let _ = send.send(());
                }
            });
            self.timer = self
                .worker
                .set_timeout_with_callback_and_timeout_and_arguments_0(
                    callback.as_ref().unchecked_ref(),
                    1_000 << (retry - 1),
                )
                .map_err(|_| INCOMPLETE)?;
            let result = self
                .pending
                .until(async {
                    crate::poc::web::publish_progress(&self.pending.session).await;
                    receive.await.map_err(|_| INCOMPLETE.to_string())
                })
                .await?;
            drop(callback);
            result
        }
        .await;
        self.worker.clear_timeout_with_handle(self.timer);
        self.pending.retry.set(None);
        self.pending
            .until(crate::poc::web::publish_progress(&self.pending.session))
            .await?;
        result
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.pending.stop();
        self.worker.clear_timeout_with_handle(self.timer);
        if let Some(timer) = self.total_timer {
            self.worker.clear_timeout_with_handle(timer);
        }
        REQUESTS.with_borrow_mut(|requests| {
            requests.retain(|r| r.upgrade().is_some_and(|r| !Rc::ptr_eq(&r, &self.pending)))
        });
    }
}

fn method(object: &JsValue, name: &str) -> Result<js_sys::Function, String> {
    js_sys::Reflect::get(object, &name.into())
        .ok()
        .and_then(|v| v.dyn_into().ok())
        .ok_or_else(|| INCOMPLETE.into())
}

fn monotonic_ms() -> Result<f64, String> {
    let performance =
        js_sys::Reflect::get(&js_sys::global(), &"performance".into()).map_err(|_| INCOMPLETE)?;
    method(&performance, "now")?
        .call0(&performance)
        .ok()
        .and_then(|value| value.as_f64())
        .filter(|value| value.is_finite())
        .ok_or_else(|| INCOMPLETE.into())
}

// Only absent, null or zero usage permits a retry. Inspect nested metadata too;
// unfamiliar usage values fail closed rather than risking another billed send.
fn has_usage(value: &Value, usage: bool) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(name, value)| {
            has_usage(value, usage || name == "usage" || name.ends_with("_tokens"))
        }),
        Value::Array(values) => values.iter().any(|value| has_usage(value, usage)),
        Value::Null => false,
        Value::Number(number) => usage && number.as_f64() != Some(0.0),
        Value::String(text) => usage && text.parse::<f64>().ok() != Some(0.0),
        Value::Bool(value) => usage && *value,
    }
}

async fn body(
    response: &web_sys::Response,
    pending: &Pending,
) -> Result<Zeroizing<Vec<u8>>, String> {
    // Read incrementally: response.array_buffer() would allocate an unbounded response first.
    let stream = js_sys::Reflect::get(response, &"body".into()).map_err(|_| INCOMPLETE)?;
    if stream.is_null() {
        return Ok(Zeroizing::new(Vec::new()));
    }
    let reader = method(&stream, "getReader")?
        .call0(&stream)
        .map_err(|_| INCOMPLETE)?;
    let read = method(&reader, "read")?;
    let mut output = Zeroizing::new(Vec::new());
    loop {
        if pending.stopped.get() {
            return Err(INCOMPLETE.into());
        }
        let promise: js_sys::Promise = read
            .call0(&reader)
            .map_err(|_| INCOMPLETE)?
            .dyn_into()
            .map_err(|_| INCOMPLETE)?;
        let chunk = JsFuture::from(promise).await.map_err(|_| INCOMPLETE)?;
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
        if output.len().saturating_add(bytes.length() as usize) > RESPONSE_BYTES {
            pending.controller.abort();
            return Err(RESPONSE_TOO_LARGE.into());
        }
        output.extend_from_slice(&bytes.to_vec());
        bytes.fill(0, 0, bytes.length());
    }
    Ok(output)
}

/// Keep transport loss distinct from provider, configuration and admission pauses.
/// The durable caller alone retires an interrupted Request and counts its replacement.
pub(crate) async fn next(
    task: &crate::store::poc::Task,
    session: &str,
) -> Result<ModelReply, ReplyError> {
    let revision = REVISION.get();
    let continuation = crate::lifecycle::owner().continuation()?;
    match exchange(task, session).await {
        Err(why) if why == INCOMPLETE && revision != REVISION.get() => Err(
            "inference configuration changed; review the endpoint and model before Resume".into(),
        ),
        Err(why) if why == INCOMPLETE && continuation.check().is_ok() => {
            Err(TRANSPORT_INTERRUPTED.into())
        }
        result => result,
    }
}

async fn exchange(task: &crate::store::poc::Task, session: &str) -> Result<ModelReply, ReplyError> {
    let machine = task.machine.as_str();
    let history = model_steps(task);
    let steps = history.as_slice();
    let continuation = crate::lifecycle::owner().continuation()?;
    let revision = REVISION.get();
    let config = CONFIG
        .with_borrow(Clone::clone)
        .ok_or("inference endpoint missing")?;
    let local = crate::worker::local();
    #[cfg(feature = "tracer")]
    crate::testonly::session_point("poc_inference_writer").await;
    // Allow 15 ms per requested token, with at least a minute for small replies.
    // The fixed 64,000-token cap gets sixteen minutes, including a stalled exchange.
    let deadline_ms = COMPLETION_TOKENS.saturating_mul(15).clamp(60_000, 960_000) as i32;
    // Five fast busy replies, 1+2+4+8+16 seconds of waits, then one full exchange.
    // This timer also bounds admission and progress waits across all re-sends.
    let total_deadline = monotonic_ms()? + f64::from(5 * BUSY_WINDOW_MS + 31_000 + deadline_ms);
    let retry_limit = MAX_RETRIES.saturating_sub(task.request_recoveries);
    for retries in 0..=retry_limit {
        continuation.check().map_err(|_| INCOMPLETE)?;
        if revision != REVISION.get() {
            return Err(INCOMPLETE.into());
        }
        let pending = Rc::new(Pending {
            session: session.into(),
            task: task.id.clone(),
            retry: Cell::new(None),
            controller: web_sys::AbortController::new().map_err(|_| INCOMPLETE)?,
            stopped: Cell::new(false),
            ready: Notify::new(),
        });
        let worker: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
        let weak = Rc::downgrade(&pending);
        let callback = Closure::<dyn FnMut()>::new(move || {
            if let Some(pending) = weak.upgrade() {
                pending.stop();
            }
        });
        let timer = worker
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.as_ref().unchecked_ref(),
                deadline_ms,
            )
            .map_err(|_| INCOMPLETE)?;
        let mut registration = Registration {
            pending: pending.clone(),
            worker: worker.clone(),
            timer,
            total_timer: None,
            _callback: callback,
        };
        let remaining_ms = total_deadline - monotonic_ms()?;
        if remaining_ms <= 0.0 {
            return Err(INCOMPLETE.into());
        }
        registration.total_timer = Some(
            worker
                .set_timeout_with_callback_and_timeout_and_arguments_0(
                    registration._callback.as_ref().unchecked_ref(),
                    remaining_ms.ceil() as i32,
                )
                .map_err(|_| INCOMPLETE)?,
        );
        REQUESTS.with_borrow_mut(|requests| requests.push(Rc::downgrade(&pending)));

        let (promise, is_credit, sent_at) = loop {
            if task.request_recoveries > 0 {
                pending
                    .until(crate::poc::web::wait_for_page(&continuation))
                    .await??;
            }
            let mut local = pending.until(local.lock()).await?;
            continuation.check()?;
            // Recheck under the writer: acquiring it can yield to a hide/offline
            // event. Drop it before waiting, then admit the same counted Request.
            if task.request_recoveries > 0 && !crate::poc::web::page_ready() {
                continue;
            }
            if revision != REVISION.get() {
                return Err(INCOMPLETE.into());
            }
            if let Some(why) = local.dispatch_refusal() {
                return Err(why.into());
            }
            let store = local.store().ok_or("locked")?;
            store.check_inference_request(task, session)?;
            store.check_inference_request(task, session)?;
            continuation.check()?;
            if revision != REVISION.get() || pending.stopped.get() {
                return Err(INCOMPLETE.into());
            }
            break with_request_key(session, store.credit_session(session), |key| {
                let body = request_for_task(store, &config, task, &[key])?;
                let init = web_sys::RequestInit::new();
                init.set_method("POST");
                init.set_signal(Some(&pending.controller.signal()));
                init.set_mode(web_sys::RequestMode::Cors);
                init.set_credentials(web_sys::RequestCredentials::Omit);
                init.set_cache(web_sys::RequestCache::NoStore);
                init.set_redirect(web_sys::RequestRedirect::Error);
                let headers = web_sys::Headers::new().map_err(|_| INCOMPLETE)?;
                headers
                    .set("Content-Type", "application/json")
                    .map_err(|_| INCOMPLETE)?;
                let authorization = Zeroizing::new(format!(
                    "Bearer {}",
                    std::str::from_utf8(key).map_err(|_| "inference key invalid")?
                ));
                headers
                    .set("Authorization", &authorization)
                    .map_err(|_| INCOMPLETE)?;
                init.set_headers(&headers);
                let body = js_sys::Uint8Array::from(body.as_slice());
                init.set_body(&body);
                let request = web_sys::Request::new_with_str_and_init(&config.endpoint, &init)
                    .map_err(|_| INCOMPLETE)?;
                body.fill(0, 0, body.length());
                let _ = headers.delete("Authorization");
                continuation.check()?;
                store.check_inference_request(task, session)?;
                let sent_at = monotonic_ms()?;
                if sent_at >= total_deadline {
                    return Err(INCOMPLETE.into());
                }
                Ok::<_, String>((
                    worker.fetch_with_request(&request),
                    store.credit_session(session),
                    sent_at,
                ))
            })?;
        };

        let ready = pending.ready.notified();
        let received_status = Cell::new(None);
        let exchange = async {
            let response: web_sys::Response = JsFuture::from(promise)
                .await
                .map_err(|_| INCOMPLETE)?
                .dyn_into()
                .map_err(|_| INCOMPLETE)?;
            continuation.check().map_err(|_| INCOMPLETE)?;
            if revision != REVISION.get() || pending.stopped.get() {
                return Err(INCOMPLETE.into());
            }
            let status = response.status();
            received_status.set(Some(status));
            if status == 0 {
                return Err(INCOMPLETE.into());
            }
            // Authentication refusal is established by the status, even if its body never ends.
            let bytes = if matches!(status, 401 | 403) && !is_credit {
                Zeroizing::new(Vec::new())
            } else {
                match body(&response, &pending).await {
                    Ok(body) => body,
                    Err(_) if !(200..300).contains(&status) => {
                        return Err(if is_credit && matches!(status, 401 | 402 | 403 | 429) {
                            crate::poc::credit::REFUSED.into()
                        } else {
                            http_failure(status)
                        }
                        .into());
                    }
                    Err(why) => return Err(why.into()),
                }
            };
            if is_credit && !(200..300).contains(&status) {
                return Err(if matches!(status, 401 | 402 | 403 | 429) {
                    crate::poc::credit::browser::refusal(status, &bytes, session).await
                } else {
                    http_failure(status)
                }
                .into());
            }
            // Bound the response read; classification and checks of consumed fields happen
            // in the shared completion path. No complete response is retained in task facts.
            let bytes = if let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) {
                if !(200..300).contains(&status)
                    && let Some(object) = value.as_object_mut()
                {
                    object.retain(|name, _| name == "error");
                }
                Zeroizing::new(
                    serde_json::to_vec(&value).map_err(|_| "inference response encoding")?,
                )
            } else if (200..300).contains(&status) {
                return Err("inference response malformed JSON".into());
            } else {
                Zeroizing::new(Vec::new())
            };
            continuation.check().map_err(|_| INCOMPLETE)?;
            if revision != REVISION.get() || pending.stopped.get() {
                return Err(INCOMPLETE.into());
            }
            let mut local = pending.until(local.lock()).await?;
            continuation.check().map_err(|_| INCOMPLETE)?;
            if revision != REVISION.get() || pending.stopped.get() {
                return Err(INCOMPLETE.into());
            }
            if local.dispatch_refusal().is_some() {
                return Err(INCOMPLETE.into());
            }
            let store = local.store().ok_or(INCOMPLETE)?;
            store.check_inference_request(task, session)?;
            let reply_at = monotonic_ms()?;
            if reply_at >= total_deadline {
                return Err(INCOMPLETE.into());
            }
            with_request_key(session, is_credit, |key| {
                if retries < retry_limit
                    && (0.0..=f64::from(BUSY_WINDOW_MS)).contains(&(reply_at - sent_at))
                    && (200..300).contains(&status)
                    && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                    && value.is_object()
                    && value.get("choices").and_then(Value::as_array).is_none()
                    && value.get("error").is_some_and(Value::is_object)
                    && value.pointer("/error/code").and_then(Value::as_f64) == Some(502.0)
                    && value
                        .pointer("/error/metadata/error_type")
                        .and_then(Value::as_str)
                        == Some("provider_unavailable")
                    && !has_usage(&value, false)
                {
                    if !safe(
                        store,
                        &json!({
                            "code":value.pointer("/error/code"),
                            "error_type":value.pointer("/error/metadata/error_type"),
                        }),
                        &[key],
                    ) {
                        return Ok(Err("inference proposal contains protected material".into()));
                    }
                    return Ok(Ok(None));
                }
                Ok(complete_response_context(
                    store,
                    status,
                    &bytes,
                    machine,
                    steps,
                    &[key],
                    Some(task),
                )
                .map(Some))
            })?
        };
        let result = match futures_util::future::select(Box::pin(exchange), Box::pin(ready)).await {
            futures_util::future::Either::Left((result, _)) => result,
            futures_util::future::Either::Right(_) => Err(INCOMPLETE.into()),
        };
        if matches!(result, Ok(None)) {
            registration.retry_wait(retries + 1, retry_limit).await?;
            continuation.check().map_err(|_| INCOMPLETE)?;
            if revision != REVISION.get() || pending.stopped.get() {
                return Err(INCOMPLETE.into());
            }
            continue;
        }
        drop(registration);
        return match result {
            Err(why)
                if why == INCOMPLETE
                    && received_status
                        .get()
                        .is_some_and(|status| status != 0 && !(200..300).contains(&status)) =>
            {
                Err(if is_credit
                    && received_status
                        .get()
                        .is_some_and(|s| matches!(s, 401 | 402 | 403 | 429))
                {
                    crate::poc::credit::REFUSED.into()
                } else {
                    http_failure(received_status.get().expect("known status"))
                }
                .into())
            }
            Ok(Some(reply)) => Ok(reply),
            Ok(None) => unreachable!("busy reply handled before completion"),
            Err(why) => Err(why),
        };
    }
    unreachable!("last busy reply completes normally")
}
