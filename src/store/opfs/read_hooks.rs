//! Mechanism-only browser controls, compiled out unless read-hooks is explicitly enabled.
//! Exports operate in the wasm worker; a fixture driver can call them while unlock is pending.

use super::{OUTSTANDING, READ_CAP, READ_WINDOW, Shared, register, wake};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::future::poll_fn;
use std::rc::{Rc, Weak};
use std::task::{Poll, Waker};
use wasm_bindgen::prelude::*;

const STAGES: &[&str] = &[
    "root",
    "directory",
    "file-handle",
    "file",
    "file-ready",
    "admission",
    "array-buffer",
    "array-buffer-ready",
    "copy",
    "fallback-root",
    "fallback-directory",
    "fallback-file-handle",
    "fallback-file",
];

#[derive(Default)]
struct Hooks {
    active: Weak<Shared>,
    holds: BTreeSet<(u64, String)>,
    waiters: Vec<Waker>,
    events: Vec<Value>,
    peak_reserved: u64,
    reserved: u64,
    retained: BTreeMap<u64, u64>,
    peak_retained: u64,
    peak_outstanding: usize,
    reads_issued: Vec<u64>,
    open_order: Vec<u64>,
    apply_order: Vec<u64>,
}

thread_local! {
    static HOOKS: RefCell<Hooks> = RefCell::default();
}

pub(super) fn reader(shared: &Rc<Shared>) {
    HOOKS.with_borrow_mut(|hooks| {
        hooks.active = Rc::downgrade(shared);
        hooks
            .events
            .push(json!({"event":"reader", "outstanding":count()}));
    });
}

fn count() -> usize {
    OUTSTANDING.with_borrow(|outstanding| outstanding.count)
}

pub(super) fn outstanding() {
    HOOKS.with_borrow_mut(|hooks| {
        let count = count();
        hooks.peak_outstanding = hooks.peak_outstanding.max(count);
        hooks
            .events
            .push(json!({"event":"outstanding", "count":count}));
    });
}

pub(super) fn event(event: &str, number: Option<u64>) {
    HOOKS.with_borrow_mut(|hooks| {
        if event == "issued" {
            hooks
                .reads_issued
                .push(number.expect("issued has a record number"));
        }
        hooks.events.push(json!({"event":event,"number":number}));
    });
}

pub(crate) fn order(stage: &str, number: u64) {
    HOOKS.with_borrow_mut(|hooks| {
        match stage {
            "open" => hooks.open_order.push(number),
            "apply" => hooks.apply_order.push(number),
            _ => unreachable!("fixed replay observation"),
        }
        hooks.events.push(json!({"event":stage,"number":number}));
    });
}

pub(super) async fn gate(shared: &Shared, number: u64, stage: &str) -> bool {
    let mut observed = false;
    poll_fn(|cx| {
        if shared.abandoned() {
            return Poll::Ready(false);
        }
        let held = HOOKS.with_borrow_mut(|hooks| {
            if !hooks.holds.contains(&(number, stage.into())) {
                return false;
            }
            if !observed {
                hooks
                    .events
                    .push(json!({"event":"held","number":number,"stage":stage}));
                observed = true;
            }
            register(&mut hooks.waiters, cx.waker());
            true
        });
        if held {
            // Abandonment also wakes hook waiters, without requiring a test-side release.
            register(&mut shared.0.borrow_mut().waiters, cx.waker());
            Poll::Pending
        } else {
            Poll::Ready(true)
        }
    })
    .await
}

pub(super) fn started(shared: &Shared, number: u64, stage: &str) {
    HOOKS.with_borrow_mut(|hooks| {
        let abandoned = shared.abandoned();
        hooks
            .events
            .push(json!({"event":"stage","number":number,"stage":stage,"abandoned":abandoned}));
    });
}

pub(super) fn settled(shared: &Shared, number: u64, stage: &str) {
    HOOKS.with_borrow_mut(|hooks| {
        hooks.events.push(
            json!({"event":"settled","number":number,"stage":stage,"abandoned":shared.abandoned()}),
        );
    });
}

pub(super) fn reserved(bytes: u64, oldest: u64, number: u64, size: u64) {
    HOOKS.with_borrow_mut(|hooks| {
        hooks.reserved = bytes;
        hooks.peak_reserved = hooks.peak_reserved.max(bytes);
        hooks.events.push(
            json!({"event":"reserved","bytes":bytes,"number":number,"size":size,"oldest":oldest}),
        );
    });
}

pub(super) fn released(bytes: u64) {
    HOOKS.with_borrow_mut(|hooks| {
        hooks.reserved = bytes;
        hooks.events.push(json!({"event":"released","bytes":bytes}));
    });
}

/// Independent of Reservation: lifetime begins immediately before arrayBuffer(), and ends
/// only when its pending/result buffer is dropped or copied. No admission value is read.
pub(super) struct Retained(u64);

impl Retained {
    pub(super) fn new(shared: &Shared, number: u64, size: u64) -> Self {
        HOOKS.with_borrow_mut(|hooks| {
            hooks.retained.insert(number, size);
            let bytes: u64 = hooks.retained.values().sum();
            hooks.peak_retained = hooks.peak_retained.max(bytes);
            hooks.events.push(json!({"event":"retained","bytes":bytes,"buffers":hooks.retained,"oldest":shared.0.borrow().oldest}));
        });
        Self(number)
    }
}

impl Drop for Retained {
    fn drop(&mut self) {
        HOOKS.with_borrow_mut(|hooks| {
            hooks.retained.remove(&self.0);
            let bytes: u64 = hooks.retained.values().sum();
            hooks
                .events
                .push(json!({"event":"buffer-released","number":self.0,"bytes":bytes}));
        });
    }
}

/// Reset observations between fixtures only after all previous tasks and buffers drain.
#[wasm_bindgen]
pub fn read_hooks_reset() -> Result<(), JsValue> {
    if count() != 0 {
        return Err("read hooks: outstanding reads".into());
    }
    HOOKS.with_borrow_mut(|hooks| {
        if hooks
            .active
            .upgrade()
            .is_some_and(|shared| !shared.abandoned())
            || hooks.reserved != 0
            || !hooks.retained.is_empty()
        {
            return Err("read hooks: active reader".into());
        }
        let waiters = std::mem::take(&mut hooks.waiters);
        *hooks = Hooks::default();
        wake(waiters);
        Ok(())
    })
}

/// Numbers are decimal strings (no JS precision loss); stages are fixed names in snapshot.
#[wasm_bindgen]
pub fn read_hooks_hold(number: String, stage: String) -> Result<(), JsValue> {
    let number = number
        .parse::<u64>()
        .map_err(|_| JsValue::from_str("read hooks: number"))?;
    if !STAGES.contains(&stage.as_str()) {
        return Err("read hooks: stage".into());
    }
    HOOKS.with_borrow_mut(|hooks| {
        hooks.holds.insert((number, stage));
    });
    Ok(())
}

#[wasm_bindgen]
pub fn read_hooks_release(number: String, stage: String) -> Result<(), JsValue> {
    let number = number
        .parse::<u64>()
        .map_err(|_| JsValue::from_str("read hooks: number"))?;
    let waiters = HOOKS.with_borrow_mut(|hooks| {
        hooks.holds.remove(&(number, stage));
        std::mem::take(&mut hooks.waiters)
    });
    wake(waiters);
    Ok(())
}

#[wasm_bindgen]
pub fn read_hooks_release_all() {
    let waiters = HOOKS.with_borrow_mut(|hooks| {
        hooks.holds.clear();
        std::mem::take(&mut hooks.waiters)
    });
    wake(waiters);
}

/// Exercise abandonment while the exported unlock future is still pending.
#[wasm_bindgen]
pub fn read_hooks_abandon() {
    let shared = HOOKS.with_borrow(|hooks| hooks.active.upgrade());
    if let Some(shared) = shared {
        shared.abandon();
    }
}

#[wasm_bindgen]
pub fn read_hooks_note(label: String) {
    HOOKS.with_borrow_mut(|hooks| {
        hooks
            .events
            .push(json!({"event":"browser-call","label":label}));
    });
}

#[wasm_bindgen]
pub fn read_hooks_snapshot() -> String {
    HOOKS.with_borrow(|hooks| {
        json!({
            "window":READ_WINDOW, "cap_bytes":READ_CAP, "stages":STAGES,
            "reserved_bytes":hooks.reserved, "peak_reserved_bytes":hooks.peak_reserved,
            "retained_js_buffer_bytes":hooks.retained.values().sum::<u64>(),
            "peak_retained_js_buffer_bytes":hooks.peak_retained, "retained_buffers":hooks.retained,
            "outstanding":count(), "peak_outstanding":hooks.peak_outstanding,
            "reads_issued":hooks.reads_issued, "open_order":hooks.open_order,
            "apply_order":hooks.apply_order, "events":hooks.events,
        })
        .to_string()
    })
}
