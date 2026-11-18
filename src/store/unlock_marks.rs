//! Ephemeral unlock measurements. Inputs are fixed marks, counts and byte sizes only.
//! No journal/credential value, identifier, text or digest belongs in this module.

macro_rules! marks {
    ($name:ident, $($variant:ident => $field:literal),+ $(,)?) => {
        #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code, reason = "browser-only marks compile to no-ops on the host"))]
        #[derive(Clone, Copy)]
        pub(crate) enum $name { $($variant,)+ End }
        #[cfg(any(target_arch = "wasm32", feature = "history-bench"))]
        impl $name {
            const NAMES: &[&str] = &[$($field,)+];
        }
    };
}
marks!(Mark,
    Kdf => "kdf_ms", Envelope => "envelope_ms", List => "list_ms", Read => "read_ms",
    Hash => "hash_ms", Decrypt => "decrypt_ms", Parse => "parse_ms", Apply => "apply_ms",
    RecordCheck => "record_check_ms", HeldCredentials => "held_credentials_ms",
    TaskCopy => "task_copy_ms", DispatchCopy => "dispatch_copy_ms", Restore => "restore_ms",
    AfterReplay => "after_replay_ms", UnlockReportBuild => "unlock_report_build_ms",
    UnlockReportProtect => "unlock_report_protect_ms", UnlockSerialize => "unlock_serialize_ms",
    PublishIncomingProtect => "publish_incoming_protect_ms", PublishBuild => "publish_build_ms",
    PublishProtect => "publish_protect_ms", PublishSerialize => "publish_serialize_ms",
    PublishCheck => "publish_check_ms", PublishPost => "publish_post_ms", Total => "total_ms",
);
marks!(Counter,
    Records => "records", RecordBytes => "record_bytes", RecordChecks => "record_checks",
    HeldCredentials => "held_credentials", DerivedKeys => "derived_keys",
    TaskCopies => "task_copies", TaskCopySteps => "task_copy_steps",
    DispatchCopies => "dispatch_copies", DispatchCopyEntries => "dispatch_copy_entries",
    UnlockReportBytes => "unlock_report_bytes", PublishBytes => "publish_bytes",
);

pub(crate) struct Timer {
    #[cfg(any(target_arch = "wasm32", feature = "history-bench"))]
    started: Option<(f64, u64, Mark)>,
}
impl Timer {
    #[inline]
    pub(crate) fn new(mark: Mark) -> Self {
        #[cfg(any(target_arch = "wasm32", feature = "history-bench"))]
        return Self {
            started: browser::start(mark),
        };
        #[cfg(not(any(target_arch = "wasm32", feature = "history-bench")))]
        {
            let _ = mark;
            Self {}
        }
    }
    #[inline]
    pub(crate) fn count(&self, counter: Counter, value: u64) {
        #[cfg(any(target_arch = "wasm32", feature = "history-bench"))]
        if let Some((_, generation, _)) = self.started {
            browser::count(generation, counter, value);
        }
        #[cfg(not(any(target_arch = "wasm32", feature = "history-bench")))]
        let _ = (counter, value);
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        #[cfg(any(target_arch = "wasm32", feature = "history-bench"))]
        if let Some((started, generation, mark)) = self.started {
            browser::stop(started, generation, mark);
        }
    }
}
pub(crate) fn measure<T>(mark: Mark, action: impl FnOnce() -> T) -> T {
    let _timer = Timer::new(mark);
    action()
}

/// Also records the return time on every refused-unlock path.
pub(crate) struct UnlockEnd;
impl Drop for UnlockEnd {
    fn drop(&mut self) {
        #[cfg(any(target_arch = "wasm32", feature = "history-bench"))]
        browser::unlock_end();
    }
}
pub(crate) fn begin() -> UnlockEnd {
    #[cfg(any(target_arch = "wasm32", feature = "history-bench"))]
    browser::begin();
    UnlockEnd
}
pub(crate) fn after_replay() {
    #[cfg(any(target_arch = "wasm32", feature = "history-bench"))]
    browser::after_replay();
}

#[cfg(target_arch = "wasm32")]
pub(crate) use browser::{post_worker, published};

#[cfg(all(feature = "history-bench", not(target_arch = "wasm32")))]
pub(super) use browser::snapshot;

#[cfg(any(target_arch = "wasm32", feature = "history-bench"))]
mod browser {
    use super::{Counter, Mark};
    use std::cell::{Cell, RefCell};
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen::JsCast;

    #[cfg(target_arch = "wasm32")]
    struct Clock {
        receiver: wasm_bindgen::JsValue,
        now: js_sys::Function,
    }
    #[cfg(target_arch = "wasm32")]
    impl Clock {
        fn load() -> Option<Self> {
            let receiver = js_sys::Reflect::get(&js_sys::global(), &"performance".into()).ok()?;
            let now = js_sys::Reflect::get(&receiver, &"now".into())
                .ok()?
                .dyn_into()
                .ok()?;
            Some(Self { receiver, now })
        }
        fn read(&self) -> Option<f64> {
            self.now
                .call0(&self.receiver)
                .ok()?
                .as_f64()
                .filter(|n| n.is_finite())
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    struct Clock(std::time::Instant);
    #[cfg(not(target_arch = "wasm32"))]
    impl Clock {
        fn load() -> Option<Self> {
            Some(Self(std::time::Instant::now()))
        }
        fn read(&self) -> Option<f64> {
            Some(self.0.elapsed().as_secs_f64() * 1000.0)
        }
    }
    struct Marks {
        active: Cell<bool>,
        generation: Cell<u64>,
        opened: Cell<f64>,
        returned: Cell<Option<f64>>,
        durations: [Cell<f64>; Mark::End as usize],
        counts: [Cell<u64>; Counter::End as usize],
        clock: RefCell<Option<Option<Clock>>>,
    }
    impl Default for Marks {
        fn default() -> Self {
            Self {
                active: Cell::new(false),
                generation: Cell::new(0),
                opened: Cell::new(0.0),
                returned: Cell::new(None),
                durations: std::array::from_fn(|_| Cell::new(0.0)),
                counts: std::array::from_fn(|_| Cell::new(0)),
                clock: RefCell::new(None),
            }
        }
    }
    thread_local! { static MARKS: Marks = Marks::default(); }
    impl Marks {
        fn now(&self) -> Option<f64> {
            let clock = self.clock.try_borrow().ok()?;
            clock.as_ref()?.as_ref()?.read()
        }
        fn add(&self, mark: Mark, started: f64, ended: f64) {
            let elapsed = ended - started;
            if elapsed.is_finite() && elapsed >= 0.0 {
                let cell = &self.durations[mark as usize];
                cell.set(cell.get() + elapsed);
            }
        }
    }
    pub(super) fn begin() {
        MARKS.with(|marks| {
            marks.active.set(false);
            if let Ok(mut clock) = marks.clock.try_borrow_mut()
                && clock.is_none()
            {
                *clock = Some(Clock::load());
            }
            let Some(now) = marks.now() else { return };
            for cell in &marks.durations {
                cell.set(0.0);
            }
            for cell in &marks.counts {
                cell.set(0);
            }
            marks.generation.set(marks.generation.get().wrapping_add(1));
            marks.opened.set(now);
            marks.returned.set(None);
            marks.active.set(true);
        });
    }
    pub(super) fn start(mark: Mark) -> Option<(f64, u64, Mark)> {
        MARKS.with(|marks| {
            if !marks.active.get() {
                return None;
            }
            Some((marks.now()?, marks.generation.get(), mark))
        })
    }
    pub(super) fn stop(started: f64, generation: u64, mark: Mark) {
        MARKS.with(|marks| {
            if marks.active.get()
                && generation == marks.generation.get()
                && let Some(now) = marks.now()
            {
                marks.add(mark, started, now);
            }
        });
    }
    pub(super) fn count(generation: u64, counter: Counter, value: u64) {
        MARKS.with(|marks| {
            if marks.active.get() && generation == marks.generation.get() {
                let cell = &marks.counts[counter as usize];
                cell.set(cell.get().saturating_add(value));
            }
        });
    }
    pub(super) fn unlock_end() {
        MARKS.with(|marks| {
            if marks.active.get() {
                marks.returned.set(marks.now());
            }
        });
    }
    pub(super) fn after_replay() {
        MARKS.with(|marks| {
            if marks.active.get()
                && let Some(started) = marks.returned.take()
                && let Some(now) = marks.now()
            {
                marks.add(Mark::AfterReplay, started, now);
            }
        });
    }
    #[cfg(target_arch = "wasm32")]
    fn post<S: super::super::Storage>(
        store: Option<&super::super::Store<S>>,
        value: serde_json::Value,
    ) {
        let encoded = value.to_string();
        if let Some(store) = store
            && store.check_output_bytes(encoded.as_bytes()).is_err()
        {
            return;
        }
        if let Ok(message) = js_sys::JSON::parse(&encoded) {
            let worker: web_sys::DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
            let _ = worker.post_message(&message);
        }
    }
    /// Called only after a store post succeeds; a refused post leaves the window open.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn published<S: super::super::Storage>(store: Option<&super::super::Store<S>>) {
        let value = MARKS.with(|marks| {
            if !marks.active.get() {
                return None;
            }
            if let Some(now) = marks.now() {
                marks.add(Mark::Total, marks.opened.get(), now);
            }
            marks.active.set(false);
            let mut fields = serde_json::Map::new();
            for (name, cell) in Mark::NAMES.iter().zip(&marks.durations) {
                fields.insert((*name).into(), serde_json::json!(cell.get().round() as u64));
            }
            for (name, cell) in Counter::NAMES.iter().zip(&marks.counts) {
                fields.insert((*name).into(), cell.get().into());
            }
            Some(serde_json::json!({"unlock_timings": fields}))
        });
        if let Some(value) = value {
            post(store, value);
        }
    }
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn post_worker<S: super::super::Storage>(
        store: Option<&super::super::Store<S>>,
        call_ms: f64,
        json_ms: f64,
    ) {
        if call_ms.is_finite() && json_ms.is_finite() && call_ms >= 0.0 && json_ms >= 0.0 {
            post(
                store,
                serde_json::json!({"unlock_worker_timings": {
                    "unlock_call_ms": call_ms.round() as u64, "worker_json_ms": json_ms.round() as u64,
                }}),
            );
        }
    }

    /// Native benchmark boundary corresponding to a successful first publication. Keep
    /// sub-millisecond resolution for medians; the browser's rounded encoding is unchanged.
    #[cfg(not(target_arch = "wasm32"))]
    pub(in crate::store) fn snapshot() -> std::collections::BTreeMap<&'static str, f64> {
        MARKS.with(|marks| {
            if marks.active.get()
                && let Some(now) = marks.now()
            {
                marks.add(Mark::Total, marks.opened.get(), now);
            }
            marks.active.set(false);
            Mark::NAMES
                .iter()
                .zip(&marks.durations)
                .map(|(name, cell)| (*name, cell.get()))
                .chain(
                    Counter::NAMES
                        .iter()
                        .zip(&marks.counts)
                        .map(|(name, cell)| (*name, cell.get() as f64)),
                )
                .collect()
        })
    }
}
