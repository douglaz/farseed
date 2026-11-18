//! Optional worker-local measurements. Only the page report reads these; never the journal.
use crate::store::poc::{Change, Record, Task};
use serde::Serialize;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use wasm_bindgen::JsCast;

#[derive(Default, Serialize)]
struct Cycle {
    number: u64,
    kind: &'static str,
    websocket_open_ms: Vec<u64>,
    relay_verdict_ms: Vec<u64>,
    ssh_handshake_ms: Vec<u64>,
    login_ms: Vec<u64>,
    job_launch_ms: Vec<u64>,
    job_observation_ms: Vec<u64>,
    collect_ms: Vec<u64>,
    journal: Vec<Commit>,
    progress_count: u64,
    progress_ms: u64,
    publish_build_ms: u64,
    publish_protect_ms: u64,
    publish_serialize_ms: u64,
    publish_post_ms: u64,
    publish_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after_settle_ms: Option<u64>,
}
#[derive(Serialize)]
struct Commit {
    label: &'static str,
    ms: u64,
}
struct Entry {
    token: u64,
    started: Option<f64>,
    finished: bool,
    after_settle_started: Option<f64>,
    recording: bool,
    cycle: Cycle,
}
#[derive(Default)]
struct Ring {
    number: u64,
    entries: VecDeque<Entry>,
}
#[derive(Default)]
struct Timings {
    token: u64,
    tasks: BTreeMap<String, Ring>,
}
thread_local! {
    static TIMINGS: RefCell<Timings> = RefCell::new(Timings::default());
}

pub(crate) fn now() -> Option<f64> {
    let performance = js_sys::Reflect::get(&js_sys::global(), &"performance".into()).ok()?;
    js_sys::Reflect::get(&performance, &"now".into())
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()?
        .call0(&performance)
        .ok()?
        .as_f64()
        .filter(|n| n.is_finite())
}
fn elapsed(started: f64) -> Option<u64> {
    duration(started, now())
}
fn duration(started: f64, ended: Option<f64>) -> Option<u64> {
    let duration = ended? - started;
    (duration >= 0.0 && duration.is_finite()).then(|| duration.round() as u64)
}
fn begin(task: &Task, started: Option<f64>, from_proposal: bool) {
    let Some(proposal) = &task.proposal else {
        return;
    };
    if !matches!(proposal.tool, crate::goals::Tool::Exec { .. }) {
        return;
    }
    close_after_settle(&task.id, started);
    let Some(started) = started else { return };
    let kind = if task.preparing_read() {
        "before_setup"
    } else if proposal.check_batch() {
        "batch"
    } else if proposal.check.is_some() {
        "read"
    } else {
        "exec"
    };
    TIMINGS.with(|cell| {
        let Ok(mut timings) = cell.try_borrow_mut() else {
            return;
        };
        let Some(token) = timings.token.checked_add(1) else {
            return;
        };
        timings.token = token;
        let ring = timings.tasks.entry(task.id.clone()).or_default();
        let Some(number) = ring.number.checked_add(1) else {
            return;
        };
        ring.number = number;
        if ring.entries.len() == 64 {
            ring.entries.pop_front();
        }
        ring.entries.push_back(Entry {
            token,
            started: from_proposal.then_some(started),
            finished: false,
            after_settle_started: None,
            recording: true,
            cycle: Cycle {
                number,
                kind,
                ..Cycle::default()
            },
        });
    });
}
pub(crate) fn proposal(task: &Task, record: &Record, started: Option<f64>) {
    if matches!(
        record,
        Record::Change {
            change: Change::Propose { .. }
                | Change::PrepareRead
                | Change::PrepareCheck
                | Change::PrepareCheckBatch
                | Change::PrepareCheckJobs,
            ..
        }
    ) {
        begin(task, started, true);
    }
}
pub(crate) fn active(id: &str) -> Option<u64> {
    TIMINGS.with(|cell| {
        let timings = cell.try_borrow().ok()?;
        let entry = timings.tasks.get(id)?.entries.back()?;
        (!entry.finished).then_some(entry.token)
    })
}
// Publications and commits also belong to the gap following Settle, until its boundary.
pub(crate) fn recording(id: &str) -> Option<u64> {
    TIMINGS.with(|cell| {
        let timings = cell.try_borrow().ok()?;
        let entry = timings.tasks.get(id)?.entries.back()?;
        entry.recording.then_some(entry.token)
    })
}
// After a worker loss only the remaining part of the cycle can be measured.
pub(crate) fn resume(task: &Task) {
    if active(&task.id).is_none() {
        begin(task, now(), false);
    }
}
pub(crate) fn finish(id: &str) {
    let settled = now();
    TIMINGS.with(|cell| {
        let Ok(mut timings) = cell.try_borrow_mut() else {
            return;
        };
        if let Some(entry) = timings
            .tasks
            .get_mut(id)
            .and_then(|r| r.entries.back_mut())
            .filter(|e| !e.finished)
        {
            // Settle fixes the command total once; the following gap has its own clock.
            entry.cycle.total_ms = entry.started.and_then(|start| duration(start, settled));
            entry.finished = true;
            entry.after_settle_started = settled;
        }
    });
}
pub(crate) fn close_after_settle(id: &str, ended: Option<f64>) {
    TIMINGS.with(|cell| {
        let Ok(mut timings) = cell.try_borrow_mut() else {
            return;
        };
        if let Some(entry) = timings
            .tasks
            .get_mut(id)
            .and_then(|r| r.entries.back_mut())
            .filter(|e| e.finished && e.recording)
        {
            entry.cycle.after_settle_ms = entry
                .after_settle_started
                .and_then(|start| duration(start, ended));
            entry.recording = false;
        }
    });
}
pub(crate) fn view(id: &str) -> serde_json::Value {
    TIMINGS.with(|cell| {
        let Ok(timings) = cell.try_borrow() else {
            return serde_json::json!([]);
        };
        timings.tasks.get(id).map_or_else(
            || serde_json::json!([]),
            |ring| {
                serde_json::to_value(ring.entries.iter().map(|e| &e.cycle).collect::<Vec<_>>())
                    .unwrap_or_else(|_| serde_json::json!([]))
            },
        )
    })
}

#[derive(Clone, Copy)]
pub(crate) enum Mark {
    WebsocketOpen,
    RelayVerdict,
    SshHandshake,
    Login,
    JobLaunch,
    JobObservation,
    Collect,
    Journal(&'static str),
    Progress,
    PublishBuild,
    PublishProtect,
    PublishSerialize,
    PublishPost(u64),
}
pub(crate) fn measure<T>(token: Option<u64>, mark: Mark, f: impl FnOnce() -> T) -> T {
    let _timing = Timer::new(token, mark);
    f()
}
pub(crate) struct Timer {
    token: Option<u64>,
    started: Option<f64>,
    mark: Mark,
}
impl Timer {
    pub(crate) fn new(token: Option<u64>, mark: Mark) -> Self {
        Self::since(token, mark, token.and_then(|_| now()))
    }
    pub(crate) fn since(token: Option<u64>, mark: Mark, started: Option<f64>) -> Self {
        Self {
            token,
            started,
            mark,
        }
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        let Some((token, ms)) = self.token.zip(self.started.and_then(elapsed)) else {
            return;
        };
        TIMINGS.with(|cell| {
            let Ok(mut timings) = cell.try_borrow_mut() else {
                return;
            };
            let Some(entry) = timings
                .tasks
                .values_mut()
                .flat_map(|r| r.entries.iter_mut())
                .find(|e| e.token == token && e.recording)
            else {
                return;
            };
            let cycle = &mut entry.cycle;
            match self.mark {
                Mark::WebsocketOpen => cycle.websocket_open_ms.push(ms),
                Mark::RelayVerdict => cycle.relay_verdict_ms.push(ms),
                Mark::SshHandshake => cycle.ssh_handshake_ms.push(ms),
                Mark::Login => cycle.login_ms.push(ms),
                Mark::JobLaunch => cycle.job_launch_ms.push(ms),
                Mark::JobObservation => cycle.job_observation_ms.push(ms),
                Mark::Collect => cycle.collect_ms.push(ms),
                Mark::Journal(label) => cycle.journal.push(Commit { label, ms }),
                Mark::Progress => {
                    cycle.progress_count = cycle.progress_count.saturating_add(1);
                    cycle.progress_ms = cycle.progress_ms.saturating_add(ms);
                }
                Mark::PublishBuild => {
                    cycle.publish_build_ms = cycle.publish_build_ms.saturating_add(ms);
                }
                Mark::PublishProtect => {
                    cycle.publish_protect_ms = cycle.publish_protect_ms.saturating_add(ms);
                }
                Mark::PublishSerialize => {
                    cycle.publish_serialize_ms = cycle.publish_serialize_ms.saturating_add(ms);
                }
                Mark::PublishPost(bytes) => {
                    cycle.publish_post_ms = cycle.publish_post_ms.saturating_add(ms);
                    cycle.publish_bytes = bytes;
                }
            }
        });
    }
}

/// Split transmission from observation without changing the launch future or its result.
pub(crate) struct Launch {
    token: Option<u64>,
    launch: std::cell::Cell<Option<Timer>>,
    observation: std::cell::Cell<Option<Timer>>,
}
impl Launch {
    pub(crate) fn new(token: Option<u64>) -> Self {
        Self {
            token,
            launch: std::cell::Cell::new(Some(Timer::new(token, Mark::JobLaunch))),
            observation: std::cell::Cell::new(None),
        }
    }
    pub(crate) fn observing(&self) {
        let Some(launch) = self.launch.take() else {
            return;
        };
        drop(launch);
        self.observation
            .set(Some(Timer::new(self.token, Mark::JobObservation)));
    }
}

pub(crate) fn change_label(change: &Change) -> &'static str {
    match change {
        Change::Request => "Request",
        Change::PrepareRead => "PrepareRead",
        Change::SkipRead(_) => "SkipRead",
        Change::Malformed { .. } => "Malformed",
        Change::CutOff { .. } => "CutOff",
        Change::CutOffAtLimit { .. } => "CutOffAtLimit",
        Change::Propose { .. } => "Propose",
        Change::ProposeDone { .. } => "ProposeDone",
        Change::ProposeOperator { .. } => "ProposeOperator",
        Change::PrepareCheck => "PrepareCheck",
        Change::PrepareCheckBatch => "PrepareCheckBatch",
        Change::PrepareCheckJobs => "PrepareCheckJobs",
        Change::SkipCheckBatch(_) => "SkipCheckBatch",
        Change::RetryChecks => "RetryChecks",
        Change::RepairFindings => "RepairFindings",
        Change::SkipReport(_) => "SkipReport",
        Change::RejectDeclaration => "RejectDeclaration",
        Change::AiKeyFailed(_) => "AiKeyFailed",
        Change::AiKeyDecision { .. } => "AiKeyDecision",
        Change::OperatorAnswer { .. } => "OperatorAnswer",
        Change::AiKeyClassDecision { .. } => "AiKeyClassDecision",
        Change::Settle => "Settle",
        Change::Inspect => "Inspect",
        Change::Wait { .. } => "Wait",
        Change::Pause(_) => "Pause",
        Change::Raise(_) => "Raise",
        Change::Abandon => "Abandon",
    }
}
