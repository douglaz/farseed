//! The attempt itself, on the browser's WebSocket: wasm32 only.

use super::wait;
use super::{AppendRefusal, BoundJournal, Done, Entry, PinSource, Target};
use crate::binding::{AdmissionRefusal, Session};
use crate::dispatch::{Approval, CommandHold, DestructiveDisposition, DispatchRefusal};
use crate::jobs::{self, Evidence, Record};
use crate::poc::timings::{self, Mark, Timer};
use futures_util::{SinkExt, StreamExt};
use pharos::{Observable, ObserveConfig};
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, client};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use ws_stream_wasm::{WsEvent, WsMessage, WsMeta, WsStream};

type RelayGate = Arc<tokio::sync::Mutex<Option<f64>>>;
thread_local! {
    // Destination host only: the relay shares its pace across ports. Worker memory only.
    static RELAY_GATES: RefCell<BTreeMap<String, RelayGate>> = RefCell::default();
}

fn relay_now() -> Result<f64, Refusal> {
    timings::now().ok_or_else(|| Refusal::Failed("relay pacing clock unavailable".into()))
}

async fn relay_wait(ms: i32, stop: &wait::Stop) -> Result<(), Refusal> {
    use wasm_bindgen::{JsCast, closure::Closure};
    struct Wake {
        worker: web_sys::WorkerGlobalScope,
        timer: i32,
        _callback: Closure<dyn FnMut()>,
    }
    impl Drop for Wake {
        fn drop(&mut self) {
            self.worker.clear_timeout_with_handle(self.timer);
        }
    }
    let worker: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let (send, receive) = tokio::sync::oneshot::channel();
    let mut send = Some(send);
    let callback = Closure::<dyn FnMut()>::new(move || {
        if let Some(send) = send.take() {
            let _ = send.send(());
        }
    });
    let timer = worker
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            callback.as_ref().unchecked_ref(),
            ms,
        )
        .map_err(|_| Refusal::Failed("relay pacing timer unavailable".into()))?;
    let _wake = Wake {
        worker,
        timer,
        _callback: callback,
    };
    stop.until(receive)
        .await
        .ok_or_else(|| Refusal::Journal("stale relay continuation".into()))?
        .map_err(|_| Refusal::Failed("relay pacing timer ended".into()))
}

async fn relay_slot(
    host: &str,
    not_before: f64,
    stop: &wait::Stop,
) -> Result<tokio::sync::OwnedMutexGuard<Option<f64>>, Refusal> {
    let gate = RELAY_GATES.with_borrow_mut(|gates| {
        gates
            .entry(host.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None)))
            .clone()
    });
    let mut last = stop
        .until(gate.lock_owned())
        .await
        .ok_or_else(|| Refusal::Journal("stale relay continuation".into()))?;
    loop {
        if stop.stopped() {
            return Err(Refusal::Journal("stale relay continuation".into()));
        }
        let now = relay_now()?;
        let remaining = last.map_or(not_before, |last| not_before.max(last + 1_250.0)) - now;
        if remaining <= 0.0 {
            // Keep the host locked through AUTH send, including any yielding sink flush.
            *last = Some(now);
            return Ok(last);
        }
        relay_wait(remaining.ceil() as i32, stop).await?;
    }
}

async fn access(
    target: &Target,
) -> Result<
    (
        Target,
        jobs::Elevation,
        Option<crate::credential::HostKeyPin>,
    ),
    String,
> {
    if !target.stored {
        if target.profile != "v1" {
            return Err(format!("unsupported relay profile: {}", target.profile));
        }
        return Ok((target.clone(), jobs::Elevation::None, None));
    }
    let local = crate::worker::local();
    let mut local = local.lock().await;
    let store = local.store().ok_or("locked before target resolution")?;
    let (resolved, pins) = crate::poc::targets::resolve(store, &target.machine)?;
    let pin = pins
        .pin(&target.machine)
        .ok_or("stored target pin missing")?;
    let elevation = store
        .poc_target(&target.machine)
        .ok_or("stored target missing")?
        .elevation;
    Ok((resolved, elevation, Some(pin)))
}

/// Why an attempt ended without the command being sent, or without its result.
#[derive(Debug)]
pub enum Refusal {
    SignatureLowering(crate::modes::SignatureRefusal),
    /// No pin for the machine: refused before the relay is contacted (`CHN-R4`, `CNF-23`).
    NoPin,
    NoEntry(String),
    Unbound(String),
    Provenance,
    /// No SSH client key or relay key to use: refused before the relay is contacted.
    NoCredentials,
    /// The relay refused the AUTH (`WIR-7`, paid-tcp-relay `844e834`) with this reason and close
    /// code.
    Relay {
        reason: String,
        close_code: Option<u16>,
    },
    /// The presented host key is not the pin: halted in the key exchange (`SEC-11`).
    HostKey {
        pinned: String,
        presented: String,
    },
    /// The journal refused the append, so no `exec` was sent (`STA-3`).
    Journal(String),
    Disposition(DestructiveDisposition),
    Barrier(Vec<crate::dispatch::OperationIntent>),
    Held(Value),
    LaunchTooLong {
        bytes: usize,
    },
    Unresolved {
        call: u64,
        why: String,
        evidence: Option<Box<jobs::Report>>,
    },
    Historical {
        why: String,
        evidence: Box<jobs::Report>,
    },
    /// Anything else: the transport, the protocol, authentication.
    Failed(String),
    /// The socket or channel ended before a usable record could be read.
    Transport(String),
}

impl Refusal {
    pub fn to_json(&self) -> Value {
        match self {
            Refusal::SignatureLowering(record) => {
                json!({"refused":"signature-lowering","machine":record.machine,"form":record.form})
            }
            Refusal::Held(answer) => answer.clone(),
            Refusal::Barrier(calls) => json!({"refused":"barrier","calls":calls}),
            Refusal::LaunchTooLong { bytes } => json!({
                "refused": "launch-too-long",
                "why": "command is too long to launch; shorten the command",
                "bytes": bytes,
                "limit": jobs::MAX_LAUNCH_BYTES,
            }),
            Refusal::Unbound(machine) => json!({"refused":"unbound","machine":machine}),
            Refusal::NoEntry(machine) => json!({"refused":"no-entry","machine":machine}),
            Refusal::Provenance => json!({"refused":"provenance"}),
            Refusal::NoPin => json!({ "refused": "no-pin" }),
            Refusal::NoCredentials => json!({ "refused": "no-credentials" }),
            Refusal::Relay { reason, close_code } => {
                json!({ "refused": "relay", "reason": reason, "close_code": close_code })
            }
            Refusal::HostKey { pinned, presented } => {
                json!({ "refused": "host-key", "pinned": pinned, "presented": presented })
            }
            Refusal::Journal(why) => json!({ "refused": "journal", "why": why }),
            Refusal::Disposition(record) => {
                json!({ "refused": "disposition", "disposition": record.disposition, "continuation": record.continuation })
            }
            Refusal::Unresolved {
                call,
                why,
                evidence,
            } => jobs::unresolved(*call, why, evidence.as_deref()),
            Refusal::Historical { why, evidence } => json!({
                "historical":true,"actionable":false,"call":evidence.evidence.call,
                "terminal":evidence.number,"why":why,"job_record":evidence,
            }),
            Refusal::Failed(why) => json!({ "refused": "failed", "why": why }),
            Refusal::Transport(why) => {
                json!({ "refused": "failed", "why": why, "connection_lost": true })
            }
        }
    }
}

pub enum CommandOutcome {
    Finished(Box<Done>),
    Background(Box<jobs::Report>),
}

impl CommandOutcome {
    pub fn report(&self) -> Value {
        match self {
            Self::Finished(done) => done.report(),
            Self::Background(report) => super::background_report(report),
        }
    }
}

/// An attempt's outcome as the worker reports it to the page: output and the reconciled record,
/// or the refusal. Never key material.
pub fn report(outcome: &Result<CommandOutcome, Refusal>) -> Value {
    match outcome {
        Ok(done) => done.report(),
        Err(refusal) => refusal.to_json(),
    }
}

fn append_refusal(refusal: AppendRefusal) -> Refusal {
    match refusal {
        AppendRefusal::SignatureLowering(record) => Refusal::SignatureLowering(record),
        AppendRefusal::Policy(DispatchRefusal::NoEntry { machine }) => Refusal::NoEntry(machine),
        AppendRefusal::Policy(DispatchRefusal::Provenance) => Refusal::Provenance,
        AppendRefusal::Storage(why) => Refusal::Journal(why),
        AppendRefusal::Policy(DispatchRefusal::Disposition(record)) => Refusal::Disposition(record),
        AppendRefusal::Policy(DispatchRefusal::TypedBarrier { calls }) => Refusal::Barrier(calls),
        AppendRefusal::Policy(DispatchRefusal::Held(_)) => {
            unreachable!("hold collects before reporting")
        }
    }
}

fn failed(context: &str) -> impl Fn(String) -> Refusal + '_ {
    move |e| {
        if e == "the relay closed the connection" {
            Refusal::Transport(format!("{context}: {e}"))
        } else {
            Refusal::Failed(format!("{context}: {e}"))
        }
    }
}

/// The host-key check, inside the SSH key exchange and before authentication. `false` makes
/// russh abort with `Error::UnknownKey`; the presented fingerprint is kept so the halt can name
/// both keys.
struct PinCheck {
    pinned: String,
    presented: Arc<Mutex<Option<String>>>,
    generation: u64,
    session: String,
    cycle: Option<u64>,
    handshake_started: Option<f64>,
}

impl PinCheck {
    async fn current(&self) -> bool {
        // russh requires a Send callback future even on this single worker. The local
        // Store acquisition stays on the worker; only its one-shot answer crosses this
        // callback boundary. No transport or second state owner is created.
        let session = self.session.clone();
        let generation = self.generation;
        let (reply, answer) = tokio::sync::oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let local = crate::worker::local();
            let mut local = local.lock().await;
            let owner = crate::lifecycle::owner();
            let eligible = owner.generation() == generation
                && owner.ordinary().is_ok()
                && local
                    .store()
                    .is_some_and(|store| store.live_goal_session(&session).is_ok());
            let _ = reply.send(eligible);
        });
        let eligible = answer.await.unwrap_or(false);
        let owner = crate::lifecycle::owner();
        eligible && owner.generation() == generation && owner.ordinary().is_ok()
    }
}

impl client::Handler for PinCheck {
    type Error = russh::Error;

    async fn auth_banner(
        &mut self,
        _banner: &str,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        #[cfg(feature = "tracer")]
        if let Some(released) = crate::testonly::session_point_receiver("session_authentication") {
            released.await.expect("fixture authentication release");
        }
        if !self.current().await {
            return Err(russh::Error::UnknownKey);
        }
        #[cfg(feature = "tracer")]
        if crate::testonly::rekey_session("session_authentication") {
            _session.initiate_rekey()?;
        }
        Ok(())
    }

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let presented = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.fingerprint(HashAlg::Sha256),
            PublicKeyOrCertificate::Certificate(cert) => {
                cert.public_key().fingerprint(HashAlg::Sha256)
            }
        }
        .to_string();
        let matches = presented == self.pinned;
        *self.presented.lock().expect("pin check lock") = Some(presented);
        let accepted = matches && self.current().await;
        if accepted {
            drop(Timer::since(
                self.cycle,
                Mark::SshHandshake,
                self.handshake_started.take(),
            ));
        }
        Ok(accepted)
    }
}

/// Runs `command` on `target`, recording it in `journal` first. `tamper_auth` is the tracer's
/// way to send a wrongly signed AUTH; it exists only in the tracer build.
pub async fn run_command(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    target: &Target,
    command: &[u8],
    origin: Option<&std::rc::Rc<Session>>,
    #[cfg(feature = "tracer")] tamper_auth: bool,
) -> Result<CommandOutcome, Refusal> {
    run_command_input(
        pins,
        journal,
        target,
        command,
        None,
        origin,
        #[cfg(feature = "tracer")]
        tamper_auth,
    )
    .await
}

pub(crate) async fn run_command_input(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    target: &Target,
    command: &[u8],
    input: Option<&[u8]>,
    origin: Option<&std::rc::Rc<Session>>,
    #[cfg(feature = "tracer")] tamper_auth: bool,
) -> Result<CommandOutcome, Refusal> {
    let (target, elevation, _) = access(target).await.map_err(Refusal::Failed)?;
    let target = &target;
    let session = resolve(journal, &target.machine, origin).await?;
    journal
        .check_signature(&target.machine, command)
        .await
        .map_err(append_refusal)?;
    if let Err(refusal) = journal.check(&target.machine).await {
        return Err(admission_refusal(
            pins,
            journal,
            &session,
            target,
            refusal,
            #[cfg(feature = "tracer")]
            tamper_auth,
        )
        .await);
    }
    let bytes = if input.is_some() {
        jobs::launch_with_input(&"0".repeat(48), &target.machine, command, elevation, true).len()
    } else {
        jobs::launch_size_with_elevation(&target.machine, command, elevation)
    };
    if !jobs::launch_fits(bytes) {
        return Err(Refusal::LaunchTooLong { bytes });
    }
    let stop = wait::Stop::collection();
    let (ssh, pinned, host_key, _socket) = stop
        .until(connect(
            pins,
            journal,
            &session,
            target,
            &stop,
            #[cfg(feature = "tracer")]
            tamper_auth,
        ))
        .await
        .ok_or_else(|| Refusal::Journal("sessions ended".into()))??;
    journal.current(&session).await.map_err(Refusal::Journal)?;
    let launch_timing = timings::Launch::new(journal.command_cycle());
    let mut channel = stop
        .until(ssh.channel_open_session())
        .await
        .ok_or_else(|| Refusal::Journal("sessions ended".into()))?
        .map_err(|e| {
            if ssh.is_closed() {
                Refusal::Transport(format!("session channel: {e}"))
            } else {
                Refusal::Failed(format!("session channel: {e}"))
            }
        })?;

    // ARC-8, STA-4: the record is appended immediately before the bytes leave, and a failed
    // append means they do not (STA-3).
    let entry = Entry {
        provenance: Some(crate::dispatch::CommandProvenance {
            target: crate::dispatch::Target::Entry(target.machine.clone()),
            session: Some(session.identity.clone()),
            requester: crate::dispatch::Requester::Session,
        }),
        machine: target.machine.clone(),
        command: command.to_vec(),
    };
    let approval = Approval::HarnessPin {
        machine: target.machine.clone(),
        fingerprint: pinned,
    };
    journal.current(&session).await.map_err(Refusal::Journal)?;
    let seq = match journal.append_bound(&session, &entry, &approval).await {
        Ok(seq) => seq,
        Err(refusal) => {
            // No exec for this request, even when it already opened a channel.
            drop(channel);
            drop(ssh);
            return Err(admission_refusal(
                pins,
                journal,
                &session,
                target,
                refusal,
                #[cfg(feature = "tracer")]
                tamper_auth,
            )
            .await);
        }
    };
    #[cfg(feature = "tracer")]
    ssh_point(&ssh, "pending_launch_committed").await;
    if stop.stopped() || journal.current(&session).await.is_err() {
        return Err(Refusal::Unresolved {
            call: seq,
            why: "sessions ended after intent committed".into(),
            evidence: None,
        });
    }
    // No await separates committed intent from registration in this single-threaded worker.
    let own = wait::DispatchResult::new(seq);
    let outcome = async {
        let intent = journal
            .intent(seq)
            .await
            .ok_or_else(|| Refusal::Unresolved {
                call: seq,
                why: "intent read-back missing".into(),
                evidence: None,
            })?;
        let job = intent.job.as_deref().expect("new intent has job identity");
        if stop.stopped() || ssh.is_closed() || journal.current(&session).await.is_err() {
            return Err(Refusal::Unresolved {
                call: seq,
                why: "sessions ended before command transmission".into(),
                evidence: None,
            });
        }
        let (_, elevation, _) = access(target).await.map_err(|why| Refusal::Unresolved {
            call: seq,
            why,
            evidence: None,
        })?;
        if stop.stopped() || ssh.is_closed() || journal.current(&session).await.is_err() {
            return Err(Refusal::Unresolved {
                call: seq,
                why: "sessions ended before command transmission".into(),
                evidence: None,
            });
        }
        let sent = jobs::launch_with_input(
            job,
            &entry.machine,
            &entry.command,
            elevation,
            input.is_some(),
        )
        .into_bytes();
        journal
            .launch_transmission(seq, &sent)
            .await
            .map_err(|why| Refusal::Unresolved {
                call: seq,
                why,
                evidence: None,
            })?;
        if stop.stopped() || ssh.is_closed() || journal.current(&session).await.is_err() {
            return Err(Refusal::Unresolved {
                call: seq,
                why: "sessions ended before command transmission".into(),
                evidence: None,
            });
        }
        let progress = super::job_read::Read::default();
        let result = stop
            .until(exec_record(
                &mut channel,
                &sent,
                Some(&progress),
                input,
                Some(&launch_timing),
            ))
            .await
            .unwrap_or_else(|| {
                Err(if progress.sent() {
                    "sessions ended while awaiting job record"
                } else {
                    "sessions ended before command transmission"
                }
                .into())
            });
        #[cfg(feature = "tracer")]
        ssh_point(&ssh, "session_evidence").await;
        if !stop.stopped() {
            let _ = stop
                .until(ssh.disconnect(russh::Disconnect::ByApplication, "", "en"))
                .await;
        }
        // CNF-30: the journal determines the wrapper's exact transmitted bytes.
        let recorded = journal.read(seq).await;
        let replayed = journal.intent(seq).await;
        let authority = access(target).await;
        let recorded = match (recorded, replayed) {
            (Some(recorded), Some(replayed))
                if replayed.job.as_deref().is_some_and(|id| {
                    authority.as_ref().is_ok_and(|(_, elevation, _)| {
                        if input.is_some() {
                            jobs::valid_id(id)
                                && jobs::launch_with_input(
                                    id,
                                    &recorded.machine,
                                    &recorded.command,
                                    *elevation,
                                    true,
                                )
                                .as_bytes()
                                    == sent
                        } else {
                            jobs::launch_reconciles(id, &recorded, *elevation, &sent)
                        }
                    })
                }) && recorded.machine == target.machine =>
            {
                recorded
            }
            _ => {
                let evidence = if let Ok(record) = &result {
                    journal
                        .uncommitted(
                            &Evidence {
                                call: seq,
                                job: job.into(),
                                record: record.clone(),
                            },
                            &entry.machine,
                            &hex::encode(&entry.command),
                        )
                        .await
                        .ok()
                        .map(Box::new)
                } else {
                    None
                };
                return Err(Refusal::Unresolved {
                    call: seq,
                    why: "transcript does not reconcile with command bytes".into(),
                    evidence,
                });
            }
        };
        let record = result.map_err(|why| Refusal::Unresolved {
            call: seq,
            why,
            evidence: None,
        })?;
        let received = Evidence {
            call: seq,
            job: job.into(),
            record,
        };
        let evidence = match journal
            .job_evidence_unless_stopped(&received, &stop)
            .await
            .unwrap_or_else(|| Err("sessions ended before journaling job evidence".into()))
        {
            Ok(evidence) => evidence,
            Err(why) => {
                return Err(Refusal::Unresolved {
                    call: seq,
                    why: format!("job evidence append: {why}"),
                    evidence: journal
                        .uncommitted(&received, &entry.machine, &hex::encode(&entry.command))
                        .await
                        .ok()
                        .map(Box::new),
                });
            }
        };
        if !evidence.settles_call() {
            return Err(Refusal::Unresolved {
                call: seq,
                why: format!("job record: {:?}", evidence.state),
                evidence: Some(Box::new(evidence)),
            });
        }
        let current = journal.current(&session).await;
        if stop.stopped() || current.is_err() {
            return Err(Refusal::Historical {
                why: current
                    .err()
                    .unwrap_or_else(|| "stale result after suspension".into()),
                evidence: Box::new(evidence),
            });
        }
        if evidence.state == jobs::State::Background {
            return Ok(CommandOutcome::Background(Box::new(evidence)));
        }
        Ok(CommandOutcome::Finished(Box::new(Done {
            seq,
            sent,
            recorded,
            stdout: evidence.stdout.as_bytes().to_vec(),
            stderr: evidence.stderr.as_bytes().to_vec(),
            exit_status: evidence.exit_status.expect("finished record"),
            terminal: evidence.number.expect("committed evidence"),
            host_key,
            evidence,
        })))
    }
    .await;
    own.finish(report(&outcome));
    outcome
}

/// Admission's hold collects only its snapshot of holding calls; it never resumes dispatch.
pub(crate) async fn admission_refusal(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    session: &Session,
    target: &Target,
    refusal: AppendRefusal,
    #[cfg(feature = "tracer")] tamper_auth: bool,
) -> Refusal {
    let AppendRefusal::Policy(DispatchRefusal::Held(hold)) = refusal else {
        return append_refusal(refusal);
    };
    Refusal::Held(
        held(
            pins,
            journal,
            session,
            target,
            hold,
            #[cfg(feature = "tracer")]
            tamper_auth,
        )
        .await,
    )
}

async fn held(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    session: &Session,
    target: &Target,
    hold: CommandHold,
    #[cfg(feature = "tracer")] tamper_auth: bool,
) -> Value {
    let stop = wait::Stop::new(&target.machine);
    let mut reports = Vec::new();
    let mut connection = None;
    let mut unreachable: Option<Value> = None;
    let calls: Vec<_> = hold
        .calls
        .iter()
        .map(|intent| (intent, wait::result(intent.call)))
        .collect();
    let stopped_why = |why: &str| {
        json!(if super::inference::ending() {
            "sessions ended before record was read"
        } else {
            why
        })
    };
    for (intent, own) in calls {
        let not_read = |why: Value| json!({"call":intent.call,"not_read":true,"why":why});
        if super::inference::ending() {
            reports.push(not_read(stopped_why("stopped before record was read")));
            continue;
        }
        let Some(job) = intent.job.as_deref() else {
            reports.push(not_read(json!(
                "no job identity; only a disposition can release this call"
            )));
            continue;
        };
        if stop.stopped() {
            reports.push(not_read(stopped_why("stopped before record was read")));
            continue;
        }
        if let Some(own) = own {
            let result = stop.until(own.get()).await;
            reports.push(match result {
                Some(result) => super::dispatch_result(intent.call, result),
                None => not_read(stopped_why("stopped while awaiting own dispatch's result")),
            });
            continue;
        }
        if let Some(why) = &unreachable {
            reports.push(not_read(why.clone()));
            continue;
        }
        if connection.is_none() {
            match stop
                .until(connect(
                    pins,
                    journal,
                    session,
                    target,
                    &stop,
                    #[cfg(feature = "tracer")]
                    tamper_auth,
                ))
                .await
            {
                Some(Ok((ssh, _, _, socket))) => connection = Some((ssh, socket)),
                Some(Err(why)) => {
                    let reason = match why {
                        Refusal::Failed(why) | Refusal::Transport(why) => {
                            json!({"connection":"unavailable","why":why})
                        }
                        other => other.to_json(),
                    };
                    let why = json!({"unreachable":reason});
                    reports.push(not_read(why.clone()));
                    unreachable = Some(why);
                    continue;
                }
                None => {
                    reports.push(not_read(stopped_why("stopped before record was read")));
                    continue;
                }
            }
        }
        let (ssh, _socket) = connection.as_ref().expect("connected for collection");
        let progress = super::job_read::Read::default();
        let read = async {
            journal.current(session).await?;
            let mut channel = ssh
                .channel_open_session()
                .await
                .map_err(|e| format!("session channel: {e}"))?;
            journal.current(session).await?;
            read_job_record(&mut channel, job, &progress, target).await
        };
        let record = match stop.until(read).await {
            Some(Ok(record)) => record,
            Some(Err(why)) => {
                reports.push(progress.failure(intent.call, None, super::inference::ending(), &why));
                if ssh.is_closed() {
                    unreachable = Some(json!("connection lost"));
                }
                continue;
            }
            None => {
                reports.push(progress.failure(
                    intent.call,
                    None,
                    super::inference::ending(),
                    "stopped while reading record",
                ));
                continue;
            }
        };
        let received = Evidence {
            call: intent.call,
            job: job.into(),
            record,
        };
        #[cfg(feature = "tracer")]
        crate::testonly::completed_read();
        #[cfg(feature = "tracer")]
        ssh_point(ssh, "session_evidence").await;
        match journal.job_evidence_unless_stopped(&received, &stop).await {
            Some(Ok(report)) => {
                reports.push(evidence_result(journal, session, &stop, report).await)
            }
            result => {
                let why = match result {
                    Some(Err(why)) => format!("job evidence append: {why}"),
                    None => "wait stopped before journaling job evidence".into(),
                    Some(Ok(_)) => unreachable!(),
                };
                reports.push(json!({"call":intent.call,"not_journaled":true,"why":why,
                    "job_record":journal.uncommitted(&received, &intent.machine, &intent.command).await.ok()}));
            }
        }
    }
    super::held_report(&target.machine, reports, hold.disposition.as_ref())
}

/// Collection execs are reads. The page adapter may reserve one recovery transmission
/// after a committed missing read; ordinary adapters do not opt in.
/// Calls whose own dispatch awaits its record are reported as not read here.
pub async fn collect_jobs(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    target: &Target,
    #[cfg(feature = "tracer")] tamper_auth: bool,
) -> Result<Vec<Value>, Refusal> {
    let (target, _, _) = access(target).await.map_err(Refusal::Failed)?;
    let target = &target;
    let stop = wait::Stop::collection();
    let session = resolve(journal, &target.machine, None).await?;
    let calls = journal
        .collectable(&target.machine)
        .await
        .map_err(Refusal::Journal)?;
    let mut reports = Vec::new();
    let had_calls = !calls.is_empty();
    let calls: Vec<_> = calls
        .into_iter()
        .filter(|intent| {
            if wait::result(intent.call).is_some() {
                reports.push(json!({"call":intent.call,"not_read":true,
                "why":"own dispatch awaits its record"}));
                false
            } else {
                true
            }
        })
        .collect();
    if had_calls && calls.is_empty() {
        return Ok(reports);
    }
    let connection = stop
        .until(connect(
            pins,
            journal,
            &session,
            target,
            &stop,
            #[cfg(feature = "tracer")]
            tamper_auth,
        ))
        .await;
    let (ssh, pinned, _, _socket) = match connection {
        Some(result) => result?,
        None => {
            reports.extend(calls.into_iter().map(|intent| {
                json!({"call":intent.call,"job":intent.job,"not_read":true,
                    "why":"sessions ended before record was read"})
            }));
            return Ok(reports);
        }
    };
    for intent in calls {
        let job = intent.job.expect("collectable has job identity");
        if super::inference::ending() {
            reports.push(json!({"call":intent.call,"job":job,"not_read":true,
                "why":"sessions ended before record was read"}));
            continue;
        }
        if ssh.is_closed() {
            reports.push(
                json!({"call":intent.call,"job":job,"not_read":true,"why":"connection lost","connection_lost":true}),
            );
            continue;
        }
        let progress = super::job_read::Read::default();
        let read = async {
            journal.current(&session).await?;
            let mut channel = ssh
                .channel_open_session()
                .await
                .map_err(|e| format!("session channel: {e}"))?;
            journal.current(&session).await?;
            read_job_record(&mut channel, &job, &progress, target).await
        };
        let record = match stop.until(read).await {
            Some(Ok(record)) => record,
            Some(Err(why)) => {
                if ssh.is_closed() {
                    progress.mark_interrupted();
                }
                reports.push(progress.failure(
                    intent.call,
                    Some(&job),
                    super::inference::ending(),
                    &why,
                ));
                continue;
            }
            None => {
                reports.push(progress.failure(
                    intent.call,
                    Some(&job),
                    super::inference::ending(),
                    "stopped while reading record",
                ));
                continue;
            }
        };
        let received = Evidence {
            call: intent.call,
            job,
            record,
        };
        #[cfg(feature = "tracer")]
        ssh_point(&ssh, "session_evidence").await;
        match journal.job_evidence_unless_stopped(&received, &stop).await {
            Some(Ok(report)) => {
                if report.state == jobs::State::Missing && journal.recovers_missing() {
                    match resend_missing(journal, &session, target, &ssh, &stop, &pinned, &report).await {
                        Ok(Some(value)) => { reports.push(value); continue; }
                        Ok(None) => {}
                        Err(why) if ssh.is_closed() && !stop.stopped() => {
                            reports.push(json!({"call":intent.call,"job":received.job,
                                "failed":true,"connection_lost":true,"why":why.to_json()}));
                            continue;
                        }
                        Err(why) => return Err(why),
                    }
                }
                reports.push(evidence_result(journal, &session, &stop, report).await)
            }
            result => reports.push(json!({
                "call":intent.call,"job":received.job,"failed":true,
                "why":match result {
                    Some(Err(why)) => format!("job evidence append: {why}"),
                    None => "wait stopped before journaling job evidence".into(),
                    Some(Ok(_)) => unreachable!(),
                },
                "job_record":journal.uncommitted(&received, &intent.machine, &intent.command).await.ok()
            })),
        }
    }
    if !stop.stopped() {
        let _ = stop
            .until(ssh.disconnect(russh::Disconnect::ByApplication, "", "en"))
            .await;
    }
    Ok(reports)
}

async fn resend_missing(
    journal: &mut impl BoundJournal,
    session: &Session,
    target: &Target,
    ssh: &client::Handle<PinCheck>,
    stop: &std::rc::Rc<wait::Stop>,
    pinned: &str,
    report: &jobs::Report,
) -> Result<Option<Value>, Refusal> {
    if stop.stopped() || super::inference::ending() {
        return Err(Refusal::Journal(
            "sessions ended before command transmission".into(),
        ));
    }
    if ssh.is_closed() {
        return Err(Refusal::Transport(
            "connection lost before command transmission".into(),
        ));
    }
    journal.current(session).await.map_err(Refusal::Journal)?;
    let (_, elevation, _) = access(target).await.map_err(Refusal::Failed)?;
    let Some(sent) = journal
        .resend_launch(
            session,
            report.evidence.call,
            &report.evidence.job,
            elevation,
            pinned,
        )
        .await
        .map_err(|refusal| match refusal {
            AppendRefusal::Policy(DispatchRefusal::Held(hold)) => {
                Refusal::Held(super::held_report(
                    &target.machine,
                    hold.calls
                        .iter()
                        .map(|intent| {
                            serde_json::json!({"call":intent.call,"not_read":true,
                    "why":"another unresolved command holds this machine"})
                        })
                        .collect(),
                    hold.disposition.as_ref(),
                ))
            }
            other => append_refusal(other),
        })?
    else {
        return Ok(None);
    };
    // The durable resend reservation has consumed the single attempt, even if a
    // stop or connection loss fences transmission at this final boundary.
    if stop.stopped() || super::inference::ending() {
        return Err(Refusal::Journal(
            "sessions ended before command transmission".into(),
        ));
    }
    if ssh.is_closed() {
        return Err(Refusal::Transport(
            "connection lost before command transmission".into(),
        ));
    }
    journal.current(session).await.map_err(Refusal::Journal)?;
    let mut channel = stop
        .until(ssh.channel_open_session())
        .await
        .ok_or_else(|| Refusal::Journal("sessions ended".into()))?
        .map_err(|e| Refusal::Failed(format!("session channel: {e}")))?;
    if stop.stopped() || super::inference::ending() {
        return Err(Refusal::Journal(
            "sessions ended before command transmission".into(),
        ));
    }
    if ssh.is_closed() {
        return Err(Refusal::Transport(
            "connection lost before command transmission".into(),
        ));
    }
    journal.current(session).await.map_err(Refusal::Journal)?;
    let progress = super::job_read::Read::default();
    let record = match stop
        .until(exec_record(
            &mut channel,
            &sent,
            Some(&progress),
            None,
            None,
        ))
        .await
    {
        // exec_record accepts only a complete, validated record on a normally
        // closed channel. Commit that evidence exactly as for the first launch.
        Some(Ok(record)) => record,
        _ => {
            // A wrapper refusal or SSH status is never a command outcome. Only
            // when no usable record arrived do we need a separate read.
            if stop.stopped() || ssh.is_closed() || super::inference::ending() {
                if ssh.is_closed() && !stop.stopped() && !super::inference::ending() {
                    progress.mark_interrupted();
                    return Ok(Some(progress.failure(
                        report.evidence.call,
                        Some(&report.evidence.job),
                        false,
                        "connection lost while awaiting job record",
                    )));
                }
                return Ok(None);
            }
            journal.current(session).await.map_err(Refusal::Journal)?;
            let mut channel = stop
                .until(ssh.channel_open_session())
                .await
                .ok_or_else(|| Refusal::Journal("sessions ended".into()))?
                .map_err(|e| Refusal::Failed(format!("session channel: {e}")))?;
            let progress = super::job_read::Read::default();
            let read = async {
                journal.current(session).await?;
                read_job_record(&mut channel, &report.evidence.job, &progress, target).await
            };
            match stop.until(read).await {
                Some(Ok(record)) => record,
                result => {
                    if ssh.is_closed() {
                        progress.mark_interrupted();
                    }
                    return Ok(Some(progress.failure(
                        report.evidence.call,
                        Some(&report.evidence.job),
                        super::inference::ending(),
                        &match result {
                            Some(Err(why)) => why,
                            _ => "stopped while reading record".into(),
                        },
                    )));
                }
            }
        }
    };
    let received = Evidence {
        call: report.evidence.call,
        job: report.evidence.job.clone(),
        record,
    };
    match journal.job_evidence_unless_stopped(&received, stop).await {
        Some(Ok(report)) => Ok(Some(evidence_result(journal, session, stop, report).await)),
        result => Ok(Some(
            json!({"call":received.call,"job":received.job,"failed":true,
            "why":match result { Some(Err(why)) => format!("job evidence append: {why}"), _ => "wait stopped before journaling job evidence".into() },
            "job_record":journal.uncommitted(&received, &target.machine,
                &journal.intent(received.call).await.map_or(String::new(), |i| i.command)).await.ok()}),
        )),
    }
}

/// Click-only synchronous harness reads share connection admission, elevation, pinned SSH,
/// deadline and private buffers. No intent, command evidence, task or report is created.
async fn private_file_read(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    target: &Target,
    script: impl FnOnce(jobs::Elevation) -> String,
    output_limit: usize,
) -> Result<(zeroize::Zeroizing<Vec<u8>>, Option<u32>), String> {
    use zeroize::Zeroizing;
    const UNAVAILABLE: &str =
        "The file could not be downloaded. Check the machine connection and try again.";
    let (target, elevation, _) = access(target).await.map_err(|_| UNAVAILABLE)?;
    let session = resolve(journal, &target.machine, None)
        .await
        .map_err(|_| UNAVAILABLE)?;
    let stop = wait::Stop::collection();
    // A read with no established outcome returns to its row; it never holds the task.
    use wasm_bindgen::{JsCast, closure::Closure};
    struct Deadline {
        worker: web_sys::WorkerGlobalScope,
        timer: i32,
        _callback: Closure<dyn FnMut()>,
    }
    impl Drop for Deadline {
        fn drop(&mut self) {
            self.worker.clear_timeout_with_handle(self.timer);
        }
    }
    let worker: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let weak = std::rc::Rc::downgrade(&stop);
    let callback = Closure::<dyn FnMut()>::new(move || {
        if let Some(stop) = weak.upgrade() {
            stop.fire();
        }
    });
    let timer = worker
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            callback.as_ref().unchecked_ref(),
            60_000,
        )
        .map_err(|_| UNAVAILABLE)?;
    let _deadline = Deadline {
        worker,
        timer,
        _callback: callback,
    };
    let work = async {
        let (ssh, _, _, _socket) = connect(
            pins,
            journal,
            &session,
            &target,
            &stop,
            #[cfg(feature = "tracer")]
            false,
        )
        .await
        .map_err(|_| UNAVAILABLE)?;
        journal.current(&session).await.map_err(|_| UNAVAILABLE)?;
        let mut channel = ssh.channel_open_session().await.map_err(|_| UNAVAILABLE)?;
        journal.current(&session).await.map_err(|_| UNAVAILABLE)?;
        channel
            .exec(true, script(elevation).as_bytes())
            .await
            .map_err(|_| UNAVAILABLE)?;
        let mut output = Zeroizing::new(Vec::new());
        let mut status = None;
        let mut closed = false;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    if output.len().saturating_add(data.len()) > output_limit {
                        return Err(
                            "The file changed or its transfer could not be verified. Try again.",
                        );
                    }
                    output.extend_from_slice(&data);
                }
                // Remote diagnostics are private too; never retain or display them.
                ChannelMsg::ExtendedData { .. } => {}
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Close => {
                    closed = true;
                    break;
                }
                _ => {}
            }
        }
        let _ = ssh
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        journal.current(&session).await.map_err(|_| UNAVAILABLE)?;
        if !closed {
            return Err("The download outcome is unknown. Try again.");
        }
        Ok((output, status))
    };
    stop.until(work)
        .await
        .ok_or("The download was interrupted. Try again.")?
        .map_err(str::to_owned)
}

/// Offers retain their existing unrestricted (except internal state) file-read behavior.
pub(crate) async fn download_file(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    target: &Target,
    path: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    download_file_with_confinement(pins, journal, target, path, false).await
}

pub(crate) async fn download_file_with_confinement(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    target: &Target,
    path: &str,
    confined: bool,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    use base64::Engine;
    use zeroize::Zeroizing;
    let (output, status) = private_file_read(
        pins,
        journal,
        target,
        |elevation| {
            if confined {
                jobs::file_read_with_confinement(path, elevation, true)
            } else {
                jobs::file_read(path, elevation)
            }
        },
        1_420_000,
    )
    .await?;
    let decode = || -> Result<Zeroizing<Vec<u8>>, &str> {
        match status {
            Some(44) => return Err("too-large"),
            Some(45) => {
                return Err(
                    "The file is missing, unreadable, or is not a regular file. Try again.",
                );
            }
            Some(46) => return Err("Files under /var/lib/tau-web/ cannot be downloaded."),
            Some(0) => {}
            _ => {
                return Err(
                    "The file could not be downloaded. Check the machine connection and try again.",
                );
            }
        }
        let invalid = "The file changed or its transfer could not be verified. Try again.";
        let split = output.iter().position(|b| *b == b'\n').ok_or(invalid)?;
        let size = std::str::from_utf8(&output[..split])
            .ok()
            .and_then(|s| s.strip_prefix("TAUFILE "))
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|size| *size <= crate::poc::files::LIMIT)
            .ok_or(invalid)?;
        let encoded = Zeroizing::new(
            output[split + 1..]
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect::<Vec<_>>(),
        );
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(&encoded)
                .map_err(|_| invalid)?,
        );
        if bytes.len() != size {
            return Err(invalid);
        }
        Ok(bytes)
    };
    decode().map_err(str::to_owned)
}

pub(crate) async fn list_files(
    pins: &impl PinSource,
    journal: &mut impl BoundJournal,
    target: &Target,
) -> Result<crate::poc::files::Listing, String> {
    let (output, status) = private_file_read(pins, journal, target, jobs::file_list, 8192).await?;
    if status != Some(0) {
        return Err(
            "The files could not be listed. Check the machine connection and try again.".into(),
        );
    }
    crate::poc::files::Listing::parse(&output)
}

async fn evidence_result(
    journal: &impl BoundJournal,
    session: &Session,
    stop: &wait::Stop,
    report: jobs::Report,
) -> Value {
    let current = journal.current(session).await;
    let mut value = serde_json::to_value(report).expect("report serialization");
    if stop.stopped() || current.is_err() {
        value["historical"] = true.into();
        value["actionable"] = false.into();
        value["why"] = current
            .err()
            .unwrap_or_else(|| "stale result after suspension".into())
            .into();
    }
    value
}

async fn read_job_record(
    channel: &mut russh::Channel<client::Msg>,
    job: &str,
    progress: &super::job_read::Read,
    target: &Target,
) -> Result<Record, String> {
    #[cfg(feature = "tracer")]
    crate::testonly::hold_job_read().await?;
    if super::inference::ending() {
        return Err("sessions ended before record was read".into());
    }
    let (_, elevation, _) = access(target).await?;
    if super::inference::ending() {
        return Err("sessions ended before record was read".into());
    }
    exec_record(
        channel,
        jobs::collect_with_elevation(job, elevation).as_bytes(),
        Some(progress),
        None,
        None,
    )
    .await
}

/// The SSH exit status belongs to the wrapper, never to the command. Only a complete,
/// valid record delivered on a normally ended read can establish the command's outcome.
async fn exec_record(
    channel: &mut russh::Channel<client::Msg>,
    bytes: &[u8],
    progress: Option<&super::job_read::Read>,
    input: Option<&[u8]>,
    launch_timing: Option<&timings::Launch>,
) -> Result<Record, String> {
    // Beginning the channel send can enqueue bytes before its future resolves. From here
    // cancellation must conservatively retain possible transmission.
    if let Some(progress) = progress {
        progress.mark_sent();
    }
    if let Err(why) = channel.exec(true, bytes).await {
        if let Some(progress) = progress {
            progress.mark_interrupted();
        }
        return Err(format!("exec: {why}"));
    }
    if let Some(input) = input {
        channel
            .data(input)
            .await
            .map_err(|_| "AI key stdin transmission interrupted")?;
        channel
            .eof()
            .await
            .map_err(|_| "AI key stdin transmission interrupted")?;
    }
    let mut delivered = jobs::ReadDelivery::default();
    let mut refused = false;
    while let Some(message) = channel.wait().await {
        if matches!(&message, ChannelMsg::Success | ChannelMsg::Failure)
            && let Some(timing) = launch_timing
        {
            timing.observing();
        }
        match message {
            ChannelMsg::Failure => refused = true,
            ChannelMsg::Data { data } => delivered.stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => delivered.extended_data(&data),
            ChannelMsg::ExitStatus { exit_status } => delivered.status = Some(exit_status),
            ChannelMsg::Close => {
                delivered.closed = true;
                break;
            }
            _ => {}
        }
    }
    if !delivered.stderr.is_empty() {
        let local = crate::worker::local();
        let mut local = local.lock().await;
        let store = local.store().ok_or("locked before output scan")?;
        let safe = crate::redaction::Redacted::for_store(store, &delivered.stderr, &[])?;
        delivered.stderr = safe.as_bytes().to_vec();
    }
    // A normal Close without ExitStatus (including ExitSignal) is a read failure.
    // The collector separately checks whether the SSH connection itself closed.
    if !refused
        && !delivered.closed
        && let Some(progress) = progress
    {
        progress.mark_interrupted();
    }
    delivered.record()
}

async fn connect(
    pins: &impl PinSource,
    journal: &impl BoundJournal,
    session: &Session,
    target: &Target,
    stop: &std::rc::Rc<wait::Stop>,
    #[cfg(feature = "tracer")] tamper_auth: bool,
) -> Result<
    (
        client::Handle<PinCheck>,
        String,
        String,
        wait::SocketRegistration,
    ),
    Refusal,
> {
    stop.associate(&session.identity);
    let (target, _, stored_pin) = access(target).await.map_err(Refusal::Failed)?;
    let target = &target;
    // CHN-R4: with no pin there is nothing to check a key against, so nothing is contacted.
    let pinned = if target.stored {
        stored_pin
    } else {
        pins.pin(&target.machine)
    }
    .ok_or(Refusal::NoPin)?
    .0;
    if !journal.credentials_available() {
        return Err(Refusal::NoCredentials);
    }
    let Some(relay_key) = journal.relay_key().await else {
        return Err(Refusal::NoCredentials);
    };
    // Borrow the holding only while deriving the transport key, before any network wait.
    let ssh_key = {
        let ssh_key = session
            .client_key(&target.machine)
            .ok_or(Refusal::NoCredentials)?;
        PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&ssh_key.0)),
            "",
        )
        .map_err(|e| Refusal::Failed(format!("ssh client key: {e}")))?
    };

    let url = target.contact_url(Some(&pinned)).map_err(Refusal::Failed)?;
    let cycle = journal.command_cycle();
    let mut retries = 0;
    let mut not_before = 0.0;
    let (ws, socket, websocket) = loop {
        journal.current(session).await.map_err(Refusal::Journal)?;
        if stop.stopped() {
            return Err(Refusal::Journal("stale relay continuation".into()));
        }
        // A retry's back-off is waited out before the new websocket opens, without the host gate.
        let back_off = (not_before - relay_now()?).ceil();
        if back_off > 0.0 {
            relay_wait(back_off as i32, stop).await?;
        }
        let websocket_timing = Timer::new(cycle, Mark::WebsocketOpen);
        let (mut meta, mut ws) = WsMeta::connect(&url, None)
            .await
            .map_err(|e| Refusal::Transport(format!("relay websocket: {e}")))?;
        drop(websocket_timing);
        let relay_timing = Timer::new(cycle, Mark::RelayVerdict);
        journal.current(session).await.map_err(Refusal::Journal)?;
        let socket = stop.socket(meta.wrapped().clone());
        let mut events = meta
            .observe(ObserveConfig::default())
            .await
            .map_err(|e| Refusal::Transport(format!("relay events: {e}")))?;

        // WIR-4 (paid-tcp-relay 844e834): the challenge.
        let challenge = text_frame(&mut ws).await.map_err(failed("challenge"))?;
        let challenge = challenge["challenge"]
            .as_str()
            .ok_or_else(|| Refusal::Failed(format!("challenge: {challenge}")))?;

        // WIR-5 (paid-tcp-relay 844e834): the AUTH, signed by the relay key.
        let mut aux = [0u8; 32];
        getrandom::fill(&mut aux).map_err(|e| Refusal::Failed(format!("getrandom: {e}")))?;
        let created_at = (js_sys::Date::now() / 1000.0) as u64;
        #[cfg_attr(not(feature = "tracer"), allow(unused_mut))]
        let mut auth = crate::relay_auth::auth_event(
            &relay_key.0,
            &target.relay,
            challenge,
            &target.host,
            target.port,
            created_at,
            &aux,
        )
        .map_err(Refusal::Failed)?;
        #[cfg(feature = "tracer")]
        if tamper_auth {
            // The signature's first hex digit, so up to four of its bits: the event keeps its shape,
            // so only check 2 of paid-tcp-relay's `WIR-6` (844e834) fails.
            let sig = auth["sig"].as_str().expect("signed").to_string();
            let flipped = if sig.starts_with('0') { "1" } else { "0" };
            auth["sig"] = format!("{flipped}{}", &sig[1..]).into();
        }
        // The host gate covers only the spacing wait and the AUTH send: a connection that stalls
        // before its challenge never holds up other dials to the same host.
        let mut slot = relay_slot(&target.host, 0.0, stop).await?;
        journal.current(session).await.map_err(Refusal::Journal)?;
        if stop.stopped() {
            return Err(Refusal::Journal("stale relay continuation".into()));
        }
        *slot = Some(relay_now()?);
        ws.send(WsMessage::Text(auth.to_string()))
            .await
            .map_err(|e| Refusal::Transport(format!("AUTH: {e}")))?;
        // Completion is conservative: even a delayed flush cannot bunch two AUTHs together.
        *slot = Some(relay_now()?);
        drop(slot);

        // WIR-7 (paid-tcp-relay 844e834): `{"ok": true}` once the relay has dialed; anything else
        // ends the attempt.
        let verdict = text_frame(&mut ws).await.map_err(failed("relay verdict"))?;
        drop(relay_timing);
        if verdict["ok"] != json!(true) {
            let reason = verdict["reason"].as_str().unwrap_or_default().to_string();
            let mut close_code = None;
            while let Some(event) = events.next().await {
                if let WsEvent::Closed(close) = event {
                    close_code = Some(close.code);
                    break;
                }
            }
            if reason == "pace" && retries < 3 {
                // The refused socket is closed before another attempt. No TCP bytes, SSH or
                // command intent exist here. Back off 1.25, 2.5, then 5 seconds, without
                // replacing the caller's stop or extending its existing deadline.
                let _ = meta.wrapped().close();
                drop(ws);
                drop(meta);
                drop(socket);
                not_before = relay_now()? + f64::from(1_250 << retries);
                retries += 1;
                continue;
            }
            return Err(Refusal::Relay { reason, close_code });
        }
        break (ws, socket, meta.wrapped().clone());
    };

    // WIR-8 (paid-tcp-relay 844e834): from here on, binary frames carry the TCP bytes; SSH runs
    // over them.
    let presented = Arc::new(Mutex::new(None));
    let handler = PinCheck {
        pinned: pinned.clone(),
        presented: presented.clone(),
        generation: crate::lifecycle::owner().generation(),
        session: session.identity.clone(),
        cycle,
        handshake_started: None,
    };
    // ADR-0024: no keepalive and no inactivity timeout, which need a tokio timer the browser
    // does not have.
    let config = Arc::new(client::Config::default());
    journal.current(session).await.map_err(Refusal::Journal)?;
    let handler = PinCheck {
        handshake_started: cycle.and_then(|_| timings::now()),
        ..handler
    };
    let mut ssh =
        match client::connect_stream(config, super::relay_io::RelayIo(ws.into_io()), handler).await
        {
            Ok(ssh) => ssh,
            Err(e) => {
                let presented = presented.lock().expect("pin check lock").clone();
                return Err(match presented {
                    Some(presented) if presented != pinned => {
                        Refusal::HostKey { pinned, presented }
                    }
                    _ if websocket.ready_state() >= web_sys::WebSocket::CLOSING => {
                        Refusal::Transport(format!("ssh: {e}"))
                    }
                    _ => Refusal::Failed(format!("ssh: {e}")),
                });
            }
        };
    let host_key = presented
        .lock()
        .expect("pin check lock")
        .clone()
        .unwrap_or_default();

    journal.current(session).await.map_err(Refusal::Journal)?;
    let login_timing = Timer::new(cycle, Mark::Login);
    let auth = ssh
        .authenticate_publickey(
            target.user.clone(),
            PrivateKeyWithHashAlg::new(Arc::new(ssh_key), None),
        )
        .await
        .map_err(|e| {
            if ssh.is_closed() || websocket.ready_state() >= web_sys::WebSocket::CLOSING {
                Refusal::Transport(format!("authentication: {e}"))
            } else {
                Refusal::Failed(format!("authentication: {e}"))
            }
        })?;
    drop(login_timing);
    if !auth.success() {
        return Err(Refusal::Failed(format!("authentication refused: {auth:?}")));
    }
    #[cfg(feature = "tracer")]
    {
        crate::testonly::session_point("session_connected").await;
        if crate::testonly::rekey_session("session_connected") {
            ssh.rekey_soon()
                .await
                .map_err(|e| Refusal::Failed(format!("rekey: {e}")))?;
        }
    }
    journal.current(session).await.map_err(Refusal::Journal)?;
    Ok((ssh, pinned, host_key, socket))
}

/// The next frame, which the handshake requires to be a JSON text frame.
async fn text_frame(ws: &mut WsStream) -> Result<Value, String> {
    match ws.next().await {
        Some(WsMessage::Text(text)) => {
            serde_json::from_str(&text).map_err(|e| format!("{e}: {text}"))
        }
        Some(WsMessage::Binary(_)) => Err("a binary frame during the handshake".into()),
        None => Err("the relay closed the connection".into()),
    }
}

async fn resolve(
    journal: &mut impl BoundJournal,
    machine: &str,
    origin: Option<&std::rc::Rc<Session>>,
) -> Result<std::rc::Rc<Session>, Refusal> {
    journal
        .connection_session(machine, origin)
        .await
        .map_err(|refusal| match refusal {
            AdmissionRefusal::NoEntry => Refusal::NoEntry(machine.into()),
            AdmissionRefusal::Unbound => Refusal::Unbound(machine.into()),
            AdmissionRefusal::Journal(why) => Refusal::Journal(why),
        })
}

#[cfg(feature = "tracer")]
async fn ssh_point(ssh: &client::Handle<PinCheck>, point: &str) {
    crate::testonly::session_point(point).await;
    if crate::testonly::rekey_session(point) {
        ssh.rekey_soon().await.expect("fixture rekey request");
    }
}
