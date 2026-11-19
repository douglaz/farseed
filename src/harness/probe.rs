//! Identity-only caller of the shared handshake: no Session, client key, authentication or job.
use super::*;
use crate::harness::{AttestProbe, ConnectionAuthority};
use std::sync::atomic::{AtomicBool, Ordering};
use wasm_bindgen::{JsCast, closure::Closure};

thread_local! {
    static ACTIVE_PROBE: RefCell<Option<(std::rc::Weak<wait::Stop>, Arc<AtomicBool>)>> = const { RefCell::new(None) };
}

pub(crate) fn stop_probe() {
    ACTIVE_PROBE.with_borrow(|active| {
        if let Some((stop, live)) = active {
            live.store(false, Ordering::SeqCst);
            if let Some(stop) = stop.upgrade() {
                stop.fire();
            }
        }
    });
}

struct ProbeJournal {
    authority: ConnectionAuthority,
}
impl HandshakeJournal for ProbeJournal {
    async fn current(&self, _: &HandshakeAuthority) -> Result<(), String> {
        let shared = crate::worker::local();
        let mut local = shared.lock().await;
        local
            .store()
            .ok_or("locked before attest probe")?
            .live_goal_session(&self.authority)
    }
    async fn relay_key(&self, machine: &str) -> Option<crate::credential::RelayKey> {
        let shared = crate::worker::local();
        let mut local = shared.lock().await;
        let store = local.store()?;
        store.live_goal_session(&self.authority).ok()?;
        let ConnectionAuthority::AttestProbe { probe, .. } = &self.authority else {
            return None;
        };
        (machine == probe.machine)
            .then(|| store.relay_key(machine))
            .flatten()
    }
    fn credentials_available(&self) -> bool {
        true
    }
    fn command_cycle(&self) -> Option<u64> {
        None
    }
    async fn relay_admitted(&self, _: &HandshakeAuthority) -> Result<(), String> {
        let shared = crate::worker::local();
        let mut local = shared.lock().await;
        let store = local.store().ok_or("locked before relay admission")?;
        store.live_goal_session(&self.authority)?;
        let ConnectionAuthority::AttestProbe { probe, .. } = &self.authority else {
            return Err("invalid probe authority".into());
        };
        store.vpsbg_relay_admitted(probe, crate::hostcert::now_unix()?)
    }
}

struct Attempt {
    live: Arc<AtomicBool>,
    stop: std::rc::Rc<wait::Stop>,
    worker: web_sys::WorkerGlobalScope,
    timer: i32,
    _callback: Closure<dyn FnMut()>,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        self.live.store(false, Ordering::SeqCst);
        self.stop.fire();
        self.worker.clear_timeout_with_handle(self.timer);
        ACTIVE_PROBE.with_borrow_mut(|p| *p = None);
    }
}

pub async fn probe_attest(
    purchase: &str,
    machine: &str,
    installation_binding: &str,
    stop: &std::rc::Rc<wait::Stop>,
) -> Result<(), Refusal> {
    let epoch =
        crate::poc::provisioning::browser::ProbeEpoch::capture().map_err(Refusal::Journal)?;
    let (probe, target, pins, deadline) = {
        let shared = crate::worker::local();
        let mut local = shared.lock().await;
        epoch.check().map_err(Refusal::Journal)?;
        let store = local
            .store()
            .ok_or_else(|| Refusal::Journal("locked before attest probe".into()))?;
        let probe: AttestProbe = store
            .vpsbg_probe_authority(
                purchase,
                crate::hostcert::now_unix().map_err(Refusal::Failed)?,
            )
            .map_err(Refusal::Journal)?;
        if probe.machine != machine || probe.installation_binding != installation_binding {
            return Err(Refusal::Journal("attest probe binding differs".into()));
        }
        let (target, pins) =
            crate::poc::targets::resolve(store, machine).map_err(Refusal::Failed)?;
        let deadline = store.attest_deadline(machine).ok_or(Refusal::NoPin)?;
        (probe, target, pins, deadline)
    };
    let ms = crate::store::vpsbg::readiness::probe_budget_ms(js_sys::Date::now() as u64, deadline)
        .ok_or_else(|| Refusal::Attest {
            why: "attest introduction expired".into(),
            deadline_unix: Some(deadline),
        })?;
    if ACTIVE_PROBE.with_borrow(|active| active.is_some()) {
        return Err(Refusal::Journal("attest probe already running".into()));
    }
    let live = Arc::new(AtomicBool::new(true));
    let authority = ConnectionAuthority::AttestProbe {
        probe,
        epoch,
        live: live.clone(),
    };
    let journal = ProbeJournal {
        authority: authority.clone(),
    };
    let worker: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let weak = std::rc::Rc::downgrade(stop);
    let timed_live = live.clone();
    let callback = Closure::<dyn FnMut()>::new(move || {
        timed_live.store(false, Ordering::SeqCst);
        if let Some(stop) = weak.upgrade() {
            stop.fire();
        }
    });
    let timer = worker
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            callback.as_ref().unchecked_ref(),
            ms as i32,
        )
        .map_err(|_| Refusal::Failed("attest timer unavailable".into()))?;
    ACTIVE_PROBE
        .with_borrow_mut(|active| *active = Some((std::rc::Rc::downgrade(stop), live.clone())));
    let _attempt = Attempt {
        live,
        stop: stop.clone(),
        worker,
        timer,
        _callback: callback,
    };
    let authority = HandshakeAuthority {
        identity: authority,
    };
    let work = crate::harness::identity_only(
        handshake(
            &pins,
            &journal,
            &authority,
            &target,
            stop,
            |_| Ok(()),
            #[cfg(feature = "tracer")]
            false,
        ),
        |(ssh, _, _, socket, _, _, ())| async move {
            // Close at the identity boundary. Never call authenticate, channel_open or exec.
            let _ = ssh
                .disconnect(
                    russh::Disconnect::ByApplication,
                    "identity probe complete",
                    "",
                )
                .await;
            drop(ssh);
            drop(socket);
            Ok(())
        },
    );
    stop.until(work).await.unwrap_or_else(|| {
        Err(Refusal::Attest {
            why: "attest attempt interrupted or timed out".into(),
            deadline_unix: Some(deadline),
        })
    })
}
