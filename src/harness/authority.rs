//! Public connection bindings, without SSH, model or session credentials.
use crate::allocation::MachinePassBinding;
use crate::store::{Storage, Store};

/// There is deliberately no authentication, job or command operation at this boundary.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) async fn identity_only<C, E, F>(
    handshake: impl std::future::Future<Output = Result<C, E>>,
    disconnect: impl FnOnce(C) -> F,
) -> Result<(), E>
where
    F: std::future::Future<Output = Result<(), E>>,
{
    let connection = handshake.await?;
    disconnect(connection).await
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttestProbe {
    pub purchase: String,
    pub machine: String,
    pub installation_binding: String,
    pub binding: MachinePassBinding,
    pub account: String,
    pub token_generation: u64,
}

/// Keeps the shared callback's session check intact while making probe admission explicit.
mod sealed {
    pub trait Sealed {}
    impl Sealed for str {}
    impl Sealed for String {}
    #[cfg(target_arch = "wasm32")]
    impl Sealed for super::ConnectionAuthority {}
}
pub trait ConnectionAdmission: sealed::Sealed {
    type Admitted;
    fn admit<S: Storage>(&self, store: &Store<S>) -> Result<Self::Admitted, String>;
}
impl ConnectionAdmission for str {
    type Admitted = std::rc::Rc<crate::binding::Session>;
    fn admit<S: Storage>(&self, store: &Store<S>) -> Result<Self::Admitted, String> {
        store.live_goal_session_id(self)
    }
}
impl ConnectionAdmission for String {
    type Admitted = std::rc::Rc<crate::binding::Session>;
    fn admit<S: Storage>(&self, store: &Store<S>) -> Result<Self::Admitted, String> {
        self.as_str().admit(store)
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
pub(crate) enum ConnectionAuthority {
    Session(String),
    AttestProbe {
        probe: AttestProbe,
        epoch: crate::poc::provisioning::browser::ProbeEpoch,
        live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    },
}
#[cfg(target_arch = "wasm32")]
impl ConnectionAdmission for ConnectionAuthority {
    type Admitted = ();
    fn admit<S: Storage>(&self, store: &Store<S>) -> Result<(), String> {
        match self {
            Self::Session(session) => store.live_goal_session_id(session).map(|_| ()),
            Self::AttestProbe { probe, epoch, live } => {
                epoch.check()?;
                if !live.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err("stale attest attempt".into());
                }
                store.vpsbg_probe_admit(probe, crate::hostcert::now_unix()?)
            }
        }
    }
}
