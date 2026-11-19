//! Pending access is separate from handoff. Only the certificate acceptance supplies a pin.
use super::*;
use crate::harness::AttestProbe;
use crate::poc::targets::TargetRecord;

pub(crate) const ATTEST_INTERVAL_MS: u32 = 5_000;

#[derive(Default)]
pub(crate) struct AttestPace {
    busy: bool,
    next_ms: u64,
}
impl AttestPace {
    pub(crate) fn begin(&mut self, now_ms: u64, deadline: u64) -> Option<u32> {
        if self.busy || now_ms < self.next_ms {
            return None;
        }
        let remaining = deadline.checked_mul(1000)?.checked_sub(now_ms)?;
        if remaining == 0 {
            return None;
        }
        self.next_ms = now_ms.checked_add(u64::from(ATTEST_INTERVAL_MS))?;
        self.busy = true;
        Some(remaining.min(15_000) as u32)
    }
    pub(crate) fn finish(&mut self) {
        self.busy = false;
    }
}

pub(crate) fn probe_budget_ms(now_ms: u64, deadline: u64) -> Option<u32> {
    let remaining = deadline.checked_mul(1000)?.checked_sub(now_ms)?;
    (remaining > 0).then_some(remaining.min(15_000) as u32)
}

impl<S: Storage> Store<S> {
    /// Effective pins on this path can only come from piece (a)'s committed acceptance.
    pub(crate) fn vpsbg_accepted(&self, purchase: &str) -> bool {
        let Some(p) = self.vpsbg_purchase(purchase) else {
            return false;
        };
        let Some(s) = self.vpsbg_purchases.get(purchase) else {
            return false;
        };
        s.closed_at.is_none()
            && s.attest_target.as_ref().is_some_and(|pending| {
                pending.pin.is_empty()
                    && self.poc_target(&p.machine) == Some(pending)
                    && self.attest_installation_binding(&p.machine).is_ok()
                    && self
                        .attest_target(&p.machine)
                        .is_some_and(|t| !t.pin.is_empty())
            })
    }

    pub(in crate::store) fn vpsbg_is_ready(&self, p: &provisioning::Purchase) -> bool {
        p.vendor == Vendor::Vpsbg
            && p.vpsbg.as_ref().is_some_and(|v| {
                self.vpsbg_purchases.get(&v.purchase).is_some_and(|s| {
                    s.ready_at.is_some()
                        && p.target == s.attest_target
                        && self.vpsbg_accepted(&v.purchase)
                })
            })
    }

    pub(crate) fn vpsbg_session_ready(&self, machine: &str) -> Result<(), String> {
        if self.vpsbg_machine_known(machine)
            && !self
                .vpsbg_history()
                .any(|p| p.machine == machine && self.vpsbg_is_ready(p))
        {
            return Err("The VPSBG machine has not completed certificate readiness.".into());
        }
        Ok(())
    }

    pub(super) fn vpsbg_introduction_view(&self, purchase: &str, now: u64) -> Value {
        let Some(p) = self.vpsbg_purchase(purchase) else {
            return Value::Null;
        };
        let Some(s) = self.vpsbg_purchases.get(purchase) else {
            return Value::Null;
        };
        if s.associated.is_none() {
            return Value::Null;
        }
        let Some(deadline) = self.attest_deadline(&p.machine) else {
            return Value::Null;
        };
        json!({"state":if self.vpsbg_accepted(purchase) {"accepted"}
            else if now >= deadline {"expired"} else {"waiting"}, "deadline":deadline})
    }

    pub(crate) fn vpsbg_probe_current(&self, probe: &AttestProbe) -> Result<(), String> {
        self.procurement_ready()?;
        let p = self
            .vpsbg_purchase(&probe.purchase)
            .ok_or(protocol::REFUSED)?;
        let s = self
            .vpsbg_purchases
            .get(&probe.purchase)
            .ok_or(protocol::REFUSED)?;
        let token = self.vpsbg_token.as_ref().ok_or(protocol::REFUSED)?;
        let v = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?;
        if p.machine != probe.machine
            || v.binding != probe.binding
            || p.account != probe.account
            || p.origin != wire::ORIGIN
            || token.account != p.account
            || token.generation != probe.token_generation
            || s.closed_at.is_some()
            || s.ready_at.is_some()
            || self.attest_installation_binding(&p.machine)? != probe.installation_binding
            || s.attest_target.as_ref() != self.poc_target(&p.machine)
            || s.attest_target.is_none()
            || self.bound_machine_relay(&p.machine)?.binding != probe.binding
        {
            return Err(protocol::REFUSED.into());
        }
        let detail = s.observed.as_ref().ok_or(protocol::REFUSED)?;
        let pending = s.attest_target.as_ref().ok_or(protocol::REFUSED)?;
        if detail.server.status != wire::ServerStatus::Active
            || detail.public_ipv4.map(|ip| ip.to_string()).as_deref() != Some(pending.host.as_str())
            || detail
                .state
                .as_ref()
                .is_some_and(|state| state.cloud_init_failed == Some(true))
            || (s.associated.as_ref().is_none_or(|(_, paid)| paid.is_none())
                && s.order_paid.is_none())
        {
            return Err("The VPSBG machine is not ready for certificate contact.".into());
        }
        Ok(())
    }

    pub(crate) fn vpsbg_probe_admit(&self, probe: &AttestProbe, now: u64) -> Result<(), String> {
        self.vpsbg_probe_current(probe)?;
        if !self.vpsbg_accepted(&probe.purchase) {
            let intro = self
                .attest_introduction(&probe.machine, now)
                .ok_or("attest introduction unavailable or expired")?;
            if intro.installation_binding != probe.installation_binding {
                return Err(protocol::REFUSED.into());
            }
        }
        Ok(())
    }

    pub(crate) fn vpsbg_probe_authority(
        &self,
        purchase: &str,
        now: u64,
    ) -> Result<AttestProbe, String> {
        let p = self.vpsbg_purchase(purchase).ok_or(protocol::REFUSED)?;
        let token = self.vpsbg_token.as_ref().ok_or(protocol::REFUSED)?;
        let probe = AttestProbe {
            purchase: purchase.into(),
            machine: p.machine.clone(),
            installation_binding: self.attest_installation_binding(&p.machine)?,
            binding: p.vpsbg.as_ref().ok_or(protocol::REFUSED)?.binding.clone(),
            account: p.account.clone(),
            token_generation: token.generation,
        };
        self.vpsbg_probe_admit(&probe, now)?;
        Ok(probe)
    }

    pub(super) fn vpsbg_project_readiness(&self, record: &Record) -> Result<Projection, String> {
        let mut p = self
            .vpsbg_purchase(&record.purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        let mut s = self
            .vpsbg_purchases
            .get(&record.purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        if s.closed_at.is_some() || s.ready_at.is_some() {
            return Err(protocol::REFUSED.into());
        }
        match &record.change {
            Change::AttestTarget {
                target,
                server_id,
                introduction_binding,
                checked_at,
            } => {
                let v = p.vpsbg.as_ref().ok_or(protocol::REFUSED)?;
                let detail = s.observed.as_ref().ok_or(protocol::REFUSED)?;
                let associated = s.associated.as_ref().ok_or(protocol::REFUSED)?;
                let intro = self
                    .attest_introduction(&p.machine, *checked_at)
                    .ok_or(protocol::REFUSED)?;
                let expected = TargetRecord {
                    machine: p.machine.clone(),
                    relay: p.relay.clone(),
                    profile: "v1".into(),
                    host: detail.public_ipv4.ok_or(protocol::REFUSED)?.to_string(),
                    port: 22,
                    user: "nixos".into(),
                    elevation: crate::jobs::Elevation::SudoNoninteractive,
                    pin: String::new(),
                };
                crate::poc::targets::Target {
                    machine: expected.machine.clone(),
                    relay: expected.relay.clone(),
                    profile: expected.profile.clone(),
                    host: expected.host.clone(),
                    port: expected.port,
                    user: expected.user.clone(),
                    stored: true,
                }
                .attest_contact_url(intro, *checked_at)?;
                if target != &expected
                    || s.attest_target.is_some()
                    || p.target.is_some()
                    || self.poc_target(&p.machine).is_some()
                    || *checked_at < p.approved_at
                    || *server_id != associated.0.ack().id
                    || *server_id != detail.server.id
                    || introduction_binding != &intro.installation_binding
                    || introduction_binding != &self.attest_installation_binding(&p.machine)?
                    || v.binding.machine != p.machine
                    || v.binding.machine_identity != p.identity
                    || v.binding.pass_identity != p.relay_identity
                    || self
                        .allocation()
                        .machine_pass_bindings()
                        .iter()
                        .filter(|b| *b == &v.binding)
                        .count()
                        != 1
                {
                    return Err(protocol::REFUSED.into());
                }
                s.attest_target = Some(target.clone());
            }
            Change::Ready { accepted_at } => {
                if !self.vpsbg_accepted(&record.purchase) || *accepted_at < p.approved_at {
                    return Err(protocol::REFUSED.into());
                }
                p.target = s.attest_target.clone();
                s.ready_at = Some(*accepted_at);
            }
            _ => return Err(protocol::REFUSED.into()),
        }
        Ok(Projection {
            purchase: p,
            state: s,
            allocations: None,
        })
    }

    /// Detail refresh and pending access commit happen while Browser owns the writer.
    pub(crate) async fn vpsbg_prepare_attest(
        &mut self,
        api: &mut impl protocol::Api,
        purchase: &str,
    ) -> Result<Option<AttestProbe>, String> {
        self.vpsbg_api(api, Some(purchase))?;
        if self.vpsbg_accepted(purchase) {
            self.vpsbg_mark_ready(purchase, api.now()).await?;
            return Ok(None);
        }
        if self
            .vpsbg_purchases
            .get(purchase)
            .is_none_or(|s| s.closed_at.is_some())
        {
            return Err(protocol::REFUSED.into());
        }
        let p = self.vpsbg_purchase(purchase).ok_or(protocol::REFUSED)?;
        if self
            .attest_deadline(&p.machine)
            .is_some_and(|end| api.now() >= end)
        {
            return Err("attest introduction expired".into());
        }
        api.vpsbg_begin_window()?;
        self.vpsbg_reconcile_create(api, purchase).await?;
        let p = self
            .vpsbg_purchase(purchase)
            .ok_or(protocol::REFUSED)?
            .clone();
        let s = &self.vpsbg_purchases[purchase];
        if s.attest_target.is_none()
            && let Some(detail) = &s.observed
            && let Some(ip) = detail.public_ipv4
        {
            let binding = self.attest_installation_binding(&p.machine)?;
            self.vpsbg_commit(
                purchase,
                Change::AttestTarget {
                    target: TargetRecord {
                        machine: p.machine.clone(),
                        relay: p.relay.clone(),
                        profile: "v1".into(),
                        host: ip.to_string(),
                        port: 22,
                        user: "nixos".into(),
                        elevation: crate::jobs::Elevation::SudoNoninteractive,
                        pin: String::new(),
                    },
                    server_id: detail.server.id,
                    introduction_binding: binding,
                    checked_at: api.now(),
                },
            )
            .await?;
        }
        self.vpsbg_api(api, Some(purchase))?;
        // Processing/no address/cloud-init failure stays concrete and read-only; active isn't identity.
        let detail = self.vpsbg_purchases[purchase]
            .observed
            .as_ref()
            .ok_or("Waiting for the associated VPSBG server detail.")?;
        if detail.public_ipv4.is_none() {
            return Err("Waiting for the VPSBG machine's main public IPv4.".into());
        }
        if detail
            .state
            .as_ref()
            .is_some_and(|s| s.cloud_init_failed == Some(true))
        {
            return Err("VPSBG reports cloud_init_failed; certificate readiness is paused.".into());
        }
        if detail.server.status != wire::ServerStatus::Active {
            return Err("Waiting for VPSBG to report the associated machine active.".into());
        }
        self.vpsbg_probe_authority(purchase, api.now()).map(Some)
    }

    pub(crate) async fn vpsbg_mark_ready(
        &mut self,
        purchase: &str,
        now: u64,
    ) -> Result<(), String> {
        self.procurement_ready()?;
        if self
            .vpsbg_purchases
            .get(purchase)
            .is_some_and(|s| s.ready_at.is_some())
        {
            return if self.vpsbg_accepted(purchase) {
                Ok(())
            } else {
                Err(protocol::REFUSED.into())
            };
        }
        self.vpsbg_commit(purchase, Change::Ready { accepted_at: now })
            .await
    }

    pub(crate) fn vpsbg_relay_admitted(
        &mut self,
        probe: &AttestProbe,
        now: u64,
    ) -> Result<(), String> {
        self.vpsbg_probe_admit(probe, now)?;
        self.vpsbg_reads
            .relay_admitted
            .insert((probe.purchase.clone(), probe.machine.clone()));
        Ok(())
    }

    pub(in crate::store) fn vpsbg_machine_view(
        &self,
        view: &mut Value,
        p: &provisioning::Purchase,
        now: u64,
    ) {
        let Some(v) = &p.vpsbg else { return };
        let Some(s) = self.vpsbg_purchases.get(&v.purchase) else {
            return;
        };
        view["purchase"] = json!(v.purchase);
        view["introduction"] = self.vpsbg_introduction_view(&v.purchase, now);
        view["trust"] = json!({"route":"AttestCertificate","residual":"VPS.BG boots the image it downloaded; the page cannot check those bytes."});
        let paid_until = s
            .observed
            .as_ref()
            .map(|d| d.server.expiry_at)
            .or_else(|| s.associated.as_ref().map(|(a, _)| a.ack().expiry_at));
        view["vm_id"] = json!(s.associated.as_ref().map(|(a, _)| a.ack().id));
        view["paid_until"] = json!(paid_until);
        view["renewal"] = json!(match s.observed.as_ref().and_then(|d| d.auto_renew) {
            Some(true) => "on",
            Some(false) => "off",
            None => "unknown",
        });
        if let Some(pin) = self.attest_target(&p.machine).filter(|t| !t.pin.is_empty()) {
            view["effective_pin"] = json!(pin.pin);
        }
        // Local issuance is the atomic reservation of this pass, including a replacement.
        // Relay2's operator may grant a shorter interval; its verdict alone marks admission.
        if let Some(expiry) = s
            .pass_issued_at
            .checked_add(31 * 86400)
            .map(|end| paid_until.map_or(end, |paid| paid.min(end)))
            && let Some(key) = self.relay_key(&p.machine)
        {
            view["relay_pass"] = json!({"key":hex::encode(key.public_key()),"host":s.observed.as_ref().and_then(|d| d.public_ipv4).map(|ip| ip.to_string()),"expiry":expiry,
                "state":if self.vpsbg_reads.relay_admitted.contains(&(v.purchase.clone(), p.machine.clone())) {"admitted"} else {"needed"}});
        }
    }

    pub(in crate::store) fn vpsbg_tombstoned_entry(
        &self,
        machine: &str,
        identity: &Identity,
    ) -> bool {
        self.vpsbg_purchases.iter().any(|(id, s)| {
            s.replaced
                .iter()
                .any(|b| b.machine == machine && &b.machine_identity == identity)
                || (s.closed_at.is_some()
                    && self
                        .vpsbg_purchase(id)
                        .is_some_and(|p| p.machine == machine && &p.identity == identity))
        }) && self.allocation().entries().iter().any(|e| {
            &e.identity == identity
                && matches!(
                    e.status,
                    allocation::Status::Failed | allocation::Status::Destroyed
                )
        })
    }
}
