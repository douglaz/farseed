//! The limited service and TCP claim derives only from journaled declaration reads.
use crate::declaration::{Declaration, Field, From, Lifecycle, Protocol, Scope, Service};
use crate::delivery::{self, FieldId, FieldResult, Finding, Measured, ServiceFact, ServiceState};
use serde::{Deserialize, Serialize};

pub const DELIVERED: &str = "Delivered (service and TCP checks only)";
pub const FINDINGS: &str = "Handed over with findings";
pub const UNKNOWN: &str = "Findings unknown until a complete re-check";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Read {
    Running { service: Service },
    Enabled { service: Service },
    Listeners,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socket {
    pub proto: Protocol,
    pub port: u16,
    pub address: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Observation {
    Running(bool),
    Enabled(bool),
    Sockets(Vec<Socket>),
    Failed(String),
}
fn template(table: &str, key: &str) -> &'static str {
    let source = include_str!("../../spec/bundle/lockdown.toml");
    source
        .split(&format!("[read.{table}]\n"))
        .nth(1)
        .expect("pinned read table")
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key} = \"")))
        .and_then(|line| line.strip_suffix('"'))
        .expect("pinned read command")
}
impl Read {
    pub fn command(&self) -> String {
        match self {
            Self::Running { service } | Self::Enabled { service } => template(
                if matches!(self, Self::Running { .. }) {
                    "service_state"
                } else {
                    "service_enablement"
                },
                "system",
            )
            .replace("{name}", &format!("'{}'", service.name)),
            Self::Listeners => template("listeners_inbound", "command").into(),
        }
    }
    pub fn observe(&self, exit: u32, stdout: &str) -> Observation {
        match self {
            Self::Running { .. } if [0, 3, 4].contains(&exit) => {
                Observation::Running(matches!(stdout.trim(), "active" | "reloading"))
            }
            Self::Enabled { .. } if [0, 1, 4].contains(&exit) => {
                Observation::Enabled(stdout.trim() == "enabled")
            }
            Self::Listeners if exit == 0 => match sockets(stdout) {
                Ok(sockets) => Observation::Sockets(sockets),
                Err(why) => Observation::Failed(why),
            },
            _ => Observation::Failed(format!("Read {} exited with status {exit}", self.command())),
        }
    }
}

pub fn unstated(d: &Declaration) -> Option<&'static str> {
    let fields = [
        (
            "listeners.inbound",
            matches!(d.listeners.inbound, Field::Unspecified(_)),
        ),
        (
            "listeners.outbound",
            matches!(d.listeners.outbound, Field::Unspecified(_)),
        ),
        ("services", matches!(d.services, Field::Unspecified(_))),
        (
            "key_material.spendable",
            matches!(d.key_material.spendable, Field::Unspecified(_)),
        ),
        (
            "key_material.permitted",
            matches!(d.key_material.permitted, Field::Unspecified(_)),
        ),
        (
            "drift_checks",
            matches!(d.drift_checks, Field::Unspecified(_)),
        ),
        ("required", matches!(d.required, Field::Unspecified(_))),
        (
            "default_credentials",
            matches!(d.default_credentials, Field::Unspecified(_)),
        ),
    ];
    fields
        .into_iter()
        .find_map(|(name, missing)| missing.then_some(name))
}
pub fn proposal(value: &serde_json::Value) -> Result<Declaration, String> {
    let declaration = Declaration::parse(value)?;
    declaration.validate_ad_hoc_minimum()?;
    if let Some(name) = unstated(&declaration) {
        return Err(format!("{name}: not stated"));
    }
    if let Field::Value(services) = &declaration.services
        && services.iter().any(|s| s.scope != Scope::System)
    {
        return Err("user-scope services are not supported in this PoC".into());
    }
    Ok(declaration)
}
pub fn reads(d: &Declaration) -> Result<Vec<Read>, String> {
    let mut reads = Vec::new();
    if let Field::Value(services) = &d.services {
        for service in services {
            if service.scope != Scope::System {
                return Err("user-scope services cannot be read in this PoC".into());
            }
            reads.push(Read::Running {
                service: service.clone(),
            });
            if service.lifecycle == Lifecycle::EnabledSurvivesReboot {
                reads.push(Read::Enabled {
                    service: service.clone(),
                });
            }
        }
    }
    reads.push(Read::Listeners);
    Ok(reads)
}
fn sockets(stdout: &str) -> Result<Vec<Socket>, String> {
    let mut sockets = Vec::new();
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 6 {
            return Err("Listener read has an unsupported row".into());
        }
        let proto = match (fields[0], fields[1]) {
            ("tcp", "LISTEN") => Protocol::Tcp,
            ("udp", "UNCONN") => Protocol::Udp,
            _ => return Err("Listener read has an unsupported protocol or state".into()),
        };
        let (address, port) = fields[4]
            .rsplit_once(':')
            .ok_or("Listener address has no port")?;
        let address = address.split('%').next().unwrap_or_default();
        let address = address.trim_start_matches('[').trim_end_matches(']');
        if address != "*" && address.parse::<std::net::IpAddr>().is_err() {
            return Err("Listener address is not numeric".into());
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| "Listener port is invalid")?;
        if port == 0 {
            return Err("Listener port is zero".into());
        }
        sockets.push(Socket {
            proto,
            port,
            address: address.into(),
        });
    }
    Ok(sockets)
}
fn result(field: FieldId, status: delivery::Status) -> FieldResult {
    FieldResult {
        field,
        status,
        findings: vec![],
        notes: vec![],
    }
}
fn finding(result: &mut FieldResult, detail: String) {
    result.status = delivery::Status::Finding;
    result.findings.push(Finding {
        field: result.field,
        detail,
        service: None,
    });
}

/// Missing observations retain standing findings. Only a complete attempt may clear them.
pub fn judge(
    d: &Declaration,
    plan: &[Read],
    observations: &[Option<Observation>],
    standing: &[Finding],
) -> delivery::ResultSet {
    let mut measurements = delivery::Measurements::missing();
    let mut facts = Vec::new();
    let mut services_unsettled = false;
    if let Field::Value(services) = &d.services {
        for (index, service) in services.iter().enumerate() {
            // Repeated declarations share one fact, but every scheduled read still binds it.
            if services[..index].contains(service) {
                continue;
            }
            let observed = |expected: &Read| {
                plan.iter()
                    .enumerate()
                    .filter(|(_, read)| *read == expected)
                    .map(|(index, _)| observations.get(index).and_then(Option::as_ref))
                    .collect::<Vec<_>>()
            };
            let running = observed(&Read::Running {
                service: service.clone(),
            });
            let enabled = observed(&Read::Enabled {
                service: service.clone(),
            });
            let unsettled = running.is_empty()
                || running.iter().any(Option::is_none)
                || service.lifecycle == Lifecycle::EnabledSurvivesReboot
                    && (enabled.is_empty() || enabled.iter().any(Option::is_none));
            services_unsettled |= unsettled;
            let differs = running
                .iter()
                .flatten()
                .any(|observation| !matches!(observation, Observation::Running(true)))
                || service.lifecycle == Lifecycle::EnabledSurvivesReboot
                    && enabled
                        .iter()
                        .flatten()
                        .any(|observation| !matches!(observation, Observation::Enabled(true)));
            // Missing evidence holds completion without hiding a measured failure beside it.
            if unsettled && !differs {
                continue;
            }
            let running = running
                .iter()
                .all(|observation| matches!(observation, Some(Observation::Running(true))));
            let enabled = enabled
                .iter()
                .all(|observation| matches!(observation, Some(Observation::Enabled(true))))
                .then_some(Observation::Enabled(true));
            let state = if running && service.lifecycle == Lifecycle::RunningAtDelivery {
                ServiceState::Running
            } else if running && matches!(enabled, Some(Observation::Enabled(true))) {
                ServiceState::EnabledRestartNotDemonstrated
            } else {
                ServiceState::Difference
            };
            facts.push(ServiceFact {
                service: service.clone(),
                state,
                running_after_last_placement: running,
            });
        }
    }
    measurements.services = Measured::Value(facts);
    let mut fields: Vec<_> = delivery::fields(
        &delivery::Intended::from(d),
        crate::dispatch::MachineClass::SinglePurpose,
        &measurements,
        standing,
    )
    .into_iter()
    .filter(|r| r.field == FieldId::Services)
    .collect();
    let mut inbound = result(FieldId::Inbound, delivery::Status::Unavailable);
    if let Some(observation) = plan
        .iter()
        .zip(observations)
        .find_map(|(read, observation)| {
            matches!(read, Read::Listeners)
                .then_some(observation.as_ref())
                .flatten()
        })
    {
        match observation {
            Observation::Sockets(sockets) => {
                inbound.status = delivery::Status::Checked;
                if let Field::Value(allowed) = &d.listeners.inbound {
                    for socket in sockets.iter().filter(|s| s.proto == Protocol::Tcp) {
                        let matching: Vec<_> = allowed
                            .iter()
                            .filter(|a| a.proto == socket.proto && a.port == socket.port)
                            .collect();
                        if matching.is_empty() {
                            finding(
                                &mut inbound,
                                format!(
                                    "Something answers on tcp port {} that the declaration does not list",
                                    socket.port
                                ),
                            );
                        } else if matching.iter().all(|a| a.from == From::None)
                            && !socket
                                .address
                                .parse::<std::net::IpAddr>()
                                .is_ok_and(|ip| ip.is_loopback())
                        {
                            finding(
                                &mut inbound,
                                format!(
                                    "tcp port {} is declared local-only but listens on {}",
                                    socket.port, socket.address
                                ),
                            );
                        }
                    }
                } else {
                    inbound.status = delivery::Status::Blocked;
                }
            }
            Observation::Failed(why) => finding(&mut inbound, why.clone()),
            _ => inbound.status = delivery::Status::Unavailable,
        }
    }
    fields.push(inbound);
    let mut result = delivery::aggregate_selected(
        &[FieldId::Services, FieldId::Inbound],
        fields,
        standing,
        true,
    );
    if unstated(d).is_some()
        || services_unsettled
        || plan.len() != observations.len()
        || observations.iter().any(Option::is_none)
    {
        result.complete = false;
        result.delivered = false;
        result.findings_unknown = true;
        for old in standing {
            if !result.findings.contains(old) {
                result.findings.push(old.clone());
            }
        }
    }
    result
}
