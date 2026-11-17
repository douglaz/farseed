//! The limited delivery claim derives only from journaled harness reads.
use crate::declaration::{Declaration, Field, From, Lifecycle, Protocol, Scope, Service};
use crate::delivery::{self, FieldId, FieldResult, Finding, Measured, ServiceFact, ServiceState};
use serde::{Deserialize, Serialize};

pub const DELIVERED: &str = "Delivered (service and TCP checks only)";
pub const DELIVERED_SIGN_IN: &str = "Delivered (service, TCP and sign-in checks only)";
pub const DELIVERED_CONTROL_CENTER: &str =
    "Delivered (service, TCP, sign-in and control-center checks only)";
pub const FINDINGS: &str = "Handed over with findings";
pub const UNKNOWN: &str = "Findings unknown until a complete re-check";

// The spec's read tables don't cover this visit yet.
const SIGN_IN_COMMAND: &str = r#"(visit=$(curl -q --silent --show-error --location --max-redirs 5 --insecure --max-time {timeout} --max-filesize 1048576 --proto '=http,https' --proto-redir '=http,https' --disallow-username-in-url --proxy '' --noproxy '' {proxy} --write-out '\nTAU_SIGN_IN %{http_code} %{url_effective}\n' -- {url}); curl_status=$?; printf '%s\n' "$visit" | LC_ALL=C awk 'NR > 1 { body = body previous "\n" } { previous = $0 } END { if (previous !~ /^TAU_SIGN_IN [0-9][0-9][0-9] https?:\/\//) exit 1; split(previous, meta, " "); path = meta[3]; sub(/^[^:]+:\/\/[^\/?#]*/, "", path); sub(/[?#].*$/, "", path); if (path == "") path = "/"; password = "no"; body = tolower(body); while (match(body, /<input[[:space:]][^>]*>/)) { tag = substr(body, RSTART, RLENGTH); if (tag ~ /[[:space:]]type[[:space:]]*=[[:space:]]*("password"|\047password\047|password[[:space:]\/>])/) password = "yes"; body = substr(body, RSTART + RLENGTH) } printf "%s %s\npassword_form %s\n", meta[2], path, password }'; parse_status=$?; [ "$curl_status" -eq 0 ] || exit "$curl_status"; exit "$parse_status")"#;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Read {
    Running { service: Service },
    Enabled { service: Service },
    Listeners,
    SignIn { url: String },
    ControlCenter { hashes: [String; 2] },
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
    SignIn {
        code: u16,
        path: String,
        password_input: bool,
    },
    SignInUnreachable,
    ControlCenter {
        passed: bool,
        names: Vec<String>,
        checks_failed: bool,
    },
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
            Self::ControlCenter { hashes } => format!(
                "printf '%s  /etc/nixos/cc-rebuild.sh\\n%s  /etc/nixos/cc-check.sh\\n' {} {} | sha256sum -c --quiet && sh /etc/nixos/cc-check.sh done",
                hashes[0], hashes[1]
            ),
            Self::SignIn { url } => {
                #[cfg(target_arch = "wasm32")]
                let host = web_sys::Url::new(url)
                    .expect("validated delivered URL")
                    .hostname();
                #[cfg(not(target_arch = "wasm32"))]
                let host = url
                    .split_once("://")
                    .expect("validated delivered URL")
                    .1
                    .split(['/', '?', '#', ':'])
                    .next()
                    .unwrap_or_default();
                let onion = host.to_ascii_lowercase().ends_with(".onion");
                SIGN_IN_COMMAND
                    .replace(
                        "{proxy}",
                        if onion {
                            "--socks5-hostname 127.0.0.1:9050"
                        } else {
                            ""
                        },
                    )
                    .replace("{timeout}", if onion { "45" } else { "15" })
                    .replace("{url}", &format!("'{}'", url.replace('\'', "'\\''")))
            }
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
            Self::SignIn { .. } => sign_in(exit, stdout),
            Self::ControlCenter { .. } => {
                let passed =
                    exit == 0 && super::template::last_line(stdout).starts_with("CHECKS done PASS");
                let names = stdout
                    .lines()
                    .filter_map(|line| {
                        let rest = line.strip_prefix("CHECK ")?;
                        let (name, _) = rest.split_once(" FAIL")?;
                        (name.len() <= 64
                            && !name.is_empty()
                            && name
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)))
                        .then(|| name.to_owned())
                    })
                    .take(8)
                    .collect();
                let checks_failed = stdout
                    .lines()
                    .any(|line| line.starts_with("CHECKS done FAIL"));
                Observation::ControlCenter {
                    passed,
                    names,
                    checks_failed,
                }
            }
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
    super::proposal::structure(value)?;
    let declaration =
        Declaration::parse(value).map_err(|why| super::proposal::semantic(value, &why))?;
    declaration
        .validate_ad_hoc_minimum()
        .map_err(|why| super::proposal::semantic(value, &why))?;
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
    reads_for_urls(d, &[])
}
pub fn reads_for_urls(
    d: &Declaration,
    urls: &[crate::goals::DeliveredUrl],
) -> Result<Vec<Read>, String> {
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
    reads.extend(urls.iter().map(|delivered| Read::SignIn {
        url: delivered.url.clone(),
    }));
    Ok(reads)
}

fn sign_in(exit: u32, stdout: &str) -> Observation {
    if exit != 0 {
        return Observation::SignInUnreachable;
    }
    let mut lines = stdout.lines();
    let parsed = (|| {
        let (code, path) = lines.next()?.split_once(' ')?;
        if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let code = code.parse::<u16>().ok()?;
        if !(100..=999).contains(&code)
            || !path.starts_with('/')
            || path.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return None;
        }
        let password_input = match lines.next()? {
            "password_form yes" => true,
            "password_form no" => false,
            _ => return None,
        };
        if lines.next().is_some() {
            return None;
        }
        Some(Observation::SignIn {
            code,
            path: path.into(),
            password_input,
        })
    })();
    parsed.unwrap_or(Observation::SignInUnreachable)
}

fn login_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.match_indices('/').any(|(index, _)| {
        [
            "login", "signin", "sign-in", "sign_in", "auth", "oauth", "session",
        ]
        .into_iter()
        .any(|name| {
            path[index + 1..].strip_prefix(name).is_some_and(|tail| {
                tail.chars()
                    .next()
                    .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
            })
        })
    })
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
    let mut required = vec![FieldId::Services, FieldId::Inbound];
    if plan.iter().any(|read| matches!(read, Read::SignIn { .. })) {
        required.push(FieldId::SignIn);
        let mut sign_in = result(FieldId::SignIn, delivery::Status::Checked);
        for (index, read) in plan.iter().enumerate() {
            let Read::SignIn { url } = read else { continue };
            let detail = match observations.get(index).and_then(Option::as_ref) {
                None => {
                    sign_in.status = delivery::Status::Unavailable;
                    continue;
                }
                Some(Observation::SignIn {
                    code,
                    path,
                    password_input,
                }) => {
                    if matches!(*code, 401 | 403)
                        || (200..400).contains(code) && login_path(path)
                        || (200..300).contains(code) && *password_input
                    {
                        continue;
                    }
                    if (200..400).contains(code) {
                        format!(
                            "Anyone who can reach {url} can use it without signing in, so what it holds may be exposed: its data, its settings and any keys it keeps. It needs a sign-in before it is handed over."
                        )
                    } else {
                        format!(
                            "{url} answered with HTTP {code} instead of the app's page, so tau-web could not check that it asks for sign-in."
                        )
                    }
                }
                Some(_) => format!(
                    "{url} could not be visited from the machine, so tau-web could not check that it asks for sign-in."
                ),
            };
            finding(&mut sign_in, detail);
        }
        fields.push(sign_in);
    }
    if plan
        .iter()
        .any(|read| matches!(read, Read::ControlCenter { .. }))
    {
        required.push(FieldId::ControlCenter);
        let mut control_center = result(FieldId::ControlCenter, delivery::Status::Checked);
        for (index, read) in plan.iter().enumerate() {
            if !matches!(read, Read::ControlCenter { .. }) {
                continue;
            }
            match observations.get(index).and_then(Option::as_ref) {
                None => control_center.status = delivery::Status::Unavailable,
                Some(Observation::ControlCenter { passed: true, .. }) => {}
                observation => {
                    let names = match observation {
                        Some(Observation::ControlCenter { names, .. }) if !names.is_empty() => {
                            names.join(", ")
                        }
                        Some(Observation::ControlCenter {
                            checks_failed: true,
                            ..
                        }) => "some checks".into(),
                        _ => "the check could not run".into(),
                    };
                    finding(
                        &mut control_center,
                        format!(
                            "The control center's final check failed: {names}. Resume the task to let the AI repair it."
                        ),
                    );
                }
            }
        }
        fields.push(control_center);
    }
    let mut result = delivery::aggregate_selected(&required, fields, standing, true);
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
