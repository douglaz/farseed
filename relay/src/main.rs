use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tau_relay::{Relay, read_bounded};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    listen: SocketAddr,
    public_url: String,
    pass_file: PathBuf,
    dns_server: SocketAddr,
    own_public: Vec<IpAddr>,
}
async fn run() -> Result<(), &'static str> {
    let hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .map_err(|_| "cannot register reload signal")?;
    let mut args = std::env::args_os().skip(1);
    let path = args.next().ok_or("usage: tau-relay CONFIG.toml")?;
    if args.next().is_some() {
        return Err("usage: tau-relay CONFIG.toml");
    }
    let config: Config = toml::from_str(&read_bounded(std::path::Path::new(&path))?)
        .map_err(|_| "invalid configuration")?;
    if !config.listen.ip().is_loopback() {
        return Err("listen must be loopback");
    }
    let origin = config
        .public_url
        .strip_prefix("wss://")
        .and_then(|s| s.strip_suffix('/'))
        .ok_or("invalid public URL")?;
    let valid_origin = if let Some((host, port)) = origin.rsplit_once(':') {
        tau_relay::policy::destination(&format!("/v1/tcp/{host}/{port}")).is_some()
    } else {
        tau_relay::policy::host_valid(origin)
    };
    if !valid_origin {
        return Err("invalid public URL");
    }
    let mut own = tau_relay::policy::interfaces().map_err(|_| "cannot enumerate interfaces")?;
    if config.own_public.is_empty()
        || config
            .own_public
            .iter()
            .any(|a| !tau_relay::policy::Policy::default().admits(*a))
    {
        return Err("own_public must list public addresses, including NAT addresses");
    }
    own.extend(config.own_public);
    let policy = tau_relay::policy::Policy::new(own);
    let resolver = Arc::new(tau_relay::dns::Dns {
        server: config.dns_server,
    });
    let passes = tau_relay::load_passes(
        &read_bounded(&config.pass_file)?,
        &policy,
        resolver.as_ref(),
    )
    .await?;
    let relay = Arc::new(Relay {
        url: config.public_url,
        policy,
        passes: std::sync::RwLock::new(Arc::new(passes)),
        resolver,
        dialer: Arc::new(tau_relay::NetworkDialer),
        clock: Arc::new(tau_relay::SystemClock::default()),
        timing: Default::default(),
        pace: Mutex::new(Default::default()),
    });
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|_| "cannot bind listener")?;
    let (files, receiver) = tokio::sync::mpsc::channel(tau_relay::PocLimits::RELOAD_QUEUE);
    let reload = tau_relay::reload_pass_files(relay.clone(), receiver);
    let signals = tau_relay::capture_pass_files(hangup, config.pass_file, files);
    println!(
        "listening {}",
        listener.local_addr().map_err(|_| "cannot read listener")?
    );
    tokio::select! {
        result = tau_relay::serve(listener, relay) => result.map_err(|_| "listener failed"),
        _ = async { tokio::join!(signals, reload); } => Err("reload signal failed"),
    }
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
