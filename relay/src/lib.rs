//! A fixture-tested /v1 TCP relay. TLS belongs to the front proxy.
pub mod auth;
pub mod dns;
mod framing;
pub mod policy;

use base64::Engine;
use futures_util::{SinkExt, Stream, StreamExt};
use policy::{Destination, Policy};
use serde::Deserialize;
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Bytes, Message,
        protocol::{CloseFrame, WebSocketConfig, frame::coding::CloseCode},
    },
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}
pub type Tcp = Box<dyn Transport>;
pub trait Resolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>>;
}
pub trait Dialer: Send + Sync {
    fn dial(&self, address: SocketAddr) -> BoxFuture<'_, io::Result<Tcp>>;
}
pub trait Clock: Send + Sync {
    fn wall(&self) -> u64;
    fn tick(&self) -> Duration;
}
pub struct SystemClock(Instant);
impl Default for SystemClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}
impl Clock for SystemClock {
    fn wall(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    fn tick(&self) -> Duration {
        self.0.elapsed()
    }
}
pub struct NetworkDialer;
impl Dialer for NetworkDialer {
    fn dial(&self, address: SocketAddr) -> BoxFuture<'_, io::Result<Tcp>> {
        Box::pin(async move { Ok(Box::new(TcpStream::connect(address).await?) as Tcp) })
    }
}

/// Local PoC choices, not upstream timing decisions. See README for rationale.
pub struct PocLimits;
impl PocLimits {
    pub const HANDSHAKE: Duration = Duration::from_secs(20);
    pub const DNS: Duration = Duration::from_secs(5);
    pub const CONNECT: Duration = Duration::from_secs(10);
    pub const STALL: Duration = Duration::from_secs(30);
    pub const IDLE: Duration = Duration::from_secs(300);
    pub const SWEEP: Duration = Duration::from_secs(1);
    pub const CLOSE: Duration = Duration::from_secs(1);
    pub const QUEUE: usize = 4;
    pub const DNS_PACKET: usize = 4096;
    pub const DNS_ANSWERS: u16 = 64;
    pub const DNS_POINTER_STEPS: usize = 128;
    pub const UPGRADE: usize = 64 * 1024;
    pub const MESSAGE: usize = 64 * 1024;
    pub const CONNECTIONS: usize = 64;
    pub const PASSES: usize = 128;
    pub const HOSTS: usize = 16;
    pub const FILE: u64 = 256 * 1024;
}

#[derive(Clone)]
pub struct Timing {
    pub skew: u64,
    pub spacing: Duration,
    pub window: Duration,
    pub cap: usize,
}
impl Default for Timing {
    fn default() -> Self {
        let value: toml::Value = toml::from_str(include_str!(
            "../../tests/vectors/paid-tcp-relay-844e834-timing.toml"
        ))
        .expect("pinned timing");
        let r = &value["relay"];
        let duration = |name: &str| {
            let s = r[name].as_str().expect("duration string");
            let (num, unit) = s.split_at(s.len() - 1);
            Duration::from_secs(
                num.parse::<u64>().expect("duration number")
                    * match unit {
                        "s" => 1,
                        "m" => 60,
                        _ => panic!("duration unit"),
                    },
            )
        };
        Self {
            skew: duration("auth_skew").as_secs(),
            spacing: duration("min_spacing"),
            window: duration("window"),
            cap: r["window_cap"].as_integer().expect("cap") as usize,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pass {
    pub key: String,
    pub hosts: Vec<String>,
    pub expiry: u64,
    #[serde(default)]
    pub revoked: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PassFile {
    passes: Vec<Pass>,
}
pub async fn load_passes(
    text: &str,
    policy: &Policy,
    resolver: &dyn Resolver,
) -> Result<HashMap<String, Pass>, &'static str> {
    let file: PassFile = toml::from_str(text).map_err(|_| "invalid pass file")?;
    if file.passes.len() > PocLimits::PASSES {
        return Err("too many passes");
    }
    let mut passes = HashMap::new();
    for pass in file.passes {
        if pass.key.len() != 64
            || !pass
                .key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || hex::decode(&pass.key)
                .ok()
                .and_then(|k| k256::schnorr::VerifyingKey::from_bytes(&k).ok())
                .is_none()
            || pass.hosts.is_empty()
            || pass.hosts.len() > PocLimits::HOSTS
            || pass.expiry == 0
        {
            return Err("invalid pass record");
        }
        let mut seen = std::collections::HashSet::new();
        for host in &pass.hosts {
            if !policy::host_valid(host) || !seen.insert(host) {
                return Err("invalid recorded host");
            }
            checked_address(host, 1, policy, resolver)
                .await
                .map_err(|_| "recorded address refused")?;
        }
        if passes.insert(pass.key.clone(), pass).is_some() {
            return Err("duplicate pass");
        }
    }
    Ok(passes)
}
async fn checked_address(
    host: &str,
    port: u16,
    policy: &Policy,
    resolver: &dyn Resolver,
) -> Result<SocketAddr, &'static str> {
    let ips = if let Ok(ip) = host.parse() {
        vec![ip]
    } else {
        resolver.resolve(host).await.map_err(|_| "address")?
    };
    policy.select(&ips, port).ok_or("address")
}

#[derive(Default)]
pub struct Pace {
    windows: HashMap<(String, String), VecDeque<Duration>>,
}
impl Pace {
    pub fn prune(&mut self, now: Duration, timing: &Timing) {
        self.windows.retain(|_, w| {
            while w
                .front()
                .is_some_and(|t| now.saturating_sub(*t) >= timing.window)
            {
                w.pop_front();
            }
            !w.is_empty()
        });
    }
    pub fn admit(&mut self, key: &str, host: &str, now: Duration, timing: &Timing) -> bool {
        self.prune(now, timing);
        let w = self
            .windows
            .entry((key.to_owned(), host.to_owned()))
            .or_default();
        if w.len() >= timing.cap
            || w.back()
                .is_some_and(|last| now < *last || now - *last < timing.spacing)
        {
            return false;
        }
        w.push_back(now);
        true
    }
}
pub struct Relay {
    pub url: String,
    pub policy: Policy,
    pub passes: HashMap<String, Pass>,
    pub resolver: Arc<dyn Resolver>,
    pub dialer: Arc<dyn Dialer>,
    pub clock: Arc<dyn Clock>,
    pub timing: Timing,
    pub pace: Mutex<Pace>,
}
impl Relay {
    pub async fn admit(
        &self,
        auth: &auth::Auth,
        challenge: &str,
        dest: &Destination,
    ) -> Result<SocketAddr, &'static str> {
        if !auth.shape(&self.url, dest, self.clock.wall(), self.timing.skew)
            || !auth.signature()
            || !auth.challenge(challenge)
        {
            return Err("auth");
        }
        let pass = self
            .passes
            .get(&auth.pubkey)
            .filter(|p| !p.revoked && self.clock.wall() < p.expiry)
            .ok_or("pass")?;
        if !pass.hosts.contains(&dest.host) {
            return Err("destination");
        }
        let address =
            checked_address(&dest.host, dest.port, &self.policy, self.resolver.as_ref()).await?;
        if !self.pace.lock().expect("pace mutex").admit(
            &pass.key,
            &dest.host,
            self.clock.tick(),
            &self.timing,
        ) {
            return Err("pace");
        }
        Ok(address)
    }
}

type Frames<S> = futures_util::stream::SplitStream<WebSocketStream<framing::Guard<S>>>;
type Writer<S> = futures_util::stream::SplitSink<WebSocketStream<framing::Guard<S>>, Message>;
async fn close<S: AsyncRead + AsyncWrite + Unpin>(sink: &mut Writer<S>, code: u16) {
    let _ = tokio::time::timeout(
        PocLimits::CLOSE,
        sink.send(Message::Close(Some(CloseFrame {
            code: CloseCode::from(code),
            reason: "".into(),
        }))),
    )
    .await;
}
async fn refuse<S: AsyncRead + AsyncWrite + Unpin>(sink: &mut Writer<S>, reason: &str) {
    let _ = tokio::time::timeout(
        PocLimits::CLOSE,
        sink.send(Message::text(
            serde_json::json!({"ok":false,"reason":reason}).to_string(),
        )),
    )
    .await;
    close(sink, if reason == "dial" { 1011 } else { 1008 }).await;
}

/// Socket-biased arbitration applies to DNS admission, dial and OK flushing.
/// Data queued before OK is rejected, including simultaneous readiness.
pub async fn before_ok<S, F, T, E>(frames: &mut S, future: F) -> Result<T, u16>
where
    S: Stream<Item = Result<Message, E>> + Unpin,
    F: Future<Output = T>,
{
    tokio::pin!(future);
    loop {
        tokio::select! {
            biased;
            frame = frames.next() => match frame {
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {},
                Some(Ok(Message::Text(_) | Message::Binary(_)) | Err(_)) => return Err(1002),
                _ => return Err(1000),
            },
            output = &mut future => return Ok(output),
        }
    }
}

// The upgrade callback signature is fixed by the WebSocket library.
#[allow(clippy::result_large_err)]
async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    relay: &Relay,
) -> Option<(
    Writer<S>,
    Frames<S>,
    SocketAddr,
    Arc<std::sync::atomic::AtomicU8>,
)> {
    let stream = framing::Guard::new(stream);
    let phase = stream.phase.clone();
    let mut path = String::new();
    let ws = tokio_tungstenite::accept_hdr_async_with_config(
        stream,
        |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
            path = request
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("")
                .to_owned();
            Ok(response)
        },
        Some(
            WebSocketConfig::default()
                .max_message_size(Some(PocLimits::MESSAGE))
                .max_frame_size(Some(PocLimits::MESSAGE)),
        ),
    )
    .await
    .ok()?;
    let (mut sink, mut frames) = ws.split();
    let Some(dest) = policy::destination(&path) else {
        close(&mut sink, 1008).await;
        return None;
    };
    let mut random = [0; 32];
    if getrandom::fill(&mut random).is_err() {
        close(&mut sink, 1011).await;
        return None;
    }
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
    sink.send(Message::text(
        serde_json::json!({"challenge":challenge,"relay":relay.url}).to_string(),
    ))
    .await
    .ok()?;
    let auth = loop {
        match frames.next().await {
            Some(Ok(Message::Text(text))) => break serde_json::from_str::<auth::Auth>(&text).ok(),
            Some(Ok(Message::Binary(_)) | Err(_)) => {
                close(&mut sink, 1002).await;
                return None;
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            _ => return None,
        }
    };
    phase.store(framing::WAIT_OK, std::sync::atomic::Ordering::SeqCst);
    let Some(auth) = auth else {
        refuse(&mut sink, "auth").await;
        return None;
    };
    let admission = match before_ok(&mut frames, relay.admit(&auth, &challenge, &dest)).await {
        Ok(result) => result,
        Err(code) => {
            close(&mut sink, code).await;
            return None;
        }
    };
    let address = match admission {
        Ok(a) => a,
        Err(reason) => {
            refuse(&mut sink, reason).await;
            return None;
        }
    };
    Some((sink, frames, address, phase))
}

pub async fn connection<S: AsyncRead + AsyncWrite + Unpin>(stream: S, relay: &Relay) {
    let Ok(Some((mut sink, mut frames, address, phase))) =
        tokio::time::timeout(PocLimits::HANDSHAKE, handshake(stream, relay)).await
    else {
        return;
    };
    // Admission has its own deadline. Once accepted, a late AUTH must still
    // receive the dial verdict, even if the connect consumes its whole timeout.
    let tcp = match before_ok(
        &mut frames,
        tokio::time::timeout(PocLimits::CONNECT, relay.dialer.dial(address)),
    )
    .await
    {
        Ok(Ok(Ok(tcp))) => tcp,
        Ok(_) => {
            refuse(&mut sink, "dial").await;
            return;
        }
        Err(code) => {
            close(&mut sink, code).await;
            return;
        }
    };
    let send_ok = tokio::time::timeout(
        PocLimits::HANDSHAKE,
        sink.send(Message::text("{\"ok\":true}")),
    );
    match before_ok(&mut frames, send_ok).await {
        Ok(Ok(Ok(()))) => phase.store(framing::OPEN, std::sync::atomic::Ordering::SeqCst),
        Err(code) => {
            close(&mut sink, code).await;
            return;
        }
        _ => return,
    }
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Bytes>(PocLimits::QUEUE);
    let progress = tokio::sync::Notify::new();
    let code = {
        // Observe closure/text while queue space remains, even with a blocked writer.
        // A bounded queue avoids turning backpressure into unbounded memory use.
        let incoming = async {
            loop {
                match frames.next().await {
                    Some(Ok(Message::Binary(bytes))) => {
                        // Queue pressure pauses reads. The writer's per-write
                        // deadline bounds failure by lack of TCP progress,
                        // even while this enqueue waits for a slot.
                        if sender.send(bytes).await.is_err() {
                            return Some(1000);
                        }
                    }
                    Some(Ok(Message::Text(_)) | Err(_)) => return Some(1002),
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    _ => return None,
                }
                progress.notify_one();
                tokio::task::yield_now().await;
            }
        };
        let writing = async {
            while let Some(bytes) = receiver.recv().await {
                let mut remaining = bytes.as_ref();
                while !remaining.is_empty() {
                    match tokio::time::timeout(PocLimits::STALL, tcp_write.write(remaining)).await {
                        Ok(Ok(n)) if n > 0 => {
                            remaining = &remaining[n..];
                            progress.notify_one();
                        }
                        Err(_) => return 1013,
                        _ => return 1000,
                    }
                }
                progress.notify_one();
            }
            1000
        };
        let outgoing = async {
            let mut buffer = vec![0; 16 * 1024];
            loop {
                match tcp_read.read(&mut buffer).await {
                    Ok(n) if n > 0 => {
                        if sink
                            .send(Message::binary(buffer[..n].to_vec()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                        progress.notify_one();
                    }
                    _ => return,
                }
            }
        };
        tokio::pin!(incoming, writing, outgoing);
        let idle = tokio::time::sleep(PocLimits::IDLE);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                biased;
                code = &mut incoming => break code,
                code = &mut writing => break Some(code),
                _ = &mut outgoing => break Some(1000),
                _ = &mut idle => break None,
                _ = progress.notified() => idle.as_mut().reset(tokio::time::Instant::now()+PocLimits::IDLE),
            }
        }
    };
    // Closing the client drops both TCP halves, including stalled operations.
    drop(tcp_read);
    drop(tcp_write);
    if let Some(code) = code {
        close(&mut sink, code).await;
    }
}

pub async fn serve(listener: TcpListener, relay: Arc<Relay>) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(PocLimits::CONNECTIONS));
    let mut sweep = tokio::time::interval(PocLimits::SWEEP);
    loop {
        tokio::select! {
            _ = sweep.tick() => relay.pace.lock().expect("pace mutex").prune(relay.clock.tick(),&relay.timing),
            accepted = listener.accept() => {
                let (stream,_) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let relay = relay.clone();
                tokio::spawn(async move { let _permit = permit; connection(stream,&relay).await; });
            }
        }
    }
}
