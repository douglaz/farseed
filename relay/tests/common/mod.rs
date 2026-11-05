#![allow(dead_code)]
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tau_relay::*;
use tokio::{
    io::{DuplexStream, duplex},
    sync::Notify,
};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};
pub const URL: &str = "wss://relay.example.net/";
pub const HOST: &str = "service.example.net";
pub const NOW: u64 = 1_800_000_000;
pub fn signed(challenge: &str, host: &str, port: u16, now: u64, secret: u8) -> Value {
    tau_web::relay_auth::auth_event(&[secret; 32], URL, challenge, host, port, now, &[0; 32])
        .unwrap()
}
pub fn key(secret: u8) -> String {
    signed("", HOST, 22, NOW, secret)["pubkey"]
        .as_str()
        .unwrap()
        .to_string()
}
pub struct TestClock(pub AtomicU64);
impl Clock for TestClock {
    fn wall(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    fn tick(&self) -> Duration {
        Duration::from_secs(self.wall())
    }
}
pub struct Answers {
    pub calls: AtomicUsize,
    pub ips: Mutex<Option<Vec<IpAddr>>>,
    pub gate: Option<Arc<Notify>>,
    pub entered: Notify,
}
impl Answers {
    pub fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            ips: Mutex::new(Some(vec![
                "8.8.8.8".parse().unwrap(),
                "1.1.1.1".parse().unwrap(),
            ])),
            gate: None,
            entered: Notify::new(),
        }
    }
}
impl Resolver for Answers {
    fn resolve<'a>(&'a self, _host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            if let Some(gate) = &self.gate {
                gate.notified().await;
            }
            self.ips
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| io::Error::other("fixture failure"))
        })
    }
}
pub struct Dials {
    pub addresses: Mutex<Vec<SocketAddr>>,
    pub stream: Mutex<Option<DuplexStream>>,
    pub gate: Option<Arc<Notify>>,
    pub entered: Notify,
}
impl Dialer for Dials {
    fn dial(&self, address: SocketAddr) -> BoxFuture<'_, io::Result<Tcp>> {
        Box::pin(async move {
            self.addresses.lock().unwrap().push(address);
            self.entered.notify_one();
            if let Some(gate) = &self.gate {
                gate.notified().await;
            }
            self.stream
                .lock()
                .unwrap()
                .take()
                .map(|s| Box::new(s) as Tcp)
                .ok_or_else(|| io::Error::other("fixture dial failure"))
        })
    }
}
pub struct Fixture {
    pub relay: Relay,
    pub resolver: Arc<Answers>,
    pub dialer: Arc<Dials>,
    pub peer: DuplexStream,
    pub clock: Arc<TestClock>,
}
impl Fixture {
    pub fn new() -> Self {
        Self::with_gates(None, None)
    }
    pub fn with_gates(resolve: Option<Arc<Notify>>, dial: Option<Arc<Notify>>) -> Self {
        let resolver = Arc::new(Answers {
            gate: resolve,
            ..Answers::new()
        });
        let (stream, peer) = duplex(4096);
        let dialer = Arc::new(Dials {
            addresses: Mutex::new(Vec::new()),
            stream: Mutex::new(Some(stream)),
            gate: dial,
            entered: Notify::new(),
        });
        let clock = Arc::new(TestClock(AtomicU64::new(NOW)));
        let pass = Pass {
            key: key(7),
            hosts: vec![HOST.to_owned()],
            expiry: NOW + 10000,
            revoked: false,
        };
        let relay = Relay {
            url: URL.to_string(),
            policy: policy::Policy::default(),
            passes: HashMap::from([(pass.key.clone(), pass)]),
            resolver: resolver.clone(),
            dialer: dialer.clone(),
            clock: clock.clone(),
            timing: Default::default(),
            pace: Mutex::new(Default::default()),
        };
        Self {
            relay,
            resolver,
            dialer,
            peer,
            clock,
        }
    }
}
pub type Client = WebSocketStream<DuplexStream>;
pub async fn connected(relay: Arc<Relay>, path: &str) -> (Client, tokio::task::JoinHandle<()>) {
    let (server, client) = duplex(256 * 1024);
    let task = tokio::spawn(async move { connection(server, &relay).await });
    let (ws, _) = tokio_tungstenite::client_async(format!("ws://localhost{path}"), client)
        .await
        .unwrap();
    (ws, task)
}
pub async fn frame<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
) -> Message {
    tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("frame timeout")
        .expect("frame present")
        .expect("valid frame")
}
pub async fn challenge<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
) -> String {
    let Message::Text(text) = frame(ws).await else {
        panic!("challenge text")
    };
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["relay"], URL);
    {
        use base64::Engine;
        let c = value["challenge"].as_str().unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(c)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(value.as_object().unwrap().len(), 2);
        c.to_string()
    }
}
pub async fn send<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
    auth: Value,
) {
    ws.send(Message::text(auth.to_string())).await.unwrap();
}
pub async fn verdict<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
    expected: Value,
) {
    let Message::Text(text) = frame(ws).await else {
        panic!("verdict text")
    };
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), expected);
}
pub async fn closed<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
    code: u16,
) {
    let Message::Close(Some(close)) = frame(ws).await else {
        panic!("close frame")
    };
    assert_eq!(u16::from(close.code), code);
}
pub fn refused(reason: &str) -> Value {
    json!({"ok":false,"reason":reason})
}

pub async fn raw_data<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
    opcode: tokio_tungstenite::tungstenite::protocol::frame::coding::Data,
    fin: bool,
    payload: &[u8],
) {
    use tokio::io::AsyncWriteExt;
    use tokio_tungstenite::tungstenite::protocol::frame::Frame;
    let mut frame = Frame::message(
        payload.to_vec(),
        tokio_tungstenite::tungstenite::protocol::frame::coding::OpCode::Data(opcode),
        fin,
    );
    frame.header_mut().mask = Some([1, 2, 3, 4]);
    let mut bytes = Vec::new();
    frame.format(&mut bytes).unwrap();
    ws.get_mut().write_all(&bytes).await.unwrap();
}
