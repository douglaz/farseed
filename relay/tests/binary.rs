mod common;
use common::*;
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Read},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};

struct Files {
    dir: PathBuf,
    config: PathBuf,
    passes: PathBuf,
}
impl Files {
    fn new(listen: &str, dns: std::net::SocketAddr, hosts: &str) -> Self {
        let root = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
        std::fs::create_dir_all(&root).unwrap();
        let dir = loop {
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let dir = root.join(format!("relay-test-{}", hex::encode(random)));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create test scratch: {e}"),
            }
        };
        let config = dir.join("config.toml");
        let passes = dir.join("passes.toml");
        let now = now();
        let records = [
            (7, now + 10000, false),
            (8, now - 1, false),
            (9, now + 10000, true),
        ]
        .into_iter()
        .map(|(secret, expiry, revoked)| {
            format!(
                "[[passes]]\nkey={:?}\nhosts=[{:?}]\nexpiry={expiry}\nrevoked={revoked}\n",
                key(secret),
                hosts
            )
        })
        .collect::<String>();
        std::fs::write(&passes, records).unwrap();
        std::fs::write(&config,format!("listen={listen:?}\npublic_url={URL:?}\npass_file={:?}\ndns_server={:?}\nown_public=[\"1.1.1.1\"]\n",passes.to_str().unwrap(),dns.to_string())).unwrap();
        Self {
            dir,
            config,
            passes,
        }
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_file(&self.config).unwrap();
        std::fs::remove_file(&self.passes).unwrap();
        std::fs::remove_dir(&self.dir).unwrap();
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
struct Process {
    child: Child,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
async fn dns() -> (
    std::net::SocketAddr,
    Arc<AtomicBool>,
    Arc<AtomicUsize>,
    JoinHandle<()>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let private = Arc::new(AtomicBool::new(false));
    let queries = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let private = private.clone();
        let queries = queries.clone();
        async move {
            let mut packet = [0; 4096];
            loop {
                let (n, peer) = socket.recv_from(&mut packet).await.unwrap();
                queries.fetch_add(1, Ordering::SeqCst);
                let mut reply = packet[..n].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80;
                let a = reply[n - 4..n - 2] == [0, 1];
                if a {
                    reply[7] = 1;
                    reply.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
                    reply.extend(if private.load(Ordering::SeqCst) {
                        [127, 0, 0, 1]
                    } else {
                        [8, 8, 8, 8]
                    });
                }
                socket.send_to(&reply, peer).await.unwrap();
            }
        }
    });
    (address, private, queries, task)
}
#[tokio::test]
async fn spawned_binary_harness_auth_refusals_replay_and_quietness() {
    let (dns, private, queries, dns_task) = dns().await;
    let observer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = observer.local_addr().unwrap().port();
    let files = Files::new("127.0.0.1:0", dns, HOST);
    let child = Command::new(env!("CARGO_BIN_EXE_tau-relay"))
        .arg(&files.config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut process = Process { child };
    let stdout = process.child.stdout.take().unwrap();
    let (mut output, line) = tokio::task::spawn_blocking(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        (reader, line)
    })
    .await
    .unwrap();
    let address = line
        .strip_prefix("listening ")
        .unwrap()
        .trim()
        .parse::<std::net::SocketAddr>()
        .unwrap();
    assert_ne!(address.port(), 0);
    private.store(true, Ordering::SeqCst);
    let registered = queries.load(Ordering::SeqCst);
    assert_eq!(registered, 6);
    for path in [
        format!("/v2/tcp/{HOST}/{port}"),
        format!("/v1/tcp/{HOST}/0{port}"),
        format!("/v1/tcp/{HOST}/{port}/extra"),
        format!("/v1/tcp/{HOST}/{port}?q"),
        format!("/v1/tcp/%65xample.net/{port}"),
    ] {
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{address}{path}"))
            .await
            .unwrap();
        closed(&mut ws, 1008).await;
    }
    assert_eq!(queries.load(Ordering::SeqCst), registered);
    let mut old: Option<(String, Value)> = None;
    for case in [
        "signature",
        "challenge",
        "destination-tag",
        "relay-tag",
        "unknown",
        "expired",
        "revoked",
        "destination",
        "address",
        "replay",
    ] {
        let host = if case == "destination" {
            "other.example.net"
        } else {
            HOST
        };
        let (mut ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{address}/v1/tcp/{host}/{port}"))
                .await
                .unwrap();
        let c = challenge(&mut ws).await;
        if let Some((old_c, _)) = &old {
            assert_ne!(old_c, &c);
        }
        let secret = match case {
            "unknown" => 10,
            "expired" => 8,
            "revoked" => 9,
            _ => 7,
        };
        let mut event = signed(
            if case == "challenge" { "wrong" } else { &c },
            if case == "destination-tag" {
                "wrong.example.net"
            } else {
                host
            },
            port,
            now(),
            secret,
        );
        if case == "signature" {
            event["sig"] = hex::encode([0; 64]).into();
        }
        if case == "relay-tag" {
            event["tags"][0][1] = "wss://relay.example.net".into();
        }
        if case == "replay" {
            event = old.as_ref().unwrap().1.clone();
        }
        if case == "address" {
            old = Some((c, event.clone()));
        }
        let expected = match case {
            "unknown" | "expired" | "revoked" => "pass",
            "destination" => "destination",
            "address" => "address",
            _ => "auth",
        };
        let before = queries.load(Ordering::SeqCst);
        send(&mut ws, event).await;
        verdict(&mut ws, refused(expected)).await;
        closed(&mut ws, 1008).await;
        assert_eq!(
            queries.load(Ordering::SeqCst) - before,
            if case == "address" { 2 } else { 0 },
            "{case}"
        );
    }
    // The controlled DNS answer points every attempted dial at this listener. It
    // would observe a dial even if the client still received a refusal frame.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), observer.accept())
            .await
            .is_err()
    );
    process.child.kill().unwrap();
    process.child.wait().unwrap();
    let mut rest = String::new();
    output.read_to_string(&mut rest).unwrap();
    assert!(rest.is_empty(), "unexpected stdout");
    let mut stderr = String::new();
    process
        .child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.is_empty(), "unexpected stderr");
    dns_task.abort();
    let _ = dns_task.await;
}
#[test]
fn spawned_startup_rejects_non_loopback_forbidden_records_and_bad_config() {
    for (listen, host) in [
        ("0.0.0.0:0", HOST),
        ("127.0.0.1:0", "127.0.0.1"),
        ("127.0.0.1:0", "::ffff:8.8.8.8"),
    ] {
        let files = Files::new(listen, "127.0.0.1:9".parse().unwrap(), host);
        let output = Command::new(env!("CARGO_BIN_EXE_tau-relay"))
            .arg(&files.config)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(!text.contains(&key(7)));
        assert!(!text.contains(host));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_tau-relay"))
        .output()
        .unwrap();
    assert!(!output.status.success());
}
#[test]
fn fixture_json_contracts() {
    let ok: Value = serde_json::from_str(include_str!("vectors/ok.json")).unwrap();
    assert_eq!(ok, serde_json::json!({"ok":true}));
    let refused_frame: Value = serde_json::from_str(include_str!("vectors/refused.json")).unwrap();
    assert_eq!(refused_frame, refused("destination"));
    let dial: Value = serde_json::from_str(include_str!("vectors/dial-failed.json")).unwrap();
    assert_eq!(dial, refused("dial"));
    let challenge: Value = serde_json::from_str(include_str!("vectors/challenge.json")).unwrap();
    assert_eq!(challenge["relay"], URL);
}
