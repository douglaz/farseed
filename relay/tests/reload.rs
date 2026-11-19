mod common;
use common::*;
use futures_util::SinkExt;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tau_relay::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

fn record(secret: u8, hosts: &[&str], expiry: u64) -> String {
    format!(
        "[[passes]]\nkey={:?}\nhosts={hosts:?}\nexpiry={expiry}\n",
        key(secret)
    )
}
async fn admission(relay: &Relay, host: &str, port: u16) -> Result<SocketAddr, &'static str> {
    let now = relay.clock.wall();
    let auth = serde_json::from_value(signed("c", host, port, now, 7)).unwrap();
    let dest = policy::destination(&format!("/v1/tcp/{host}/{port}")).unwrap();
    relay.admit(&auth, "c", &dest).await
}

#[tokio::test]
async fn refused_reloads_leave_the_whole_old_set_unchanged() {
    let valid = record(7, &[HOST], NOW + 100);
    let invalid = vec![
        ("malformed TOML", "[[passes]".to_owned()),
        ("unknown top field", "unknown=true\npasses=[]".to_owned()),
        ("unknown record field", valid.clone() + "unknown=true\n"),
        (
            "duplicate key",
            valid.clone() + &record(7, &["other.example.net"], NOW + 100),
        ),
        (
            "host on two passes",
            valid.clone() + &record(8, &[HOST], NOW + 100),
        ),
        ("duplicate host", record(7, &[HOST, HOST], NOW + 100)),
        ("invalid host", record(7, &["BAD.example.net"], NOW + 100)),
        (
            "missing expiry",
            valid.replace(&format!("expiry={}\n", NOW + 100), ""),
        ),
        ("zero expiry", record(7, &[HOST], 0)),
        (
            "invalid curve point",
            valid.replace(&key(7), &"f".repeat(64)),
        ),
        (
            "uppercase key",
            valid.replace(&key(7), &key(7).to_uppercase()),
        ),
        ("private literal", record(7, &["10.2.3.4"], NOW + 100)),
        ("own address", record(7, &["9.9.9.9"], NOW + 100)),
    ];
    for (case, text) in invalid {
        let mut f = Fixture::new();
        f.relay.policy = policy::Policy::new(["9.9.9.9".parse().unwrap()]);
        let old = f.relay.passes.read().unwrap().clone();
        assert!(f.relay.reload_passes(&text).await.is_err(), "{case}");
        assert!(Arc::ptr_eq(&old, &f.relay.passes.read().unwrap()), "{case}");
        assert!(admission(&f.relay, HOST, 22).await.is_ok(), "{case}");
    }
}

#[tokio::test]
async fn reload_limits_refuse_distinct_valid_hosts_and_keys() {
    let f = Fixture::new();
    let hosts = (0..17)
        .map(|i| format!("host-{i}.example.net"))
        .collect::<Vec<_>>();
    let hosts = hosts.iter().map(String::as_str).collect::<Vec<_>>();
    f.relay
        .reload_passes(&record(7, &hosts[..16], NOW + 100))
        .await
        .unwrap();
    let old = f.relay.passes.read().unwrap().clone();
    assert_eq!(
        f.relay.reload_passes(&record(7, &hosts, NOW + 100)).await,
        Err("invalid pass record")
    );
    assert!(Arc::ptr_eq(&old, &f.relay.passes.read().unwrap()));
    let mut records = (1..=128)
        .map(|i| record(i, &[&format!("pass-{i}.example.net")], NOW + 100))
        .collect::<String>();
    f.relay.reload_passes(&records).await.unwrap();
    let old = f.relay.passes.read().unwrap().clone();
    records += &record(129, &["pass-129.example.net"], NOW + 100);
    assert_eq!(
        f.relay.reload_passes(&records).await,
        Err("too many passes")
    );
    assert!(Arc::ptr_eq(&old, &f.relay.passes.read().unwrap()));
}

#[tokio::test]
async fn reload_dns_failures_and_any_forbidden_answer_keep_old_set() {
    for ips in [
        None,
        Some(vec![]),
        Some(vec![
            "8.8.8.8".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ]),
        Some(vec!["8.8.8.8".parse().unwrap(), "9.9.9.9".parse().unwrap()]),
    ] {
        let mut f = Fixture::new();
        f.relay.policy = policy::Policy::new(["9.9.9.9".parse().unwrap()]);
        *f.resolver.ips.lock().unwrap() = ips;
        let old = f.relay.passes.read().unwrap().clone();
        assert!(
            f.relay
                .reload_passes(&record(7, &[HOST], NOW + 100))
                .await
                .is_err()
        );
        assert!(Arc::ptr_eq(&old, &f.relay.passes.read().unwrap()));
        *f.resolver.ips.lock().unwrap() = Some(vec!["8.8.8.8".parse().unwrap()]);
        assert!(admission(&f.relay, HOST, 22).await.is_ok());
    }
}

#[tokio::test]
async fn expired_pass_loads_but_admits_nothing() {
    let f = Fixture::new();
    f.relay
        .reload_passes(&record(7, &[HOST], NOW))
        .await
        .unwrap();
    assert_eq!(admission(&f.relay, HOST, 22).await, Err("pass"));
    assert_eq!(f.resolver.calls.load(Ordering::SeqCst), 1);
    assert!(f.dialer.addresses.lock().unwrap().is_empty());
}

#[tokio::test]
async fn standing_pass_keeps_spacing_and_window_across_reload() {
    let mut f = Fixture::new();
    f.relay.timing.cap = 2;
    assert!(admission(&f.relay, HOST, 22).await.is_ok());
    let changed = record(7, &[HOST], NOW + 100) + &record(8, &["new.example.net"], NOW + 100);
    f.relay.reload_passes(&changed).await.unwrap();
    assert_eq!(admission(&f.relay, HOST, 443).await, Err("pace"));
    f.clock.0.store(NOW + 1, Ordering::SeqCst);
    assert!(admission(&f.relay, HOST, 443).await.is_ok());
    f.relay.reload_passes(&changed).await.unwrap();
    f.clock.0.store(NOW + 2, Ordering::SeqCst);
    assert_eq!(admission(&f.relay, HOST, 22).await, Err("pace"));
}

#[tokio::test]
async fn successful_reload_adds_host_and_refuses_removed_host() {
    let f = Fixture::new();
    f.relay
        .reload_passes(&record(7, &["new.example.net"], NOW + 100))
        .await
        .unwrap();
    assert_eq!(admission(&f.relay, HOST, 22).await, Err("destination"));
    assert!(admission(&f.relay, "new.example.net", 22).await.is_ok());
}

async fn exchange(ws: &mut Client, peer: &mut tokio::io::DuplexStream, bytes: &[u8]) {
    ws.send(Message::binary(bytes.to_vec())).await.unwrap();
    let mut data = vec![0; bytes.len()];
    tokio::time::timeout(Duration::from_secs(3), peer.read_exact(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data, bytes);
    peer.write_all(bytes).await.unwrap();
    assert_eq!(frame(ws).await, Message::binary(bytes.to_vec()));
}

#[tokio::test]
async fn open_session_relays_both_ways_after_drop_revocation_or_expiry() {
    for replacement in [
        "passes=[]".to_owned(),
        record(7, &[HOST], NOW + 100) + "revoked=true\n",
        record(7, &[HOST], NOW),
    ] {
        let Fixture {
            relay, mut peer, ..
        } = Fixture::new();
        let relay = Arc::new(relay);
        let (mut ws, task) = connected(relay.clone(), &format!("/v1/tcp/{HOST}/22")).await;
        let c = challenge(&mut ws).await;
        send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
        verdict(&mut ws, serde_json::json!({"ok":true})).await;
        exchange(&mut ws, &mut peer, b"before").await;
        relay.reload_passes(&replacement).await.unwrap();
        assert_eq!(admission(&relay, HOST, 22).await, Err("pass"));
        exchange(&mut ws, &mut peer, b"after").await;
        ws.send(Message::text("end")).await.unwrap();
        closed(&mut ws, 1002).await;
        task.await.unwrap();
    }
}

type Resolution = (
    String,
    tokio::sync::oneshot::Sender<io::Result<Vec<IpAddr>>>,
);
struct Controlled(tokio::sync::mpsc::UnboundedSender<Resolution>);
impl Resolver for Controlled {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let (send, receive) = tokio::sync::oneshot::channel();
            self.0.send((host.to_owned(), send)).unwrap();
            receive.await.unwrap()
        })
    }
}

#[tokio::test]
async fn queued_reloads_finish_in_order_failure_between_successes_changes_nothing() {
    let mut f = Fixture::new();
    let (resolve, mut requests) = tokio::sync::mpsc::unbounded_channel();
    f.relay.resolver = Arc::new(Controlled(resolve));
    let relay = Arc::new(f.relay);
    let old = relay.passes.read().unwrap().clone();
    let (send, receive) = tokio::sync::mpsc::channel(PocLimits::RELOAD_QUEUE);
    let worker = tokio::spawn(reload_pass_files(relay.clone(), receive));
    send.send(Ok(record(7, &["9.9.9.9", "first.example.net"], NOW + 100)))
        .await
        .unwrap();
    let (host, release) = requests.recv().await.unwrap();
    assert_eq!(host, "first.example.net");
    assert!(Arc::ptr_eq(&old, &relay.passes.read().unwrap()));
    send.send(Ok("[[passes]".to_owned())).await.unwrap();
    send.send(Err("cannot read configuration")).await.unwrap();
    send.send(Ok(record(8, &["last.example.net"], NOW + 100)))
        .await
        .unwrap();
    release.send(Ok(vec!["8.8.8.8".parse().unwrap()])).unwrap();
    let (host, release) = requests.recv().await.unwrap();
    assert_eq!(host, "last.example.net");
    let first = relay.passes.read().unwrap().clone();
    assert_eq!(first.len(), 1);
    assert_eq!(first[&key(7)].hosts, ["9.9.9.9", "first.example.net"]);
    assert!(!first.contains_key(&key(8)));
    release.send(Ok(vec!["8.8.8.8".parse().unwrap()])).unwrap();
    drop(send);
    tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap();
    let last = relay.passes.read().unwrap();
    assert_eq!(last.len(), 1);
    assert_eq!(last[&key(8)].hosts, ["last.example.net"]);
    assert!(!last.contains_key(&key(7)));
    assert_eq!(old[&key(7)].hosts, [HOST]);
}

#[tokio::test]
async fn signal_burst_bounds_buffering_preserves_fifo_and_keeps_session_relaying() {
    struct ReloadFile(std::path::PathBuf);
    impl Drop for ReloadFile {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).unwrap();
        }
    }
    let root = std::env::var_os("TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_TARGET_TMPDIR").into());
    std::fs::create_dir_all(&root).unwrap();
    let mut random = [0; 16];
    getrandom::fill(&mut random).unwrap();
    let file = ReloadFile(root.join(format!("reload-{}.toml", hex::encode(random))));
    let mut f = Fixture::new();
    let session_host = "9.9.9.9";
    Arc::make_mut(&mut f.relay.passes.write().unwrap())
        .get_mut(&key(7))
        .unwrap()
        .hosts = vec![session_host.to_owned()];
    let (resolve, mut requests) = tokio::sync::mpsc::unbounded_channel();
    f.relay.resolver = Arc::new(Controlled(resolve));
    let relay = Arc::new(f.relay);
    let (mut ws, session) = connected(relay.clone(), &format!("/v1/tcp/{session_host}/22")).await;
    let c = challenge(&mut ws).await;
    send(&mut ws, signed(&c, session_host, 22, NOW, 7)).await;
    verdict(&mut ws, serde_json::json!({"ok":true})).await;
    let hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
    let (files, receiver) = tokio::sync::mpsc::channel(PocLimits::RELOAD_QUEUE);
    assert_eq!(files.max_capacity(), 4);
    let signals = tokio::spawn(capture_pass_files(hangup, file.0.clone(), files.clone()));
    let mut worker = tokio::spawn(reload_pass_files(relay.clone(), receiver));
    let hup = || {
        // SAFETY: this test has installed a SIGHUP stream in its own process.
        assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGHUP) }, 0);
    };
    std::fs::write(&file.0, record(7, &["queued-0.example.net"], NOW + 100)).unwrap();
    hup();
    let (host, mut release) = tokio::time::timeout(Duration::from_secs(3), requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(host, "queued-0.example.net");
    for i in 1..=4 {
        std::fs::write(
            &file.0,
            record(7, &[&format!("queued-{i}.example.net")], NOW + 100),
        )
        .unwrap();
        hup();
        tokio::time::timeout(Duration::from_secs(3), async {
            while files.capacity() != 4 - i {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    std::fs::write(&file.0, record(8, &["last.example.net"], NOW + 100)).unwrap();
    for _ in 0..8 {
        hup();
        tokio::task::yield_now().await;
    }
    assert!(matches!(
        files.try_reserve(),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_))
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), requests.recv())
            .await
            .is_err()
    );
    exchange(&mut ws, &mut f.peer, b"while DNS and the full queue wait").await;
    for i in 1..=5 {
        release.send(Ok(vec!["8.8.8.8".parse().unwrap()])).unwrap();
        let (host, next) = tokio::time::timeout(Duration::from_secs(3), requests.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            host,
            if i == 5 {
                "last.example.net".to_owned()
            } else {
                format!("queued-{i}.example.net")
            }
        );
        assert_eq!(
            relay.passes.read().unwrap()[&key(7)].hosts,
            [format!("queued-{}.example.net", i - 1)]
        );
        release = next;
    }
    signals.abort();
    let _ = signals.await;
    drop(files);
    release.send(Ok(vec!["8.8.8.8".parse().unwrap()])).unwrap();
    // Standard signals may leave another final revision queued after coalescing.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            tokio::select! {
                result = &mut worker => {
                    result.unwrap();
                    break;
                }
                request = requests.recv() => {
                    let (host, release) = request.unwrap();
                    assert_eq!(host, "last.example.net");
                    release.send(Ok(vec!["8.8.8.8".parse().unwrap()])).unwrap();
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(relay.passes.read().unwrap().len(), 1);
    assert_eq!(
        relay.passes.read().unwrap()[&key(8)].hosts,
        ["last.example.net"]
    );
    assert_eq!(admission(&relay, session_host, 22).await, Err("pass"));
    exchange(&mut ws, &mut f.peer, b"after the last success").await;
    ws.send(Message::text("end")).await.unwrap();
    closed(&mut ws, 1002).await;
    session.await.unwrap();
}
