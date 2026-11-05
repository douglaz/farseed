mod common;
use common::*;
use futures_util::{FutureExt, SinkExt, StreamExt};
use serde_json::json;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tau_relay::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn success_only_checked_numeric_dial_any_port_and_banner_after_ok() {
    let Fixture {
        relay,
        resolver,
        dialer,
        mut peer,
        ..
    } = Fixture::new();
    peer.write_all(b"banner").await.unwrap();
    let (mut ws, task) = connected(Arc::new(relay), &format!("/v1/tcp/{HOST}/443")).await;
    let c = challenge(&mut ws).await;
    assert!(dialer.addresses.lock().unwrap().is_empty());
    send(&mut ws, signed(&c, HOST, 443, NOW, 7)).await;
    verdict(&mut ws, json!({"ok":true})).await;
    assert_eq!(frame(&mut ws).await, Message::binary(b"banner".to_vec()));
    ws.send(Message::binary(b"hello".to_vec())).await.unwrap();
    let mut data = [0; 5];
    peer.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"hello");
    assert_eq!(
        dialer.addresses.lock().unwrap().as_slice(),
        ["8.8.8.8:443".parse().unwrap()]
    );
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    ws.send(Message::text("bad")).await.unwrap();
    closed(&mut ws, 1002).await;
    task.await.unwrap();
    assert_eq!(peer.read(&mut data).await.unwrap(), 0);
}
#[tokio::test]
async fn dial_failure_no_ok() {
    let f = Fixture::new();
    f.dialer.stream.lock().unwrap().take();
    let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
    let c = challenge(&mut ws).await;
    send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
    verdict(&mut ws, refused("dial")).await;
    closed(&mut ws, 1011).await;
    task.await.unwrap();
}
#[tokio::test]
async fn every_admission_refusal_stops_before_later_stages() {
    for reason in [
        "auth",
        "signature",
        "pass",
        "destination",
        "address",
        "pace",
    ] {
        let mut f = Fixture::new();
        if reason == "pass" {
            f.relay.passes.clear();
        }
        if reason == "destination" {
            f.relay.passes.get_mut(&key(7)).unwrap().hosts.clear();
        }
        if reason == "address" {
            *f.resolver.ips.lock().unwrap() = Some(vec!["127.0.0.1".parse().unwrap()]);
        }
        if reason == "pace" {
            assert!(f.relay.pace.lock().unwrap().admit(
                &key(7),
                HOST,
                Duration::from_secs(NOW),
                &f.relay.timing
            ));
        }
        let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
        let c = challenge(&mut ws).await;
        let mut auth = signed(&c, HOST, 22, NOW, 7);
        if reason == "auth" {
            auth["kind"] = 0.into();
        }
        if reason == "signature" {
            auth["sig"] = hex::encode([0; 64]).into();
        }
        send(&mut ws, auth).await;
        verdict(
            &mut ws,
            refused(if reason == "signature" {
                "auth"
            } else {
                reason
            }),
        )
        .await;
        closed(&mut ws, 1008).await;
        task.await.unwrap();
        assert!(f.dialer.addresses.lock().unwrap().is_empty(), "{reason}");
        assert_eq!(
            f.resolver.calls.load(Ordering::SeqCst),
            usize::from(matches!(reason, "address" | "pace")),
            "{reason}"
        );
    }
}
#[tokio::test]
async fn signature_shape_skew_expiry_and_first_failure_boundaries() {
    let mut f = Fixture::new();
    let dest = policy::destination(&format!("/v1/tcp/{HOST}/22")).unwrap();
    for offset in [-601i64, -600, 600, 601] {
        let auth =
            serde_json::from_value(signed("c", HOST, 22, (NOW as i64 + offset) as u64, 7)).unwrap();
        let result = f.relay.admit(&auth, "c", &dest).await;
        assert_eq!(result.is_ok(), offset.abs() <= 600);
        f.relay
            .pace
            .lock()
            .unwrap()
            .prune(Duration::MAX, &f.relay.timing);
    }
    let auth: auth::Auth = serde_json::from_value(signed("c", HOST, 22, NOW, 7)).unwrap();
    f.relay.passes.get_mut(&key(7)).unwrap().expiry = NOW;
    assert_eq!(f.relay.admit(&auth, "c", &dest).await, Err("pass"));
    f.relay.passes.get_mut(&key(7)).unwrap().expiry = NOW + 1;
    f.relay.passes.get_mut(&key(7)).unwrap().revoked = true;
    assert_eq!(f.relay.admit(&auth, "c", &dest).await, Err("pass"));
    let mut bad = auth.clone();
    bad.kind = 0;
    f.relay.passes.clear();
    assert_eq!(f.relay.admit(&bad, "wrong", &dest).await, Err("auth"));
    assert_eq!(f.relay.admit(&auth, "wrong", &dest).await, Err("auth"));
    assert!(f.dialer.addresses.lock().unwrap().is_empty());
}
#[tokio::test]
async fn dns_rebinding_all_answers_and_registration() {
    let f = Fixture::new();
    let dest = policy::destination(&format!("/v1/tcp/{HOST}/22")).unwrap();
    let record = format!(
        "[[passes]]\nkey={:?}\nhosts=[{:?}]\nexpiry={}\n",
        key(7),
        HOST,
        NOW + 10
    );
    assert!(
        load_passes(&record, &f.relay.policy, f.resolver.as_ref())
            .await
            .is_ok()
    );
    for ips in [
        None,
        Some(vec![]),
        Some(vec![
            "8.8.8.8".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        ]),
    ] {
        *f.resolver.ips.lock().unwrap() = ips;
        assert!(
            load_passes(&record, &f.relay.policy, f.resolver.as_ref())
                .await
                .is_err()
        );
        let auth = serde_json::from_value(signed("c", HOST, 22, NOW, 7)).unwrap();
        assert_eq!(f.relay.admit(&auth, "c", &dest).await, Err("address"));
    }
    let record = record.replace(HOST, "127.0.0.1");
    assert!(
        load_passes(&record, &f.relay.policy, f.resolver.as_ref())
            .await
            .is_err()
    );
    assert!(
        load_passes(
            &record.replace(&format!("expiry={}\n", NOW + 10), ""),
            &f.relay.policy,
            f.resolver.as_ref()
        )
        .await
        .is_err()
    );
    assert!(
        load_passes(
            &record.replace(&key(7), "bad"),
            &f.relay.policy,
            f.resolver.as_ref()
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn address_before_pace_and_cross_port_scope() {
    let f = Fixture::new();
    for port in [22, 443] {
        let auth = serde_json::from_value(signed("c", HOST, port, NOW, 7)).unwrap();
        let dest = policy::destination(&format!("/v1/tcp/{HOST}/{port}")).unwrap();
        assert_eq!(f.relay.admit(&auth, "c", &dest).await.is_ok(), port == 22);
    }
    *f.resolver.ips.lock().unwrap() = Some(vec!["127.0.0.1".parse().unwrap()]);
    let auth = serde_json::from_value(signed("c", HOST, 443, NOW, 7)).unwrap();
    assert_eq!(
        f.relay
            .admit(
                &auth,
                "c",
                &policy::destination(&format!("/v1/tcp/{HOST}/443")).unwrap()
            )
            .await,
        Err("address")
    );
}
#[tokio::test]
async fn binary_during_dns_or_dial_never_forwards() {
    for at_dns in [true, false] {
        let gate = Arc::new(Notify::new());
        let Fixture {
            relay,
            resolver,
            dialer,
            mut peer,
            ..
        } = Fixture::with_gates(
            at_dns.then(|| gate.clone()),
            (!at_dns).then(|| gate.clone()),
        );
        let (mut ws, task) = connected(Arc::new(relay), &format!("/v1/tcp/{HOST}/22")).await;
        let c = challenge(&mut ws).await;
        send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
        if at_dns {
            resolver.entered.notified().await;
        } else {
            dialer.entered.notified().await;
        }
        ws.send(Message::binary(b"premature".to_vec()))
            .await
            .unwrap();
        closed(&mut ws, 1002).await;
        task.await.unwrap();
        assert_eq!(dialer.addresses.lock().unwrap().len(), usize::from(!at_dns));
        dialer.stream.lock().unwrap().take();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}
#[tokio::test]
async fn socket_wins_simultaneous_completion_and_ok_flush() {
    let mut frames = futures_util::stream::iter([Ok::<_, ()>(Message::binary(vec![1]))]);
    let result = before_ok(&mut frames, std::future::ready(7)).await;
    assert_eq!(result, Err(1002));
    let f = Fixture::new();
    let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
    challenge(&mut ws).await;
    ws.send(Message::binary(vec![1])).await.unwrap();
    closed(&mut ws, 1002).await;
    task.await.unwrap();
    assert!(f.dialer.addresses.lock().unwrap().is_empty());
    let mut frames = futures_util::stream::pending::<Result<Message, ()>>();
    assert!(
        before_ok(&mut frames, std::future::pending::<()>())
            .now_or_never()
            .is_none()
    );
}

#[tokio::test]
async fn duplicate_destination_tags_and_wrong_challenges_stop_at_auth() {
    let f = Fixture::new();
    let dest = policy::destination(&format!("/v1/tcp/{HOST}/22")).unwrap();
    let event = signed("c", HOST, 22, NOW, 7);
    for name in ["destination", "relay", "challenge"] {
        let mut event = event.clone();
        let tag = event["tags"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t[0] == name)
            .unwrap()
            .clone();
        event["tags"].as_array_mut().unwrap().push(tag);
        let auth = serde_json::from_value(event).unwrap();
        assert_eq!(f.relay.admit(&auth, "c", &dest).await, Err("auth"));
    }
    assert_eq!(f.resolver.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn text_and_close_tear_down_a_blocked_tcp_writer() {
    for text in [false, true] {
        let Fixture {
            relay, mut peer, ..
        } = Fixture::new();
        let (mut ws, task) = connected(Arc::new(relay), &format!("/v1/tcp/{HOST}/22")).await;
        let c = challenge(&mut ws).await;
        send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
        verdict(&mut ws, json!({"ok":true})).await;
        ws.send(Message::binary(vec![1; PocLimits::MESSAGE]))
            .await
            .unwrap();
        if text {
            ws.send(Message::text("bad")).await.unwrap();
            closed(&mut ws, 1002).await;
        } else {
            ws.close(None).await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert!(received.len() < PocLimits::MESSAGE);
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_upgrade_admission_and_idle_sessions_expire() {
    let f = Fixture::new();
    let relay = Arc::new(f.relay);
    let (server, mut client) = tokio::io::duplex(4096);
    let task = tokio::spawn({
        let relay = relay.clone();
        async move { connection(server, &relay).await }
    });
    tokio::task::yield_now().await;
    tokio::time::advance(PocLimits::HANDSHAKE).await;
    task.await.unwrap();
    let mut byte = [0];
    assert_eq!(client.read(&mut byte).await.unwrap(), 0);
    let (mut ws, task) = connected(relay, &format!("/v1/tcp/{HOST}/22")).await;
    let c = challenge(&mut ws).await;
    send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
    verdict(&mut ws, json!({"ok":true})).await;
    tokio::time::advance(PocLimits::IDLE).await;
    task.await.unwrap();
    let f = Fixture::new();
    let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
    challenge(&mut ws).await;
    tokio::time::advance(PocLimits::HANDSHAKE).await;
    task.await.unwrap();
    assert!(f.dialer.addresses.lock().unwrap().is_empty());
    let gate = Arc::new(Notify::new());
    let f = Fixture::with_gates(Some(gate), None);
    let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
    let c = challenge(&mut ws).await;
    send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
    f.resolver.entered.notified().await;
    tokio::time::advance(PocLimits::HANDSHAKE).await;
    task.await.unwrap();
    assert!(f.dialer.addresses.lock().unwrap().is_empty());
}

#[tokio::test]
async fn registration_rejects_invalid_records_and_own_public_addresses() {
    let f = Fixture::new();
    let record = format!(
        "[[passes]]\nkey={:?}\nhosts=[\"8.8.8.8\"]\nexpiry={}\n",
        key(7),
        NOW + 1
    );
    assert!(
        load_passes(&record, &f.relay.policy, f.resolver.as_ref())
            .await
            .is_ok()
    );
    for bad in [
        record.replace(&key(7), "00"),
        record.replace(&format!("expiry={}\n", NOW + 1), ""),
        record.replace("hosts=[\"8.8.8.8\"]", "hosts=[]"),
        record.replace("hosts=[\"8.8.8.8\"]", "hosts=[\"8.8.8.8\",\"8.8.8.8\"]"),
        record.clone() + "unknown=true\n",
        record.clone() + &record,
    ] {
        assert!(
            load_passes(&bad, &f.relay.policy, f.resolver.as_ref())
                .await
                .is_err()
        );
    }
    let own = policy::Policy::new(["8.8.8.8".parse().unwrap()]);
    assert!(
        load_passes(&record, &own, f.resolver.as_ref())
            .await
            .is_err()
    );
    assert_eq!(f.resolver.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn raw_binary_frame_boundaries_during_admission_and_dial() {
    use tokio_tungstenite::tungstenite::protocol::frame::coding::Data;
    for at_dns in [true, false] {
        for fin in [false, true] {
            for simultaneous in [false, true] {
                let gate = Arc::new(Notify::new());
                let f = Fixture::with_gates(
                    at_dns.then(|| gate.clone()),
                    (!at_dns).then(|| gate.clone()),
                );
                let (mut ws, task) =
                    connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
                let c = challenge(&mut ws).await;
                send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
                if at_dns {
                    f.resolver.entered.notified().await;
                } else {
                    f.dialer.entered.notified().await;
                }
                raw_data(&mut ws, Data::Binary, fin, b"early").await;
                // Both the readable frame and stage completion become ready
                // before the connection task can next run on this thread.
                if simultaneous {
                    gate.notify_one();
                }
                closed(&mut ws, 1002).await;
                task.await.unwrap();
                assert_eq!(
                    f.dialer.addresses.lock().unwrap().len(),
                    usize::from(!at_dns)
                );
                f.dialer.stream.lock().unwrap().take();
                let mut peer = f.peer;
                let mut bytes = Vec::new();
                peer.read_to_end(&mut bytes).await.unwrap();
                assert!(bytes.is_empty());
            }
        }
    }
}

#[tokio::test]
async fn raw_fragmented_binary_before_auth_and_text_after_ok_are_protocol_errors() {
    use tokio_tungstenite::tungstenite::protocol::frame::coding::Data;
    let f = Fixture::new();
    let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
    challenge(&mut ws).await;
    raw_data(&mut ws, Data::Binary, false, b"early").await;
    closed(&mut ws, 1002).await;
    task.await.unwrap();
    assert!(f.dialer.addresses.lock().unwrap().is_empty());

    let f = Fixture::new();
    let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
    let c = challenge(&mut ws).await;
    send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
    verdict(&mut ws, json!({"ok":true})).await;
    raw_data(&mut ws, Data::Text, false, b"bad").await;
    closed(&mut ws, 1002).await;
    task.await.unwrap();
    let mut peer = f.peer;
    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn allowed_fragmentation_controls_and_size_limits_after_ok() {
    use tokio_tungstenite::tungstenite::protocol::frame::coding::Data;
    let f = Fixture::new();
    let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
    let c = challenge(&mut ws).await;
    // AUTH can also be fragmented, with controls between fragments.
    let auth = signed(&c, HOST, 22, NOW, 7).to_string();
    raw_data(&mut ws, Data::Text, false, &auth.as_bytes()[..20]).await;
    ws.send(Message::Ping(vec![9].into())).await.unwrap();
    raw_data(&mut ws, Data::Continue, true, &auth.as_bytes()[20..]).await;
    assert_eq!(frame(&mut ws).await, Message::Pong(vec![9].into()));
    verdict(&mut ws, json!({"ok":true})).await;
    raw_data(&mut ws, Data::Binary, false, b"hello").await;
    ws.send(Message::Ping(vec![8].into())).await.unwrap();
    raw_data(&mut ws, Data::Continue, true, b" world").await;
    assert_eq!(frame(&mut ws).await, Message::Pong(vec![8].into()));
    let mut peer = f.peer;
    let mut bytes = [0; 11];
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"hello world");
    ws.close(None).await.unwrap();
    task.await.unwrap();

    for fragmented in [false, true] {
        let f = Fixture::new();
        let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
        let c = challenge(&mut ws).await;
        send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
        verdict(&mut ws, json!({"ok":true})).await;
        if fragmented {
            raw_data(
                &mut ws,
                Data::Binary,
                false,
                &vec![1; PocLimits::MESSAGE / 2],
            )
            .await;
            raw_data(
                &mut ws,
                Data::Continue,
                true,
                &vec![2; PocLimits::MESSAGE / 2 + 1],
            )
            .await;
        } else {
            raw_data(
                &mut ws,
                Data::Binary,
                true,
                &vec![1; PocLimits::MESSAGE + 1],
            )
            .await;
        }
        closed(&mut ws, 1002).await;
        task.await.unwrap();
        let mut peer = f.peer;
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn transient_backpressure_preserves_a_burst_in_order() {
    let f = Fixture::new();
    let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
    let c = challenge(&mut ws).await;
    send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
    verdict(&mut ws, json!({"ok":true})).await;
    let expected: Vec<u8> = (0..12).flat_map(|i| vec![i; 8192]).collect();
    // The 4-KiB target remains undrained until well beyond the old queue cap.
    for bytes in expected.chunks(8192) {
        ws.send(Message::binary(bytes.to_vec())).await.unwrap();
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }
    assert!(
        !task.is_finished(),
        "ordinary queue pressure closed the stream"
    );
    let mut peer = f.peer;
    let mut received = vec![0; expected.len()];
    tokio::time::timeout(Duration::from_secs(3), peer.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, expected);
    ws.send(Message::binary(b"resumed".to_vec())).await.unwrap();
    let mut tail = [0; 7];
    peer.read_exact(&mut tail).await.unwrap();
    assert_eq!(&tail, b"resumed");
    ws.close(None).await.unwrap();
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn saturated_queue_preserves_slow_write_progress_and_later_traffic() {
    let f = Fixture::new();
    let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
    let c = challenge(&mut ws).await;
    send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
    verdict(&mut ws, json!({"ok":true})).await;

    // One active message, four queued messages and one pending enqueue.
    // The target holds only 4 KiB, so even the first message needs over STALL
    // to complete when the target drains 1 KiB per second.
    let expected: Vec<u8> = (0..6).flat_map(|i| vec![i; PocLimits::MESSAGE]).collect();
    for bytes in expected.chunks(PocLimits::MESSAGE) {
        ws.send(Message::binary(bytes.to_vec())).await.unwrap();
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }
    let started = tokio::time::Instant::now();
    let mut peer = f.peer;
    let mut received = Vec::new();
    for chunk in expected.chunks(1024) {
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(!task.is_finished(), "closed despite regular write progress");
        assert!(
            ws.next().now_or_never().is_none(),
            "unexpected server frame"
        );
        let mut bytes = [0; 1024];
        peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, chunk);
        received.extend_from_slice(&bytes);
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        if received.len() == PocLimits::MESSAGE {
            assert!(started.elapsed() > PocLimits::STALL);
        }
    }
    assert_eq!(received, expected);
    ws.send(Message::binary(b"still connected".to_vec()))
        .await
        .unwrap();
    let mut tail = [0; 15];
    peer.read_exact(&mut tail).await.unwrap();
    assert_eq!(&tail, b"still connected");
    peer.write_all(b"reply").await.unwrap();
    assert_eq!(frame(&mut ws).await, Message::binary(b"reply".to_vec()));
    ws.close(None).await.unwrap();
    task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn sustained_tcp_write_and_full_queue_stalls_are_bounded() {
    for full_queue in [false, true] {
        let f = Fixture::new();
        let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
        let c = challenge(&mut ws).await;
        send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
        verdict(&mut ws, json!({"ok":true})).await;
        for _ in 0..if full_queue { 12 } else { 1 } {
            ws.send(Message::binary(vec![1; 8192])).await.unwrap();
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
        }
        assert!(!task.is_finished());
        tokio::time::advance(PocLimits::STALL + Duration::from_secs(1)).await;
        closed(&mut ws, 1013).await;
        task.await.unwrap();
        let mut peer = f.peer;
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received.len(), 4096);
    }
}

#[tokio::test(start_paused = true)]
async fn late_valid_auth_retains_the_full_dial_timeout_and_failure_verdict() {
    let f = Fixture::with_gates(None, Some(Arc::new(Notify::new())));
    let (mut ws, task) = connected(Arc::new(f.relay), &format!("/v1/tcp/{HOST}/22")).await;
    let c = challenge(&mut ws).await;
    tokio::time::advance(Duration::from_secs(12)).await;
    send(&mut ws, signed(&c, HOST, 22, NOW, 7)).await;
    f.dialer.entered.notified().await;
    tokio::time::advance(PocLimits::CONNECT).await;
    verdict(&mut ws, refused("dial")).await;
    closed(&mut ws, 1011).await;
    task.await.unwrap();
    assert_eq!(f.dialer.addresses.lock().unwrap().len(), 1);
}
