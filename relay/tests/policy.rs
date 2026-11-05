use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tau_relay::{
    policy::{self, Policy},
    *,
};

#[test]
fn raw_path_grammar() {
    for host in [
        "example.net",
        "xn--bcher-kva.example",
        "1.2.3.4",
        "2001:4860::1",
    ] {
        assert!(
            policy::destination(&format!("/v1/tcp/{host}/65535")).is_some(),
            "{host}"
        );
    }
    for path in [
        "/v2/tcp/example.net/22",
        "/v1/tcp/example.net/022",
        "/v1/tcp/example.net/+22",
        "/v1/tcp/example.net/0",
        "/v1/tcp/example.net/65536",
        "/v1/tcp/EXAMPLE.net/22",
        "/v1/tcp/example.net./22",
        "/v1/tcp/%65xample.net/22",
        "/v1/tcp/example.net/22/",
        "/v1/tcp/example.net/22?x",
        "/v1/tcp/127.1/22",
        "/v1/tcp/0177.0.0.1/22",
        "/v1/tcp/2130706433/22",
        "/v1/tcp/0x7f000001/22",
        "/v1/tcp/[2001:4860::1]/22",
        "/v1/tcp/2001:4860:0:0:0:0:0:1/22",
        "/v1/tcp/fe80::1%eth0/22",
        "/v1/tcp/bücher.example/22",
        "/v1/tcp/xn--.example/22",
        "/v1/tcp/a_b.example/22",
    ] {
        assert!(policy::destination(path).is_none(), "{path}");
    }
}
#[test]
fn registry_ranges_and_boundaries() {
    let policy = Policy::default();
    for &(base, bits) in policy::V4_DENY {
        for n in [base, base | (u32::MAX >> bits)] {
            assert!(!policy.admits(Ipv4Addr::from(n).into()));
        }
        for n in [
            base.wrapping_sub(1),
            (base | (u32::MAX >> bits)).wrapping_add(1),
        ] {
            let excluded = policy::V4_DENY
                .iter()
                .any(|(b, p)| n >> (32 - p) == b >> (32 - p));
            assert_eq!(policy.admits(Ipv4Addr::from(n).into()), !excluded);
        }
    }
    for &(base, bits) in policy::V6_DENY {
        for n in [base, base | (u128::MAX >> bits)] {
            assert!(!policy.admits(Ipv6Addr::from(n).into()));
        }
        for n in [base - 1, (base | (u128::MAX >> bits)) + 1] {
            let excluded = n >> 125 != 1
                || policy::V6_DENY
                    .iter()
                    .any(|(b, p)| n >> (128 - p) == b >> (128 - p));
            assert_eq!(policy.admits(Ipv6Addr::from(n).into()), !excluded);
        }
    }
    for ip in [
        "::",
        "::1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "64:ff9b:1::1",
        "2002:808:808::1",
        "2001::1",
        "2001:10::1",
        "2001:20::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "5f00::1",
        "100::1",
        "100:0:0:1::1",
        "192.0.0.9",
        "192.31.196.1",
        "192.52.193.1",
        "192.175.48.1",
    ] {
        assert!(!policy.admits(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "8.8.8.8",
        "1.1.1.1",
        "2001:4860:4860::8888",
        "2606:4700::1111",
    ] {
        assert!(policy.admits(ip.parse().unwrap()), "{ip}");
    }
    let own: IpAddr = "8.8.8.8".parse().unwrap();
    assert!(!Policy::new([own]).admits(own));
    let interfaces = policy::interfaces().unwrap();
    for ip in interfaces.clone() {
        assert!(!Policy::new(interfaces.clone()).admits(ip));
    }
}
#[test]
fn pace_sliding_boundaries_and_concurrent_accounting() {
    let timing = Timing::default();
    assert_eq!(
        (
            timing.skew,
            timing.spacing.as_secs(),
            timing.window.as_secs(),
            timing.cap
        ),
        (600, 1, 900, 200)
    );
    let mut pace = Pace::default();
    assert!(pace.admit("k", "h", Duration::ZERO, &timing));
    assert!(!pace.admit("k", "h", Duration::from_millis(999), &timing));
    for t in 1..200 {
        assert!(pace.admit("k", "h", Duration::from_secs(t), &timing));
    }
    assert!(!pace.admit("k", "h", Duration::from_secs(899), &timing));
    assert!(pace.admit("k", "h", Duration::from_secs(900), &timing));
    assert!(pace.admit("k2", "h", Duration::from_secs(900), &timing));
    let pace = Arc::new(Mutex::new(Pace::default()));
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let pace = pace.clone();
            let timing = timing.clone();
            std::thread::spawn(move || {
                pace.lock()
                    .unwrap()
                    .admit("k", "h", Duration::ZERO, &timing)
            })
        })
        .collect();
    assert_eq!(
        handles
            .into_iter()
            .filter(|h| h.thread().id() != std::thread::current().id())
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>(),
        1
    );
}
#[test]
fn independent_signature_vector() {
    let event: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/vectors/paid-tcp-relay-844e834-auth.json"
    ))
    .unwrap();
    let auth: auth::Auth = serde_json::from_value(event.clone()).unwrap();
    assert!(auth.signature());
    let mut changed = event.clone();
    changed["content"] = "changed".into();
    assert!(
        !serde_json::from_value::<auth::Auth>(changed)
            .unwrap()
            .signature()
    );
    let mut changed = event;
    changed["sig"] = hex::encode([0; 64]).into();
    assert!(
        !serde_json::from_value::<auth::Auth>(changed)
            .unwrap()
            .signature()
    );
}
