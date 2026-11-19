use std::process::Command;
fn args() -> Vec<&'static str> {
    vec![
        "--dry-run",
        "--host",
        "relay.example.net",
        "--domain",
        "relay.example.net",
        "--known-hosts",
        "/operator/known_hosts",
        "--identity",
        "/operator/key 'file",
        "--binary",
        "/artifacts/tau-relay",
        "--passes",
        "/operator/passes.toml",
        "--dns-server",
        "192.0.2.53",
        "--own-address",
        "203.0.113.10",
    ]
}
#[test]
fn dry_run_has_no_transport_and_quotes_paths_and_permissions() {
    let output = Command::new("/usr/bin/python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/deploy.py"))
        .args(args())
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("StrictHostKeyChecking=yes"));
    assert!(text.contains("GlobalKnownHostsFile=/dev/null"));
    assert!(text.contains("pacman -Syu --noconfirm --needed caddy nftables"));
    assert!(text.contains("chmod 0640 /etc/tau-relay/passes.toml.new"));
    assert!(text.contains("nft -c -f /etc/tau-relay/relay.nft"));
    assert!(text.contains("UserKnownHostsFile=/operator/known_hosts"));
    assert!(text.contains("key '\"'\"'file"));
    assert!(!text.contains("StrictHostKeyChecking=no"));
}
#[test]
fn deploy_rejects_argument_injection_before_transport() {
    for bad in ["--host", "--domain", "--dns-server", "--own-address"] {
        let mut args = args();
        let index = args.iter().position(|a| *a == bad).unwrap() + 1;
        args[index] = "x;exit 0";
        let result = Command::new("/usr/bin/python3")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/deploy.py"))
            .args(args)
            .env("PATH", "/nonexistent")
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn known_hosts_rejects_option_syntax_and_expansion_before_transport() {
    for value in [
        "/operator/known hosts",
        "/operator/known'hosts",
        "/operator/known\"hosts",
        "/operator/known\\hosts",
        "~/known_hosts",
        "/operator/%h",
        "/operator/%%",
        "/operator/${HOME}/known_hosts",
        "/operator/$HOME",
        "/operator/known\thosts",
        "none",
        "relative/known_hosts",
        "",
    ] {
        for dry in [true, false] {
            let mut args = args();
            if !dry {
                args.remove(0);
            }
            let index = args.iter().position(|a| *a == "--known-hosts").unwrap() + 1;
            args[index] = value;
            let output = Command::new("/usr/bin/python3")
                .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/deploy.py"))
                .args(args)
                .env("PATH", "/nonexistent")
                .output()
                .unwrap();
            assert!(!output.status.success(), "{value:?}");
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("absolute literal path"));
        }
    }
}

#[test]
fn generated_ssh_options_parse_as_one_literal_known_hosts_file() {
    let dry = Command::new("/usr/bin/python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/deploy.py"))
        .args(args())
        .output()
        .unwrap();
    assert!(dry.status.success());
    // Decode the printed argv, then ask OpenSSH to parse its own option grammar.
    // -G never opens a transport or reads these placeholder credential files.
    let line = String::from_utf8(dry.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned();
    let decoded = Command::new("/usr/bin/python3")
        .args([
            "-c",
            "import json,shlex,sys; print(json.dumps(shlex.split(sys.argv[1])))",
            &line,
        ])
        .output()
        .unwrap();
    assert!(decoded.status.success());
    let argv: Vec<String> = serde_json::from_slice(&decoded.stdout).unwrap();
    assert_eq!(argv[argv.len() - 3], "/operator/key 'file");
    let parsed = Command::new("ssh")
        .arg("-G")
        .args(&argv[1..argv.len() - 1])
        .output()
        .unwrap();
    assert!(
        parsed.status.success(),
        "{}",
        String::from_utf8_lossy(&parsed.stderr)
    );
    let config = String::from_utf8(parsed.stdout).unwrap();
    assert_eq!(
        config
            .lines()
            .find(|l| l.starts_with("userknownhostsfile ")),
        Some("userknownhostsfile /operator/known_hosts")
    );
    assert_eq!(
        config
            .lines()
            .find(|l| l.starts_with("globalknownhostsfile ")),
        Some("globalknownhostsfile /dev/null")
    );
}

#[test]
fn dry_run_preserves_reload_unit_for_static_validation() {
    use base64::Engine;
    let output = Command::new("/usr/bin/python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/deploy/deploy.py"))
        .args(args())
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    assert!(output.status.success());
    let script = String::from_utf8(output.stdout).unwrap();
    let mut lines = script.lines();
    let mut unit = None;
    while let Some(line) = lines.next() {
        if line == "base64 -d > /etc/systemd/system/tau-relay.service.new <<'RELAY_PAYLOAD'" {
            unit = Some(
                String::from_utf8(
                    base64::engine::general_purpose::STANDARD
                        .decode(lines.next().unwrap())
                        .unwrap(),
                )
                .unwrap(),
            );
            break;
        }
    }
    let unit = unit.expect("service payload");
    assert!(
        unit.lines()
            .any(|line| line == "ExecReload=/bin/kill -HUP $MAINPID")
    );
    assert!(script.contains("systemd-analyze verify /etc/systemd/system/tau-relay.service"));
}
