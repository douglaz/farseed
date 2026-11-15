#!/usr/bin/env python3
"""Build each completion mutant, require a behavioral red, restore and rebuild green.

Run alone on a quiet tree. Logs are retained in --output; source bytes are restored
in finally, including on a failed command. This script does not change git state.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--identity", type=Path, required=True)
parser.add_argument("--cargo", default="cargo")
parser.add_argument("--web", required=True)
parser.add_argument("--only", choices=["K1", "K2", "K3", "K4", "K5"])
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
cargo = shlex.split(args.cargo)
web = shlex.split(args.web)
root = Path.cwd()
suite = "store::poc::tests::completion_tests::"


def identity():
    return subprocess.check_output(
        [sys.executable, "-I", "-B", str(args.identity)], text=True
    ).strip()


def run(label, argv, expected, behavioral=False):
    before = identity()
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    clock = time.monotonic()
    log = args.output / (label + ".log")
    with log.open("wb") as output:
        result = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT)
    body = log.read_bytes()
    record = dict(
        label=label, argv=argv, cwd=str(root), lane="tail", expected=expected,
        actual=result.returncode, start=start, duration=time.monotonic() - clock,
        log=str(log), sha256=hashlib.sha256(body).hexdigest(),
        source_before=before, source_after=identity(),
    )
    with (args.output / "commands.jsonl").open("a") as output:
        output.write(json.dumps(record) + "\n")
    print(json.dumps(record), flush=True)
    if result.returncode != expected:
        raise RuntimeError(label + ": unexpected exit")
    if behavioral and not (b"test result: FAILED" in body and b"Finished `test`" in body):
        raise RuntimeError(label + ": red was not a successfully built test failure")


def native(control, phase, name):
    run(control + "-" + phase + "-native", cargo + [
        "test", "--locked", "--lib", suite + name,
    ], 101 if phase == "red" else 0, behavioral=phase == "red")


def browser(control, phase):
    run(control + "-" + phase + "-build", web + ["scripts/build-web.sh", "tracer"], 0)
    for case in ["delivery-web", "delivery-report-stopped"]:
        run(control + "-" + phase + "-" + case,
            web + ["node", "scripts/check-poc-page.mjs", case],
            1 if phase == "red" else 0)


controls = [
    ("K1", "src/store/poc.rs",
     "task.status = Status::Verifying;",
     "task.verifying = false; task.status = Status::Complete; task.verdict = Some(crate::poc::completion::DELIVERED.into());",
     "completion_optional_reports_never_judge_and_recheck_never_repeats_them"),
    ("K2", "src/poc/completion.rs",
     "let declaration = Declaration::parse(value)?;",
     'let mut value = value.clone(); value["required"] = serde_json::json!([]); '
     'value["drift_checks"] = serde_json::json!([]); let declaration = Declaration::parse(&value)?;',
     "completion_proposal_admission_returns_each_refusal_without_commands"),
    ("K3", "src/poc/completion.rs",
     "for socket in sockets.iter().filter(|s| s.proto == Protocol::Tcp) {",
     "for socket in sockets.iter().filter(|s| s.proto == Protocol::Tcp && "
     "!s.address.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())) {",
     "completion_tcp_permissions_judge_loopback_and_record_udp"),
    ("K4", "src/poc/completion.rs",
     "} else if running && matches!(enabled, Some(Observation::Enabled(true))) {",
     "} else if running {",
     "completion_pinned_reads_and_lifecycle_statuses"),
    ("K5", "src/poc/completion.rs",
     "let mut measurements = delivery::Measurements::missing();",
     "let supplied: Vec<_> = plan.iter().enumerate().map(|(i, read)| Some("
     "observations.get(i).cloned().flatten().unwrap_or_else(|| match read {"
     "Read::Running { .. } => Observation::Running(true),"
     "Read::Enabled { .. } => Observation::Enabled(true),"
     "Read::Listeners => Observation::Sockets(vec![]),"
     "}))).collect(); let observations = supplied.as_slice();"
     "let mut measurements = delivery::Measurements::missing();",
     "completion_unknown_reads_never_clear_findings_and_full_retry_can"),
]

for control, path, old, new, name in controls:
    if args.only and control != args.only:
        continue
    source = Path(path)
    original = source.read_bytes()
    text = original.decode()
    if text.count(old) != 1:
        raise RuntimeError(control + ": mutation site is not unique")
    before = identity()
    red_ok = False
    try:
        source.write_text(text.replace(old, new))
        native(control, "red", name)
        if control == "K1":
            browser(control, "red")
        red_ok = True
    finally:
        source.write_bytes(original)
        if identity() != before:
            raise RuntimeError(control + ": restored source identity differs")
        # Each control owns a separate restored build and test, even after a bad red.
        native(control, "green", name)
        if control == "K1":
            browser(control, "green")
    if not red_ok or identity() != before:
        raise RuntimeError(control + ": incomplete control or source changed")
    print(json.dumps({"control": control, "restored": before, "passed": True}), flush=True)
