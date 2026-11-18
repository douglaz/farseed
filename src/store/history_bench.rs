//! Native, feature-only history measurements through the real encrypted store paths.
//! No provider, relay, filesystem storage, browser, or product decisions are replaced.
use super::*;
use crate::credential::InferenceAccountCredential;
use crate::goals::Tool;
use poc::{Binding, Change, Status, Task};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use unlock_marks::{Counter, Mark, Timer};

type Files = BTreeMap<String, Vec<u8>>;
type Sample = BTreeMap<&'static str, f64>;
type BenchResult<T> = Result<T, &'static str>;
const REPEATS: usize = 3;
const STEPS: usize = 40;
/// 14 minutes unless `TAU_HISTORY_BENCH_BUDGET_SECONDS` names another whole number of seconds.
fn budget() -> Duration {
    std::env::var("TAU_HISTORY_BENCH_BUDGET_SECONDS")
        .ok()
        .and_then(|text| text.parse().ok())
        .map_or(Duration::from_secs(14 * 60), Duration::from_secs)
}
const MACHINE: &str = "fixture";
const FIXTURE_SECONDS: u64 = 100;
const COMMAND_BYTES: [usize; 6] = [800, 12000, 4000, 1000, 1500, 2500];
const OUTPUT_BYTES: [usize; 8] = [200, 800, 1200, 1600, 2000, 2400, 8192, 200];

/// Functions supplied by the binary's counting global allocator. All phase baselines
/// exclude the generator, snapshot, and fresh encrypted input files already in memory.
pub struct MemoryMeter {
    pub live: fn() -> usize,
    pub peak: fn() -> usize,
    pub reset_peak: fn(),
}

fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"history benchmark fixture passphrase".to_vec())
}

fn timed<T>(sample: &mut Sample, name: &'static str, action: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = action();
    sample.insert(name, start.elapsed().as_secs_f64() * 1000.0);
    value
}

fn ready() -> BenchResult<Store<MemoryStorage>> {
    let mut store = block_on(create(MemoryStorage::default(), &Pbkdf2, pass()))
        .map_err(|_| "fixture_create_failed")?;
    block_on(store.seed_backup(allocation::Completion::Skipped))
        .map_err(|_| "fixture_backup_failed")?;
    // Since the launch fence every command needs its machine's stored target, which every
    // enrolled or purchased machine has; enroll the fixture machine as an existing machine.
    block_on(store.poc_enroll(poc_targets::Enrollment {
        target: crate::poc::targets::TargetRecord {
            machine: MACHINE.into(),
            relay: "wss://relay.invalid/".into(),
            profile: "v1".into(),
            host: "192.0.2.1".into(),
            port: 22,
            user: "arch".into(),
            elevation: crate::jobs::Elevation::None,
            pin: format!(
                "SHA256:{}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD_NO_PAD,
                    [3u8; 32]
                )
            ),
        },
        approve_existing: true,
        class_answer: crate::dispatch::ClassAnswer::No,
        approve_maintained_access: true,
    }))
    .map_err(|_| "fixture_enroll_failed")?;
    block_on(store.set_inference_account(InferenceAccountCredential::new(
        b"plainly-fake-benchmark-account".to_vec(),
    )))
    .map_err(|_| "fixture_account_failed")?;
    Ok(store)
}

fn change(store: &mut Store<MemoryStorage>, task: &Task, change: Change) -> BenchResult<Task> {
    block_on(store.poc_change(&task.id, task.revision, change)).map_err(|_| "fixture_change_failed")
}

fn done() -> Tool {
    Tool::Done {
        machine: MACHINE.into(),
        checks: vec![],
        urls: vec![],
    }
}

fn start_task(store: &mut Store<MemoryStorage>) -> BenchResult<Task> {
    let session = block_on(store.admit_fixture(MACHINE)).map_err(|_| "fixture_admission_failed")?;
    // One fixed fixture time (authority::BENCH_PAIR) serves every native clock read,
    // so the confirmed limits never age. There is no wall-clock wait.
    authority::BENCH_PAIR.with(|pair| pair.set(Some(authority::current_pair(FIXTURE_SECONDS))));
    store
        .synthetic_confirm_limits(FIXTURE_SECONDS)
        .map_err(|_| "fixture_limits_failed")?;
    block_on(store.enter_goal(&session, "install and run a small service".into(), None))
        .map_err(|_| "fixture_goal_failed")?;
    block_on(store.accept_mode(&session, Mode::NoBrief)).map_err(|_| "fixture_mode_failed")?;
    let task = block_on(store.poc_create(&session)).map_err(|_| "fixture_task_failed")?;
    let proposal = crate::declaration::Proposal::parse(&json!({
        "kind":"declaration", "machine":MACHINE,
        "declaration":crate::declaration::ad_hoc_minimum()
    }))
    .map_err(|_| "fixture_declaration_failed")?;
    let candidate = store.next;
    store
        .propose_requirements(&session, candidate, proposal, &done())
        .map_err(|_| "fixture_proposal_failed")?;
    block_on(store.approve_requirements(&session, MACHINE, candidate))
        .map_err(|_| "fixture_approval_failed")?;
    // Requirements approval can advance the task revision.
    store.poc_task(&task.id).map_err(|_| "fixture_task_failed")
}

fn command(step: usize) -> String {
    let mut text = format!("true # fixture step {step}\n#");
    text.extend(std::iter::repeat_n(
        'x',
        COMMAND_BYTES[step % COMMAND_BYTES.len()] - text.len(),
    ));
    text
}

/// Same append/evidence/Settle sequence as the host task fixtures. The command is
/// recorded only, never executed. Evidence represents a completed synthetic job.
fn settle(store: &mut Store<MemoryStorage>, task: &Task, stdout: &str) -> BenchResult<Task> {
    let Some(proposal) = &task.proposal else {
        return Err("fixture_proposal_missing");
    };
    let Tool::Exec { machine, command } = &proposal.tool else {
        return Err("fixture_exec_missing");
    };
    let entry = Entry {
        machine: machine.clone(),
        command: command.as_bytes().to_vec(),
        provenance: Some(crate::dispatch::CommandProvenance {
            target: crate::dispatch::Target::Entry(machine.clone()),
            session: Some(task.start_session.clone()),
            requester: crate::dispatch::Requester::Session,
        }),
    };
    block_on(store.poc_append(
        &Binding {
            task: task.id.clone(),
            revision: task.revision,
            session: task.start_session.clone(),
        },
        &entry,
        &Approval::HarnessPin {
            machine: machine.clone(),
            fingerprint: "SHA256:fixture".into(),
        },
    ))
    .map_err(|_| "fixture_append_failed")?;
    let task = store
        .poc_task(&task.id)
        .map_err(|_| "fixture_task_failed")?;
    let pending = task.pending.as_ref().ok_or("fixture_pending_missing")?;
    // The page reserves the transmission (one LaunchTransmission record) before the
    // prepared wrapper can be sent; the same product function records it here.
    let elevation = store
        .poc_target(machine)
        .map(|target| target.elevation)
        .ok_or("fixture_target_missing")?;
    let sent =
        crate::jobs::launch_with_elevation(&pending.job, machine, command.as_bytes(), elevation);
    block_on(store.poc_launch_transmission(pending.call, sent.as_bytes()))
        .map_err(|_| "fixture_transmission_failed")?;
    block_on(store.job_evidence(&crate::jobs::Evidence {
        call: pending.call,
        job: pending.job.clone(),
        record: crate::jobs::Record::Present {
            machine: hex::encode(machine),
            command: hex::encode(command),
            boot: "fixture-boot".into(),
            current_boot: "fixture-boot".into(),
            pid: 123,
            alive: false,
            exit_status: Some(0),
            stdout: hex::encode(stdout),
            stderr: String::new(),
        },
    }))
    .map_err(|_| "fixture_evidence_failed")?;
    change(store, &task, Change::Settle)
}

fn exec_step(store: &mut Store<MemoryStorage>, task: &Task, step: usize) -> BenchResult<Task> {
    let task = change(store, task, Change::Request)?;
    let task = change(
        store,
        &task,
        Change::Propose {
            call_id: format!("fixture-step-{step}"),
            tool: Tool::Exec {
                machine: MACHINE.into(),
                command: command(step),
            },
        },
    )?;
    settle(
        store,
        &task,
        &"o".repeat(OUTPUT_BYTES[step % OUTPUT_BYTES.len()]),
    )
}

fn finish_task(store: &mut Store<MemoryStorage>, task: &Task) -> BenchResult<Task> {
    let task = change(store, task, Change::Request)?;
    let mut task = change(
        store,
        &task,
        Change::Propose {
            call_id: "fixture-done".into(),
            tool: done(),
        },
    )?;
    // The approved minimum requires the real listener verification path. Only the
    // synthetic result is supplied here; product judgment establishes completion.
    for _ in 0..8 {
        task = change(store, &task, Change::PrepareCheck)?;
        if task.status == Status::Complete {
            return Ok(task);
        }
        if task.proposal.is_none() {
            return Err("fixture_verification_failed");
        }
        task = settle(store, &task, "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")?;
    }
    Err("fixture_verification_failed")
}

fn history_task(store: &mut Store<MemoryStorage>, started: Instant) -> BenchResult<String> {
    let identity =
        block_on(store.allocate(Family::Machines)).map_err(|_| "fixture_allocation_failed")?;
    block_on(store.observe(allocation::Event::Created(identity.clone())))
        .map_err(|_| "fixture_created_failed")?;
    let mut task = start_task(store)?;
    // One interrupted AI request per run, re-made after the page reopened (RecoverRequest).
    let requested = change(store, &task, Change::Request)?;
    task = change(store, &requested, Change::RecoverRequest)?;
    for step in 0..STEPS {
        if started.elapsed() >= budget() {
            return Err("runtime_budget_exceeded");
        }
        task = exec_step(store, &task, step)?;
    }
    let task = finish_task(store, &task)?;
    block_on(store.end_session(&task.start_session)).map_err(|_| "fixture_end_failed")?;
    // Tombstones go through the journal and remain in held_credentials' derivation
    // scan. There is no native configured-target withdrawal path to call instead.
    block_on(store.observe(allocation::Event::Destroyed(identity)))
        .map_err(|_| "fixture_destroyed_failed")?;
    Ok(task.id)
}

/// Native equivalent of publication's normal successful no-transient-fields path.
/// Browser owner/generation checks, JS parsing, and postMessage are not simulated.
fn publication(
    local: &mut Local<MemoryStorage, Pbkdf2>,
    incoming: Option<&str>,
    sample: &mut Sample,
    first: bool,
) -> BenchResult<()> {
    let _ = timed(
        sample,
        if first {
            "first_sessions_ms"
        } else {
            "cycle_sessions_ms"
        },
        || local.store().map(|store| store.sessions()),
    );
    // publication parses the incoming report once for historical outcome metadata,
    // once for the incoming protection, and again for its error-step selection.
    if let Some(incoming) = incoming {
        timed(sample, "first_history_parse_ms", || {
            serde_json::from_str::<Value>(incoming)
        })
        .map_err(|_| "publication_parse_failed")?;
    }
    // publication keeps the parsed and the protected incoming report alive until its fresh
    // report is built and protected (src/harness/inference.rs, the `result` closure).
    let mut retained = None;
    if let Some(incoming) = incoming {
        let value = timed(sample, "publish_parse_ms", || {
            serde_json::from_str::<Value>(incoming)
        })
        .map_err(|_| "publication_parse_failed")?;
        let safe = unlock_marks::measure(Mark::PublishIncomingProtect, || {
            local
                .store()
                .ok_or("publication_locked")?
                .protect_publication(&value, &[])
                .map_err(|_| "publication_incoming_failed")
        })?;
        if safe["state"] != "unlocked" || safe.get("error").is_some() {
            return Err("publication_incoming_failed");
        }
        retained = Some((value, safe));
    }
    let start = Instant::now();
    let value = timed(
        sample,
        if first {
            "first_build_ms"
        } else {
            "cycle_build_ms"
        },
        || unlock_marks::measure(Mark::PublishBuild, || local.build_report(None)),
    );
    let mut value = timed(
        sample,
        if first {
            "first_protect_ms"
        } else {
            "cycle_protect_ms"
        },
        || unlock_marks::measure(Mark::PublishProtect, || local.protect_report(value)),
    );
    if value["state"] != "unlocked" || value.get("error").is_some() {
        return Err("publication_report_failed");
    }
    drop(retained);
    if let Some(incoming) = incoming {
        timed(sample, "first_display_parse_ms", || {
            serde_json::from_str::<Value>(incoming)
        })
        .map_err(|_| "publication_parse_failed")?;
    }
    // The two unconditional custody metadata protections in publication matter:
    // both enumerate all held credentials, even without a provider purchase. The
    // browser-only holders are empty in this native fixture (no network key).
    value["poc_configuration"] = timed(
        sample,
        if first {
            "first_inference_metadata_ms"
        } else {
            "cycle_inference_metadata_ms"
        },
        || {
            local
                .store()
                .ok_or("publication_locked")?
                .protect_publication(&json!({"key_set":false,"configuration":null}), &[])
                .map_err(|_| "publication_configuration_failed")
        },
    )?;
    value["provider_configuration"] = timed(
        sample,
        if first {
            "first_provider_metadata_ms"
        } else {
            "cycle_provider_metadata_ms"
        },
        || {
            let store = local.store().ok_or("publication_locked")?;
            store
                .protect_publication(
                    &json!({
                        "key_set":false,
                        "origin":store.procurement_origin(),
                        "account":store.provider_account().map(|account| account.public()),
                        "recorded":store.provider_account().is_some(),
                        "relay_deployed":store.deployment_relay_present(),
                    }),
                    &[],
                )
                .map_err(|_| "publication_configuration_failed")
        },
    )?;
    let serialize = Timer::new(Mark::PublishSerialize);
    let encoded = timed(
        sample,
        if first {
            "first_report_serialize_ms"
        } else {
            "cycle_report_serialize_ms"
        },
        || value.to_string(),
    );
    let message = timed(
        sample,
        if first {
            "first_message_ms"
        } else {
            "cycle_message_ms"
        },
        || {
            let mut message = value.clone();
            if let Some(fields) = message.as_object_mut() {
                for (from, to) in [
                    ("state", "store_state"),
                    ("error", "store_error"),
                    ("reason", "store_reason"),
                ] {
                    if let Some(value) = fields.remove(from) {
                        fields.insert(to.into(), value);
                    }
                }
            }
            json!({"store":message}).to_string()
        },
    );
    if first {
        serialize.count(Counter::PublishBytes, message.len() as u64);
    }
    drop(serialize);
    timed(
        sample,
        if first {
            "first_check_ms"
        } else {
            "cycle_check_ms"
        },
        || {
            unlock_marks::measure(Mark::PublishCheck, || {
                let store = local.store().ok_or("publication_locked")?;
                store
                    .check_output_bytes(encoded.as_bytes())
                    .map_err(|_| "publication_check_failed")?;
                store
                    .check_output_bytes(message.as_bytes())
                    .map_err(|_| "publication_check_failed")?;
                store
                    .check_report_sessions(&value)
                    .map_err(|_| "publication_session_failed")
            })
        },
    )?;
    sample.insert(
        if first {
            "first_message_bytes"
        } else {
            "cycle_message_bytes"
        },
        message.len() as f64,
    );
    sample.insert(
        if first {
            "first_report_ms"
        } else {
            "cycle_report_ms"
        },
        start.elapsed().as_secs_f64() * 1000.0,
    );
    Ok(())
}

fn details(store: &Store<MemoryStorage>, oldest: &str, sample: &mut Sample) -> BenchResult<()> {
    let start = Instant::now();
    let value = timed(sample, "details_build_ms", || -> BenchResult<Value> {
        let task = store.poc_task(oldest).map_err(|_| "details_task_failed")?;
        Ok(
            json!({"task_details":{"id":oldest,"request":"fixture-details",
            "generation":"0","task":store.poc_task_view(&task)}}),
        )
    })?;
    let protected = timed(sample, "details_protect_ms", || {
        store.protect_page_publication(&value)
    })
    .map_err(|_| "details_protect_failed")?;
    if protected["task_details"]["id"] != oldest
        || protected["task_details"]["task"]["id"] != oldest
        || protected["task_details"]["request"] != "fixture-details"
        || protected["task_details"]["generation"] != "0"
    {
        return Err("details_correlation_failed");
    }
    let encoded = timed(sample, "details_serialize_ms", || protected.to_string());
    timed(sample, "details_check_ms", || {
        store.check_output_bytes(encoded.as_bytes())
    })
    .map_err(|_| "details_check_failed")?;
    sample.insert("details_bytes", encoded.len() as f64);
    sample.insert("details_total_ms", start.elapsed().as_secs_f64() * 1000.0);
    Ok(())
}

fn measure(files: &Files, oldest: &str, meter: &MemoryMeter) -> BenchResult<Sample> {
    let mut sample = Sample::new();
    let storage = MemoryStorage::with_files(files.clone());
    let mut local = Local::new(storage, Pbkdf2);
    block_on(local.open());
    let baseline = (meter.live)();
    (meter.reset_peak)();
    let report = timed(&mut sample, "unlock_call_ms", || {
        block_on(local.unlock(pass()))
    });
    if report["state"] != "unlocked" || report.get("error").is_some() {
        return Err("unlock_failed");
    }
    let encoded = {
        let timer = Timer::new(Mark::UnlockSerialize);
        let encoded = report.to_string();
        timer.count(Counter::UnlockReportBytes, encoded.len() as u64);
        encoded
    };
    drop(report);
    let live = (meter.live)().saturating_sub(baseline);
    let peak = (meter.peak)().saturating_sub(baseline);
    sample.insert("memory_live_after_unlock_bytes", live as f64);
    sample.insert("memory_peak_unlock_bytes", peak as f64);
    (meter.reset_peak)();
    let first = Instant::now();
    publication(&mut local, Some(&encoded), &mut sample, true)?;
    let first_ms = first.elapsed().as_secs_f64() * 1000.0;
    let peak = (meter.peak)().saturating_sub(baseline);
    let marks = unlock_marks::snapshot();
    sample.extend(marks);
    sample.insert("memory_baseline_bytes", baseline as f64);
    // No native message post exists; retain the round-1 field as an explicit zero.
    sample.insert("publish_post_ms", 0.0);
    sample.insert("first_update_ms", first_ms);
    sample.insert("memory_peak_first_update_bytes", peak as f64);
    drop(encoded);
    let store = local.store().ok_or("unlock_failed")?;
    sample.insert("tasks", store.poc.len() as f64);
    sample.insert("sessions", store.sessions.len() as f64);
    sample.insert(
        "allocation_entries",
        store.allocation().entries().len() as f64,
    );
    details(store, oldest, &mut sample)?;
    let cycle = Instant::now();
    let task = timed(&mut sample, "cycle_start_ms", || start_task(store))?;
    let task = timed(&mut sample, "cycle_exec_ms", || exec_step(store, &task, 0))?;
    if task.pending.is_some() || task.completed.is_empty() {
        return Err("cycle_unsettled");
    }
    sample.insert("cycle_command_ms", cycle.elapsed().as_secs_f64() * 1000.0);
    publication(&mut local, None, &mut sample, false)?;
    sample.insert("cycle_total_ms", cycle.elapsed().as_secs_f64() * 1000.0);
    Ok(sample)
}

fn sizes() -> BenchResult<Vec<usize>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let raw = match args.as_slice() {
        [] => std::env::var("TAU_HISTORY_BENCH_SIZES").unwrap_or_else(|_| "1,10,50,200".into()),
        [value] => value.clone(),
        _ => return Err("sizes_invalid"),
    };
    let mut sizes = raw
        .split(',')
        .map(|value| value.parse::<usize>().map_err(|_| "sizes_invalid"))
        .collect::<BenchResult<Vec<_>>>()?;
    sizes.sort_unstable();
    sizes.dedup();
    if sizes.first() != Some(&1) || sizes.last().is_none_or(|size| *size > 200) {
        return Err("sizes_invalid");
    }
    Ok(sizes)
}

#[allow(
    unexpected_cfgs,
    reason = "the crypto dependencies' documented force-soft cfgs"
)]
fn header() {
    println!("native release single_thread RustCrypto AES256GCM SHA256 pbkdf2");
    println!(
        "aes_hardware {}",
        u8::from(aes_gcm::aes::hardware_accelerated())
    );
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let (sha_hardware, ghash_hardware) = (
        std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("sse2")
            && std::arch::is_x86_feature_detected!("ssse3")
            && std::arch::is_x86_feature_detected!("sse4.1"),
        std::arch::is_x86_feature_detected!("avx")
            && std::arch::is_x86_feature_detected!("pclmulqdq"),
    );
    #[cfg(target_arch = "aarch64")]
    let (sha_hardware, ghash_hardware) = (
        std::arch::is_aarch64_feature_detected!("sha2"),
        std::arch::is_aarch64_feature_detected!("aes"),
    );
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    let (sha_hardware, ghash_hardware) = (false, false);
    println!(
        "sha256_hardware {}",
        u8::from(sha_hardware && !cfg!(any(sha2_backend = "soft", sha2_256_backend = "soft")))
    );
    println!(
        "ghash_hardware {}",
        u8::from(ghash_hardware && !cfg!(polyval_backend = "soft"))
    );
    println!("aes_force_soft {}", u8::from(cfg!(aes_backend = "soft")));
    println!(
        "sha256_force_soft {}",
        u8::from(cfg!(any(sha2_backend = "soft", sha2_256_backend = "soft")))
    );
    println!(
        "ghash_force_soft {}",
        u8::from(cfg!(polyval_backend = "soft"))
    );
    println!("crypto_backend runtime_dispatch_unless_forced_soft");
    println!("phone wasm32 software_AES_GCM_SHA256 single_thread slower_CPU WebCrypto_PBKDF2");
    println!("median_repeats {REPEATS}");
    println!("budget_seconds {}", budget().as_secs());
}

/// One generation pass, snapshots at the requested sizes, three independent unlocks
/// from each copied snapshot. Failure never prints product errors or fixture values.
pub fn run(meter: MemoryMeter) -> BenchResult<()> {
    if cfg!(debug_assertions) {
        return Err("release_required");
    }
    let sizes = sizes()?;
    header();
    let started = Instant::now();
    let mut store = ready()?;
    let base_records = store.next;
    let mut generated = 0;
    let mut oldest = None;
    let mut columns: Vec<(usize, Sample)> = Vec::new();
    let mut generation_ms = started.elapsed().as_secs_f64() * 1000.0;
    let mut cutoff = 0;
    for size in sizes {
        // Project the next column with the growth measured between the last two columns
        // (between linear and quadratic; quadratic with one column), with a margin for the
        // measurement repeats. Keep 1, 10 and 50; omit an over-budget larger column.
        if size > 50
            && let Some((previous, sample)) = columns.last()
        {
            let exponent = match columns.len() {
                n if n >= 2 => {
                    let (earlier, older) = &columns[n - 2];
                    let size_ratio = *previous as f64 / *earlier as f64;
                    let time_ratio = sample["generation_ms"] / older["generation_ms"];
                    (time_ratio.ln() / size_ratio.ln()).clamp(1.0, 2.0)
                }
                _ => 2.0,
            };
            let scale = (size as f64 / *previous as f64).powf(exponent);
            let projected =
                generation_ms * (scale - 1.0) + sample["measurement_wall_ms"] * scale * 2.0;
            if started.elapsed().as_secs_f64() * 1000.0 + projected
                > budget().as_secs_f64() * 1000.0
            {
                cutoff = 1;
                break;
            }
        }
        let generation = Instant::now();
        while generated < size {
            if started.elapsed() >= budget() {
                return Err("runtime_budget_exceeded");
            }
            let id = history_task(&mut store, started)?;
            oldest.get_or_insert(id);
            generated += 1;
        }
        generation_ms += generation.elapsed().as_secs_f64() * 1000.0;
        let files = store.storage.files();
        let wall = Instant::now();
        let mut samples = Vec::new();
        for _ in 0..REPEATS {
            if started.elapsed() >= budget() {
                return Err("runtime_budget_exceeded");
            }
            samples.push(measure(
                &files,
                oldest.as_deref().ok_or("oldest_missing")?,
                &meter,
            )?);
        }
        let mut median = Sample::new();
        for name in samples[0].keys() {
            let mut values = samples
                .iter()
                .map(|sample| sample[name])
                .collect::<Vec<_>>();
            values.sort_by(f64::total_cmp);
            median.insert(*name, values[REPEATS / 2]);
        }
        median.insert("measurement_wall_ms", wall.elapsed().as_secs_f64() * 1000.0);
        median.insert("generation_ms", generation_ms);
        median.insert(
            "records_per_task",
            (store.next - base_records) as f64 / generated as f64,
        );
        median.insert(
            "destroyed_allocations",
            store
                .allocation()
                .entries()
                .iter()
                .filter(|entry| entry.status == allocation::Status::Destroyed)
                .count() as f64,
        );
        median.insert(
            "journal_bytes",
            files
                .iter()
                .filter(|(name, _)| name.as_str() != ENVELOPE)
                .map(|(_, bytes)| bytes.len())
                .sum::<usize>() as f64,
        );
        columns.push((size, median));
    }
    println!("budget_cutoff {cutoff}");
    print!("{:<40}", "metric");
    for (size, _) in &columns {
        print!(" {size:>16}");
    }
    println!(" {:>16}", "largest_over_1");
    for name in columns[0].1.keys() {
        print!("{name:<40}");
        for (_, sample) in &columns {
            print!(" {:>16.3}", sample[name]);
        }
        let first = columns[0].1[name];
        let last = columns[columns.len() - 1].1[name];
        // Zero/zero is flat; a nonzero numerator with zero baseline uses a fixed
        // numeric sentinel, never infinity or a misleading flat ratio.
        let ratio = if first > 0.0 {
            last / first
        } else if last == 0.0 {
            1.0
        } else {
            -1.0
        };
        println!(" {ratio:>16.3}");
    }
    held_set()
}

/// Extra machines (created, then destroyed) and relay passes per held-set column, on top of one
/// finished task: the held set, not the task count, sizes the protection matcher.
const HELD_SET_SIZES: [usize; 4] = [0, 100, 400, 1600];
const HELD_SET_REPEATS: usize = 101;

fn median_of(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

/// Plain fixture text split into strings, as a task view holds it; about `bytes` long.
fn held_set_value(bytes: usize) -> Value {
    let mut lines = Vec::new();
    let mut total = 0;
    while total < bytes {
        let text = format!("fixture output line {} with ordinary words", lines.len());
        total += text.len();
        lines.push(Value::String(text));
    }
    json!({"task": {"completed": lines}})
}

/// One machine, created and destroyed, and one relay pass, created, through the allocation journal.
fn add_machine_and_pass(store: &mut Store<MemoryStorage>) -> BenchResult<()> {
    let machine =
        block_on(store.allocate(Family::Machines)).map_err(|_| "held_set_allocation_failed")?;
    block_on(store.observe(allocation::Event::Created(machine.clone())))
        .map_err(|_| "held_set_created_failed")?;
    block_on(store.observe(allocation::Event::Destroyed(machine)))
        .map_err(|_| "held_set_destroyed_failed")?;
    let relay =
        block_on(store.allocate(Family::Passes)).map_err(|_| "held_set_allocation_failed")?;
    block_on(store.observe(allocation::Event::Created(relay)))
        .map_err(|_| "held_set_created_failed")?;
    Ok(())
}

/// Per-check protection cost against the held set: a small history (one finished task) with
/// 0, 100, 400 and 1,600 extra machines and passes. Prints its own fixed table.
fn held_set() -> BenchResult<()> {
    let started = Instant::now();
    let mut store = ready()?;
    history_task(&mut store, started)?;
    let check = held_set_value(8 * 1024);
    let page = held_set_value(200 * 1024);
    let mut added = 0;
    let mut columns: Vec<(usize, Sample)> = Vec::new();
    for target in HELD_SET_SIZES {
        while added < target {
            add_machine_and_pass(&mut store)?;
            added += 1;
        }
        let mut sample = Sample::new();
        sample.insert(
            "held_set_allocation_entries",
            store.allocation().entries().len() as f64,
        );
        let (mut helds, mut checks, mut pages) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..HELD_SET_REPEATS {
            let start = Instant::now();
            drop(
                store
                    .held_credentials()
                    .map_err(|_| "held_set_held_failed")?,
            );
            helds.push(start.elapsed().as_secs_f64() * 1000.0);
            let start = Instant::now();
            store
                .protect_output(&check)
                .map_err(|_| "held_set_check_failed")?;
            checks.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        for _ in 0..11 {
            let start = Instant::now();
            store
                .protect_page_publication(&page)
                .map_err(|_| "held_set_page_failed")?;
            pages.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        sample.insert("held_set_held_credentials_ms", median_of(helds));
        sample.insert("held_set_check_8k_ms", median_of(checks));
        sample.insert("held_set_page_200k_ms", median_of(pages));
        let files = store.storage.files();
        timed(&mut sample, "held_set_unlock_ms", || {
            block_on(unlock(MemoryStorage::with_files(files), &Pbkdf2, pass()))
        })
        .map_err(|_| "held_set_unlock_failed")?;
        // Adding one more machine and pass after the measurements: five journal appends, whose
        // own protection checks derive the new keys and rebuild the seed matcher. The next
        // column adds the rest of its count.
        timed(&mut sample, "held_set_extend_ms", || {
            add_machine_and_pass(&mut store)
        })?;
        added += 1;
        columns.push((target, sample));
    }
    print!("{:<40}", "held_set_extra_machines_and_passes");
    for (size, _) in &columns {
        print!(" {size:>16}");
    }
    println!(" {:>16}", "largest_over_0");
    for name in columns[0].1.keys() {
        print!("{name:<40}");
        for (_, sample) in &columns {
            print!(" {:>16.3}", sample[name]);
        }
        let first = columns[0].1[name];
        let last = columns[columns.len() - 1].1[name];
        println!(" {:>16.3}", if first > 0.0 { last / first } else { -1.0 });
    }
    Ok(())
}
