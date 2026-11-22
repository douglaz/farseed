//! Fixed diagnostics for durable collection waits.
pub(crate) const UNKNOWN_TASK: &str = "unknown task";
pub(crate) const TASK_ENCODING: &str = "task encoding";
pub(crate) const TASK_BOUNDARY: &str = "task credential boundary";
pub(crate) const PROTECTED_UNAVAILABLE: &str = "protected output unavailable";
pub(crate) const JOB_OUTPUT_HEX: &str = "job output hex";
pub(crate) const OUTPUT_COLLISION: &str = "output key collision after protection";
pub(crate) const UNLOCKED_SEED: &str = "response requires an unlocked seed";
pub(crate) const CREDENTIAL_SCAN: &str = "session credential has no response scan representation";
pub(crate) const DERIVATION: &str = "held credential derivation refused";
pub(crate) const REDACTION_MARKER: &str = "redaction marker cannot exclude held credentials";
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const LOCKED: &str = "locked";
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const MISSING_PENDING_JOB: &str = "missing pending job";
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const MISSING_PENDING_IDENTITY: &str = "missing pending identity";
pub(crate) const TARGET_DIFFERS: &str = "resolved target differs from task machine";
pub(crate) const TARGET_REQUIRED: &str = "resolved relay, host and user are required before Resume";
pub(crate) const PIN_REQUIRED: &str = "trusted host pin missing; configure it before Resume";
pub(crate) const RESULT_ENCODING: &str = "task result encoding";
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const RESULT_PUBLICATION: &str = "task result publication";
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const COMMITTED_MISMATCH: &str = "committed job record differs from its intent and cannot checkpoint; pending identity retained for inspection; to configure, Stop task; remote effects and command holds remain";
pub(crate) const TASK_ENDED: &str = "task ended";
pub(crate) const SESSION_OWNER: &str =
    "session authority belongs to another task; use the task’s original session";
pub(crate) const BOUND_MACHINE: &str = "fresh authority must bind only the task machine";
pub(crate) const APPROVAL_PENDING: &str = "proposal approval pending; review the open requirements card and approve explicitly or reject before Resume";
pub(crate) const ACCEPTANCE: &str =
    "original session requires acceptance of Acting on a goal with no brief";
pub(crate) const SESSIONS_ENDED: &str = "sessions ended";
pub(crate) const NO_SESSION: &str = "no live session";
pub(crate) const SESSION_ENDED: &str = "session ended";
pub(crate) const LIVE_GOAL: &str = "goal requires a live session";
pub(crate) const SUSPENSION: &str = "reconciliation or verification required after suspension";
pub(crate) const CAP_EXHAUSTED: &str = "session cap exhausted";
pub(crate) const SESSION_EXPIRED: &str = "session expired";
pub(crate) const ISSUER_USAGE: &str = "incompatible issuer usage";
pub(crate) const ISSUER_ACCEPTANCE: &str = "incompatible or missing issuer acceptance";
pub(crate) const CLOCK_UNCERTAIN: &str = "clock uncertain; verification required";
pub(crate) const CLOCK_RANGE: &str = "clock evidence out of range";
pub(crate) const INVALID_SPEND: &str = "invalid spend";
pub(crate) const SPEND_EXPONENT: &str = "invalid spend exponent";
pub(crate) const NONNEGATIVE_SPEND: &str = "invalid nonnegative spend";
pub(crate) const SPEND_SCALE: &str = "spend scale";
pub(crate) const SPEND_PRECISION: &str = "unsupported spend precision";
pub(crate) const RUNNING: &str = "recorded job is running; Resume inspects it again";
pub(crate) const FALLBACK: &str =
    "task paused: diagnostic protection failed; inspect authority and configuration before Resume";
pub(crate) const STALE_TASK: &str = "stale or ended task";
pub(crate) const NO_PENDING: &str = "task has no pending job";
pub(crate) const NO_EVIDENCE: &str = "no committed job evidence";
pub(crate) const UNTRUSTWORTHY: &str = "job outcome is not trustworthy";
pub(crate) const NO_PROPOSAL: &str = "pending task has no proposal";
pub(crate) const NO_EXIT: &str = "missing job exit";
pub(crate) const CHECKPOINT_PROTECTION: &str =
    "recorded job output requires protection before checkpoint";
pub(crate) const NO_VERIFICATION: &str = "missing verification record";
pub(crate) const VERIFICATION_MISMATCH: &str = "verification job mismatch";
pub(crate) const EXCERPT_PROTECTION: &str =
    "verification excerpt requires protection before checkpoint";
pub(crate) const REVISION_EXHAUSTED: &str = "task revision exhausted";
pub(crate) const JOURNAL_REFUSED: &str = "journal refused";
pub(crate) const ENCRYPTION_REFUSED: &str = "AES-GCM refused the record";
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const MOVE_UNAVAILABLE: &str = "move: FileSystemHandle.move() is not available";
pub(crate) const CHECKPOINT: &str = "recorded result could not be checkpointed: ";
#[derive(Clone, Copy)]
pub(crate) struct Shape(pub(crate) &'static str);
impl Shape {
    pub(crate) fn render(self, number: u64, job: &str, payload: &str) -> String {
        render(self.0, number, job, payload)
    }
}
pub(crate) const NO_OUTCOME: Shape = Shape(
    "collection returned no outcome for pending call {number} job {job}; pending identity retained",
);
pub(crate) const IDENTITY_MISMATCH: Shape = Shape(
    "collection record identity mismatch for pending call {number} job {job}; pending identity retained",
);
pub(crate) const COLLECTION_PROTECTION: Shape = Shape(
    "collection failed for pending call {number} job {job}: diagnostic protection failed; pending identity retained",
);
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const COLLECTION_FAILED: Shape =
    Shape("collection failed for pending call {number}: {payload}; pending identity retained");
pub(crate) const EARLIER_APPEND: Shape =
    Shape("an earlier append failed ({payload}), so none follows until the worker restarts");
pub(crate) const ENCRYPTION_CAP: Shape =
    Shape("record {number} would be the 2^32nd encryption under this store's data key");
pub(crate) const ENTROPY: Shape = Shape("getrandom: {payload}");
pub(crate) const COLLECTION: Shape =
    Shape("collection {payload} for pending call {number} job {job}; pending identity retained");
pub(crate) const CHECKPOINT_UNCERTAIN: &str =
    "evidence checkpoint not confirmed; observation remains uncertain";
pub(crate) const NOT_READ: &str = "not read";
pub(crate) const READ_FAILED: &str = "record read failed";
pub(crate) const MALFORMED: &str = "has missing or malformed outcome metadata";
pub(crate) const NO_METADATA: &str = "has no committed observation metadata";
pub(crate) const FOREIGN: &str = "recorded a foreign machine record; record mismatch";
pub(crate) const COMMAND_MISMATCH: &str = "recorded a command/record mismatch";
pub(crate) const MISSING: &str = "could not confirm whether the command reached the machine; Resume will check again without running it twice";
pub(crate) const ENDED: &str = "recorded process ended without a trustworthy exit status";
pub(crate) const INCOMPLETE: &str = "recorded an incomplete job record";
pub(crate) const STILL_RUNNING: &str = "recorded job still running";
pub(crate) const FINISHED: &str =
    "returned a finished record without matching committed terminal evidence";
pub(crate) fn checkpoint(why: &str) -> String {
    format!("{CHECKPOINT}{why}")
}
pub(crate) fn decode_error(field: &str, detail: &str) -> String {
    format!("{field}: not unpadded base64url ({detail})")
}
pub(crate) fn decode_length(field: &str, actual: u64, expected: u64) -> String {
    length_parts(field, &decimal(actual), expected)
}
fn length_parts(field: &str, actual: &str, expected: u64) -> String {
    format!("{field}: {actual} bytes, not {expected}")
}

pub(crate) fn with_detail(category: &str, detail: &str) -> String {
    format!("{category}: {detail}")
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const OPFS_CONTEXT: &str = "OPFS";
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const MOVE_CONTEXT: &str = "move";
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn storage_error(context: &str, detail: &str) -> String {
    format!("{context}: {detail}")
}
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn move_context(from: &str, to: &str) -> String {
    format!("move {from} to {to}")
}
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn directory_missing() -> String {
    storage_error(crate::store::DIRECTORY, "not found")
}

pub(crate) fn decimal(number: u64) -> String {
    number.to_string()
}
pub(crate) fn render(pattern: &str, number: u64, job: &str, payload: &str) -> String {
    pattern
        .replace("{number}", &decimal(number))
        .replace("{job}", job)
        .replace("{payload}", payload)
}
