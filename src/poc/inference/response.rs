//! Preserve the protection inventory until a machine response leaves the worker.
use std::cell::Cell;

thread_local! {
    static COMMAND_RESPONSES: Cell<usize> = const { Cell::new(0) };
}

/// Each caller owns its reservation. This holds no store writer over transport waits.
pub(crate) struct CommandResponse;
impl CommandResponse {
    pub(crate) fn reserve() -> Self {
        COMMAND_RESPONSES.set(
            COMMAND_RESPONSES
                .get()
                .checked_add(1)
                .expect("command response count"),
        );
        Self
    }
}
impl Drop for CommandResponse {
    fn drop(&mut self) {
        COMMAND_RESPONSES.set(COMMAND_RESPONSES.get() - 1);
    }
}
pub(crate) fn response_pending() -> bool {
    COMMAND_RESPONSES.get() != 0
}
