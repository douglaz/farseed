pub(crate) mod check_batch;
pub mod completion;
pub mod files;
#[cfg_attr(
    not(target_arch = "wasm32"),
    allow(
        dead_code,
        reason = "the browser transport is not compiled on the host"
    )
)]
pub mod inference;
pub(crate) mod proposal;
#[cfg_attr(
    not(target_arch = "wasm32"),
    allow(
        dead_code,
        reason = "the provider adapter is driven by the dedicated browser worker"
    )
)]
pub mod provisioning;
pub(crate) mod question;
pub mod run;
pub mod targets;
pub mod template;
#[cfg(target_arch = "wasm32")]
pub(crate) mod timings;
#[cfg(target_arch = "wasm32")]
pub(crate) mod web;

pub(crate) mod wait;

#[cfg_attr(
    not(target_arch = "wasm32"),
    allow(dead_code, reason = "credit is driven by the browser worker")
)]
pub mod credit;
