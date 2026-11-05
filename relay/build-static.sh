#!/bin/sh
# Supply an isolated toolchain through PATH, RUSTUP_HOME/CARGO_HOME and
# RUSTUP_TOOLCHAIN, or supply CARGO as an absolute executable path.
set -eu
cd "$(dirname "$0")/.."
: "${CARGO:=cargo}"
"$CARGO" build --locked --release --target x86_64-unknown-linux-musl -p tau-relay --bin tau-relay
