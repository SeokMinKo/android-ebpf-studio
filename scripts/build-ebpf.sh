#!/usr/bin/env bash
set -euo pipefail

if ! command -v bpf-linker >/dev/null 2>&1; then
  echo "bpf-linker is required. Install it with: cargo binstall bpf-linker" >&2
  exit 2
fi

rustup toolchain install nightly --profile minimal --component rust-src
cargo +nightly build \
  --manifest-path crates/android-ebpf/Cargo.toml \
  --target bpfel-unknown-none \
  -Z build-std=core \
  --release

echo "Built crates/android-ebpf/target/bpfel-unknown-none/release/android-storage-ebpf"
