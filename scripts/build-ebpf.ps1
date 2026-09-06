$ErrorActionPreference = "Stop"
if (-not (Get-Command bpf-linker -ErrorAction SilentlyContinue)) {
    throw "Put the Windows bpf-linker v0.11.0 executable on PATH."
}
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js is required for the BPF register regression check."
}
rustup toolchain install nightly --profile minimal --component rust-src
if ($LASTEXITCODE -ne 0) { throw "Rust toolchain setup failed." }
cargo +nightly build --manifest-path crates/android-ebpf/Cargo.toml --target bpfel-unknown-none -Z build-std=core --release
if ($LASTEXITCODE -ne 0) { throw "BPF build failed." }
node scripts/check-bpf-registers.mjs crates/android-ebpf/target/bpfel-unknown-none/release/android-storage-ebpf
if ($LASTEXITCODE -ne 0) { throw "BPF object contains unsupported registers." }
