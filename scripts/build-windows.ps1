$ErrorActionPreference = "Stop"

rustup toolchain install 1.98.0 --profile minimal --component rustfmt,clippy
cargo +1.98.0 build --release -p android-ebpf-studio --features gui

Write-Host "Built target\release\android-ebpf-studio.exe"
