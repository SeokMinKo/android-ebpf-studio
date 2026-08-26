$ErrorActionPreference = "Stop"

if (-not $env:ANDROID_NDK_ROOT) {
    throw "Set ANDROID_NDK_ROOT to an installed Android NDK directory."
}

$toolchain = Join-Path $env:ANDROID_NDK_ROOT "toolchains\llvm\prebuilt\windows-x86_64\bin"
$linker = Join-Path $toolchain "aarch64-linux-android35-clang.cmd"
if (-not (Test-Path $linker)) {
    throw "Android linker not found: $linker"
}

rustup target add aarch64-linux-android --toolchain 1.98.0
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $linker
cargo +1.98.0 build --release -p android-ebpf-agent --target aarch64-linux-android

Write-Host "Built target\aarch64-linux-android\release\android-ebpf-agent"
