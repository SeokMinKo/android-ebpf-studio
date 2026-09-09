# PYK110 collector compatibility

The installed collector failed before acquisition on kernel 6.6.118-android15-8: raw block discovery reported `ambiguous request`, and generic block loading reported `combined stack size of 3 calls is 544. Too large`. This is a verifier failure, not proof of missing root permission.

The BTF parser now follows each callback request pointer and its queue/disk fields. It still validates widths, offsets, pointer targets and agreement across the three callback layouts. An unrelated same-name structure no longer disables raw capture. A synthetic duplicate-name regression failed before the fix and passed afterward; the actual PYK110 BTF also parsed successfully.

Inlining the block entry wrappers reduced compiled generic completion stack accesses from 456 to 360 bytes, and raw completion from 472 to 368 bytes. Disassembly is host evidence; the revised object still requires target verifier/load/attach validation.

The syscall regression runner `scripts/check-syscall-pairing.mjs RUSTC LINKER OUTPUT_DIR` extracts the actual capture functions into a host harness with mocked kernel helpers. It reproduces stale calls surviving filtered/untracked entries and mismatched exits being accepted. Four cases failed before the fix; all five pass afterward. It does not simulate kernel recursion loss or prove device correctness.

Validation: host workspace tests 271 passed, 13 ignored; host and Android Clippy, rustfmt, Android agent release and BPF release passed. The revised binaries have not replaced the installation and physical acceptance is pending reconnection.
