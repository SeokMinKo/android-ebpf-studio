# BPF runtime loss visibility

The collector now samples cumulative recursion-miss counters from BPF program FDs owned by the current capture. Program FD clones remain readable through detach so the final health sample includes the last callbacks. This does not keep attach links alive.

Health probe entries runtime.<program> store optional recursion_misses. Missing values mean unmeasured; previously observed nonzero values survive failed later queries as cumulative observed lower bounds. Counts are probe callbacks, not unique requests, and must not be added to ring reservation failures. One lost I/O may affect several probe programs.

Live and reopened sessions display ring loss and observed BPF recursion misses separately. Legacy sessions explicitly show runtime misses as not reported. This change exposes loss; it cannot reconstruct skipped completions or promote uncertain file attribution.

A physical root workload reproduced successful direct reads whose completion appeared in a separate loss-free tracefs instance but was absent from collector NDJSON. A later capture showed block_rq_complete recursion_misses=9 via bpftool. Its follow-up workload was blocked by device disconnection. Physical verification of the updated collector counters remains pending.

Regression: cargo test -p android-ebpf-studio --test bpf_runtime_health

The regression first failed with ring loss 0 hiding a supplied miss count of 9, then passed with separate status. It also checks legacy absence and lossless u64 serialization. Native and physical results are recorded separately in the local acceptance report.
