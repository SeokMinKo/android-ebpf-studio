# Explicit dense-session interaction budget

The ordinary opt-in native QA gesture budget is eight seconds. A physical dense replay takes about 12 seconds to load; the old harness timed out at frame 3 and step 0 before area selection began. Exit code zero only meant the screenshot was written and was not an interaction pass.

ANDROID_EBPF_QA_TIMEOUT_SECONDS allows an explicit 8–120 second gesture budget (default eight; invalid input falls back to eight). The override is recorded in result JSON. Device capture and stream replay retain their dedicated budgets. This only changes opt-in QA, not production selection logic or performance targets. Use a separately bounded process runner, then require qa_timed_out=false and the intended input step and independently checked selection result.

The failed installed run is retained as installed-dense-recheck/lba-area: step 0, timed_out true, no selection. Dense retest uses an explicitly recorded 60-second budget with a 90-second outer process deadline. Slow loading and render latency remain separate reported measurements.
