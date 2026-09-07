# Remaining work after selected integration scope

On2026-09-07 the user selected items2/3/4 from the integration plan and authorized main merge: Overall/Custom/Raw Log, latest-main integration and full graph/performance/device validation. Those are recorded in [UPAS_MERGE_CHECKPOINT.md](UPAS_MERGE_CHECKPOINT.md). The original full Goal is not complete.

## Still outstanding

1. **Hardware Queue acquisition and UI**: finish validated issue/completion queue identity, protocol/storage/reload, device scope, Trend and linked Summary. Do not substitute CPU, tag, doorbell or software QD. Preserved WIP below is not build-verified and must be reviewed before reuse.
2. **Scheduler I/O wait on this Vivo kernel**: native task-delay population works in deterministic/large saved fixtures and supported Perfetto data. The available Vivo kernel exposes dynamic `comm` (4-byte data-location field); the current fixed-layout probe correctly declines attachment and records the reason. This run does not establish physical scheduler acquisition. Supporting that format and validating it requires a collector follow-up.
3. **Release installation / installed launch**: compatible desktop, Android agent and BPF Release artifacts are built and exercised from the QA bundle. Back up the installed files, deploy the compatible bundle, preserve sessions/settings/logs and verify the installed EXE when resuming the original full Goal. The user-selected merge scope did not include that installation step; the installed application is unchanged.

Documented semantic differences remain deliberate: observed/sampled detail is not kernel-wide distribution; unsupported source fields are not zero; Busy/Idle requires defensible device activity; block issuer is not necessarily the originating application; Overall follows current filters; uPAS percentile/CDF indexing, idle population and chunk-class threshold differences are recorded per feature. These are not hidden full-parity claims.

## Preserved state

- Completed feature implementation through `259e46e4aef6df55cc44e60e1ea2b79bdf1c6e03` on `feat/upas-io-analysis`.
- Independent backup branch: `backup/upas-before-cleanup-20260907`, pointing to that same completed implementation.
- Unfinished hardware queue changes: stash `beafa50e0ac2b99362f9ebed7e7936e6c532e02c` and task `outputs/worktree-cleanup/hardware-queue-in-progress.patch`.
- Patch SHA256: `91aad08ff45e7cc9595304bb5ae3c228597fb68a744b68bf3c544c5bece92163`. Stash diff was compared byte-for-byte with the independent patch before confirming cleanup.
-29 modified tracked files were preserved. Working tree/index were clean after stash. This documentation is committed separately so the final working tree remains clean.
- Worktree directory, completed branch, saved traces, QA evidence, build artifacts and installed application were retained by cleanup. Subsequent integration is described in UPAS_MERGE_CHECKPOINT.md.

The stashed HW Queue experiment is **not build-verified**. It adds optional issue/completion queue fields, proposes schema9, and starts a native tracepoint layout path. Last check failed because the offset-field rename landed in SchedulerWaitLayout while TraceLayout still had `reserved`; no UI or end-to-end queue acquisition acceptance exists. Review before any future `git stash apply beafa50e0ac2b99362f9ebed7e7936e6c532e02c`; do not treat this stash as completed functionality. The retained clean implementation remains schema8.
