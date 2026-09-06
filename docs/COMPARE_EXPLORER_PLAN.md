# Compare Explore implementation / Page Contract

Primary mode: understand. Compare the shape and selected populations of two sessions; observed differences do not prove causation.
Existing-product extension, integrated review. Preserve native egui tokens, Explore metrics, confidence and missing-data semantics.

1. Keep complete retained baseline request/evidence data, load baseline asynchronously, preserve previous data on load failure. Isolate current and baseline view state.
2. Extract existing Explore plot renderer for reuse. Provide paired graphs with common preset, axes, category, size and colors. Align relative completion time against each source origin. Linked bounds by default; independent bounds optional. Narrow windows stack panes.
3. Explicit Apply of common time/operation/confidence/name filters; session-specific PID/TID/device/file overrides. Never match PIDs, inodes or request keys across sessions automatically.
4. Point/rectangle selection per pane, all-filtered selection, optional same rectangle in both panes; background exact summaries. Zoom/Back, paired count/span/Read-Write volume/throughput/percentiles, file/process lists, chunk and access distributions, original request details. Baseline and Current labels everywhere.
5. Regression tests for isolation, relative origin, filters, missing metrics and stale selection. Native inputs and captures in three themes + small/200%; two distinct fixtures and 100k requests per side. Build, Clippy, install with backup, launch and package source.

Composition: shared controls first, equal-width graphs second, one aligned metric comparison table then Files/Processes/Distributions/Details tabs. Reject overlay as the default because selection ownership and overlapping points are ambiguous. Side-by-side at >=1000 available logical px, stacked below.
Outcome proof: question/scope=two labelled source windows; relationship=same metrics/axes and explicit relative time; implication=selected population delta; caveat=workload comparability, retained window, unknown evidence and absent metrics. Verify actual native render plus semantic input postconditions; no device required for offline comparison.
Risks: independent timestamps/identities, stale async results, manual axis vs filters, sample vs exact counts, unreadable paired legends, 5-second performance target, empty selection and unsupported graph metrics.
Evidence boundaries: old device trace replay, clearly labelled synthetic variant/stress. No new phone validation. Previous intermittent startup access violation remains a separate unresolved issue.
