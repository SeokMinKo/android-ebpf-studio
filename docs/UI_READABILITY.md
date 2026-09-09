# Reading and operating the analysis workspace

This refinement uses the existing native egui interface and themes. It does not change captured data, file-attribution confidence, measurement definitions or export semantics.

## Start from a phone or a saved session

Use **Open session** in the top bar to analyze an existing capture without a phone. The first-run Overview also has **Open saved session**. Opening a different session is disabled while recording. If **Start analysis** is unavailable because no device is selected, the header explains how to connect/authorize a phone and offers the saved-session route.

## Know which data you are viewing

**Analysis scope** places **Clear filters** outside the advanced-controls disclosure. When criteria are active, the summary names the path match mode, time, PID/TID, process, device, operation, confidence, size, access pattern, CPU, layer, latency range and selected-request cohort as applicable. Hover a truncated summary to read it in full. CPU 0 and an empty explicit request cohort are meaningful and are not hidden.

Filters apply to Overview, Explore and Investigate. They do not remove original captured data. **Clear filters** restores the loaded analysis scope through the existing query invalidation path. **Clear selection** remains a different action: it clears the graph selection. Zoom changes the visible range rather than the analysis filter. Specialized scheduler/device measurement caveats remain next to their controls.

On windows narrower than 1100 logical pixels, **Plot settings** also contains **Draw as**, **Connect issue to completion** and **Footprint layout**. Graph choice and Select/Zoom remain visible. This keeps the primary plot higher on short screens without removing the controls.

## Read the completed-I/O table

Column headings remain above the vertically scrolling rows. A shared horizontal scroll moves headings and data together, retaining all fourteen columns. Numerical columns use right alignment and monospace text; identifiers retain full values on hover. Units and missing-value semantics are unchanged: Time ns stays the original timestamp, and latency formatting still uses the existing measurement formatter.

Rows remain newest-first and virtualized. **Open I/O**, by click or keyboard activation, opens the selected request in Investigate. **Export table I/O CSV** retains its existing cohort semantics. If no completed request matches the active scope, the empty state points to **Clear filters**; a genuinely empty session points to Diagnostics.

## Validation boundary

Regression coverage is in `filter_input_tests` and `readability_tests`. The native replay workflow uses the checked-in `known-read-tooltip.ndjson` test fixture, not a physical Android recording made during this change. Its captures and JSON reports are retained as the `native-ui-readability` artifact. Headless egui layout/input checks and native screenshots provide different evidence; neither establishes a user-study result or physical capture compatibility. See `.goal/changes/ui-readability/evidence.md` for actual execution status.
