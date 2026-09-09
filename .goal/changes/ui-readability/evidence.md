# UI readability execution evidence

Spec revision 1. Skill: expert-ui-design 4.6.0 from SeokMinKo/skills commit b3a3ca2bf65556ad3f7f38b29087ef7d835de8e3. Product baseline: 09008f5d38ccea4fdedb5d1144f4dbc6a3c4588e.

## Sequence

1. Inspected app.rs, analysis_ui.rs, ui_layout.rs, selection.rs, page_purpose.rs, plot_style.rs and UI_WORKFLOW/UI_REFINEMENT. Repository has no AGENTS.md in the recursive baseline tree. Read the skill's existing-product, dashboard, UX, layout, accessibility and data-viz rules. Existing egui themes and English labels are authoritative.
2. REQ-1 test added before production changes. Local `cargo +1.98.0 test -p android-ebpf-studio --features gui collapsed_filters_offer_reset_without_opening_advanced_controls` exited 127: cargo not found. This is ENV, not RED.
3. Test-only commit 18a17ca0b57139f5cc551026265decc59bb5241b ran in [CI 34360671236](https://github.com/SeokMinKo/android-ebpf-studio/actions/runs/34360671236). Windows GUI compilation passed. Desktop library suite: 135 passed, 1 failed, 3 ignored, 1 filtered out. The sole failure was the new collapsed-reset assertion, `Reset must be available while advanced filters are collapsed`. Excerpt: reset-red.log. This is valid assertion-level RED.
4. Added visible scope/reset, a shared table-column contract, independently scrolling body and open-session/mouse-mode guidance. Query matching, wire protocol, attribution and exports remain unchanged. New alignment and scrolling tests were added with implementation; they are not claimed as test-first RED cycles.
5. Implementation commit e9de5f09794beddb3bc76fad8c856afabaf2518d failed the repository Format step. Used the exact rustfmt diff to fix app.rs indentation/trailing whitespace. No formatting rule was disabled.
6. Windows production GUI compilation passed, but the added scroll-test initializer omitted egui 0.36.1 MouseWheel.phase (E0063). Added TouchPhase::Move as specified by the pinned API documentation. This was a test-compilation error, not a product regression or a valid RED.
7. Native replay uses the repository's existing saved-session QA path and renderer. It neither connects a physical device nor invokes browser automation. Required UI rendering is checked separately from Rust compilation and headless egui tests.

## Research boundary

[egui 0.36.1 Ui](https://docs.rs/egui/0.36.1/egui/struct.Ui.html) confirms the scoped layout API used by fixed-width cells. Existing repository ScrollArea/show_rows usage supplies the virtualization contract. No new UI dependency, hosted service or external asset is added.

## Current status

This log records the observed execution sequence. [PR #28](https://github.com/SeokMinKo/android-ebpf-studio/pull/28) carries the final CI links and review status, including checks completing after this documentation commit. Do not infer a GUI/visual pass from this document's presence or the change's version. Native fixtures do not prove physical Android behavior, assistive-technology support or user-study improvements.

## First native review (c3edeaac)

[Native replay 34361387105](https://github.com/SeokMinKo/android-ebpf-studio/actions/runs/34361387105) generated Light, Dark, High Contrast and narrow captures and uploaded artifact 10108135573. The producer inspected the actual Light (1024×768 on the hosted Windows display) and narrow (800×600) PNGs from the native renderer. This is integrated review, not an independent visual review. The two other themes were captured but were not visually inspected at this point.

Observed: reset/scope and Open session are visible; controls wrap instead of overlapping. On the 800×600 capture, existing geometry/footprint rows plus the connection guidance push nearly all of the plot below the viewport. Correction: when width <1100 logical px, move Draw as and footprint controls into Plot settings; keep graph choice and Select/Zoom visible. Suppress disconnected-device setup guidance after a saved session has already been opened. The ADB-not-found status in the fixture capture is a hosted-runner limitation; it is not a physical-device test failure. A follow-up native capture is required before claiming the narrow correction verified.

The hosted display constrained the nominal wide window to 1024×768. No 1600×1000 native screenshot was obtained. The normal layout must not be called visually reviewed at that target. Native table capture was added after review because the initial screen did not show the below-fold request table.

## Regression found during integration

At fcf0eb007b089d3d83c96364a37f5a3eb60bef32, Windows production compile passed; the new collapsed reset, scope labels, numerical alignment and actual body-scroll/header tests passed. Two existing filter-input tests failed: full-path toggle did not narrow 2→1, and the buffered PID input did not accept its second value. Desktop library result: 138 passed, 2 failed, 3 ignored, 1 filtered out (CI 34361773165).

Root cause: the new scope label was conditionally inserted before the editors only after a query became active. Typing the first criterion changed both control positions and automatic egui identities on the next frame. Fix: retain the scope row from the initial unfiltered state (All loaded requests) and change only its text/color. Existing tests were retained unchanged; no expectation was weakened. This is a real UI integration regression found and corrected during the task, not a baseline defect.

## Final native review (8de24990)

[Native replay 34362677496](https://github.com/SeokMinKo/android-ebpf-studio/actions/runs/34362677496) passed on 8de24990ae35003d828bd0de499fa55d47b776b5. Actual Light 1024×768, narrow 800×600 and table PNGs were individually inspected. Scope/reset, Open session and Select/Zoom are visible without overlapping; the narrow plot now begins in the initial viewport. The table capture shows right-aligned raw numbers, matching headings, the keyboard-focused Open I/O control and a horizontal viewport into the retained columns. Body-scroll/header persistence is additionally tested with 100 requests; the one-request native fixture alone cannot establish this.

Review outcome: pass with notes at the observed sizes. 800×600 still requires vertical scrolling for the full plot/table, and the table requires horizontal scrolling for all columns. Dark and High Contrast captures were generated successfully but not manually visually reviewed. Native empty-result, long-path and 1600×1000 captures were not obtained; corresponding claims are limited to source inspection and the applicable input/string tests. No physical Android, screen-reader or user-study result is claimed.
