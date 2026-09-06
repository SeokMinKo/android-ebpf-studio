# Linked Summary category reconciliation — Goal remains active

2026-09-07. The main graph continues to determine the right Summary's cohort and numeric histogram/percentiles. These changes add aggregation choices inside that same panel.

## Changes and definitions

- **Chunk size** groups by exact integer request bytes. 1000B and1001B remain separate even when their size class is identical. Zero-byte commands remain counted. Count weighting includes all commands; transferred payload includes Read+Write only. A Discard extent is not transferred bytes.
- **Command / access / size** exposes joint category counts/payload with labelled leaf categories. Existing individual Command, Access pattern and Size class choices remain available. The pie shows the largest4 categories plus the summed remainder; the pageable table and CSV include every category.
- Shared graph filters, full-resolution point/rectangle selection and exported cohort remain authoritative. Direction-specific categories use the common Read/Write filter. Numeric histogram/percentile Total/Read/Write tabs continue to describe the main graph metric.
- Access pattern and sorted latency were already implemented. This checkpoint checks their actual uPAS correspondence and updates previously stale pending rows, without declaring the complete43-feature matrix finished.

## Actual uPAS comparison

`work/verify_category_reconciliation.py` executes plotting AST from the unmodified reference `source/uPAS/UpasAnalyzer.py` on8247 equivalent records and compares Plotly output with native Summary/CSV and an independent raw-record grouping oracle:

| Reference | Lines | Verified meaning |
| --- | --- | --- |
| draw_chunk_length_cnt_data_size |7606–7635| Exact Chunk count per Read/Write; despite its name, this function does not plot byte-weighted shares |
| draw_sequentiality_information |7529–7558| Per-direction counts grouped by the same supplied access classification |
| draw_cmd_cnt_data_size |7766–7823| Joint command/access/size leaf count and Read/Write byte sum; root/parent totals are not counted as extra requests |
| draw_latency_sort_graph |2218–2247| Every measured D2C latency sorted ascending |

Deliberate differences:

- Studio adds Chunk payload weighting and excludes non-R/W extent bytes from transferred payload. uPAS command data-size chart sums all chunk extents.
- Studio retains its existing Small/Large boundary32KiB (`LARGE_IO_BYTES`). uPAS default `Trace_SR_Decider` is40KiB and configurable. The equivalent-input grouping comparison supplies the same classes; it does not claim both defaults classify identically. UI displays the Studio boundary.
- Studio observes adjacency per device and operation in issue order, first observation Unknown, and preserves classification before filters. uPAS parser compares against its parser-wide previous end and converts LBA to integerKiB. This checkpoint compares grouped classified input, not an assertion that those classifiers are equivalent.
- Studio uses a1-based rank and tie-inclusive CDF ending at100%. uPAS rank graph uses zero-based index/count percentage ending below100%. Sorted values agree exactly.
- Studio's single current graph cohort and shared operation filters replace per-input-file Read/Write subplots. The joint category choice is a flat labelled pie/table, not a nested sunburst.

## Verification

- Native real saved Samsung trace device8:0:8247 I/O,52 exact Chunk categories; transferred payload185200640B. Read7415 I/O/37 categories/169197568B; Write648 I/O/32 categories/16003072B. The remaining184 I/O are non-R/W and correctly contribute no transferred payload.
- Native single-point selection1 and empty file-filter result0; all four dimensions' values and CSV denominators match the independent original-record oracle. Native scrolled Summary shows all-category paging (52 categories,3 pages) and accessible export controls. All52 CSV rows were checked; this slice did not click through all three table pages.
- Native rank screenshot displays actual sorted D2C values. CSV contains all8247 ranks and exact CDF counts. At most512 points are drawn, without changing statistics.
- New deterministic test covers adjacent odd byte sizes, repeated size, zero-byte Flush,1GiB Discard and exact CSV payload/count. Desktop library92passed/2environment-dependent ignored; compatible all-target clippy `-D warnings` passed. Previous collector checkpoint's191-test full compatible suite remains separately recorded.
- Inspected native screenshots: `category-chunk-exact.png`, `category-chunk-scrolled.png`, `category-rank.png`. Nine native cases completed including eight base cases plus scrolled view. First empty harness incorrectly supplied PROCESS without a gesture; corrected to supported empty file filter and reran. First rank harness used wrong axis11; corrected to measured DeviceLatency axis6 plus sorted-rank display and reran. Corrected artifacts/oracle are the reported results.

Evidence: task `outputs/graph-summary-validation/category-reconciliation.json`, `category-*.json`, `category-*.summary.csv`, `category-*.io.csv`; reusable `work/run_category_reconciliation.py` and `work/verify_category_reconciliation.py` (uPAS venv Python with `-I`). No final performance/Release install claim.

Remaining Goal work includes hardware queue acquisition/UI, composite/custom surfaces and source-log navigation audit, full43 matrix/performance, compatible Release backup/install and installed launch.
