# Analysis UI Performance

Status: CONFIRMED-AUTO  
Rigor: L2 / DURABLE / REFACTOR

## Goal

Keep the desktop UI interactive after loading or capturing up to 100,000 analysis events, while preserving measured values and file-attribution confidence.

## Requirements

- Derived summaries, transaction graphs, pipelines, and RCA results must not be rebuilt on every unchanged frame.
- Explorer must bound rendered points and disclose displayed versus available samples.
- Graph-backed Explorer dimensions must build at most one transaction graph per displayed request.
- `Group by File` must use the File I/O attribution path/identity and must not claim an ambiguous origin as a single file.
- Live capture must bound message processing per frame so rendering is not starved.
- Large tabular pages must render only visible rows.

## Contracts

- Cache invalidation occurs whenever newly ingested data can change the cached result.
- Missing or ambiguous file attribution remains `Unattributed` or `Multiple files`; it is never guessed.
- Sampling changes display density only. Summary and stored session data remain complete.
- Explorer sampling is deterministic and preserves chronological coverage.

## Verification

- Unit tests cover deterministic sample selection, File grouping, cache reuse/invalidation, and bounded RCA cohorts.
- `cargo fmt --check`, Clippy with warnings denied, workspace tests, and Windows GUI check must pass in CI.

