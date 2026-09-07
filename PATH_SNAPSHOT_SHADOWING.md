# Recorded path snapshots and pathless observations

A physical V2606A 2,500-read capture reproduced a missing first Read path in analysis export. The request origin had an inode but no path; FileIo supplied a matching path snapshot. A later FileIo for the same identity had no path after the descriptor closed. Graph enrichment selected that latest record and lost the recorded path.

Enrichment now selects among records containing a nonempty path. Identity compatibility and the existing 30-second evidence interval remain unchanged. No new path is invented and confidence is not upgraded. A seven-event verbatim physical subset is in crates/protocol/tests/fixtures/pathless-tail.ndjson; path_snapshot_replay tests both restoration and the all-paths-missing case.

This change does not solve physical completion callback losses or prove Exact attribution on this device. The observed origin lifetime is Probable. Native installation/retest must be recorded separately from host tests.
