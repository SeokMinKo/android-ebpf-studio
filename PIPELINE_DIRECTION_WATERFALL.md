# Pipeline direction and waterfall time fidelity

A six-event verbatim physical subset contains one block Read, its spanning 808229 ns Read syscall, and a later 99583 ns Write to stdout. Previously the ±10 ms task lookup inserted both syscall stages into the Read transaction and labeled both with the block request's Read/bytes/task metadata.

Pipeline observations now retain an optional observed operation. FileIo-derived syscalls provide it; legacy and kernel observations without a decoded direction keep None. Opposite directions and explicitly different request identities cannot fall back to time matching. Non-context probable stages must overlap the actual block interval; context markers retain the surrounding context window. Graph stages preserve observed operation/bytes/PID/TID, including unknown values.

The waterfall previously saturated timestamps before its origin to zero, so a real 3.509792 ms syscall was drawn as 0.325469 ms. Signed offsets now preserve its full span from -3.184323 to +0.325469 ms. This does not enlarge or relabel the block latency accounting window.

Regression-first evidence covers adjacent Write, overlapping Write, a later same-direction syscall, metadata preservation/unknown values, foreign request identity, and full signed bar width. The optional native QA report records coordinates submitted to the waterfall plot. scripts/check-native-waterfall.mjs independently derives expected values from a one-request raw FileIo-only subset and compares them with those rendered coordinates and the screenshot. --oracle-only does not launch the renderer.

Host tests, Clippy, rustfmt, Windows release and Android target compatibility build passed. The user stopped Computer Use before native redeployment/retest; these are pending. Physical original sessions are unchanged.
