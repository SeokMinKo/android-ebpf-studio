# Default LBA graph and selection clearing

Explore opens by default, including after capture finalization. Its LBA distribution preset plots Time (ms) against Address (MB). Compare uses the same default preset. Address MB is the block sector multiplied by 512 bytes and divided by 1,000,000, not MiB; it is a storage address, not a file offset. Sector and Address (KiB) remain available as custom axes. Address tooltips retain FilePath evidence and confidence.

The graph toolbar has a Clear selection button. It clears selected points and any in-flight or queued selection; the worker receives cancellation and its result receiver is dropped so late results cannot restore the selection. Filters, current zoom bounds and Back history are retained. The inspector Clear control uses the same behavior.

Host regressions cover the default preset, independent decimal-MB conversion, cancellation, late delivery and retained bounds. Opt-in native QA gestures selection-clear and selection-cancel-pending exercise the actual toolbar button. No QA page or preset override is needed when validating the product default.

Acceptance evidence is recorded separately from source tests; this change does not resolve physical capture loss or complete the all-graph acceptance matrix.
