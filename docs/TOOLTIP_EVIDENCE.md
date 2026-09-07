# Tooltip evidence evaluation

A Time/Latency or Queue/Latency view grouped by direction does not build transaction graphs for every plotted point. An unevaluated graph previously produced a false `File: <unattributed>` label even when the same request had a defensible path in I/O details. Such views now omit the file-evidence line. LBA/Address and file-grouped views continue to resolve and show paths and confidence. This preserves existing sampling limits and avoids adding per-point transaction analysis.

The regression fixture contains three unmodified issue/origin/complete records from a physical known-file root capture; it verifies that the graph has the expected path before exercising both non-graph presets. It failed before the fix and passes after it. This change does not fix kernel completion loss or prove the full acceptance matrix.
