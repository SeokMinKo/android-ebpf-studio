# Compare rectangle acceptance

A completed empty rectangle is valid. The earlier QA required non-empty subsets in both sessions and timed out on a physical capture whose addresses were outside its fixed vertical band. This was a harness defect, not evidence of a production selection mismatch.

Native QA now records the actual rectangle returned by the plot. The Node gate independently pairs raw block issues and completions, preserves 64-bit request IDs, derives the session origin from raw timestamps, and compares inclusive Time(ms)/Address(MB) membership against both selected request sets and Read/Write bytes. It rejects unsupported axes and origin differences. This gate uses unfiltered saved sessions; it does not prove arbitrary filters or other axes.

Run empty and populated rectangles for each theme:

~~~sh
node scripts/check-compare-interaction.mjs <installed-exe> <baseline.ndjson> <current.ndjson> <new-output-dir> compare-area 1 empty contrast
node scripts/check-compare-interaction.mjs <installed-exe> <baseline.ndjson> <current.ndjson> <new-output-dir> compare-area 1 populated contrast
~~~

The populated mode expands the vertical drag band; the raw oracle must still prove a non-empty population. The empty mode requires zero raw matches in both sessions. Use suitable datasets for each mode. UI interaction completion alone is insufficient: inspect rectangle-oracle.json, verdict.json and compare.png. Original session hashes must remain unchanged.
