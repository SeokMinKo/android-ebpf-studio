# Native Compare filter matrix

The compare-filter gesture accepts optional ANDROID_EBPF_QA_COMPARE_FILTER JSON. Shared fields are operation (read/write or null), start_ms, end_ms and process. Session-local baseline/current objects accept pid, file and device. Unknown fields are rejected. Without this JSON the legacy Read case is retained.

QA fills the same filter state used by the form and clicks its actual Apply button. It does not validate typing or dropdown navigation. Both applied queries must equal their requested shared/local combination before the gesture completes. This completion check is not a numeric acceptance gate: independently match raw keys, bytes, clock origin and rendered coordinates.

Example:

~~~json
{"operation":"read","start_ms":1000,"end_ms":2000,"baseline":{"device":"8:0"},"current":{"pid":12891,"file":"alpha/sequential-a.bin","device":"8:0"}}
~~~

Keep fixture expectations outside product analysis code. Record source and EXE hashes, theme, fields, expected and actual request sets, and native screenshots. A partial matrix must not be called full graph acceptance.
