# Common filter native rendering QA

The installed GUI can exercise common filters through its opt-in native input harness. Set ANDROID_EBPF_QA_OUTPUT and ANDROID_EBPF_QA_SESSION, PAGE=explore, PRESET=4, and GESTURE to pid-filter, process-filter, file-filter, or device-filter (all names have the ANDROID_EBPF_QA_ prefix).

The harness clicks Analysis filters and the real text field, enters a matching value, replaces it with a nonmatching value, then clicks Clear filters. PID, PROCESS, FILE, and DEVICE_TEXT specify the matching value. DEVICE_TEXT is intentionally distinct from DEVICE_FILTER, which seeds query state directly and is not an input-interaction test.

FILTER_STOP_STEP=5 captures the matching result; 7 captures the empty result. Omit it for the full sequence and final cleared result. Intermediate CSV snapshots do not by themselves prove the rendered screen; inspect each corresponding PNG. Run distinct output directories for each step. The harness leaves the real product query and graph rendering code unchanged.

This mechanism provides capture points, not an acceptance verdict. Compare keys, bytes, operation counts, and distributions independently against raw NDJSON and preserve its hash. Physical capture and complete graph-matrix acceptance remain separate requirements.
