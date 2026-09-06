# Remaining acquisition audit — implementation pending

Completion CPU is implemented and verified at checkpoint5489a96. The following source findings guide the next continuation; they do not mark missing features implemented.

## I/O wait

uPAS `UpasParser.py`1188-1236 defines `Parser_SCHED_IOWait`: extracts trace timestamp and integer `delay=`, subtracts session origin, and writes scheduler delay records to a separate CSV. Its declared pattern is currently the placeholder`aaaddd`; actual enabled dispatch and source event availability still need verification. `UpasAnalyzer.py`8120-8158 reads `iowait_parsing_file`, divides delay by1000 and plots time(s)/iowait(us), with log Y. This is a scheduler delay event population, not `/proc/stat` CPU percentage, per-block-request latency, or device Idle. Do not relabel those available quantities as I/O wait.

Next: inspect actual scheduler event/configuration support and implement optional collector/protocol/storage/event-cohort analysis when feasible. Keep scheduler events distinct from block request counts/payload/BW and state which common filters apply. Current ADB device list is empty; physical event/configuration acceptance requires reconnection. Offline fixture/decoder/collector builds remain possible. This is not grounds for declaring the whole Goal blocked.

## Hardware queue

Corrected initial matrix assumption: `draw_db_trend_graph`, `UpasAnalyzer.py`5060-5110, uses **send_hwq/complete_hwq**, renamed tohwq, at their respective send/complete times. It does not use send_db. `UpasParser.py`359/406 stores phase hardware queue fields. Parser-specific extraction includes blkq_info third component at734, and hwq_id at2471/2657. Many other parsers substitute0 (e.g. SCSI1138), which must not be copied as a measured queue when the field is absent.

Next: read those parser regexes and corresponding collector tracepoint/BTF fields, distinguish blk-mq hardware context identity from hardware tag/doorbell occupancy/software QD, preserve device/controller identity and per-phase evidence. Existing lower-layer stage_key can pair scoped spans but is not automatically a hardware queue ID. Current code has no hctx/queue_num/hardware queue field in its block protocol, so acquiring and preserving one still requires implementation or concrete kernel/layout restrictions documented after the audit.

## Other remaining matrix items

Reconcile existing implemented Summary category/rank functions with pending command-count/data-size, sequentiality ratio and latency sorting entries; exact chunk-size category pie may require a separate category from the current coarse Size class. Overall composite, custom categorical axes and raw-log navigation need actual source/UI audits. Then execute one full43-feature real/synthetic/empty/single/missing/large matrix and baseline/new load/filter/render/memory measurements before Release backup/install and installed launch.
