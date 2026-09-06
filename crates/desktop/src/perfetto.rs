//! Bounded decoding of Perfetto's public protobuf trace format. Raw trace files
//! remain the source of truth; this projection never invents kernel request IDs.
//! Schema references and limitations are recorded in docs/PERFETTO_BLOCK_IO.md.
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read},
};

const MAX_PACKET: usize = 16 * 1024 * 1024;
const MAX_EVENTS: usize = 2_000_000;
const MAX_METADATA: usize = 200_000;
const MAX_PENDING_PER_DEVICE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockKind {
    Issue,
    Complete,
    Insert,
    Requeue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEvent {
    /// Trace-local record number, not a request pointer or kernel request ID.
    pub record_id: u64,
    pub kind: BlockKind,
    pub timestamp_ns: u64,
    pub cpu: Option<u32>,
    /// Kernel tracepoint common_pid is a TID, including completion context.
    pub tid: Option<u32>,
    pub device_encoded: u64,
    pub sector: u64,
    pub sectors: u32,
    pub bytes: u64,
    pub rwbs: String,
    pub comm: Option<String>,
    pub error: Option<i32>,
    /// Zero denotes Perfetto's default boot clock. Other domains are retained
    /// but not silently treated as globally synchronized timestamps.
    pub clock: u32,
}

impl BlockEvent {
    pub fn operation(&self) -> char {
        self.rwbs.chars().next().unwrap_or('?')
    }
    fn overlaps(&self, other: &Self) -> bool {
        if self.sectors == 0 || other.sectors == 0 {
            return self.sector == other.sector;
        }
        self.sector < other.sector.saturating_add(other.sectors as u64)
            && other.sector < self.sector.saturating_add(self.sectors as u64)
    }
    fn same_range(&self, other: &Self) -> bool {
        self.sector == other.sector && self.sectors == other.sectors
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMetadata {
    pub snapshot_ns: Option<u64>,
    pub pid: u32,
    pub tid: Option<u32>,
    pub name: String,
    pub start_from_boot_ns: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceQuality {
    pub packets: u64,
    pub lost_bundles: u64,
    pub parse_errors: u64,
    pub unsupported_clocks: BTreeSet<u32>,
    pub unknown_events: BTreeSet<String>,
    pub failed_events: BTreeSet<String>,
    pub diagnostics: Vec<String>,
    pub ftrace_start_seen: bool,
    pub ftrace_end_seen: bool,
    /// Per CPU: overrun, commit_overrun and dropped_events counters. Preserve
    /// snapshots; missing/reset counters must not be reported as measured zero.
    pub kernel_start: BTreeMap<u64, [Option<u64>; 3]>,
    pub kernel_end: BTreeMap<u64, [Option<u64>; 3]>,
    pub truncated: bool,
    pub projection_limited: bool,
    pub service_stats_seen: bool,
    pub service_loss_counters: BTreeMap<String, u64>,
    pub final_flush_outcome: Option<u64>,
}
impl TraceQuality {
    pub fn kernel_lost_events(&self) -> Option<u64> {
        if !self.ftrace_start_seen || !self.ftrace_end_seen || self.kernel_end.is_empty() {
            return None;
        }
        let mut sum = 0u64;
        for (cpu, end) in &self.kernel_end {
            let start = self.kernel_start.get(cpu)?;
            for (a, b) in start.iter().zip(end) {
                sum = sum.checked_add((*b)?.checked_sub((*a)?)?)?;
            }
        }
        Some(sum)
    }
    fn compromised(&self) -> bool {
        self.truncated
            || self.projection_limited
            || self.lost_bundles > 0
            || self.parse_errors > 0
            || self.kernel_lost_events().is_some_and(|v| v > 0)
            || self.service_loss_counters.values().any(|v| *v > 0)
            || self.final_flush_outcome == Some(2)
    }
    fn diagnostic(&mut self, message: String) {
        if self.diagnostics.len() < 128 {
            self.diagnostics.push(message);
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecodedTrace {
    pub events: Vec<BlockEvent>,
    pub processes: Vec<ProcessMetadata>,
    pub quality: TraceQuality,
}

#[derive(Clone, Copy)]
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}
#[derive(Clone, Copy)]
struct Field<'a> {
    id: u32,
    value: Value<'a>,
}
fn varint(reader: &mut impl Read) -> io::Result<u64> {
    let mut n = 0u64;
    for shift in (0..70).step_by(7) {
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        if shift == 63 && byte[0] > 1 {
            return Err(io::Error::other("overflowing protobuf varint"));
        }
        n |= u64::from(byte[0] & 127) << shift;
        if byte[0] < 128 {
            return Ok(n);
        }
    }
    Err(io::Error::other("unterminated protobuf varint"))
}
fn fields(mut data: &[u8]) -> io::Result<Vec<Field<'_>>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let tag = varint(&mut data)?;
        if tag >> 3 == 0 || tag >> 3 > 0x1fff_ffff {
            return Err(io::Error::other("invalid protobuf field"));
        }
        let value = match tag & 7 {
            0 => Value::Varint(varint(&mut data)?),
            2 => {
                let len = usize::try_from(varint(&mut data)?).map_err(io::Error::other)?;
                let bytes = data
                    .get(..len)
                    .ok_or_else(|| io::Error::other("truncated protobuf field"))?;
                data = &data[len..];
                Value::Bytes(bytes)
            }
            wire @ (1 | 5) => {
                let len = if wire == 1 { 8 } else { 4 };
                data = data
                    .get(len..)
                    .ok_or_else(|| io::Error::other("truncated fixed protobuf field"))?;
                Value::Fixed
            }
            _ => return Err(io::Error::other("unsupported protobuf wire type")),
        };
        out.push(Field {
            id: (tag >> 3) as u32,
            value,
        });
    }
    Ok(out)
}
fn number(f: &[Field<'_>], id: u32) -> Option<u64> {
    f.iter().rev().find_map(|f| match f.value {
        Value::Varint(n) if f.id == id => Some(n),
        _ => None,
    })
}
fn bytes<'a>(f: &[Field<'a>], id: u32) -> Option<&'a [u8]> {
    f.iter().rev().find_map(|f| match f.value {
        Value::Bytes(b) if f.id == id => Some(b),
        _ => None,
    })
}
fn text(f: &[Field<'_>], id: u32) -> Option<String> {
    bytes(f, id).map(|b| String::from_utf8_lossy(&b[..b.len().min(4096)]).into_owned())
}
fn children<'a>(f: &'a [Field<'a>], id: u32) -> impl Iterator<Item = &'a [u8]> {
    f.iter().filter_map(move |f| match f.value {
        Value::Bytes(b) if f.id == id => Some(b),
        _ => None,
    })
}
fn required(f: &[Field<'_>], id: u32) -> io::Result<u64> {
    number(f, id).ok_or_else(|| io::Error::other(format!("missing block field {id}")))
}

/// Stream root packets with bounded allocation. A damaged tail returns the
/// intact prefix and an explicit quality error; it never erases collected data.
pub fn decode(mut reader: impl Read) -> DecodedTrace {
    let mut result = DecodedTrace::default();
    loop {
        let mut first = [0];
        match reader.read(&mut first) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                result.quality.truncated = true;
                result.quality.diagnostic(e.to_string());
                break;
            }
        }
        let packet = (|| -> io::Result<Vec<u8>> {
            // Trace root is repeated length-delimited TracePacket field 1.
            if first[0] != 0x0a {
                return Err(io::Error::other(
                    "unsupported Trace root field; raw file preserved",
                ));
            }
            let len = usize::try_from(varint(&mut reader)?).map_err(io::Error::other)?;
            if len > MAX_PACKET {
                return Err(io::Error::other(
                    "Perfetto packet exceeds 16 MiB decode limit",
                ));
            }
            let mut packet = vec![0; len];
            reader.read_exact(&mut packet)?;
            Ok(packet)
        })();
        match packet {
            Ok(packet) => {
                result.quality.packets += 1;
                if let Err(e) = result.packet(&packet) {
                    result.quality.parse_errors += 1;
                    result.quality.diagnostic(e.to_string());
                }
            }
            Err(e) => {
                result.quality.truncated = true;
                result.quality.diagnostic(e.to_string());
                break;
            }
        }
    }
    // Producers and CPUs emit separate packet sequences, not a global timeline.
    result.events.sort_by_key(|e| (e.timestamp_ns, e.record_id));
    result
}

impl DecodedTrace {
    fn packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let f = fields(packet)?;
        for bundle in children(&f, 1) {
            self.bundle(bundle)?;
        }
        for tree in children(&f, 2) {
            self.process_tree(tree, number(&f, 8))?;
        }
        for stats in children(&f, 34) {
            self.ftrace_stats(stats)?;
        }
        for stats in children(&f, 35) {
            self.service_stats(stats)?;
        }
        if bytes(&f, 50).is_some() {
            self.quality.parse_errors += 1;
            self.quality
                .diagnostic("Compressed packets require decompression; raw trace retained".into());
        }
        Ok(())
    }
    fn bundle(&mut self, data: &[u8]) -> io::Result<()> {
        let f = fields(data)?;
        let cpu = number(&f, 1).and_then(|v| v.try_into().ok());
        let clock = number(&f, 5).unwrap_or(0) as u32;
        if clock != 0 {
            self.quality.unsupported_clocks.insert(clock);
        }
        if number(&f, 3) == Some(1) {
            self.quality.lost_bundles += 1;
        }
        self.quality.parse_errors += children(&f, 8).count() as u64;
        for raw in children(&f, 2) {
            let e = fields(raw)?;
            for (id, kind) in [
                (45, BlockKind::Issue),
                (125, BlockKind::Complete),
                (126, BlockKind::Insert),
                (129, BlockKind::Requeue),
            ] {
                let Some(payload) = bytes(&e, id) else {
                    continue;
                };
                if self.events.len() >= MAX_EVENTS {
                    self.quality.projection_limited = true;
                    continue;
                }
                let b = fields(payload)?;
                let sectors = u32::try_from(required(&b, 3)?).map_err(io::Error::other)?;
                let has_bytes = matches!(kind, BlockKind::Issue | BlockKind::Insert);
                self.events.push(BlockEvent {
                    record_id: self.events.len() as u64 + 1,
                    kind,
                    timestamp_ns: required(&e, 1)?,
                    cpu,
                    tid: number(&e, 2).and_then(|v| v.try_into().ok()),
                    device_encoded: required(&b, 1)?,
                    sector: required(&b, 2)?,
                    sectors,
                    bytes: if has_bytes {
                        required(&b, 4)?
                    } else {
                        u64::from(sectors) * 512
                    },
                    rwbs: text(&b, 5).ok_or_else(|| io::Error::other("missing block rwbs"))?,
                    comm: has_bytes.then(|| text(&b, 6)).flatten(),
                    error: (!has_bytes)
                        .then(|| number(&b, 7).or_else(|| number(&b, 4)).map(|n| n as i32))
                        .flatten(),
                    clock,
                });
            }
        }
        Ok(())
    }
    fn process_tree(&mut self, data: &[u8], snapshot_ns: Option<u64>) -> io::Result<()> {
        let f = fields(data)?;
        for (id, is_thread) in [(1, false), (2, true)] {
            for raw in children(&f, id) {
                if self.processes.len() >= MAX_METADATA {
                    self.quality.projection_limited = true;
                    return Ok(());
                }
                let p = fields(raw)?;
                let pid = required(&p, if is_thread { 3 } else { 1 })?
                    .try_into()
                    .map_err(io::Error::other)?;
                self.processes.push(ProcessMetadata {
                    snapshot_ns,
                    pid,
                    tid: if is_thread {
                        number(&p, 1).and_then(|v| v.try_into().ok())
                    } else {
                        None
                    },
                    name: text(&p, if is_thread { 2 } else { 3 }).unwrap_or_default(),
                    start_from_boot_ns: if is_thread { None } else { number(&p, 7) },
                });
            }
        }
        Ok(())
    }
    fn ftrace_stats(&mut self, data: &[u8]) -> io::Result<()> {
        let f = fields(data)?;
        let phase = number(&f, 1);
        self.quality.ftrace_start_seen |= phase == Some(1);
        self.quality.ftrace_end_seen |= phase == Some(2);
        for (id, unknown) in [(6, true), (7, false)] {
            for value in children(&f, id) {
                let name = String::from_utf8_lossy(&value[..value.len().min(4096)]).into_owned();
                if unknown {
                    self.quality.unknown_events.insert(name);
                } else {
                    self.quality.failed_events.insert(name);
                }
            }
        }
        for field in &f {
            if field.id == 9 {
                self.quality.parse_errors += 1;
            }
        }
        for raw in children(&f, 2) {
            let c = fields(raw)?;
            let cpu = required(&c, 1)?;
            let counters = [number(&c, 3), number(&c, 4), number(&c, 8)];
            if phase == Some(1) {
                self.quality.kernel_start.entry(cpu).or_insert(counters);
            }
            if phase == Some(2) {
                self.quality.kernel_end.insert(cpu, counters);
            }
        }
        Ok(())
    }
    fn service_stats(&mut self, data: &[u8]) -> io::Result<()> {
        let f = fields(data)?;
        self.quality.service_stats_seen = true;
        self.quality.final_flush_outcome = number(&f, 15).or(self.quality.final_flush_outcome);
        for (id, name) in [
            (8, "chunks_discarded"),
            (9, "patches_discarded"),
            (10, "invalid_packets"),
            (14, "flushes_failed"),
        ] {
            if let Some(v) = number(&f, id) {
                self.quality.service_loss_counters.insert(name.into(), v);
            }
        }
        for (idx, raw) in children(&f, 1).enumerate() {
            let b = fields(raw)?;
            for (id, name) in [
                (13, "bytes_overwritten"),
                (3, "chunks_overwritten"),
                (18, "chunks_discarded"),
                (6, "patches_failed"),
                (9, "abi_violations"),
                (19, "trace_writer_packet_loss"),
            ] {
                if let Some(v) = number(&b, id) {
                    self.quality
                        .service_loss_counters
                        .insert(format!("buffer_{idx}_{name}"), v);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockObservation {
    pub completion_record: u64,
    pub timestamp_ns: u64,
    pub device_encoded: u64,
    pub sector: u64,
    pub bytes: u64,
    pub rwbs: String,
    pub error: Option<i32>,
    pub clock: u32,
    /// Candidates refer to raw issue records in this trace only. No candidate
    /// is chosen when overlapping, partial or repeated requests are observed.
    pub issue_candidates: Vec<u64>,
    pub issue_timestamp_ns: Option<u64>,
    pub issuer_tid: Option<u32>,
    pub issuer_comm: Option<String>,
    pub device_latency_ns: Option<u64>,
    pub queue_latency_ns: Option<u64>,
    pub timing_confidence: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockAnalysis {
    pub completions: Vec<BlockObservation>,
    /// Issues without an unambiguous consumed completion, including issues
    /// whose completion was observed but could not be assigned uniquely.
    pub unmatched_issue_records: Vec<u64>,
    pub orphan_insert_records: Vec<u64>,
    pub unpaired_requeue_records: Vec<u64>,
    pub correlation_limit_hits: u64,
}
struct Pending<'a> {
    issue: &'a BlockEvent,
    insert: Option<&'a BlockEvent>,
    compromised: bool,
}

/// All completions contribute to volume/address analysis, even if timing has
/// no usable match. Unique observed range matches are probable, never Exact.
pub fn analyze(trace: &DecodedTrace) -> BlockAnalysis {
    let mut out = BlockAnalysis::default();
    let mut pending: BTreeMap<(u64, char), Vec<Pending<'_>>> = BTreeMap::new();
    let mut inserted: BTreeMap<(u64, char), Vec<&BlockEvent>> = BTreeMap::new();
    let mut limited = BTreeSet::new();
    for e in &trace.events {
        let key = (e.device_encoded, e.operation());
        match e.kind {
            BlockKind::Insert => {
                let list = inserted.entry(key).or_default();
                if list.len() >= MAX_PENDING_PER_DEVICE {
                    out.orphan_insert_records
                        .extend(list.drain(..).map(|v| v.record_id));
                    out.correlation_limit_hits += 1;
                    limited.insert(key);
                }
                list.push(e);
            }
            BlockKind::Issue => {
                let ins = inserted.entry(key).or_default();
                let matching: Vec<_> = ins
                    .iter()
                    .enumerate()
                    .filter(|(_, i)| i.overlaps(e))
                    .map(|(idx, _)| idx)
                    .collect();
                let insert = if matching.len() == 1 && ins[matching[0]].same_range(e) {
                    Some(ins.remove(matching[0]))
                } else {
                    None
                };
                let list = pending.entry(key).or_default();
                let mut compromised = limited.contains(&key);
                for p in list.iter_mut().filter(|p| p.issue.overlaps(e)) {
                    p.compromised = true;
                    compromised = true;
                }
                if list.len() >= MAX_PENDING_PER_DEVICE {
                    out.unmatched_issue_records
                        .extend(list.drain(..).map(|p| p.issue.record_id));
                    out.correlation_limit_hits += 1;
                    limited.insert(key);
                    compromised = true;
                }
                list.push(Pending {
                    issue: e,
                    insert,
                    compromised,
                });
            }
            BlockKind::Requeue => {
                let list = pending.entry(key).or_default();
                let mut matched = false;
                for p in list.iter_mut().filter(|p| p.issue.overlaps(e)) {
                    p.compromised = true;
                    matched = true;
                }
                if !matched {
                    out.unpaired_requeue_records.push(e.record_id);
                }
            }
            BlockKind::Complete => {
                let list = pending.entry(key).or_default();
                let candidates: Vec<_> = list
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| p.issue.overlaps(e))
                    .map(|(i, _)| i)
                    .collect();
                let mut observation = BlockObservation {
                    completion_record: e.record_id,
                    timestamp_ns: e.timestamp_ns,
                    device_encoded: e.device_encoded,
                    sector: e.sector,
                    bytes: e.bytes,
                    rwbs: e.rwbs.clone(),
                    error: e.error,
                    clock: e.clock,
                    issue_candidates: candidates
                        .iter()
                        .map(|i| list[*i].issue.record_id)
                        .collect(),
                    issue_timestamp_ns: None,
                    issuer_tid: None,
                    issuer_comm: None,
                    device_latency_ns: None,
                    queue_latency_ns: None,
                    timing_confidence: "Unresolved".into(),
                    reason:
                        "No observed issue candidate; raw completion volume and address retained"
                            .into(),
                };
                if candidates.len() == 1 {
                    let p = &mut list[candidates[0]];
                    let exact_range = p.issue.same_range(e);
                    if p.compromised || !exact_range {
                        observation.reason="Overlapping, repeated, partial or requeued request; timing and issuer unresolved".into();
                    } else if trace.quality.compromised() {
                        observation.reason="Trace loss, corruption or projection limit makes issue/completion matching unreliable".into();
                    } else if e.clock != 0 || p.issue.clock != 0 {
                        observation.reason =
                            "Unsupported ftrace clock; cross-CPU timing is unavailable".into();
                    } else if e.timestamp_ns <= p.issue.timestamp_ns {
                        observation.reason =
                            "Equal or reversed timestamps do not establish event order".into();
                    } else {
                        observation.issue_timestamp_ns = Some(p.issue.timestamp_ns);
                        observation.issuer_tid = p.issue.tid;
                        observation.issuer_comm = p.issue.comm.clone();
                        observation.device_latency_ns = Some(e.timestamp_ns - p.issue.timestamp_ns);
                        observation.queue_latency_ns = p
                            .insert
                            .filter(|i| i.clock == 0 && i.timestamp_ns < p.issue.timestamp_ns)
                            .map(|i| p.issue.timestamp_ns - i.timestamp_ns);
                        observation.timing_confidence = "Probable".into();
                        observation.reason="Unique observed device/sector/size/direction match; Perfetto provides no kernel request ID. FilePath unavailable".into();
                    }
                    if exact_range {
                        list.remove(candidates[0]);
                    } else {
                        p.compromised = true;
                    }
                } else if !candidates.is_empty() {
                    observation.reason="Multiple overlapping issue candidates; no arbitrary issuer or latency assigned".into();
                    for i in candidates {
                        list[i].compromised = true;
                    }
                }
                out.completions.push(observation);
            }
        }
    }
    out.unmatched_issue_records
        .extend(pending.values().flatten().map(|p| p.issue.record_id));
    out.orphan_insert_records
        .extend(inserted.values().flatten().map(|i| i.record_id));
    out
}
