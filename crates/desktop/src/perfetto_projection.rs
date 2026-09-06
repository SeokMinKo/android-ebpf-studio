use crate::perfetto::{
    BlockAnalysis, BlockEvent, BlockKind, BlockObservation, DecodedTrace, ProcessMetadata,
};
use android_ebpf_protocol::{
    AccessPattern, BlockComplete, BlockInsert, BlockIssue, CompletedIo, CompletionEvidence,
    CorrelationConfidence, IoOperation, IoSizeClass, SequentialClassifier,
};
use std::collections::HashMap;

/// Inverse of Perfetto CpuReader::TranslateBlockDeviceIDToUserspace (makedev).
/// Trace protobuf contains userspace dev_t, not the kernel's major << 20 layout.
pub fn device_numbers(encoded: u64) -> (u32, u32) {
    (
        (((encoded >> 8) & 0xfff) | ((encoded >> 32) & 0xfffff000)) as u32,
        ((encoded & 0xff) | ((encoded >> 12) & 0xffffff00)) as u32,
    )
}
fn operation(rwbs: &str) -> IoOperation {
    match rwbs.chars().next() {
        Some('R') => IoOperation::Read,
        Some('W') => IoOperation::Write,
        Some('D') => IoOperation::Discard,
        Some('F') => IoOperation::Flush,
        _ => IoOperation::Other,
    }
}

pub struct Projection<'a> {
    records: HashMap<u64, &'a BlockEvent>,
    patterns: HashMap<u64, AccessPattern>,
    metadata: HashMap<u32, Vec<&'a ProcessMetadata>>,
}
impl<'a> Projection<'a> {
    pub fn new(trace: &'a DecodedTrace) -> Self {
        let mut patterns = HashMap::new();
        let mut classifier = SequentialClassifier::default();
        let mut metadata: HashMap<u32, Vec<&ProcessMetadata>> = HashMap::new();
        for row in &trace.processes {
            if row.snapshot_ns.is_none() {
                continue;
            }
            metadata
                .entry(row.tid.unwrap_or(row.pid))
                .or_default()
                .push(row);
        }
        for rows in metadata.values_mut() {
            rows.sort_by_key(|r| r.snapshot_ns);
        }
        for e in trace.events.iter().filter(|e| e.kind == BlockKind::Issue) {
            let (major, minor) = device_numbers(e.device_encoded);
            let issue = BlockIssue {
                ts_ns: e.timestamp_ns,
                request_id: e.record_id,
                device_major: major,
                device_minor: minor,
                sector: e.sector,
                sectors: e.sectors,
                bytes: u32::try_from(e.bytes).unwrap_or(u32::MAX),
                operation: operation(&e.rwbs),
                pid: 0,
                tid: e.tid.unwrap_or(0),
                cpu: e.cpu.unwrap_or(0),
                comm: e.comm.clone().unwrap_or_default(),
            };
            patterns.insert(
                e.record_id,
                if e.clock == 0 {
                    classifier.classify(&issue)
                } else {
                    AccessPattern::Unknown
                },
            );
        }
        Self {
            records: trace.events.iter().map(|e| (e.record_id, e)).collect(),
            patterns,
            metadata,
        }
    }
    fn process_candidate(&self, tid: Option<u32>, ts: Option<u64>) -> Option<&ProcessMetadata> {
        let ts = ts?;
        let rows = self.metadata.get(&tid?)?;
        let end = rows.partition_point(|r| r.snapshot_ns.is_some_and(|t| t <= ts));
        // Metadata is a candidate snapshot, never upgraded to kernel request
        // identity. Future-only snapshots cannot establish an earlier issuer.
        let candidate = rows
            .get(end.checked_sub(1)?)
            .copied()
            .filter(|r| r.start_from_boot_ns.is_none_or(|start| start <= ts))?;
        // Equal-time contradictory snapshots cannot establish one TGID/name.
        if rows[..end]
            .iter()
            .rev()
            .take_while(|r| r.snapshot_ns == candidate.snapshot_ns)
            .any(|r| {
                r.pid != candidate.pid
                    || r.name != candidate.name
                    || r.start_from_boot_ns != candidate.start_from_boot_ns
            })
        {
            return None;
        }
        Some(candidate)
    }
    pub fn completion(&self, o: &BlockObservation) -> anyhow::Result<CompletedIo> {
        let raw = self
            .records
            .get(&o.completion_record)
            .ok_or_else(|| anyhow::anyhow!("Missing raw completion evidence"))?;
        let bytes=u32::try_from(o.bytes).map_err(|_|anyhow::anyhow!("Completion {} exceeds the session's 32-bit I/O size representation; raw trace preserved",o.completion_record))?;
        let (major, minor) = device_numbers(o.device_encoded);
        let process = self.process_candidate(o.issuer_tid, o.issue_timestamp_ns);
        let pid = process.map(|p| p.pid);
        let mut reason = o.reason.clone();
        if process.is_some() {
            reason.push_str("; TGID/name are candidates from an earlier process snapshot");
        }
        let issue_ts = o.issue_timestamp_ns.unwrap_or(o.timestamp_ns);
        let issuer_cpu = if o.issue_timestamp_ns.is_some() && o.issue_candidates.len() == 1 {
            self.records.get(&o.issue_candidates[0]).and_then(|e| e.cpu)
        } else {
            None
        };
        let issue = BlockIssue {
            ts_ns: issue_ts,
            request_id: o.completion_record,
            device_major: major,
            device_minor: minor,
            sector: o.sector,
            sectors: raw.sectors,
            bytes,
            operation: operation(&o.rwbs),
            pid: pid.unwrap_or(0),
            tid: o.issuer_tid.unwrap_or(0),
            cpu: issuer_cpu.unwrap_or(0),
            comm: o
                .issuer_comm
                .clone()
                .unwrap_or_else(|| "<issuer unavailable>".into()),
        };
        let insert = o
            .queue_latency_ns
            .and_then(|q| o.issue_timestamp_ns?.checked_sub(q))
            .map(|ts_ns| BlockInsert {
                ts_ns,
                request_id: issue.request_id,
                device_major: major,
                device_minor: minor,
                sector: o.sector,
                sectors: raw.sectors,
                bytes,
                operation: issue.operation,
            });
        let access_pattern = if o.issue_timestamp_ns.is_some() && o.issue_candidates.len() == 1 {
            self.patterns
                .get(&o.issue_candidates[0])
                .copied()
                .unwrap_or(AccessPattern::Unknown)
        } else {
            AccessPattern::Unknown
        };
        Ok(CompletedIo {
            insert,
            issue,
            completion: BlockComplete {
                ts_ns: o.timestamp_ns,
                request_id: o.completion_record,
                device_major: major,
                device_minor: minor,
                status: o.error.unwrap_or(0),
            },
            latency_ns: o.device_latency_ns,
            device_latency_ns: o.device_latency_ns,
            total_latency_ns: o
                .device_latency_ns
                .and_then(|d| d.checked_add(o.queue_latency_ns.unwrap_or(0))),
            queue_latency_ns: o.queue_latency_ns,
            queue_depth_after: None,
            access_pattern,
            size_class: IoSizeClass::classify(bytes),
            evidence: Some(Box::new(CompletionEvidence {
                source: "Perfetto block tracepoints".into(),
                record_id: o.completion_record,
                issue_record_candidates: o.issue_candidates.clone(),
                issue_timestamp_ns: o.issue_timestamp_ns,
                issuer_pid: pid,
                issuer_tid: o.issuer_tid,
                issuer_cpu,
                completion_status: o.error,
                process_name: process.map(|p| p.name.clone()),
                timing_confidence: if o.device_latency_ns.is_some() {
                    CorrelationConfidence::Probable
                } else {
                    CorrelationConfidence::ContextOnly
                },
                reason,
                clock: o.clock,
            })),
        })
    }
    pub fn events(&self, analysis: &BlockAnalysis) -> anyhow::Result<Vec<CompletedIo>> {
        analysis
            .completions
            .iter()
            .map(|o| self.completion(o))
            .collect()
    }
}
