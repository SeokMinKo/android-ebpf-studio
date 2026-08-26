//! Platform-independent event protocol and storage analysis core.

use std::{
    collections::{BTreeMap, HashMap},
    io::{self, BufRead, Write},
};

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoOperation {
    Read,
    Write,
    Flush,
    Discard,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockIssue {
    pub ts_ns: u64,
    pub request_id: u64,
    pub device_major: u32,
    pub device_minor: u32,
    pub sector: u64,
    pub sectors: u32,
    pub bytes: u32,
    pub operation: IoOperation,
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub comm: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockComplete {
    pub ts_ns: u64,
    pub request_id: u64,
    pub device_major: u32,
    pub device_minor: u32,
    pub status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum StorageEvent {
    BlockIssue(BlockIssue),
    BlockComplete(BlockComplete),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeCapabilities {
    pub bpf_syscall: bool,
    pub btf: bool,
    pub ring_buffer: bool,
    pub block_issue: bool,
    pub block_complete: bool,
    #[serde(default)]
    pub exact_request_correlation: bool,
    #[serde(default)]
    pub ufs_events: Vec<String>,
    #[serde(default)]
    pub fs_events: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum WireRecord {
    Hello {
        schema_version: u16,
        agent_version: String,
        boot_id: String,
        kernel_release: String,
    },
    Capabilities {
        schema_version: u16,
        capabilities: ProbeCapabilities,
    },
    Event {
        schema_version: u16,
        sequence: u64,
        event: StorageEvent,
    },
    Health {
        schema_version: u16,
        emitted_events: u64,
        kernel_drops: u64,
        userspace_drops: u64,
    },
    Footer {
        schema_version: u16,
        events_seen: u64,
        events_persisted: u64,
        events_dropped: u64,
        events_rejected: u64,
    },
}

#[derive(Debug, Default)]
pub struct SessionLoad {
    pub hello: Option<WireRecord>,
    pub capabilities: Option<ProbeCapabilities>,
    pub events: Vec<StorageEvent>,
    pub health: Vec<WireRecord>,
    pub footer: Option<WireRecord>,
    pub total_lines: u64,
    pub rejected_lines: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("record serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct SessionReader {
    max_line_bytes: usize,
}

impl SessionReader {
    pub fn new(max_line_bytes: usize) -> Self {
        assert!(max_line_bytes > 0, "maximum line size must be positive");
        Self { max_line_bytes }
    }

    pub fn read<R: BufRead>(&self, mut input: R) -> Result<SessionLoad, SessionError> {
        let mut loaded = SessionLoad::default();
        let mut line = String::new();
        loop {
            line.clear();
            if input.read_line(&mut line)? == 0 {
                break;
            }
            if line.trim().is_empty() {
                continue;
            }
            loaded.total_lines += 1;
            if line.len() > self.max_line_bytes {
                loaded.rejected_lines += 1;
                continue;
            }
            match serde_json::from_str::<WireRecord>(&line) {
                Ok(record @ WireRecord::Hello { .. }) => loaded.hello = Some(record),
                Ok(WireRecord::Capabilities { capabilities, .. }) => {
                    loaded.capabilities = Some(capabilities)
                }
                Ok(WireRecord::Event { event, .. }) => loaded.events.push(event),
                Ok(record @ WireRecord::Health { .. }) => loaded.health.push(record),
                Ok(record @ WireRecord::Footer { .. }) => loaded.footer = Some(record),
                Err(_) => loaded.rejected_lines += 1,
            }
        }
        Ok(loaded)
    }
}

impl Default for SessionReader {
    fn default() -> Self {
        Self::new(1024 * 1024)
    }
}

pub fn write_record<W: Write>(mut output: W, record: &WireRecord) -> Result<(), SessionError> {
    serde_json::to_writer(&mut output, record)?;
    output.write_all(b"\n")?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedIo {
    pub issue: BlockIssue,
    pub completion: BlockComplete,
    pub latency_ns: u64,
    pub queue_depth_after: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RequestKey {
    request_id: u64,
    device_major: u32,
    device_minor: u32,
}

impl RequestKey {
    fn issue(value: &BlockIssue) -> Self {
        Self {
            request_id: value.request_id,
            device_major: value.device_major,
            device_minor: value.device_minor,
        }
    }

    fn complete(value: &BlockComplete) -> Self {
        Self {
            request_id: value.request_id,
            device_major: value.device_major,
            device_minor: value.device_minor,
        }
    }
}

/// Correlates block request issue/completion events while guarding request-ID reuse.
#[derive(Debug)]
pub struct RequestCorrelator {
    ttl_ns: u64,
    pending: HashMap<RequestKey, BlockIssue>,
    ambiguous: HashMap<RequestKey, u64>,
    expired: u64,
    replaced: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPattern {
    Unknown,
    Sequential,
    Random,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StreamKey {
    device_major: u32,
    device_minor: u32,
    operation: IoOperation,
}

#[derive(Debug, Clone, Copy)]
struct LastAccess {
    ts_ns: u64,
    sector: u64,
    sectors: u32,
}

#[derive(Debug)]
pub struct SequentialClassifier {
    window_ns: u64,
    streams: HashMap<StreamKey, LastAccess>,
}

impl SequentialClassifier {
    pub fn new(window_ns: u64) -> Self {
        assert!(
            window_ns > 0,
            "sequential classification window must be positive"
        );
        Self {
            window_ns,
            streams: HashMap::new(),
        }
    }

    pub fn classify(&mut self, issue: &BlockIssue) -> AccessPattern {
        let key = StreamKey {
            device_major: issue.device_major,
            device_minor: issue.device_minor,
            operation: issue.operation,
        };
        let current = LastAccess {
            ts_ns: issue.ts_ns,
            sector: issue.sector,
            sectors: issue.sectors,
        };
        match self.streams.insert(key, current) {
            None => AccessPattern::Unknown,
            Some(previous) => {
                let elapsed = issue.ts_ns.checked_sub(previous.ts_ns);
                let next_sector = previous.sector.checked_add(previous.sectors as u64);
                if elapsed.is_some_and(|value| value <= self.window_ns)
                    && next_sector == Some(issue.sector)
                {
                    AccessPattern::Sequential
                } else {
                    AccessPattern::Random
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub issued_ios: u64,
    pub completed_ios: u64,
    pub uncorrelated_completions: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub other_bytes: u64,
    pub sequential_ios: u64,
    pub random_ios: u64,
    pub max_queue_depth: usize,
    pub p50_latency_ns: Option<u64>,
    pub p95_latency_ns: Option<u64>,
    pub p99_latency_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeBucket {
    pub second: u64,
    pub completed_ios: u64,
    pub bytes: u64,
    pub average_latency_ns: f64,
    pub max_queue_depth: usize,
}

#[derive(Debug, Default)]
struct MutableBucket {
    completed_ios: u64,
    bytes: u64,
    latency_sum_ns: u128,
    max_queue_depth: usize,
}

#[derive(Debug)]
pub struct AnalysisEngine {
    correlator: RequestCorrelator,
    classifier: SequentialClassifier,
    summary: AnalysisSummary,
    latencies_ns: Vec<u64>,
    buckets: BTreeMap<u64, MutableBucket>,
}

impl AnalysisEngine {
    pub fn new() -> Self {
        Self::with_windows(30_000_000_000, 10_000_000)
    }

    pub fn with_windows(correlation_ttl_ns: u64, sequential_window_ns: u64) -> Self {
        Self {
            correlator: RequestCorrelator::new(correlation_ttl_ns),
            classifier: SequentialClassifier::new(sequential_window_ns),
            summary: AnalysisSummary::default(),
            latencies_ns: Vec::new(),
            buckets: BTreeMap::new(),
        }
    }

    pub fn ingest(&mut self, event: StorageEvent) -> Option<CompletedIo> {
        match event {
            StorageEvent::BlockIssue(issue) => {
                self.summary.issued_ios += 1;
                match self.classifier.classify(&issue) {
                    AccessPattern::Sequential => self.summary.sequential_ios += 1,
                    AccessPattern::Random => self.summary.random_ios += 1,
                    AccessPattern::Unknown => {}
                }
                let depth = self.correlator.on_issue(issue.clone());
                self.summary.max_queue_depth = self.summary.max_queue_depth.max(depth);
                self.buckets
                    .entry(issue.ts_ns / 1_000_000_000)
                    .or_default()
                    .max_queue_depth = depth;
                None
            }
            StorageEvent::BlockComplete(completion) => {
                let Some(completed) = self.correlator.on_complete(completion) else {
                    self.summary.uncorrelated_completions += 1;
                    return None;
                };
                self.summary.completed_ios += 1;
                match completed.issue.operation {
                    IoOperation::Read => {
                        self.summary.read_bytes += completed.issue.bytes as u64;
                    }
                    IoOperation::Write => {
                        self.summary.write_bytes += completed.issue.bytes as u64;
                    }
                    _ => self.summary.other_bytes += completed.issue.bytes as u64,
                }
                self.latencies_ns.push(completed.latency_ns);
                let bucket = self
                    .buckets
                    .entry(completed.completion.ts_ns / 1_000_000_000)
                    .or_default();
                bucket.completed_ios += 1;
                bucket.bytes += completed.issue.bytes as u64;
                bucket.latency_sum_ns += completed.latency_ns as u128;
                bucket.max_queue_depth = bucket.max_queue_depth.max(completed.queue_depth_after);
                Some(completed)
            }
        }
    }

    pub fn summary(&self) -> AnalysisSummary {
        let mut summary = self.summary.clone();
        let mut values = self.latencies_ns.clone();
        values.sort_unstable();
        summary.p50_latency_ns = percentile(&values, 50);
        summary.p95_latency_ns = percentile(&values, 95);
        summary.p99_latency_ns = percentile(&values, 99);
        summary
    }

    pub fn buckets(&self) -> Vec<TimeBucket> {
        self.buckets
            .iter()
            .map(|(second, value)| TimeBucket {
                second: *second,
                completed_ios: value.completed_ios,
                bytes: value.bytes,
                average_latency_ns: if value.completed_ios == 0 {
                    0.0
                } else {
                    value.latency_sum_ns as f64 / value.completed_ios as f64
                },
                max_queue_depth: value.max_queue_depth,
            })
            .collect()
    }
}

impl Default for AnalysisEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn percentile(sorted: &[u64], percentile: usize) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((percentile * sorted.len()).div_ceil(100)).max(1);
    sorted.get(rank - 1).copied()
}

impl RequestCorrelator {
    pub fn new(ttl_ns: u64) -> Self {
        assert!(ttl_ns > 0, "request correlation TTL must be positive");
        Self {
            ttl_ns,
            pending: HashMap::new(),
            ambiguous: HashMap::new(),
            expired: 0,
            replaced: 0,
        }
    }

    pub fn on_issue(&mut self, issue: BlockIssue) -> usize {
        self.expire_before(issue.ts_ns);
        let key = RequestKey::issue(&issue);
        let collision = self.ambiguous.contains_key(&key) || self.pending.remove(&key).is_some();
        if collision {
            self.replaced += 1;
            self.ambiguous.insert(key, issue.ts_ns);
        } else {
            self.pending.insert(key, issue);
        }
        self.pending.len()
    }

    pub fn on_complete(&mut self, completion: BlockComplete) -> Option<CompletedIo> {
        self.expire_before(completion.ts_ns);
        let key = RequestKey::complete(&completion);
        if self.ambiguous.remove(&key).is_some() {
            return None;
        }
        let issue = self.pending.remove(&key)?;
        let latency_ns = completion.ts_ns.checked_sub(issue.ts_ns)?;
        Some(CompletedIo {
            issue,
            completion,
            latency_ns,
            queue_depth_after: self.pending.len(),
        })
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn expired_count(&self) -> u64 {
        self.expired
    }

    pub fn replaced_count(&self) -> u64 {
        self.replaced
    }

    fn expire_before(&mut self, now_ns: u64) {
        let ttl_ns = self.ttl_ns;
        let before = self.pending.len();
        self.pending
            .retain(|_, issue| now_ns.saturating_sub(issue.ts_ns) <= ttl_ns);
        let pending_expired = before - self.pending.len();
        let ambiguous_before = self.ambiguous.len();
        self.ambiguous
            .retain(|_, ts_ns| now_ns.saturating_sub(*ts_ns) <= ttl_ns);
        self.expired +=
            (pending_expired + ambiguous_before.saturating_sub(self.ambiguous.len())) as u64;
    }
}
