//! Platform-independent event protocol and storage analysis core.

use std::{
    collections::{BTreeMap, HashMap},
    io::{self, BufRead, Write},
};

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u16 = 2;
pub const LARGE_IO_BYTES: u32 = 32 * 1024;
const MAX_ANALYSIS_SAMPLES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoOperation {
    Read,
    Write,
    Flush,
    Discard,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockInsert {
    pub ts_ns: u64,
    pub request_id: u64,
    pub device_major: u32,
    pub device_minor: u32,
    pub sector: u64,
    pub sectors: u32,
    pub bytes: u32,
    pub operation: IoOperation,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionConfidence {
    Unknown,
    Attributed,
    Exact,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIo {
    pub start_ts_ns: u64,
    pub end_ts_ns: u64,
    pub operation: IoOperation,
    pub fd: i32,
    pub requested_bytes: u64,
    pub completed_bytes: i64,
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    pub path: Option<String>,
    pub confidence: AttributionConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum StorageEvent {
    BlockInsert(BlockInsert),
    BlockIssue(BlockIssue),
    BlockComplete(BlockComplete),
    FileIo(FileIo),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeCapabilities {
    pub bpf_syscall: bool,
    pub btf: bool,
    pub ring_buffer: bool,
    #[serde(default)]
    pub block_insert: bool,
    pub block_issue: bool,
    pub block_complete: bool,
    #[serde(default)]
    pub file_io: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPattern {
    Unknown,
    Sequential,
    Random,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoSizeClass {
    Small,
    Large,
}

impl IoSizeClass {
    pub fn classify(bytes: u32) -> Self {
        if bytes >= LARGE_IO_BYTES {
            Self::Large
        } else {
            Self::Small
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedIo {
    pub insert: Option<BlockInsert>,
    pub issue: BlockIssue,
    pub completion: BlockComplete,
    /// Compatibility alias for issue-to-complete time.
    pub latency_ns: u64,
    pub queue_latency_ns: Option<u64>,
    pub device_latency_ns: u64,
    pub total_latency_ns: u64,
    pub queue_depth_after: usize,
    pub access_pattern: AccessPattern,
    pub size_class: IoSizeClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RequestKey {
    request_id: u64,
    device_major: u32,
    device_minor: u32,
}

impl RequestKey {
    fn new(request_id: u64, device_major: u32, device_minor: u32) -> Self {
        Self {
            request_id,
            device_major,
            device_minor,
        }
    }
    fn issue(value: &BlockIssue) -> Self {
        Self::new(value.request_id, value.device_major, value.device_minor)
    }
    fn insert(value: &BlockInsert) -> Self {
        Self::new(value.request_id, value.device_major, value.device_minor)
    }
    fn complete(value: &BlockComplete) -> Self {
        Self::new(value.request_id, value.device_major, value.device_minor)
    }
}

#[derive(Debug)]
struct PendingRequest {
    issue: BlockIssue,
    insert: Option<BlockInsert>,
    access_pattern: AccessPattern,
}

/// Correlates optional insert, issue and completion events while guarding ID reuse.
#[derive(Debug)]
pub struct RequestCorrelator {
    ttl_ns: u64,
    inserted: HashMap<RequestKey, BlockInsert>,
    pending: HashMap<RequestKey, PendingRequest>,
    ambiguous: HashMap<RequestKey, u64>,
    expired: u64,
    replaced: u64,
}

impl RequestCorrelator {
    pub fn new(ttl_ns: u64) -> Self {
        assert!(ttl_ns > 0, "request correlation TTL must be positive");
        Self {
            ttl_ns,
            inserted: HashMap::new(),
            pending: HashMap::new(),
            ambiguous: HashMap::new(),
            expired: 0,
            replaced: 0,
        }
    }

    pub fn on_insert(&mut self, insert: BlockInsert) {
        self.expire_before(insert.ts_ns);
        let key = RequestKey::insert(&insert);
        let ts_ns = insert.ts_ns;
        if self.inserted.insert(key, insert).is_some() {
            self.replaced += 1;
            self.ambiguous.insert(key, ts_ns);
        }
    }

    pub fn on_issue(&mut self, issue: BlockIssue) -> usize {
        self.on_issue_classified(issue, AccessPattern::Unknown)
    }

    pub fn on_issue_classified(
        &mut self,
        issue: BlockIssue,
        access_pattern: AccessPattern,
    ) -> usize {
        self.expire_before(issue.ts_ns);
        let key = RequestKey::issue(&issue);
        let insert = self.inserted.remove(&key);
        let collision = self.ambiguous.contains_key(&key) || self.pending.remove(&key).is_some();
        if collision {
            self.replaced += 1;
            self.ambiguous.insert(key, issue.ts_ns);
        } else {
            self.pending.insert(
                key,
                PendingRequest {
                    issue,
                    insert,
                    access_pattern,
                },
            );
        }
        self.pending.len()
    }

    pub fn on_complete(&mut self, completion: BlockComplete) -> Option<CompletedIo> {
        self.expire_before(completion.ts_ns);
        let key = RequestKey::complete(&completion);
        if self.ambiguous.remove(&key).is_some() {
            return None;
        }
        let pending = self.pending.remove(&key)?;
        let device_latency_ns = completion.ts_ns.checked_sub(pending.issue.ts_ns)?;
        let queue_latency_ns = pending
            .insert
            .as_ref()
            .and_then(|insert| pending.issue.ts_ns.checked_sub(insert.ts_ns));
        let total_latency_ns = pending
            .insert
            .as_ref()
            .and_then(|insert| completion.ts_ns.checked_sub(insert.ts_ns))
            .unwrap_or(device_latency_ns);
        let size_class = IoSizeClass::classify(pending.issue.bytes);
        Some(CompletedIo {
            insert: pending.insert,
            issue: pending.issue,
            completion,
            latency_ns: device_latency_ns,
            queue_latency_ns,
            device_latency_ns,
            total_latency_ns,
            queue_depth_after: self.pending.len(),
            access_pattern: pending.access_pattern,
            size_class,
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
        let ttl = self.ttl_ns;
        let mut expired = 0;
        self.inserted.retain(|_, value| {
            let keep = now_ns.saturating_sub(value.ts_ns) <= ttl;
            expired += u64::from(!keep);
            keep
        });
        self.pending.retain(|_, value| {
            let keep = now_ns.saturating_sub(value.issue.ts_ns) <= ttl;
            expired += u64::from(!keep);
            keep
        });
        self.ambiguous.retain(|_, ts_ns| {
            let keep = now_ns.saturating_sub(*ts_ns) <= ttl;
            expired += u64::from(!keep);
            keep
        });
        self.expired += expired;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StreamKey {
    device_major: u32,
    device_minor: u32,
    operation: IoOperation,
}

#[derive(Debug, Clone, Copy)]
struct LastAccess {
    sector: u64,
    sectors: u32,
}

#[derive(Debug, Default)]
pub struct SequentialClassifier {
    streams: HashMap<StreamKey, LastAccess>,
}

impl SequentialClassifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn classify(&mut self, issue: &BlockIssue) -> AccessPattern {
        let key = StreamKey {
            device_major: issue.device_major,
            device_minor: issue.device_minor,
            operation: issue.operation,
        };
        let current = LastAccess {
            sector: issue.sector,
            sectors: issue.sectors,
        };
        match self.streams.insert(key, current) {
            None => AccessPattern::Unknown,
            Some(previous)
                if previous.sector.checked_add(previous.sectors as u64) == Some(issue.sector) =>
            {
                AccessPattern::Sequential
            }
            Some(_) => AccessPattern::Random,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategorySummary {
    pub operation: IoOperation,
    pub access_pattern: AccessPattern,
    pub size_class: IoSizeClass,
    pub completed_ios: u64,
    pub bytes: u64,
    pub average_chunk_bytes: u64,
    pub p50_latency_ns: Option<u64>,
    pub p95_latency_ns: Option<u64>,
    pub p99_latency_ns: Option<u64>,
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
    pub small_ios: u64,
    pub large_ios: u64,
    pub max_queue_depth: usize,
    pub p50_latency_ns: Option<u64>,
    pub p95_latency_ns: Option<u64>,
    pub p99_latency_ns: Option<u64>,
    pub logging_ns: u64,
    pub busy_ns: u64,
    pub idle_ns: u64,
    pub file_ios: u64,
    pub attributed_file_ios: u64,
    pub category_summaries: Vec<CategorySummary>,
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

#[derive(Debug, Default)]
struct MutableCategory {
    completed_ios: u64,
    bytes: u64,
    latencies: Vec<u64>,
}

#[derive(Debug)]
pub struct AnalysisEngine {
    correlator: RequestCorrelator,
    classifier: SequentialClassifier,
    summary: AnalysisSummary,
    latencies_ns: Vec<u64>,
    buckets: BTreeMap<u64, MutableBucket>,
    categories: BTreeMap<(IoOperation, AccessPattern, IoSizeClass), MutableCategory>,
    busy_intervals: Vec<(u64, u64)>,
    first_ts_ns: Option<u64>,
    last_ts_ns: Option<u64>,
    completed: Vec<CompletedIo>,
    file_ios: Vec<FileIo>,
}

impl AnalysisEngine {
    pub fn new() -> Self {
        Self::with_windows(30_000_000_000, 0)
    }

    /// The second argument remains for source compatibility; continuity is now purely spatial.
    pub fn with_windows(correlation_ttl_ns: u64, _sequential_window_ns: u64) -> Self {
        Self {
            correlator: RequestCorrelator::new(correlation_ttl_ns),
            classifier: SequentialClassifier::new(),
            summary: AnalysisSummary::default(),
            latencies_ns: Vec::new(),
            buckets: BTreeMap::new(),
            categories: BTreeMap::new(),
            busy_intervals: Vec::new(),
            first_ts_ns: None,
            last_ts_ns: None,
            completed: Vec::new(),
            file_ios: Vec::new(),
        }
    }

    pub fn ingest(&mut self, event: StorageEvent) -> Option<CompletedIo> {
        match event {
            StorageEvent::BlockInsert(insert) => {
                self.observe_ts(insert.ts_ns);
                self.correlator.on_insert(insert);
                None
            }
            StorageEvent::BlockIssue(issue) => {
                self.observe_ts(issue.ts_ns);
                self.summary.issued_ios += 1;
                let pattern = self.classifier.classify(&issue);
                match pattern {
                    AccessPattern::Sequential => self.summary.sequential_ios += 1,
                    AccessPattern::Random => self.summary.random_ios += 1,
                    AccessPattern::Unknown => {}
                }
                match IoSizeClass::classify(issue.bytes) {
                    IoSizeClass::Small => self.summary.small_ios += 1,
                    IoSizeClass::Large => self.summary.large_ios += 1,
                }
                let ts_ns = issue.ts_ns;
                let depth = self.correlator.on_issue_classified(issue, pattern);
                self.summary.max_queue_depth = self.summary.max_queue_depth.max(depth);
                self.buckets
                    .entry(ts_ns / 1_000_000_000)
                    .or_default()
                    .max_queue_depth = depth;
                None
            }
            StorageEvent::BlockComplete(completion) => {
                self.observe_ts(completion.ts_ns);
                let Some(completed) = self.correlator.on_complete(completion) else {
                    self.summary.uncorrelated_completions += 1;
                    return None;
                };
                self.record_completed(&completed);
                if self.completed.len() == MAX_ANALYSIS_SAMPLES {
                    self.completed.drain(..MAX_ANALYSIS_SAMPLES / 10);
                }
                self.completed.push(completed.clone());
                Some(completed)
            }
            StorageEvent::FileIo(file) => {
                self.observe_ts(file.start_ts_ns);
                self.observe_ts(file.end_ts_ns);
                self.summary.file_ios += 1;
                if matches!(
                    file.confidence,
                    AttributionConfidence::Attributed | AttributionConfidence::Exact
                ) {
                    self.summary.attributed_file_ios += 1;
                }
                if self.file_ios.len() == MAX_ANALYSIS_SAMPLES {
                    self.file_ios.drain(..MAX_ANALYSIS_SAMPLES / 10);
                }
                self.file_ios.push(file);
                None
            }
        }
    }

    fn record_completed(&mut self, completed: &CompletedIo) {
        self.summary.completed_ios += 1;
        let bytes = completed.issue.bytes as u64;
        match completed.issue.operation {
            IoOperation::Read => self.summary.read_bytes += bytes,
            IoOperation::Write => self.summary.write_bytes += bytes,
            _ => self.summary.other_bytes += bytes,
        }
        self.latencies_ns.push(completed.total_latency_ns);
        let start = completed
            .insert
            .as_ref()
            .map_or(completed.issue.ts_ns, |value| value.ts_ns);
        merge_interval(
            &mut self.busy_intervals,
            (start, completed.completion.ts_ns),
        );
        let bucket = self
            .buckets
            .entry(completed.completion.ts_ns / 1_000_000_000)
            .or_default();
        bucket.completed_ios += 1;
        bucket.bytes += bytes;
        bucket.latency_sum_ns += completed.total_latency_ns as u128;
        bucket.max_queue_depth = bucket.max_queue_depth.max(completed.queue_depth_after);
        let category = self
            .categories
            .entry((
                completed.issue.operation,
                completed.access_pattern,
                completed.size_class,
            ))
            .or_default();
        category.completed_ios += 1;
        category.bytes += bytes;
        category.latencies.push(completed.total_latency_ns);
    }

    fn observe_ts(&mut self, ts_ns: u64) {
        self.first_ts_ns = Some(self.first_ts_ns.map_or(ts_ns, |value| value.min(ts_ns)));
        self.last_ts_ns = Some(self.last_ts_ns.map_or(ts_ns, |value| value.max(ts_ns)));
    }

    pub fn summary(&self) -> AnalysisSummary {
        let mut summary = self.summary.clone();
        let mut values = self.latencies_ns.clone();
        values.sort_unstable();
        summary.p50_latency_ns = percentile(&values, 50);
        summary.p95_latency_ns = percentile(&values, 95);
        summary.p99_latency_ns = percentile(&values, 99);
        summary.logging_ns = self
            .first_ts_ns
            .zip(self.last_ts_ns)
            .map_or(0, |(first, last)| last.saturating_sub(first));
        summary.busy_ns = union_duration(&self.busy_intervals).min(summary.logging_ns);
        summary.idle_ns = summary.logging_ns.saturating_sub(summary.busy_ns);
        summary.category_summaries = self
            .categories
            .iter()
            .map(|(&(operation, access_pattern, size_class), value)| {
                let mut latencies = value.latencies.clone();
                latencies.sort_unstable();
                CategorySummary {
                    operation,
                    access_pattern,
                    size_class,
                    completed_ios: value.completed_ios,
                    bytes: value.bytes,
                    average_chunk_bytes: value.bytes / value.completed_ios.max(1),
                    p50_latency_ns: percentile(&latencies, 50),
                    p95_latency_ns: percentile(&latencies, 95),
                    p99_latency_ns: percentile(&latencies, 99),
                }
            })
            .collect();
        summary
    }

    pub fn completed_ios(&self) -> &[CompletedIo] {
        &self.completed
    }
    pub fn file_ios(&self) -> &[FileIo] {
        &self.file_ios
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

fn union_duration(intervals: &[(u64, u64)]) -> u64 {
    let mut values: Vec<_> = intervals
        .iter()
        .copied()
        .filter(|(start, end)| end >= start)
        .collect();
    values.sort_unstable();
    let Some((mut start, mut end)) = values.first().copied() else {
        return 0;
    };
    let mut total = 0_u64;
    for (next_start, next_end) in values.into_iter().skip(1) {
        if next_start <= end {
            end = end.max(next_end);
        } else {
            total = total.saturating_add(end.saturating_sub(start));
            start = next_start;
            end = next_end;
        }
    }
    total.saturating_add(end.saturating_sub(start))
}

fn merge_interval(intervals: &mut Vec<(u64, u64)>, (mut start, mut end): (u64, u64)) {
    if end < start {
        return;
    }
    let first = intervals.partition_point(|(_, current_end)| *current_end < start);
    let mut last = first;
    while last < intervals.len() && intervals[last].0 <= end {
        start = start.min(intervals[last].0);
        end = end.max(intervals[last].1);
        last += 1;
    }
    intervals.splice(first..last, [(start, end)]);
}
