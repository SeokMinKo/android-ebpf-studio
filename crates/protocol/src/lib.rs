//! Platform-independent event protocol and storage analysis core.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    io::{self, BufRead, Write},
};

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u16 = 4;
pub const LARGE_IO_BYTES: u32 = 32 * 1024;
const MAX_ANALYSIS_SAMPLES: usize = 100_000;
const MAX_DERIVED_CACHE_ENTRIES: usize = 4_096;
const MAX_RCA_COHORT_SAMPLES: usize = 512;

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FileIdentity {
    pub fs_device_major: u32,
    pub fs_device_minor: u32,
    pub inode: u64,
    #[serde(default)]
    pub inode_generation: Option<u32>,
    #[serde(default)]
    pub mount_id: Option<u64>,
}

impl FileIdentity {
    pub fn fallback_label(&self) -> String {
        format!(
            "<inode {}:{}:{}>",
            self.fs_device_major, self.fs_device_minor, self.inode
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathSource {
    BpfDPath,
    ProcFd,
    InodeOnly,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathSnapshot {
    pub path: Option<String>,
    pub source: PathSource,
    pub captured_ts_ns: u64,
    #[serde(default)]
    pub deleted: bool,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FileIoMode {
    #[default]
    Unknown,
    Buffered,
    Direct,
    Sync,
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
    #[serde(default)]
    pub file_identity: Option<FileIdentity>,
    #[serde(default)]
    pub path_snapshot: Option<PathSnapshot>,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub io_mode: FileIoMode,
    #[serde(default)]
    pub node_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoNodeKind {
    FileOperation,
    Syscall,
    Vfs,
    Filesystem,
    PageCache,
    Writeback,
    Bio,
    BlockQueue,
    BlockRequest,
    ScsiCommand,
    UfsCommand,
    UicContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoOrigin {
    File,
    FilesystemMetadata,
    Journal,
    GarbageCollection,
    Checkpoint,
    Writeback,
    Readahead,
    Swap,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeConfidence {
    Exact,
    Probable,
    ProbableAsync,
    ContextOnly,
}

impl EdgeConfidence {
    fn rank(self) -> u8 {
        match self {
            Self::Exact => 3,
            Self::Probable => 2,
            Self::ProbableAsync => 1,
            Self::ContextOnly => 0,
        }
    }

    fn weakest(self, other: Self) -> Self {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoRelation {
    Calls,
    Contains,
    Submits,
    SplitsInto,
    MergedInto,
    RemapsTo,
    Dispatches,
    CompletesInto,
    CausesAsync,
    ContextFor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationEvidence {
    pub match_type: String,
    #[serde(default)]
    pub opaque_key: Option<u64>,
    #[serde(default)]
    pub delta_ns: Option<u64>,
    #[serde(default)]
    pub candidate_count: u32,
    #[serde(default)]
    pub sector_match: bool,
    #[serde(default)]
    pub bytes_match: bool,
    #[serde(default)]
    pub task_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoNode {
    pub node_id: u64,
    /// Owning block transaction when the capture source can identify it.
    /// This is deliberately separate from `node_id`: pointers and tags may be
    /// reused, while a transaction is scoped to the current boot/session.
    #[serde(default)]
    pub transaction_id: Option<u64>,
    pub kind: IoNodeKind,
    pub start_ts_ns: u64,
    #[serde(default)]
    pub end_ts_ns: Option<u64>,
    pub origin: IoOrigin,
    #[serde(default)]
    pub file: Option<FileIdentity>,
    #[serde(default)]
    pub path: Option<PathSnapshot>,
    #[serde(default)]
    pub operation: Option<IoOperation>,
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub tid: u32,
    pub name: String,
}

impl IoNode {
    pub fn end_or_start(&self) -> u64 {
        self.end_ts_ns.unwrap_or(self.start_ts_ns)
    }

    pub fn duration_ns(&self) -> u64 {
        self.end_or_start().saturating_sub(self.start_ts_ns)
    }

    fn additive(&self) -> bool {
        self.kind != IoNodeKind::UicContext
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoEdge {
    pub edge_id: u64,
    #[serde(default)]
    pub transaction_id: Option<u64>,
    pub from_node_id: u64,
    pub to_node_id: u64,
    pub relation: IoRelation,
    pub confidence: EdgeConfidence,
    #[serde(default)]
    pub evidence: Vec<CorrelationEvidence>,
}

impl IoEdge {
    pub fn exact(edge_id: u64, from_node_id: u64, to_node_id: u64, relation: IoRelation) -> Self {
        Self {
            edge_id,
            transaction_id: None,
            from_node_id,
            to_node_id,
            relation,
            confidence: EdgeConfidence::Exact,
            evidence: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOriginView {
    pub file: FileIdentity,
    pub path: Option<PathSnapshot>,
    pub confidence: EdgeConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GraphMetrics {
    pub start_ts_ns: u64,
    pub end_ts_ns: u64,
    pub total_ns: u64,
    pub accounted_ns: u64,
    pub unaccounted_ns: u64,
    pub exclusive_ns: BTreeMap<u64, u64>,
    pub critical_path: Vec<u64>,
    pub critical_path_ns: u64,
    pub unaccounted: Vec<UnaccountedInterval>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnaccountedReason {
    ProbeUnavailable,
    EventLost,
    Ambiguous,
    ClockInvalid,
    VendorInternal,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnaccountedInterval {
    pub start_ts_ns: u64,
    pub end_ts_ns: u64,
    pub reason: UnaccountedReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AttributionSummary {
    pub exact: u64,
    pub probable: u64,
    pub probable_async: u64,
    pub unattributed: u64,
    pub multi_origin: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlowReason {
    pub node_kind: IoNodeKind,
    pub stage: String,
    pub selected_ns: u64,
    pub cohort_median_ns: u64,
    pub delta_ns: u64,
    pub confidence: EdgeConfidence,
    pub cohort_samples: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GraphError {
    #[error("node {0} already exists")]
    DuplicateNode(u64),
    #[error("edge {0} already exists")]
    DuplicateEdge(u64),
    #[error("node {0} does not exist")]
    MissingNode(u64),
    #[error("node {0} has an invalid time range")]
    InvalidTime(u64),
    #[error("edge would introduce a graph cycle")]
    Cycle,
    #[error("edge {0} points backward in monotonic time")]
    ReverseTime(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoTransactionGraph {
    pub transaction_id: u64,
    pub nodes: Vec<IoNode>,
    pub edges: Vec<IoEdge>,
}

impl IoTransactionGraph {
    pub fn new(transaction_id: u64) -> Self {
        Self {
            transaction_id,
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node: IoNode) -> Result<(), GraphError> {
        if node.end_or_start() < node.start_ts_ns {
            return Err(GraphError::InvalidTime(node.node_id));
        }
        if self.nodes.iter().any(|value| value.node_id == node.node_id) {
            return Err(GraphError::DuplicateNode(node.node_id));
        }
        self.nodes.push(node);
        Ok(())
    }

    pub fn add_edge(&mut self, edge: IoEdge) -> Result<(), GraphError> {
        if self.edges.iter().any(|value| value.edge_id == edge.edge_id) {
            return Err(GraphError::DuplicateEdge(edge.edge_id));
        }
        for node_id in [edge.from_node_id, edge.to_node_id] {
            if !self.nodes.iter().any(|value| value.node_id == node_id) {
                return Err(GraphError::MissingNode(node_id));
            }
        }
        let from = self
            .nodes
            .iter()
            .find(|value| value.node_id == edge.from_node_id)
            .expect("validated source node");
        let to = self
            .nodes
            .iter()
            .find(|value| value.node_id == edge.to_node_id)
            .expect("validated target node");
        if from.start_ts_ns > to.end_or_start() {
            return Err(GraphError::ReverseTime(edge.edge_id));
        }
        if edge.from_node_id == edge.to_node_id
            || self.reachable(edge.to_node_id, edge.from_node_id)
        {
            return Err(GraphError::Cycle);
        }
        self.edges.push(edge);
        Ok(())
    }

    fn reachable(&self, start: u64, target: u64) -> bool {
        let mut queue = VecDeque::from([start]);
        let mut seen = HashSet::new();
        while let Some(node) = queue.pop_front() {
            if node == target {
                return true;
            }
            if !seen.insert(node) {
                continue;
            }
            queue.extend(
                self.edges
                    .iter()
                    .filter(|edge| edge.from_node_id == node)
                    .map(|edge| edge.to_node_id),
            );
        }
        false
    }

    pub fn file_origins_for(&self, node_id: u64) -> Vec<FileOriginView> {
        let mut queue = VecDeque::from([(node_id, EdgeConfidence::Exact)]);
        let mut seen = HashSet::new();
        let mut origins = BTreeMap::<FileIdentity, FileOriginView>::new();
        while let Some((current, confidence)) = queue.pop_front() {
            if !seen.insert((current, confidence)) {
                continue;
            }
            if let Some(node) = self.nodes.iter().find(|node| node.node_id == current)
                && let Some(file) = &node.file
            {
                let candidate = FileOriginView {
                    file: file.clone(),
                    path: node.path.clone(),
                    confidence,
                };
                origins
                    .entry(file.clone())
                    .and_modify(|existing| {
                        if candidate.confidence.rank() > existing.confidence.rank() {
                            *existing = candidate.clone();
                        }
                    })
                    .or_insert(candidate);
            }
            for edge in self.edges.iter().filter(|edge| edge.to_node_id == current) {
                queue.push_back((edge.from_node_id, confidence.weakest(edge.confidence)));
            }
        }
        origins.into_values().collect()
    }

    pub fn metrics(&self) -> GraphMetrics {
        if self.nodes.is_empty() {
            return GraphMetrics::default();
        }
        let start_ts_ns = self
            .nodes
            .iter()
            .map(|node| node.start_ts_ns)
            .min()
            .unwrap_or_default();
        let end_ts_ns = self
            .nodes
            .iter()
            .map(IoNode::end_or_start)
            .max()
            .unwrap_or(start_ts_ns);
        let intervals: Vec<_> = self
            .nodes
            .iter()
            .filter(|node| node.additive())
            .map(|node| (node.start_ts_ns, node.end_or_start()))
            .collect();
        let accounted_ns = union_duration(&intervals);
        let mut exclusive_ns = BTreeMap::new();
        for node in &self.nodes {
            if !node.additive() {
                exclusive_ns.insert(node.node_id, 0);
                continue;
            }
            let end = node.end_or_start();
            let children: Vec<_> = self
                .edges
                .iter()
                .filter(|edge| edge.from_node_id == node.node_id)
                .filter_map(|edge| {
                    self.nodes
                        .iter()
                        .find(|child| child.node_id == edge.to_node_id)
                })
                .filter(|child| child.additive())
                .filter_map(|child| {
                    let start = child.start_ts_ns.max(node.start_ts_ns);
                    let child_end = child.end_or_start().min(end);
                    (child_end >= start).then_some((start, child_end))
                })
                .collect();
            exclusive_ns.insert(
                node.node_id,
                node.duration_ns().saturating_sub(union_duration(&children)),
            );
        }
        let (critical_path, critical_path_ns) = self.longest_path(&exclusive_ns);
        let total_ns = end_ts_ns.saturating_sub(start_ts_ns);
        GraphMetrics {
            start_ts_ns,
            end_ts_ns,
            total_ns,
            accounted_ns: accounted_ns.min(total_ns),
            unaccounted_ns: total_ns.saturating_sub(accounted_ns.min(total_ns)),
            exclusive_ns,
            critical_path,
            critical_path_ns,
            unaccounted: uncovered_intervals(start_ts_ns, end_ts_ns, &intervals),
        }
    }

    fn longest_path(&self, weights: &BTreeMap<u64, u64>) -> (Vec<u64>, u64) {
        let mut indegree = HashMap::<u64, usize>::new();
        for node in &self.nodes {
            indegree.insert(node.node_id, 0);
        }
        for edge in self
            .edges
            .iter()
            .filter(|edge| edge.confidence != EdgeConfidence::ContextOnly)
        {
            *indegree.entry(edge.to_node_id).or_default() += 1;
        }
        let mut queue: VecDeque<_> = indegree
            .iter()
            .filter_map(|(&id, &degree)| (degree == 0).then_some(id))
            .collect();
        let mut score = HashMap::<u64, u64>::new();
        let mut previous = HashMap::<u64, u64>::new();
        while let Some(id) = queue.pop_front() {
            let duration = weights.get(&id).copied().unwrap_or(0);
            score.entry(id).or_insert(duration);
            let base = score[&id];
            for edge in self.edges.iter().filter(|edge| {
                edge.from_node_id == id && edge.confidence != EdgeConfidence::ContextOnly
            }) {
                let child = weights.get(&edge.to_node_id).copied().unwrap_or(0);
                let candidate = base.saturating_add(child);
                if candidate > score.get(&edge.to_node_id).copied().unwrap_or(0) {
                    score.insert(edge.to_node_id, candidate);
                    previous.insert(edge.to_node_id, id);
                }
                if let Some(value) = indegree.get_mut(&edge.to_node_id) {
                    *value = value.saturating_sub(1);
                    if *value == 0 {
                        queue.push_back(edge.to_node_id);
                    }
                }
            }
        }
        let Some((&end, &value)) = score.iter().max_by_key(|(_, value)| *value) else {
            return (Vec::new(), 0);
        };
        let mut path = vec![end];
        let mut current = end;
        while let Some(&parent) = previous.get(&current) {
            path.push(parent);
            current = parent;
        }
        path.reverse();
        (path, value)
    }
}

/// A storage-stack layer. `KernelSpace` is intentionally not a value: it is a
/// visual container for VFS through UFS rather than an additive latency stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineLayer {
    Syscall,
    Vfs,
    Filesystem,
    PageCache,
    Writeback,
    Bio,
    BlockQueue,
    BlockDevice,
    Scsi,
    Ufs,
    UicContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelinePhase {
    Begin,
    End,
    Instant,
    Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationConfidence {
    Exact,
    Probable,
    ContextOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineObservation {
    pub ts_ns: u64,
    #[serde(default)]
    pub end_ts_ns: Option<u64>,
    pub phase: PipelinePhase,
    pub layer: PipelineLayer,
    #[serde(default)]
    pub correlation_id: Option<u64>,
    /// Stage-local command/tag identity. It can pair begin/end exactly inside
    /// one layer but does not by itself prove a block-request association.
    #[serde(default)]
    pub stage_key: Option<u64>,
    #[serde(default)]
    pub sector: Option<u64>,
    #[serde(default)]
    pub bytes: Option<u32>,
    #[serde(default)]
    pub opcode: Option<u32>,
    #[serde(default)]
    pub status: Option<i32>,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub tid: u32,
    pub name: String,
    pub confidence: CorrelationConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineSpan {
    pub layer: PipelineLayer,
    pub start_ts_ns: u64,
    pub end_ts_ns: u64,
    pub name: String,
    pub confidence: CorrelationConfidence,
    pub source: String,
    #[serde(default)]
    pub opcode: Option<u32>,
    #[serde(default)]
    pub status: Option<i32>,
}

impl PipelineSpan {
    pub fn duration_ns(&self) -> u64 {
        self.end_ts_ns.saturating_sub(self.start_ts_ns)
    }

    fn additive(&self) -> bool {
        self.confidence != CorrelationConfidence::ContextOnly
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IoPipeline {
    pub request_id: u64,
    pub start_ts_ns: u64,
    pub end_ts_ns: u64,
    pub accounted_ns: u64,
    pub unaccounted_ns: u64,
    pub spans: Vec<PipelineSpan>,
}

impl IoPipeline {
    pub fn total_ns(&self) -> u64 {
        self.end_ts_ns.saturating_sub(self.start_ts_ns)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum StorageEvent {
    BlockInsert(BlockInsert),
    BlockIssue(BlockIssue),
    BlockComplete(BlockComplete),
    FileIo(FileIo),
    Pipeline(PipelineObservation),
    Node(IoNode),
    Edge(IoEdge),
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
    #[serde(default)]
    pub scsi_events: Vec<String>,
    #[serde(default)]
    pub ext4_events: Vec<String>,
    #[serde(default)]
    pub vfs_probe_candidates: Vec<String>,
    #[serde(default)]
    pub pipeline_layers: Vec<PipelineLayer>,
    #[serde(default)]
    pub attach_plan: Vec<ProbePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbePlan {
    pub layer: PipelineLayer,
    pub probe_kind: String,
    pub group: String,
    pub event_or_function: String,
    pub state: CapabilityState,
    #[serde(default)]
    pub format_hash: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Measured,
    Derived,
    Context,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProbeHealth {
    pub emitted: u64,
    pub reserve_failures: u64,
    pub paired: u64,
    pub unpaired: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticRecord {
    pub schema_version: u16,
    pub ts_unix_ms: i64,
    pub level: DiagnosticLevel,
    pub component: String,
    pub event: String,
    pub session_id: String,
    #[serde(default)]
    pub boot_id: String,
    pub outcome: String,
    pub code: String,
    #[serde(default)]
    pub correlation_id: Option<u64>,
    #[serde(default)]
    pub node_id: Option<u64>,
    #[serde(default)]
    pub probe: Option<String>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub count: Option<u64>,
    #[serde(default)]
    pub detail: Option<String>,
}

impl DiagnosticRecord {
    pub fn bounded(mut self) -> Self {
        truncate_string(&mut self.component, 128);
        truncate_string(&mut self.event, 128);
        truncate_string(&mut self.session_id, 128);
        truncate_string(&mut self.boot_id, 128);
        truncate_string(&mut self.outcome, 64);
        truncate_string(&mut self.code, 128);
        if let Some(probe) = &mut self.probe {
            truncate_string(probe, 256);
        }
        if let Some(detail) = &mut self.detail
            && detail.len() > 4096
        {
            detail.truncate(detail.floor_char_boundary(4096));
        }
        self
    }
}

fn truncate_string(value: &mut String, limit: usize) {
    if value.len() > limit {
        value.truncate(value.floor_char_boundary(limit));
    }
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
        kernel_drops: Option<u64>,
        userspace_drops: u64,
        #[serde(default)]
        probe_health: BTreeMap<String, ProbeHealth>,
        #[serde(default)]
        correlation_ambiguous: u64,
        #[serde(default)]
        correlation_expired: u64,
        #[serde(default)]
        key_reused: u64,
    },
    Footer {
        schema_version: u16,
        events_seen: u64,
        events_persisted: u64,
        events_dropped: u64,
        events_rejected: u64,
        #[serde(default)]
        graceful: Option<bool>,
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
    pub integrity_ok: Option<bool>,
    pub graceful: Option<bool>,
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
                Ok(
                    record @ WireRecord::Footer {
                        events_seen,
                        events_persisted,
                        events_dropped,
                        events_rejected,
                        graceful,
                        ..
                    },
                ) => {
                    loaded.integrity_ok = Some(
                        events_seen
                            == events_persisted
                                .saturating_add(events_dropped)
                                .saturating_add(events_rejected),
                    );
                    loaded.graceful = graceful;
                    loaded.footer = Some(record);
                }
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
    #[serde(default)]
    pub attribution: AttributionSummary,
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

fn time_buckets(start_ts_ns: u64, end_ts_ns: u64) -> Vec<u64> {
    if end_ts_ns < start_ts_ns {
        return Vec::new();
    }
    let start = start_ts_ns / 1_000_000_000;
    let end = end_ts_ns / 1_000_000_000;
    let count = end.saturating_sub(start).saturating_add(1).min(121);
    (0..count).map(|offset| start + offset).collect()
}

fn request_time_buckets(io: &CompletedIo) -> Vec<u64> {
    let start = io
        .insert
        .as_ref()
        .map_or(io.issue.ts_ns, |insert| insert.ts_ns)
        .saturating_sub(10_000_000)
        / 1_000_000_000;
    let end = io.completion.ts_ns.saturating_add(10_000_000) / 1_000_000_000;
    (start..=end).collect()
}

fn request_cache_key(io: &CompletedIo) -> (u64, u64, u64) {
    (io.issue.request_id, io.issue.ts_ns, io.completion.ts_ns)
}

#[derive(Debug, Default)]
struct AnalysisIndex {
    files_by_pid_time: HashMap<(u32, u64), Vec<usize>>,
    files_by_tid_time: HashMap<(u32, u64), Vec<usize>>,
    long_files: Vec<usize>,
    observations_by_request: HashMap<u64, Vec<usize>>,
    observations_by_pid_time: HashMap<(u32, u64), Vec<usize>>,
    observations_by_sector_time: HashMap<(u64, u64), Vec<usize>>,
    context_observations_by_time: HashMap<u64, Vec<usize>>,
    long_observations: Vec<usize>,
    nodes_by_transaction: HashMap<u64, Vec<usize>>,
    edges_by_transaction: HashMap<u64, Vec<usize>>,
}

impl AnalysisIndex {
    fn build(engine: &AnalysisEngine) -> Self {
        let mut index = Self::default();
        for (position, file) in engine.file_ios.iter().enumerate() {
            let seconds = time_buckets(file.start_ts_ns, file.end_ts_ns);
            if seconds.len() > 120 {
                index.long_files.push(position);
                continue;
            }
            for second in seconds {
                index
                    .files_by_pid_time
                    .entry((file.pid, second))
                    .or_default()
                    .push(position);
                if file.tid != 0 {
                    index
                        .files_by_tid_time
                        .entry((file.tid, second))
                        .or_default()
                        .push(position);
                }
            }
        }
        for (position, observation) in engine.pipeline_observations.iter().enumerate() {
            if let Some(request_id) = observation.correlation_id {
                index
                    .observations_by_request
                    .entry(request_id)
                    .or_default()
                    .push(position);
            }
            let end_ts_ns = observation.end_ts_ns.unwrap_or(observation.ts_ns);
            let seconds = time_buckets(observation.ts_ns, end_ts_ns);
            if seconds.len() > 120 {
                index.long_observations.push(position);
                continue;
            }
            for second in seconds {
                index
                    .observations_by_pid_time
                    .entry((observation.pid, second))
                    .or_default()
                    .push(position);
                if let Some(sector) = observation.sector {
                    index
                        .observations_by_sector_time
                        .entry((sector, second))
                        .or_default()
                        .push(position);
                }
                if observation.confidence == CorrelationConfidence::ContextOnly {
                    index
                        .context_observations_by_time
                        .entry(second)
                        .or_default()
                        .push(position);
                }
            }
        }
        for (position, node) in engine.graph_nodes.iter().enumerate() {
            if let Some(transaction_id) = node.transaction_id {
                index
                    .nodes_by_transaction
                    .entry(transaction_id)
                    .or_default()
                    .push(position);
            }
        }
        for (position, edge) in engine.graph_edges.iter().enumerate() {
            if let Some(transaction_id) = edge.transaction_id {
                index
                    .edges_by_transaction
                    .entry(transaction_id)
                    .or_default()
                    .push(position);
            }
        }
        index
    }
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
    pipeline_observations: Vec<PipelineObservation>,
    pending_pipeline: HashMap<(PipelineLayer, u64, String), PipelineObservation>,
    ambiguous_pipeline: HashMap<(PipelineLayer, u64, String), u64>,
    graph_nodes: Vec<IoNode>,
    graph_edges: Vec<IoEdge>,
    summary_cache: RefCell<Option<AnalysisSummary>>,
    pipeline_cache: RefCell<HashMap<(u64, u64, u64), IoPipeline>>,
    transaction_cache: RefCell<HashMap<(u64, u64, u64), IoTransactionGraph>>,
    analysis_index: RefCell<Option<AnalysisIndex>>,
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
            pipeline_observations: Vec::new(),
            pending_pipeline: HashMap::new(),
            ambiguous_pipeline: HashMap::new(),
            graph_nodes: Vec::new(),
            graph_edges: Vec::new(),
            summary_cache: RefCell::new(None),
            pipeline_cache: RefCell::new(HashMap::new()),
            transaction_cache: RefCell::new(HashMap::new()),
            analysis_index: RefCell::new(None),
        }
    }

    pub fn ingest(&mut self, event: StorageEvent) -> Option<CompletedIo> {
        self.summary_cache.get_mut().take();
        if matches!(
            &event,
            StorageEvent::FileIo(_)
                | StorageEvent::Pipeline(_)
                | StorageEvent::Node(_)
                | StorageEvent::Edge(_)
        ) {
            self.pipeline_cache.get_mut().clear();
            self.transaction_cache.get_mut().clear();
            self.analysis_index.get_mut().take();
        }
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
                if file.end_ts_ns >= file.start_ts_ns {
                    self.pipeline_observations.push(PipelineObservation {
                        ts_ns: file.start_ts_ns,
                        end_ts_ns: Some(file.end_ts_ns),
                        phase: PipelinePhase::Span,
                        layer: PipelineLayer::Syscall,
                        correlation_id: None,
                        stage_key: None,
                        sector: None,
                        bytes: u32::try_from(file.requested_bytes).ok(),
                        opcode: None,
                        status: None,
                        pid: file.pid,
                        tid: file.tid,
                        name: format!("{:?} fd {}", file.operation, file.fd),
                        confidence: CorrelationConfidence::Probable,
                    });
                }
                self.file_ios.push(file);
                None
            }
            StorageEvent::Pipeline(observation) => {
                self.observe_ts(observation.ts_ns);
                if let Some(end) = observation.end_ts_ns {
                    self.observe_ts(end);
                }
                let key = observation
                    .correlation_id
                    .or(observation.stage_key)
                    .map(|id| (observation.layer, id, observation.name.clone()));
                match (observation.phase, key) {
                    (PipelinePhase::Begin, Some(key)) => {
                        if self.pending_pipeline.remove(&key).is_some() {
                            self.ambiguous_pipeline.insert(key, observation.ts_ns);
                        } else if !self.ambiguous_pipeline.contains_key(&key) {
                            self.pending_pipeline.insert(key, observation);
                        }
                    }
                    (PipelinePhase::End, Some(key)) => {
                        if self.ambiguous_pipeline.remove(&key).is_some() {
                            self.pending_pipeline.remove(&key);
                            return None;
                        }
                        if let Some(begin) = self.pending_pipeline.remove(&key)
                            && observation.ts_ns >= begin.ts_ns
                        {
                            bounded_push(
                                &mut self.pipeline_observations,
                                PipelineObservation {
                                    ts_ns: begin.ts_ns,
                                    end_ts_ns: Some(observation.ts_ns),
                                    phase: PipelinePhase::Span,
                                    layer: begin.layer,
                                    correlation_id: begin.correlation_id,
                                    stage_key: begin.stage_key,
                                    sector: begin.sector.or(observation.sector),
                                    bytes: begin.bytes.or(observation.bytes),
                                    opcode: begin.opcode.or(observation.opcode),
                                    status: observation.status.or(begin.status),
                                    pid: begin.pid,
                                    tid: begin.tid,
                                    name: begin.name,
                                    confidence: begin.confidence,
                                },
                            );
                        }
                    }
                    _ => bounded_push(&mut self.pipeline_observations, observation),
                }
                let newest = self.last_ts_ns.unwrap_or_default();
                self.pending_pipeline
                    .retain(|_, begin| newest.saturating_sub(begin.ts_ns) <= 30_000_000_000);
                self.ambiguous_pipeline.retain(|_, observed_ts_ns| {
                    newest.saturating_sub(*observed_ts_ns) <= 30_000_000_000
                });
                None
            }
            StorageEvent::Node(node) => {
                self.observe_ts(node.start_ts_ns);
                self.observe_ts(node.end_or_start());
                bounded_push(&mut self.graph_nodes, node);
                None
            }
            StorageEvent::Edge(edge) => {
                bounded_push(&mut self.graph_edges, edge);
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
        if let Some(summary) = self.summary_cache.borrow().as_ref() {
            return summary.clone();
        }
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
        for io in &self.completed {
            let graph = self.transaction_for(io);
            let Some(request) = graph
                .nodes
                .iter()
                .find(|node| node.kind == IoNodeKind::BlockRequest)
            else {
                summary.attribution.unattributed += 1;
                continue;
            };
            let origins = graph.file_origins_for(request.node_id);
            if origins.len() > 1 {
                summary.attribution.multi_origin += 1;
            }
            match origins
                .iter()
                .map(|origin| origin.confidence)
                .max_by_key(|confidence| confidence.rank())
            {
                Some(EdgeConfidence::Exact) => summary.attribution.exact += 1,
                Some(EdgeConfidence::Probable) => summary.attribution.probable += 1,
                Some(EdgeConfidence::ProbableAsync) => summary.attribution.probable_async += 1,
                Some(EdgeConfidence::ContextOnly) | None => summary.attribution.unattributed += 1,
            }
        }
        *self.summary_cache.borrow_mut() = Some(summary.clone());
        summary
    }

    pub fn completed_ios(&self) -> &[CompletedIo] {
        &self.completed
    }
    pub fn file_ios(&self) -> &[FileIo] {
        &self.file_ios
    }

    pub fn pipeline_observations(&self) -> &[PipelineObservation] {
        &self.pipeline_observations
    }

    pub fn pipeline_for(&self, io: &CompletedIo) -> IoPipeline {
        let cache_key = request_cache_key(io);
        if let Some(pipeline) = self.pipeline_cache.borrow().get(&cache_key) {
            return pipeline.clone();
        }
        if self.analysis_index.borrow().is_none() {
            *self.analysis_index.borrow_mut() = Some(AnalysisIndex::build(self));
        }
        let index = self.analysis_index.borrow();
        let index = index.as_ref().expect("analysis index is initialized");
        let mut positions = index.long_observations.clone();
        if let Some(candidates) = index.observations_by_request.get(&io.issue.request_id) {
            positions.extend_from_slice(candidates);
        }
        for second in request_time_buckets(io) {
            for candidates in [
                index.observations_by_pid_time.get(&(io.issue.pid, second)),
                index
                    .observations_by_sector_time
                    .get(&(io.issue.sector, second)),
                index.context_observations_by_time.get(&second),
            ]
            .into_iter()
            .flatten()
            {
                positions.extend_from_slice(candidates);
            }
        }
        positions.sort_unstable();
        positions.dedup();
        let observations: Vec<_> = positions
            .into_iter()
            .map(|position| self.pipeline_observations[position].clone())
            .collect();
        drop(index);
        let pipeline = build_io_pipeline(io, &observations);
        let mut cache = self.pipeline_cache.borrow_mut();
        if cache.len() >= MAX_DERIVED_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(cache_key, pipeline.clone());
        pipeline
    }

    pub fn transaction_for(&self, io: &CompletedIo) -> IoTransactionGraph {
        let cache_key = request_cache_key(io);
        if let Some(graph) = self.transaction_cache.borrow().get(&cache_key) {
            return graph.clone();
        }
        if self.analysis_index.borrow().is_none() {
            *self.analysis_index.borrow_mut() = Some(AnalysisIndex::build(self));
        }
        let index = self.analysis_index.borrow();
        let index = index.as_ref().expect("analysis index is initialized");
        let mut file_positions = index.long_files.clone();
        for second in request_time_buckets(io) {
            if let Some(positions) = index.files_by_pid_time.get(&(io.issue.pid, second)) {
                file_positions.extend_from_slice(positions);
            }
            if let Some(positions) = index.files_by_tid_time.get(&(io.issue.tid, second)) {
                file_positions.extend_from_slice(positions);
            }
        }
        file_positions.sort_unstable();
        file_positions.dedup();
        let files: Vec<_> = file_positions
            .into_iter()
            .map(|position| self.file_ios[position].clone())
            .collect();

        let mut observation_positions = index.long_observations.clone();
        if let Some(positions) = index.observations_by_request.get(&io.issue.request_id) {
            observation_positions.extend_from_slice(positions);
        }
        for second in request_time_buckets(io) {
            for positions in [
                index.observations_by_pid_time.get(&(io.issue.pid, second)),
                index
                    .observations_by_sector_time
                    .get(&(io.issue.sector, second)),
                index.context_observations_by_time.get(&second),
            ]
            .into_iter()
            .flatten()
            {
                observation_positions.extend_from_slice(positions);
            }
        }
        observation_positions.sort_unstable();
        observation_positions.dedup();
        let observations: Vec<_> = observation_positions
            .into_iter()
            .map(|position| self.pipeline_observations[position].clone())
            .collect();
        let nodes: Vec<_> = index
            .nodes_by_transaction
            .get(&io.issue.request_id)
            .into_iter()
            .flatten()
            .map(|&position| self.graph_nodes[position].clone())
            .collect();
        let edges: Vec<_> = index
            .edges_by_transaction
            .get(&io.issue.request_id)
            .into_iter()
            .flatten()
            .map(|&position| self.graph_edges[position].clone())
            .collect();
        drop(index);
        let graph = build_transaction_graph(io, &files, &observations, &nodes, &edges);
        let mut cache = self.transaction_cache.borrow_mut();
        if cache.len() >= MAX_DERIVED_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(cache_key, graph.clone());
        graph
    }

    pub fn transactions(&self) -> Vec<IoTransactionGraph> {
        self.completed
            .iter()
            .map(|io| self.transaction_for(io))
            .collect()
    }

    /// Explains only a measured positive stage delta against requests in the
    /// same operation/access/size cohort. Returning `None` is preferable to a
    /// cause claim with insufficient evidence.
    pub fn why_slow(&self, selected: &CompletedIo) -> Option<SlowReason> {
        let selected_graph = self.transaction_for(selected);
        let selected_durations = durations_by_kind(&selected_graph);
        let cohort: Vec<_> = self
            .completed
            .iter()
            .filter(|io| {
                io.issue.operation == selected.issue.operation
                    && io.access_pattern == selected.access_pattern
                    && io.size_class == selected.size_class
            })
            .collect();
        if cohort.len() < 3 {
            return None;
        }
        let cohort = evenly_sample_refs(&cohort, MAX_RCA_COHORT_SAMPLES);
        let cohort_durations: Vec<_> = cohort
            .iter()
            .map(|io| durations_by_kind(&self.transaction_for(io)))
            .collect();
        let mut best: Option<SlowReason> = None;
        for (&kind, &selected_ns) in &selected_durations {
            let mut values: Vec<_> = cohort_durations
                .iter()
                .map(|durations| durations.get(&kind).copied().unwrap_or(0))
                .collect();
            values.sort_unstable();
            let median = percentile(&values, 50).unwrap_or(0);
            let delta = selected_ns.saturating_sub(median);
            if delta == 0 || best.as_ref().is_some_and(|value| value.delta_ns >= delta) {
                continue;
            }
            let confidence = selected_graph
                .edges
                .iter()
                .filter(|edge| {
                    selected_graph.nodes.iter().any(|node| {
                        node.kind == kind
                            && (node.node_id == edge.from_node_id
                                || node.node_id == edge.to_node_id)
                    })
                })
                .map(|edge| edge.confidence)
                .min_by_key(|confidence| confidence.rank())
                .unwrap_or(EdgeConfidence::Exact);
            best = Some(SlowReason {
                node_kind: kind,
                stage: format!("{kind:?}"),
                selected_ns,
                cohort_median_ns: median,
                delta_ns: delta,
                confidence,
                cohort_samples: cohort_durations.len(),
            });
        }
        best
    }

    pub fn pipelines(&self) -> Vec<IoPipeline> {
        self.completed
            .iter()
            .map(|io| self.pipeline_for(io))
            .collect()
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

fn durations_by_kind(graph: &IoTransactionGraph) -> BTreeMap<IoNodeKind, u64> {
    let mut intervals = BTreeMap::<IoNodeKind, Vec<(u64, u64)>>::new();
    for node in graph.nodes.iter().filter(|node| node.additive()) {
        intervals
            .entry(node.kind)
            .or_default()
            .push((node.start_ts_ns, node.end_or_start()));
    }
    intervals
        .into_iter()
        .map(|(kind, values)| (kind, union_duration(&values)))
        .collect()
}

fn bounded_push<T>(values: &mut Vec<T>, value: T) {
    if values.len() == MAX_ANALYSIS_SAMPLES {
        values.drain(..MAX_ANALYSIS_SAMPLES / 10);
    }
    values.push(value);
}

fn synthetic_node_id(tag: u8, request_id: u64) -> u64 {
    request_id.rotate_left(17) ^ ((tag as u64) << 56) ^ 0x9e37_79b9_7f4a_7c15
}

fn pipeline_node_kind(layer: PipelineLayer) -> IoNodeKind {
    match layer {
        PipelineLayer::Syscall => IoNodeKind::Syscall,
        PipelineLayer::Vfs => IoNodeKind::Vfs,
        PipelineLayer::Filesystem => IoNodeKind::Filesystem,
        PipelineLayer::PageCache => IoNodeKind::PageCache,
        PipelineLayer::Writeback => IoNodeKind::Writeback,
        PipelineLayer::Bio => IoNodeKind::Bio,
        PipelineLayer::BlockQueue => IoNodeKind::BlockQueue,
        PipelineLayer::BlockDevice => IoNodeKind::BlockRequest,
        PipelineLayer::Scsi => IoNodeKind::ScsiCommand,
        PipelineLayer::Ufs => IoNodeKind::UfsCommand,
        PipelineLayer::UicContext => IoNodeKind::UicContext,
    }
}

/// Builds a direction-preserving graph for one completed block request. Legacy
/// v1-v3 observations are promoted to nodes without fabricating direct keys.
pub fn build_transaction_graph(
    io: &CompletedIo,
    files: &[FileIo],
    observations: &[PipelineObservation],
    raw_nodes: &[IoNode],
    raw_edges: &[IoEdge],
) -> IoTransactionGraph {
    let request_id = io.issue.request_id;
    let block_start = io.insert.as_ref().map_or(io.issue.ts_ns, |item| item.ts_ns);
    let block_end = io.completion.ts_ns;
    let mut graph = IoTransactionGraph::new(request_id);
    let request_node_id = synthetic_node_id(9, request_id);
    let mut queue_id = None;
    let _ = graph.add_node(IoNode {
        node_id: request_node_id,
        transaction_id: Some(request_id),
        kind: IoNodeKind::BlockRequest,
        start_ts_ns: io.issue.ts_ns,
        end_ts_ns: Some(block_end),
        origin: IoOrigin::Unknown,
        file: None,
        path: None,
        operation: Some(io.issue.operation),
        bytes: Some(io.issue.bytes as u64),
        pid: io.issue.pid,
        tid: io.issue.tid,
        name: format!("block request {request_id}"),
    });
    if let Some(insert) = &io.insert {
        let queue_node_id = synthetic_node_id(8, request_id);
        queue_id = Some(queue_node_id);
        let _ = graph.add_node(IoNode {
            node_id: queue_node_id,
            transaction_id: Some(request_id),
            kind: IoNodeKind::BlockQueue,
            start_ts_ns: insert.ts_ns,
            end_ts_ns: Some(io.issue.ts_ns),
            origin: IoOrigin::Unknown,
            file: None,
            path: None,
            operation: Some(io.issue.operation),
            bytes: Some(io.issue.bytes as u64),
            pid: io.issue.pid,
            tid: io.issue.tid,
            name: "block queue".into(),
        });
        let _ = graph.add_edge(IoEdge::exact(
            synthetic_node_id(18, request_id),
            queue_node_id,
            request_node_id,
            IoRelation::Dispatches,
        ));
    }

    let probable_window_start = block_start.saturating_sub(10_000_000);
    let probable_window_end = block_end.saturating_add(10_000_000);
    let file_candidates: Vec<_> = files
        .iter()
        .filter(|file| file.operation == io.issue.operation)
        .filter(|file| {
            file.start_ts_ns <= probable_window_end && file.end_ts_ns >= probable_window_start
        })
        .filter(|file| {
            file.requested_bytes >= io.issue.bytes as u64
                || file.completed_bytes.unsigned_abs() >= io.issue.bytes as u64
        })
        .filter(|file| file.pid == io.issue.pid || (file.tid != 0 && file.tid == io.issue.tid))
        .collect();
    if file_candidates.len() == 1 {
        let file = file_candidates[0];
        let file_node_id = file
            .node_id
            .unwrap_or_else(|| synthetic_node_id(1, request_id));
        let snapshot = file.path_snapshot.clone().or_else(|| {
            file.path.clone().map(|path| PathSnapshot {
                deleted: path.ends_with(" (deleted)"),
                path: Some(path),
                source: PathSource::ProcFd,
                captured_ts_ns: file.end_ts_ns,
            })
        });
        if graph
            .add_node(IoNode {
                node_id: file_node_id,
                transaction_id: Some(request_id),
                kind: IoNodeKind::FileOperation,
                start_ts_ns: file.start_ts_ns,
                end_ts_ns: Some(file.end_ts_ns),
                origin: IoOrigin::File,
                file: file.file_identity.clone(),
                path: snapshot,
                operation: Some(file.operation),
                bytes: Some(file.requested_bytes),
                pid: file.pid,
                tid: file.tid,
                name: file
                    .path
                    .clone()
                    .unwrap_or_else(|| format!("fd {}", file.fd)),
            })
            .is_ok()
        {
            let delta_ns = block_start.saturating_sub(file.start_ts_ns);
            let _ = graph.add_edge(IoEdge {
                edge_id: synthetic_node_id(19, request_id),
                transaction_id: Some(request_id),
                from_node_id: file_node_id,
                to_node_id: request_node_id,
                relation: if file.io_mode == FileIoMode::Buffered && block_start > file.end_ts_ns {
                    IoRelation::CausesAsync
                } else {
                    IoRelation::Submits
                },
                confidence: if file.io_mode == FileIoMode::Buffered && block_start > file.end_ts_ns
                {
                    EdgeConfidence::ProbableAsync
                } else {
                    EdgeConfidence::Probable
                },
                evidence: vec![CorrelationEvidence {
                    match_type: "unique_time_task_operation".into(),
                    opaque_key: None,
                    delta_ns: Some(delta_ns),
                    candidate_count: 1,
                    sector_match: false,
                    bytes_match: file.requested_bytes == io.issue.bytes as u64,
                    task_match: true,
                }],
            });
        }
    }

    let pipeline = build_io_pipeline(io, observations);
    let mut upper_prior = None;
    let mut upper_last = None;
    let mut lower_prior = None;
    let mut lower_first = None;
    for (index, span) in pipeline
        .spans
        .iter()
        .filter(|span| {
            !matches!(
                span.layer,
                PipelineLayer::BlockQueue | PipelineLayer::BlockDevice
            )
        })
        .enumerate()
    {
        let confidence = match span.confidence {
            CorrelationConfidence::Exact => EdgeConfidence::Exact,
            CorrelationConfidence::Probable => EdgeConfidence::Probable,
            CorrelationConfidence::ContextOnly => EdgeConfidence::ContextOnly,
        };
        let node_id = synthetic_node_id(32_u8.saturating_add(index as u8), request_id);
        if graph
            .add_node(IoNode {
                node_id,
                transaction_id: Some(request_id),
                kind: pipeline_node_kind(span.layer),
                start_ts_ns: span.start_ts_ns,
                end_ts_ns: Some(span.end_ts_ns),
                origin: IoOrigin::Unknown,
                file: None,
                path: None,
                operation: Some(io.issue.operation),
                bytes: Some(io.issue.bytes as u64),
                pid: io.issue.pid,
                tid: io.issue.tid,
                name: span.name.clone(),
            })
            .is_ok()
        {
            let upper = span.layer <= PipelineLayer::Bio;
            let prior = if upper { upper_prior } else { lower_prior };
            if let Some(parent) = prior {
                let _ = graph.add_edge(IoEdge {
                    edge_id: synthetic_node_id(64_u8.saturating_add(index as u8), request_id),
                    transaction_id: Some(request_id),
                    from_node_id: parent,
                    to_node_id: node_id,
                    relation: if confidence == EdgeConfidence::ContextOnly {
                        IoRelation::ContextFor
                    } else {
                        IoRelation::Calls
                    },
                    confidence,
                    evidence: Vec::new(),
                });
            }
            if upper {
                upper_prior = Some(node_id);
                upper_last = Some((node_id, confidence));
            } else {
                lower_first.get_or_insert((node_id, confidence));
                lower_prior = Some(node_id);
            }
        }
    }
    if let Some((node_id, confidence)) = upper_last {
        let _ = graph.add_edge(IoEdge {
            edge_id: synthetic_node_id(90, request_id),
            transaction_id: Some(request_id),
            from_node_id: node_id,
            to_node_id: queue_id.unwrap_or(request_node_id),
            relation: IoRelation::Submits,
            confidence,
            evidence: Vec::new(),
        });
    }
    if let Some((node_id, confidence)) = lower_first {
        let _ = graph.add_edge(IoEdge {
            edge_id: synthetic_node_id(91, request_id),
            transaction_id: Some(request_id),
            from_node_id: request_node_id,
            to_node_id: node_id,
            relation: if confidence == EdgeConfidence::ContextOnly {
                IoRelation::ContextFor
            } else {
                IoRelation::Dispatches
            },
            confidence,
            evidence: Vec::new(),
        });
    }

    for node in raw_nodes {
        if node.transaction_id == Some(request_id) {
            let _ = graph.add_node(node.clone());
        }
    }
    for edge in raw_edges {
        if edge.transaction_id == Some(request_id)
            && graph
                .nodes
                .iter()
                .any(|node| node.node_id == edge.from_node_id)
            && graph
                .nodes
                .iter()
                .any(|node| node.node_id == edge.to_node_id)
        {
            let _ = graph.add_edge(edge.clone());
        }
    }
    graph
}

/// Builds a bounded request view from measured observations. Nested spans are
/// retained for the waterfall, while accounting uses their clipped union.
pub fn build_io_pipeline(io: &CompletedIo, observations: &[PipelineObservation]) -> IoPipeline {
    let block_start = io
        .insert
        .as_ref()
        .map_or(io.issue.ts_ns, |value| value.ts_ns);
    let block_end = io.completion.ts_ns;
    let request_id = io.issue.request_id;
    let probable_window_start = block_start.saturating_sub(10_000_000);
    let probable_window_end = block_end.saturating_add(10_000_000);

    let mut candidates: Vec<&PipelineObservation> = observations
        .iter()
        .filter(|value| {
            let end = value.end_ts_ns.unwrap_or(value.ts_ns);
            if end < value.ts_ns {
                return false;
            }
            let exact = value.correlation_id == Some(request_id);
            if exact {
                return true;
            }
            let overlaps = value.ts_ns <= probable_window_end && end >= probable_window_start;
            let storage_match = value.sector.is_some_and(|sector| sector == io.issue.sector)
                && value.bytes.is_some_and(|bytes| bytes == io.issue.bytes);
            let thread_match =
                value.pid == io.issue.pid && (value.tid == 0 || value.tid == io.issue.tid);
            overlaps
                && (value.confidence == CorrelationConfidence::ContextOnly
                    || storage_match
                    || thread_match)
        })
        .collect();

    // When an exact observation exists for a layer, probable candidates for the
    // same layer are deliberately excluded to avoid ambiguous duplicate bars.
    let exact_layers: std::collections::HashSet<_> = candidates
        .iter()
        .filter(|value| value.correlation_id == Some(request_id))
        .map(|value| value.layer)
        .collect();
    candidates.retain(|value| {
        value.correlation_id == Some(request_id) || !exact_layers.contains(&value.layer)
    });

    let mut spans: Vec<PipelineSpan> = candidates
        .into_iter()
        .filter_map(|value| {
            let end = value.end_ts_ns.unwrap_or(value.ts_ns);
            (end >= value.ts_ns).then(|| PipelineSpan {
                layer: value.layer,
                start_ts_ns: value.ts_ns,
                end_ts_ns: end,
                name: value.name.clone(),
                confidence: if value.correlation_id == Some(request_id)
                    && value.confidence != CorrelationConfidence::ContextOnly
                {
                    CorrelationConfidence::Exact
                } else if value.confidence == CorrelationConfidence::Exact {
                    // A tag/pointer may pair the lower-layer span exactly, but
                    // the edge to this block request is still field-derived.
                    CorrelationConfidence::Probable
                } else {
                    value.confidence
                },
                source: match value.phase {
                    PipelinePhase::Span => "measured span",
                    PipelinePhase::Begin | PipelinePhase::End => "paired boundary",
                    PipelinePhase::Instant => "context marker",
                }
                .into(),
                opcode: value.opcode,
                status: value.status,
            })
        })
        .collect();

    if let Some(insert) = &io.insert {
        spans.push(PipelineSpan {
            layer: PipelineLayer::BlockQueue,
            start_ts_ns: insert.ts_ns,
            end_ts_ns: io.issue.ts_ns,
            name: "block queue".into(),
            confidence: CorrelationConfidence::Exact,
            source: "block_rq_insert → block_rq_issue".into(),
            opcode: None,
            status: None,
        });
    }
    spans.push(PipelineSpan {
        layer: PipelineLayer::BlockDevice,
        start_ts_ns: io.issue.ts_ns,
        end_ts_ns: io.completion.ts_ns,
        name: "block device".into(),
        confidence: CorrelationConfidence::Exact,
        source: "block_rq_issue → block_rq_complete".into(),
        opcode: None,
        status: Some(io.completion.status),
    });

    let start_ts_ns = spans
        .iter()
        .filter(|span| span.confidence == CorrelationConfidence::Exact)
        .map(|span| span.start_ts_ns)
        .min()
        .unwrap_or(block_start)
        .min(block_start);
    let end_ts_ns = spans
        .iter()
        .filter(|span| span.confidence == CorrelationConfidence::Exact)
        .map(|span| span.end_ts_ns)
        .max()
        .unwrap_or(block_end)
        .max(block_end);
    spans.sort_by_key(|span| (span.layer, span.start_ts_ns, span.end_ts_ns));

    let additive: Vec<_> = spans
        .iter()
        .filter(|span| span.additive())
        .filter_map(|span| {
            let start = span.start_ts_ns.max(start_ts_ns);
            let end = span.end_ts_ns.min(end_ts_ns);
            (end >= start).then_some((start, end))
        })
        .collect();
    let total_ns = end_ts_ns.saturating_sub(start_ts_ns);
    let accounted_ns = union_duration(&additive).min(total_ns);
    IoPipeline {
        request_id,
        start_ts_ns,
        end_ts_ns,
        accounted_ns,
        unaccounted_ns: total_ns.saturating_sub(accounted_ns),
        spans,
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

fn evenly_sample_refs<'a, T>(values: &[&'a T], limit: usize) -> Vec<&'a T> {
    if values.len() <= limit {
        return values.to_vec();
    }
    (0..limit)
        .map(|index| values[index * values.len() / limit])
        .collect()
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

fn uncovered_intervals(
    bounds_start: u64,
    bounds_end: u64,
    intervals: &[(u64, u64)],
) -> Vec<UnaccountedInterval> {
    let mut values: Vec<_> = intervals
        .iter()
        .map(|&(start, end)| (start.max(bounds_start), end.min(bounds_end)))
        .filter(|(start, end)| end > start)
        .collect();
    values.sort_unstable();
    let mut result = Vec::new();
    let mut cursor = bounds_start;
    for (start, end) in values {
        if start > cursor {
            result.push(UnaccountedInterval {
                start_ts_ns: cursor,
                end_ts_ns: start,
                reason: UnaccountedReason::Unknown,
            });
        }
        cursor = cursor.max(end);
    }
    if cursor < bounds_end {
        result.push(UnaccountedInterval {
            start_ts_ns: cursor,
            end_ts_ns: bounds_end,
            reason: UnaccountedReason::Unknown,
        });
    }
    result
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
