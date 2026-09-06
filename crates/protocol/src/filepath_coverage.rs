//! Whole-source FilePath classification. Run on the persistence/replay worker,
//! never on the render thread. Detail-window eviction does not apply here.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilePathConfidence {
    Exact,
    Probable,
    Unresolved,
}

impl FilePathConfidence {
    /// Every contributing origin needs both a path and causal evidence. One
    /// resolved candidate cannot conceal another missing/context-only candidate.
    pub fn from_origins(origins: &[FileOriginView]) -> Self {
        if origins.is_empty()
            || origins.iter().any(|origin| {
                origin.incomplete
                    || origin
                        .path
                        .as_ref()
                        .and_then(|p| p.path.as_deref())
                        .is_none_or(str::is_empty)
                    || origin.confidence == EdgeConfidence::ContextOnly
            })
        {
            Self::Unresolved
        } else if origins
            .iter()
            .all(|v| v.confidence == EdgeConfidence::Exact)
        {
            Self::Exact
        } else {
            Self::Probable
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoverageVolume {
    pub count: u64,
    /// Sum of known request bytes, never an estimate of missing volume.
    pub known_bytes: u64,
}

impl CoverageVolume {
    fn observe(&mut self, bytes: u64) {
        self.count += 1;
        self.known_bytes += bytes;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FilePathCoverage {
    pub exact: CoverageVolume,
    pub probable: CoverageVolume,
    pub unresolved: CoverageVolume,
    /// Overlaps the confidence rows; never add it to their denominator.
    pub multi_origin: CoverageVolume,
    /// Included in Unresolved/count denominator; their bytes are unavailable.
    pub unmatched_completions: u64,
    /// Issue event count minus paired completions; not a queue-depth estimate.
    pub issue_events_without_completion: u64,
    /// Disjoint unresolved reasons, each measured in completion records.
    pub no_origin: u64,
    pub missing_path: u64,
    pub context_only: u64,
    pub incomplete_origin_set: u64,
    pub observation_without_file_identity: u64,
}

impl FilePathCoverage {
    /// All observed block completion records, including unpaired completions.
    /// Lost/suppressed events and pending issues cannot be assigned FilePaths.
    pub fn completion_records(&self) -> u64 {
        self.exact.count + self.probable.count + self.unresolved.count
    }

    pub fn known_bytes(&self) -> u64 {
        self.exact.known_bytes + self.probable.known_bytes + self.unresolved.known_bytes
    }

    fn observe(&mut self, io: &CompletedIo, origins: &[FileOriginView]) {
        let bytes = u64::from(io.issue.bytes);
        if origins.len() > 1 {
            self.multi_origin.observe(bytes);
        }
        match FilePathConfidence::from_origins(origins) {
            FilePathConfidence::Exact => self.exact.observe(bytes),
            FilePathConfidence::Probable => self.probable.observe(bytes),
            FilePathConfidence::Unresolved => {
                self.unresolved.observe(bytes);
                if io.evidence.is_some() {
                    self.observation_without_file_identity += 1;
                } else if origins.is_empty() {
                    self.no_origin += 1;
                } else if origins.iter().any(|v| v.incomplete) {
                    self.incomplete_origin_set += 1;
                } else if origins.iter().any(|v| {
                    v.path
                        .as_ref()
                        .and_then(|p| p.path.as_deref())
                        .is_none_or(str::is_empty)
                }) {
                    self.missing_path += 1;
                } else {
                    self.context_only += 1;
                }
            }
        }
    }
}

/// Keeps root request lifetimes and attribution evidence until the source ends,
/// so evidence arriving after detail eviction still changes the final result.
/// Perfetto observations cannot join root identities and reduce immediately to
/// counters; their large raw payloads are not retained by this worker.
#[derive(Debug)]
pub struct FilePathCoverageEngine {
    engine: AnalysisEngine,
    coverage: FilePathCoverage,
}

impl Default for FilePathCoverageEngine {
    fn default() -> Self {
        let mut engine = AnalysisEngine::new();
        engine.retain_all_evidence = true;
        Self {
            engine,
            coverage: FilePathCoverage::default(),
        }
    }
}

impl FilePathCoverageEngine {
    pub fn ingest(&mut self, event: &StorageEvent) {
        if let StorageEvent::ObservedBlockCompletion(io) = event
            && io.evidence.is_some()
        {
            self.coverage.observe(io, &[]);
            return;
        }
        self.engine.ingest(event.clone());
    }

    pub fn finish(self) -> FilePathCoverage {
        // Infallible callback for callers that do not expose cancellation.
        self.finish_with(|| Ok::<(), std::convert::Infallible>(()))
            .unwrap()
    }

    pub fn finish_with<E>(
        mut self,
        mut check: impl FnMut() -> Result<(), E>,
    ) -> Result<FilePathCoverage, E> {
        for io in self.engine.completed_ios() {
            check()?;
            let graph = self.engine.transaction_for(io);
            let origins = graph.file_origins_for(block_request_node_id(io.issue.request_id));
            self.coverage.observe(io, &origins);
        }
        let unmatched = self.engine.summary.uncorrelated_completions;
        self.coverage.unmatched_completions = unmatched;
        self.coverage.unresolved.count += unmatched;
        self.coverage.issue_events_without_completion = self
            .engine
            .summary
            .issued_ios
            .saturating_sub(self.engine.summary.completed_ios);
        Ok(self.coverage)
    }
}
