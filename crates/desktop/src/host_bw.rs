//! Host bandwidth has a completion-counted numerator and a device-wide clock.
//! Activity is collected before UI filters and detail-window eviction. Unknown
//! coverage never converts an unobserved gap into measured device idle.
use android_ebpf_protocol::{CompletedIo, IoOperation, WireRecord};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type Device = (u32, u32);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceCoverage {
    pub device: Device,
    pub completions: u64,
    pub unresolved: u64,
    pub unmatched: u64,
    pub requeues: u64,
}

#[derive(Debug, Clone, Default)]
pub struct IntervalUnion(BTreeMap<u64, u64>);
impl IntervalUnion {
    pub fn insert(&mut self, mut start: u64, mut end: u64) {
        if start >= end {
            return;
        }
        if let Some((&a, &b)) = self.0.range(..=start).next_back()
            && b >= start
        {
            start = a;
            end = end.max(b);
            self.0.remove(&a);
        }
        while let Some((&a, &b)) = self.0.range(start..=end).next() {
            end = end.max(b);
            self.0.remove(&a);
        }
        self.0.insert(start, end);
    }
    pub fn clipped(&self, start: u64, end: u64) -> impl Iterator<Item = (u64, u64)> + '_ {
        let first = self
            .0
            .range(..=start)
            .next_back()
            .map_or(start, |(&a, _)| a);
        self.0
            .range(first..end.max(first))
            .filter_map(move |(&a, &b)| {
                let (a, b) = (a.max(start), b.min(end));
                (a < b).then_some((a, b))
            })
    }
    pub fn duration(&self, start: u64, end: u64) -> u64 {
        if start >= end {
            return 0;
        }
        self.clipped(start, end).map(|(a, b)| b - a).sum()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ActivityTimeline {
    pub range: Option<(u64, u64)>,
    pub devices: BTreeMap<Device, IntervalUnion>,
    pub observed_requests: u64,
    pub missing_issue: u64,
    /// Exact coverage must be supported by acquisition provenance, never
    /// inferred from zero drops alone or the retained event count.
    pub verified_complete: bool,
    pub limitation: Option<String>,
    unfiltered_perfetto: bool,
    expected_perfetto: Option<u64>,
    reconstructed: bool,
    expected_devices: BTreeMap<Device, u64>,
    device_coverage_supplied: bool,
    observed_devices: BTreeMap<Device, u64>,
    missing_devices: BTreeMap<Device, u64>,
}
impl ActivityTimeline {
    /// The capture recipe emits scope provenance; imported/older traces without
    /// it remain unknown even when their recorded loss counters are zero.
    pub fn observe_record(&mut self, record: &WireRecord) {
        match record {
            WireRecord::SourceInfo {
                source, metadata, ..
            } if source == "perfetto" => {
                self.reconstructed = false;
                if metadata["stage"] == "recording" {
                    self.unfiltered_perfetto =
                        metadata["block_activity_scope"] == "unfiltered_issue_complete_v1";
                }
                if metadata["stage"] == "complete" {
                    self.expected_perfetto = None;
                    self.expected_devices.clear();
                    self.device_coverage_supplied = false;
                    let quality = serde_json::from_value::<crate::perfetto::TraceQuality>(
                        metadata["quality"].clone(),
                    );
                    let complete = quality.is_ok_and(|q| {
                        q.kernel_lost_events() == Some(0)
                            && q.kernel_start.len() == q.kernel_end.len()
                            && q.service_stats_seen
                            && !q.service_loss_counters.is_empty()
                            && q.service_loss_counters.values().all(|v| *v == 0)
                            && q.final_flush_outcome.is_some_and(|v| v <= 1)
                            && q.packets > 0
                            && q.lost_bundles == 0
                            && q.parse_errors == 0
                            && !q.truncated
                            && !q.projection_limited
                            && q.unsupported_clocks.is_empty()
                            && q.failed_events.is_empty()
                            && q.diagnostics.is_empty()
                            && q.unknown_events.iter().all(|v| {
                                v == "block/block_rq_insert" || v == "block/block_rq_requeue"
                            })
                    });
                    if complete
                        && [
                            "unresolved_timing",
                            "unmatched_issues",
                            "unpaired_requeues",
                            "correlation_limit_hits",
                        ]
                        .iter()
                        .all(|k| metadata[*k].as_u64() == Some(0))
                    {
                        self.expected_perfetto = metadata["completion_observations"].as_u64();
                    }
                    if complete
                        && metadata["correlation_limit_hits"].as_u64() == Some(0)
                        && let Ok(rows) = serde_json::from_value::<Vec<DeviceCoverage>>(
                            metadata["block_activity_devices"].clone(),
                        )
                    {
                        self.expected_perfetto = metadata["completion_observations"].as_u64();
                        self.device_coverage_supplied = true;
                        self.expected_devices = rows
                            .into_iter()
                            .filter(|r| r.unresolved == 0 && r.unmatched == 0 && r.requeues == 0)
                            .map(|r| (r.device, r.completions))
                            .collect();
                    }
                }
            }
            WireRecord::Footer {
                events_seen,
                events_persisted,
                events_dropped,
                events_rejected,
                graceful,
                ..
            } => {
                self.reconstructed = self.unfiltered_perfetto
                    && self.expected_perfetto == Some(self.observed_requests)
                    && *events_seen == self.observed_requests
                    && *events_persisted == self.observed_requests
                    && *events_dropped == 0
                    && *events_rejected == 0
                    && *graceful == Some(true);
            }
            _ => {}
        }
    }
    pub fn reconstructed(&self) -> bool {
        self.reconstructed_for(&self.devices.keys().copied().collect::<Vec<_>>())
    }
    pub fn reconstructed_for(&self, devices: &[Device]) -> bool {
        self.reconstructed
            && self.expected_perfetto == Some(self.observed_requests)
            && !devices.is_empty()
            && devices.iter().all(|device| {
                if !self.device_coverage_supplied {
                    self.missing_issue == 0
                } else {
                    self.expected_devices.get(device) == self.observed_devices.get(device)
                        && self.expected_devices.contains_key(device)
                        && self.missing_devices.get(device).copied().unwrap_or(0) == 0
                }
            })
            && self.limitation.is_none()
    }
    pub fn observe_range(&mut self, start: u64, end: u64) {
        self.range = Some(
            self.range
                .map_or((start, end), |(a, b)| (a.min(start), b.max(end))),
        );
    }
    pub fn observe(&mut self, io: &CompletedIo) {
        self.observe_range(io.start_timestamp(), io.completion.ts_ns);
        self.observed_requests += 1;
        let device = (io.issue.device_major, io.issue.device_minor);
        *self.observed_devices.entry(device).or_default() += 1;
        let union = self
            .devices
            .entry((io.issue.device_major, io.issue.device_minor))
            .or_default();
        if let Some(start) = io.issue_timestamp() {
            union.insert(start, io.completion.ts_ns);
        } else {
            self.missing_issue += 1;
            *self.missing_devices.entry(device).or_default() += 1;
        }
    }
    pub fn exact(&self) -> bool {
        self.verified_complete && self.missing_issue == 0 && self.limitation.is_none()
    }
    pub fn reason(&self) -> String {
        if self.missing_issue > 0 {
            return format!(
                "{} requests have no measured issue timestamp",
                self.missing_issue
            );
        }
        if self.reconstructed() {
            return "Reconstructed unfiltered Perfetto block activity: all completions paired, no reported kernel/service loss, complete saved stream. Request matching is Probable; trace boundaries and unobserved requeues limit physical-device interpretation.".into();
        }
        self.limitation.clone().unwrap_or_else(||if self.verified_complete {"Complete device activity coverage".into()}else{"Full, unfiltered block activity coverage is not proven for this source; detail gaps may be sampling, capture filters or loss".into()})
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TransferBytes {
    pub read: u64,
    pub write: u64,
    /// Non-R/W command extents, excluded from transferred payload and BW.
    pub other: u64,
}
impl TransferBytes {
    pub fn observe(&mut self, io: &CompletedIo) {
        let target = match io.issue.operation {
            IoOperation::Read => &mut self.read,
            IoOperation::Write => &mut self.write,
            _ => &mut self.other,
        };
        *target = target.saturating_add(io.issue.bytes as u64);
    }
    pub fn total(&self) -> u64 {
        self.read.saturating_add(self.write)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HostBandwidth {
    pub estimated: bool,
    pub start_ns: u64,
    pub end_ns: u64,
    pub duration_ns: u64,
    pub observed_busy_ns: u64,
    pub busy_ns: Option<u64>,
    pub idle_ns: Option<u64>,
    pub bytes: TransferBytes,
    /// Total, Read, Write. Same wall-clock denominator for each direction.
    pub with_idle_mib_s: [Option<f64>; 3],
    pub without_idle_mib_s: [Option<f64>; 3],
    pub devices: Vec<Device>,
    pub coverage: String,
}
pub fn calculate(
    activity: &ActivityTimeline,
    range: (u64, u64),
    bytes: TransferBytes,
    devices: Vec<Device>,
) -> HostBandwidth {
    let (start_ns, end_ns) = range;
    let duration_ns = end_ns.saturating_sub(start_ns);
    let mut combined = IntervalUnion::default();
    if duration_ns > 0 {
        for device in &devices {
            if let Some(union) = activity.devices.get(device) {
                for (a, b) in union.clipped(start_ns, end_ns) {
                    combined.insert(a, b);
                }
            }
        }
    }
    let observed_busy_ns = combined.duration(start_ns, end_ns);
    let estimated = activity.reconstructed_for(&devices);
    let busy_ns = (activity.exact() || estimated).then_some(observed_busy_ns);
    let idle_ns = busy_ns.map(|v| duration_ns.saturating_sub(v));
    let rate = |bytes: u64, ns: Option<u64>| {
        ns.filter(|n| *n > 0)
            .map(|n| bytes as f64 * 1e9 / n as f64 / 1_048_576.)
    };
    let counts = [bytes.total(), bytes.read, bytes.write];
    HostBandwidth {
        estimated,
        start_ns,
        end_ns,
        duration_ns,
        observed_busy_ns,
        busy_ns,
        idle_ns,
        with_idle_mib_s: counts.map(|b| rate(b, Some(duration_ns))),
        without_idle_mib_s: counts.map(|b| rate(b, busy_ns)),
        bytes,
        devices,
        coverage: if estimated {
            "Reconstructed unfiltered Perfetto block activity on selected devices: all completions paired, no reported kernel/service loss, complete saved stream. Probable request matching; capture boundaries and unobserved requeues limit physical-device interpretation.".into()
        } else {
            activity.reason()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discard_and_flush_extents_do_not_inflate_transferred_payload() {
        let mut a = ActivityTimeline {
            verified_complete: true,
            ..Default::default()
        };
        a.devices.entry((8, 0)).or_default().insert(0, 500_000_000);
        let b = calculate(
            &a,
            (0, 1_000_000_000),
            TransferBytes {
                read: 1_048_576,
                write: 2_097_152,
                other: 1_073_741_824,
            },
            vec![(8, 0)],
        );
        assert_eq!(b.bytes.total(), 3_145_728);
        assert_eq!(b.with_idle_mib_s, [Some(3.), Some(1.), Some(2.)]);
        assert_eq!(b.without_idle_mib_s, [Some(6.), Some(2.), Some(4.)]);
    }
    fn coverage_fixture() -> (ActivityTimeline, WireRecord, WireRecord, WireRecord) {
        let mut a = ActivityTimeline {
            observed_requests: 1,
            ..Default::default()
        };
        a.devices.entry((8, 0)).or_default().insert(2, 8);
        let scope = WireRecord::SourceInfo {
            schema_version: 6,
            source: "perfetto".into(),
            status: String::new(),
            metadata: serde_json::json!({"stage":"recording","block_activity_scope":"unfiltered_issue_complete_v1"}),
        };
        let q = crate::perfetto::TraceQuality {
            packets: 10,
            ftrace_start_seen: true,
            ftrace_end_seen: true,
            kernel_start: BTreeMap::from([(0, [Some(0); 3])]),
            kernel_end: BTreeMap::from([(0, [Some(0); 3])]),
            service_stats_seen: true,
            service_loss_counters: BTreeMap::from([("chunks_discarded".into(), 0)]),
            final_flush_outcome: Some(0),
            ..Default::default()
        };
        let quality = WireRecord::SourceInfo {
            schema_version: 6,
            source: "perfetto".into(),
            status: String::new(),
            metadata: serde_json::json!({"stage":"complete","quality":q,"completion_observations":1,"unresolved_timing":0,"unmatched_issues":0,"unpaired_requeues":0,"correlation_limit_hits":0}),
        };
        let footer = WireRecord::Footer {
            schema_version: 6,
            events_seen: 1,
            events_persisted: 1,
            events_dropped: 0,
            events_rejected: 0,
            graceful: Some(true),
        };
        (a, scope, quality, footer)
    }
    #[test]
    fn only_complete_unfiltered_loss_free_source_can_provide_reconstructed_bw() {
        let (mut a, scope, quality, footer) = coverage_fixture();
        a.observe_record(&quality);
        a.observe_record(&footer);
        assert!(
            !a.reconstructed(),
            "legacy zero-loss metadata alone is not scope proof"
        );
        a.observe_record(&scope);
        a.observe_record(&quality);
        a.observe_record(&footer);
        let b = calculate(&a, (0, 10), TransferBytes::default(), vec![(8, 0)]);
        assert!(b.estimated);
        assert!(!a.exact());
        assert_eq!(b.busy_ns, Some(6));
        assert_eq!(b.idle_ns, Some(4));
        a.observed_requests += 1;
        assert!(!a.reconstructed(), "a footer cannot cover later events");
        for name in ["truncated", "projection_limited"] {
            let (mut a, scope, mut quality, footer) = coverage_fixture();
            if let WireRecord::SourceInfo { metadata, .. } = &mut quality {
                metadata["quality"][name] = serde_json::json!(true);
            }
            a.observe_record(&scope);
            a.observe_record(&quality);
            a.observe_record(&footer);
            assert!(!a.reconstructed(), "{name}");
        }
        for name in [
            "unresolved_timing",
            "unmatched_issues",
            "unpaired_requeues",
            "correlation_limit_hits",
        ] {
            let (mut a, scope, mut quality, footer) = coverage_fixture();
            if let WireRecord::SourceInfo { metadata, .. } = &mut quality {
                metadata[name] = serde_json::json!(1);
            }
            a.observe_record(&scope);
            a.observe_record(&quality);
            a.observe_record(&footer);
            assert!(!a.reconstructed(), "{name}");
        }
        let (mut a, scope, mut quality, footer) = coverage_fixture();
        if let WireRecord::SourceInfo { metadata, .. } = &mut quality {
            metadata["quality"]["kernel_end"]["0"] = serde_json::json!([1, 0, 0]);
        }
        a.observe_record(&scope);
        a.observe_record(&quality);
        a.observe_record(&footer);
        assert!(!a.reconstructed());
    }
    #[test]
    fn incomplete_other_device_does_not_erase_verified_device_activity() {
        let (mut a, scope, mut quality, mut footer) = coverage_fixture();
        a.observed_requests = 2;
        a.missing_issue = 1;
        a.observed_devices = BTreeMap::from([((8, 0), 1), ((7, 0), 1)]);
        a.missing_devices = BTreeMap::from([((7, 0), 1)]);
        a.devices.entry((7, 0)).or_default();
        if let WireRecord::SourceInfo { metadata, .. } = &mut quality {
            metadata["completion_observations"] = serde_json::json!(2);
            metadata["unresolved_timing"] = serde_json::json!(1);
            metadata["block_activity_devices"] = serde_json::json!([
                DeviceCoverage {
                    device: (8, 0),
                    completions: 1,
                    ..Default::default()
                },
                DeviceCoverage {
                    device: (7, 0),
                    completions: 1,
                    unresolved: 1,
                    ..Default::default()
                }
            ]);
        }
        if let WireRecord::Footer {
            events_seen,
            events_persisted,
            ..
        } = &mut footer
        {
            *events_seen = 2;
            *events_persisted = 2;
        }
        a.observe_record(&scope);
        a.observe_record(&quality);
        a.observe_record(&footer);
        assert!(a.reconstructed_for(&[(8, 0)]));
        assert!(!a.reconstructed());
        assert!(!a.reconstructed_for(&[(7, 0)]));
        let b = calculate(&a, (0, 10), TransferBytes::default(), vec![(8, 0)]);
        assert!(b.estimated);
        assert_eq!(b.busy_ns, Some(6));
        if let WireRecord::SourceInfo { metadata, .. } = &mut quality {
            metadata["block_activity_devices"][0]["unmatched"] = serde_json::json!(1);
        }
        a.observe_record(&quality);
        a.observe_record(&footer);
        assert!(
            !a.reconstructed_for(&[(8, 0)]),
            "an explicitly empty eligible device set is not global coverage"
        );
    }
    #[test]
    fn overlap_unordered_adjacency_and_boundaries_use_union_not_latency_sum() {
        let mut a = ActivityTimeline {
            verified_complete: true,
            ..Default::default()
        };
        let u = a.devices.entry((8, 0)).or_default();
        for (x, y) in [(7, 10), (1, 4), (3, 8), (10, 11), (20, 21)] {
            u.insert(x * 1_000_000_000, y * 1_000_000_000);
        }
        let b = calculate(
            &a,
            (2_000_000_000, 12_000_000_000),
            TransferBytes {
                read: 10 * 1_048_576,
                ..Default::default()
            },
            vec![(8, 0)],
        );
        assert_eq!(b.busy_ns, Some(9_000_000_000));
        assert_eq!(b.idle_ns, Some(1_000_000_000));
        assert_eq!(b.with_idle_mib_s, [Some(1.), Some(1.), Some(0.)]);
        assert!((b.without_idle_mib_s[0].unwrap() - 10. / 9.).abs() < 1e-12);
    }
    #[test]
    fn process_filter_changes_bytes_but_other_process_activity_still_excludes_idle() {
        let mut a = ActivityTimeline {
            verified_complete: true,
            ..Default::default()
        };
        let u = a.devices.entry((8, 0)).or_default();
        u.insert(0, 2_000_000_000); // selected process
        u.insert(2_000_000_000, 8_000_000_000); // another process
        a.devices
            .entry((8, 1))
            .or_default()
            .insert(0, 10_000_000_000);
        let b = calculate(
            &a,
            (0, 10_000_000_000),
            TransferBytes {
                read: 8 * 1_048_576,
                ..Default::default()
            },
            vec![(8, 0)],
        );
        assert_eq!(b.idle_ns, Some(2_000_000_000));
        assert_eq!(b.without_idle_mib_s[1], Some(1.));
        let all = calculate(&a, (0, 10_000_000_000), b.bytes, vec![(8, 0), (8, 1)]);
        assert_eq!(all.busy_ns, Some(10_000_000_000)); // wall-clock union, not device-seconds
    }
    #[test]
    fn sampled_unknown_empty_and_zero_denominators_never_invent_idle_or_nan() {
        let mut a = ActivityTimeline::default();
        a.devices.entry((8, 0)).or_default().insert(1, 2);
        let b = calculate(&a, (0, 10), TransferBytes::default(), vec![(8, 0)]);
        assert_eq!(b.observed_busy_ns, 1);
        assert_eq!(b.idle_ns, None);
        assert_eq!(b.without_idle_mib_s, [None; 3]);
        let z = calculate(&a, (2, 2), TransferBytes::default(), vec![(8, 0)]);
        assert_eq!(z.with_idle_mib_s, [None; 3]);
        a.verified_complete = true;
        let empty = calculate(&a, (3, 5), TransferBytes::default(), vec![(8, 0)]);
        assert_eq!(empty.idle_ns, Some(2));
        assert_eq!(empty.with_idle_mib_s, [Some(0.); 3]);
        assert_eq!(empty.without_idle_mib_s, [None; 3]);
    }
}
