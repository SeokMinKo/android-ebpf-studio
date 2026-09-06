//! Host bandwidth has a completion-counted numerator and a device-wide clock.
//! Activity is collected before UI filters and detail-window eviction. Unknown
//! coverage never converts an unobserved gap into measured device idle.
use android_ebpf_protocol::{CompletedIo, IoOperation};
use serde::Serialize;
use std::collections::BTreeMap;

pub type Device = (u32, u32);

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
}
impl ActivityTimeline {
    pub fn observe_range(&mut self, start: u64, end: u64) {
        self.range = Some(
            self.range
                .map_or((start, end), |(a, b)| (a.min(start), b.max(end))),
        );
    }
    pub fn observe(&mut self, io: &CompletedIo) {
        self.observe_range(io.start_timestamp(), io.completion.ts_ns);
        self.observed_requests += 1;
        let union = self
            .devices
            .entry((io.issue.device_major, io.issue.device_minor))
            .or_default();
        if let Some(start) = io.issue_timestamp() {
            union.insert(start, io.completion.ts_ns);
        } else {
            self.missing_issue += 1;
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
        self.limitation.clone().unwrap_or_else(||if self.verified_complete {"Complete device activity coverage".into()}else{"Full, unfiltered block activity coverage is not proven for this source; detail gaps may be sampling, capture filters or loss".into()})
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TransferBytes {
    pub read: u64,
    pub write: u64,
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
        self.read
            .saturating_add(self.write)
            .saturating_add(self.other)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HostBandwidth {
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
    let busy_ns = activity.exact().then_some(observed_busy_ns);
    let idle_ns = busy_ns.map(|v| duration_ns.saturating_sub(v));
    let rate = |bytes: u64, ns: Option<u64>| {
        ns.filter(|n| *n > 0)
            .map(|n| bytes as f64 * 1e9 / n as f64 / 1_048_576.)
    };
    let counts = [bytes.total(), bytes.read, bytes.write];
    HostBandwidth {
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
        coverage: activity.reason(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
