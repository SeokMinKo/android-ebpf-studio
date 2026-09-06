//! One statistical sample per elapsed-time window, including empty windows.
//! Payload and device activity deliberately have different filter scopes.
use crate::host_bw::{ActivityTimeline, Device, IntervalUnion};
use android_ebpf_protocol::{CompletedIo, IoOperation};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum WindowMetric {
    Bandwidth,
    Iops,
    CumulativePayload,
    BusyPercent,
    BusyMs,
    IdleMs,
}
impl WindowMetric {
    pub fn label(self) -> &'static str {
        match self {
            Self::Bandwidth => "Window bandwidth (MiB/s)",
            Self::Iops => "Window IOPS (requests/s)",
            Self::CumulativePayload => "Cumulative payload (MiB)",
            Self::BusyPercent => "Device busy (%)",
            Self::BusyMs => "Window active time (ms)",
            Self::IdleMs => "Window idle time (ms)",
        }
    }
    pub fn device_activity(self) -> bool {
        matches!(self, Self::BusyPercent | Self::BusyMs | Self::IdleMs)
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct WindowSample {
    pub start_ns: u64,
    pub end_ns: u64,
    /// Total / Read / Write. IOPS Total includes all command types.
    pub requests: [u64; 3],
    pub payload: [u64; 3],
    pub values: [Option<f64>; 3],
}
#[derive(Debug, Clone, Serialize)]
pub struct WindowSeries {
    pub metric: WindowMetric,
    pub range: (u64, u64),
    pub width_ns: u64,
    pub samples: Vec<WindowSample>,
    pub estimated_activity: bool,
}
impl WindowSeries {
    pub fn index_at(&self, ts: u64) -> Option<usize> {
        if ts < self.range.0 || ts > self.range.1 || self.samples.is_empty() {
            return None;
        }
        Some(((ts - self.range.0) / self.width_ns).min(self.samples.len() as u64 - 1) as usize)
    }
}
pub fn build(
    ios: &[CompletedIo],
    activity: &ActivityTimeline,
    devices: &[Device],
    range: (u64, u64),
    requested_width: u64,
    metric: WindowMetric,
) -> WindowSeries {
    let duration = range.1.saturating_sub(range.0);
    let width = requested_width.max(duration.div_ceil(20_000)).max(1);
    let n = duration.div_ceil(width) as usize;
    let mut result = WindowSeries {
        metric,
        range,
        width_ns: width,
        samples: (0..n)
            .map(|i| {
                let start = range.0 + i as u64 * width;
                WindowSample {
                    start_ns: start,
                    end_ns: start.saturating_add(width).min(range.1),
                    requests: [0; 3],
                    payload: [0; 3],
                    values: [None; 3],
                }
            })
            .collect(),
        estimated_activity: activity.reconstructed_for(devices),
    };
    for io in ios {
        let Some(index) = result.index_at(io.completion.ts_ns) else {
            continue;
        };
        let sample = &mut result.samples[index];
        sample.requests[0] += 1;
        let direction = match io.issue.operation {
            IoOperation::Read => Some(1),
            IoOperation::Write => Some(2),
            _ => None,
        };
        if let Some(direction) = direction {
            sample.requests[direction] += 1;
            sample.payload[direction] += io.issue.bytes as u64;
            sample.payload[0] += io.issue.bytes as u64;
        }
    }
    let mut combined = IntervalUnion::default();
    if metric.device_activity() && duration > 0 {
        for device in devices {
            if let Some(union) = activity.devices.get(device) {
                for (a, b) in union.clipped(range.0, range.1) {
                    combined.insert(a, b);
                }
            }
        }
    }
    let known = activity.exact() || result.estimated_activity;
    let mut cumulative = [0u64; 3];
    for sample in &mut result.samples {
        let ns = sample.end_ns - sample.start_ns;
        for (sum, bytes) in cumulative.iter_mut().zip(sample.payload) {
            *sum += bytes;
        }
        sample.values = match metric {
            WindowMetric::Bandwidth => sample
                .payload
                .map(|b| Some(b as f64 * 1e9 / ns as f64 / 1_048_576.)),
            WindowMetric::Iops => sample
                .requests
                .map(|count| Some(count as f64 * 1e9 / ns as f64)),
            WindowMetric::CumulativePayload => cumulative.map(|b| Some(b as f64 / 1_048_576.)),
            _ => {
                let busy = combined.duration(sample.start_ns, sample.end_ns);
                let value = if !known {
                    None
                } else {
                    Some(match metric {
                        WindowMetric::BusyPercent => busy as f64 * 100. / ns as f64,
                        WindowMetric::BusyMs => busy as f64 / 1e6,
                        WindowMetric::IdleMs => (ns - busy) as f64 / 1e6,
                        _ => unreachable!(),
                    })
                };
                [value, None, None]
            }
        };
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use android_ebpf_protocol::{AnalysisEngine, BlockComplete, BlockIssue, StorageEvent};
    #[test]
    fn windows_include_empty_time_and_boundary_completions_with_partial_duration() {
        let mut e = AnalysisEngine::new();
        for (id, ts, op) in [
            (1, 1_000_000_000, IoOperation::Read),
            (2, 2_500_000_000, IoOperation::Write),
            (3, 2_500_000_000, IoOperation::Discard),
        ] {
            e.ingest(StorageEvent::BlockIssue(BlockIssue {
                ts_ns: ts - 100,
                request_id: id,
                device_major: 8,
                device_minor: 0,
                sector: 0,
                sectors: 2048,
                bytes: 1_048_576,
                operation: op,
                pid: 1,
                tid: 1,
                cpu: 0,
                comm: "x".into(),
            }));
            e.ingest(StorageEvent::BlockComplete(BlockComplete {
                ts_ns: ts,
                request_id: id,
                device_major: 8,
                device_minor: 0,
                status: 0,
            }));
        }
        let mut a = ActivityTimeline::default();
        a.verified_complete = true;
        a.devices
            .entry((8, 0))
            .or_default()
            .insert(500_000_000, 1_500_000_000);
        a.devices
            .entry((8, 1))
            .or_default()
            .insert(1_000_000_000, 2_000_000_000);
        let b = build(
            e.completed_ios(),
            &a,
            &[(8, 0)],
            (0, 2_500_000_000),
            1_000_000_000,
            WindowMetric::Bandwidth,
        );
        assert_eq!(
            b.samples.iter().map(|s| s.values[0]).collect::<Vec<_>>(),
            [Some(0.), Some(1.), Some(2.)]
        );
        assert_eq!(b.samples[2].requests, [2, 0, 1]);
        let b = build(
            e.completed_ios(),
            &a,
            &[(8, 0), (8, 1)],
            (0, 2_500_000_000),
            1_000_000_000,
            WindowMetric::BusyPercent,
        );
        assert_eq!(
            b.samples.iter().map(|s| s.values[0]).collect::<Vec<_>>(),
            [Some(50.), Some(100.), Some(0.)]
        );
        a.verified_complete = false;
        let b = build(
            e.completed_ios(),
            &a,
            &[(8, 0)],
            (0, 2_500_000_000),
            1_000_000_000,
            WindowMetric::IdleMs,
        );
        assert!(b.samples.iter().all(|s| s.values[0].is_none()));
        assert!(
            build(&[], &a, &[], (1, 1), 1, WindowMetric::Iops)
                .samples
                .is_empty()
        );
    }
}
