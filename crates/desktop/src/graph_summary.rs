//! Summary of the main graph's full-resolution cohort. No rendering samples
//! enter these calculations. Address counts are split at interval boundaries,
//! so even very large requests never require expanding every sector.
use std::collections::BTreeMap;

use android_ebpf_protocol::{CompletedIo, IoOperation};
use serde::Serialize;

#[derive(Debug, Default, Clone, Serialize)]
pub struct Distribution {
    pub values: Vec<f64>,
    pub missing: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistogramBin {
    pub lower: f64,
    pub upper: f64,
    pub count: usize,
}

impl Distribution {
    pub fn observe(&mut self, value: Option<f64>) {
        match value.filter(|v| v.is_finite()) {
            Some(value) => self.values.push(value),
            None => self.missing += 1,
        }
    }
    pub fn finish(&mut self) {
        self.values.sort_unstable_by(f64::total_cmp);
    }
    /// Exact nearest rank. P0 is the minimum; P100 is the maximum.
    pub fn percentile(&self, p: usize) -> Option<f64> {
        let index = (self.values.len() * p.min(100))
            .div_ceil(100)
            .saturating_sub(1);
        self.values.get(index).copied()
    }
    pub fn histogram(&self, requested_bins: usize) -> Vec<HistogramBin> {
        let (Some(&min), Some(&max)) = (self.values.first(), self.values.last()) else {
            return Vec::new();
        };
        if min == max {
            return vec![HistogramBin {
                lower: min,
                upper: max,
                count: self.values.len(),
            }];
        }
        let count = requested_bins.clamp(1, 128).min(self.values.len());
        let width = (max - min) / count as f64;
        let mut bins: Vec<_> = (0..count)
            .map(|i| HistogramBin {
                lower: min + i as f64 * width,
                upper: if i + 1 == count {
                    max
                } else {
                    min + (i + 1) as f64 * width
                },
                count: 0,
            })
            .collect();
        // Use the actual displayed boundaries, avoiding arithmetic rounding
        // disagreement between a sample exactly on a boundary and its bin.
        for &value in &self.values {
            let i = bins.partition_point(|b| b.upper <= value).min(count - 1);
            bins[i].count += 1;
        }
        bins
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct MetricDistribution {
    pub total: Distribution,
    pub read: Distribution,
    pub write: Distribution,
    pub other: Distribution,
}
impl MetricDistribution {
    pub fn observe(&mut self, op: IoOperation, value: Option<f64>) {
        self.total.observe(value);
        match op {
            IoOperation::Read => &mut self.read,
            IoOperation::Write => &mut self.write,
            _ => &mut self.other,
        }
        .observe(value);
    }
    pub fn finish(&mut self) {
        for dist in [
            &mut self.total,
            &mut self.read,
            &mut self.write,
            &mut self.other,
        ] {
            dist.finish();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressCount {
    pub device: (u32, u32),
    pub start_sector: u64,
    pub end_sector: u64,
    pub reads: u64,
    pub writes: u64,
}
impl AddressCount {
    pub fn repeated(&self) -> bool {
        self.reads.saturating_add(self.writes) > 1
    }
}

type AddressEdges = BTreeMap<(u32, u32), BTreeMap<u64, (i64, i64)>>;
#[derive(Debug, Default)]
pub struct AddressAccumulator {
    edges: AddressEdges,
    pub unknown_or_empty: usize,
}
impl AddressAccumulator {
    pub fn observe(&mut self, io: &CompletedIo) {
        if !matches!(io.issue.operation, IoOperation::Read | IoOperation::Write) {
            return;
        }
        let start = io.issue.sector;
        // BlockIssue sectors are authoritative address length. Never infer
        // volume from a discard's extent or from an unrelated origin size.
        let end = start.saturating_add(io.issue.sectors as u64);
        if end <= start {
            self.unknown_or_empty += 1;
            return;
        }
        let edges = self
            .edges
            .entry((io.issue.device_major, io.issue.device_minor))
            .or_default();
        let direction = if io.issue.operation == IoOperation::Read {
            (1, 0)
        } else {
            (0, 1)
        };
        let edge = edges.entry(start).or_default();
        edge.0 += direction.0;
        edge.1 += direction.1;
        let edge = edges.entry(end).or_default();
        edge.0 -= direction.0;
        edge.1 -= direction.1;
    }
    pub fn finish(self) -> Vec<AddressCount> {
        let mut rows: Vec<AddressCount> = Vec::new();
        for (device, edges) in self.edges {
            let (mut reads, mut writes, mut previous) = (0i64, 0i64, None);
            for (sector, delta) in edges {
                if let Some(start) = previous
                    && sector > start
                    && (reads > 0 || writes > 0)
                {
                    if let Some(last) = rows.last_mut()
                        && last.device == device
                        && last.end_sector == start
                        && last.reads == reads as u64
                        && last.writes == writes as u64
                    {
                        last.end_sector = sector;
                    } else {
                        rows.push(AddressCount {
                            device,
                            start_sector: start,
                            end_sector: sector,
                            reads: reads as u64,
                            writes: writes as u64,
                        });
                    }
                }
                reads += delta.0;
                writes += delta.1;
                previous = Some(sector);
            }
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use android_ebpf_protocol::{AnalysisEngine, BlockComplete, BlockIssue, StorageEvent};

    #[test]
    fn histogram_boundaries_percentiles_missing_and_constant_are_independent() {
        let mut d = Distribution::default();
        for v in [
            Some(0.),
            Some(1.),
            Some(2.),
            Some(3.),
            Some(4.),
            None,
            Some(f64::NAN),
        ] {
            d.observe(v);
        }
        d.finish();
        assert_eq!(d.missing, 2);
        assert_eq!(
            d.histogram(2).iter().map(|b| b.count).collect::<Vec<_>>(),
            [2, 3]
        );
        assert_eq!(d.percentile(50), Some(2.));
        assert_eq!(d.percentile(95), Some(4.));
        assert_eq!(Distribution::default().percentile(99), None);
        d.values = vec![8.; 10];
        assert_eq!(d.histogram(20)[0].count, 10);
        assert_eq!(d.histogram(20).len(), 1);
    }
    #[test]
    fn address_overlaps_count_read_write_independently_and_split_devices() {
        let mut engine = AnalysisEngine::new();
        for (id, sector, sectors, op, minor) in [
            (1, 0, 8, IoOperation::Read, 0),
            (2, 4, 8, IoOperation::Read, 0),
            (3, 6, 2, IoOperation::Write, 0),
            (4, 0, 8, IoOperation::Write, 1),
        ] {
            engine.ingest(StorageEvent::BlockIssue(BlockIssue {
                ts_ns: id * 10,
                request_id: id,
                device_major: 8,
                device_minor: minor,
                sector,
                sectors,
                bytes: sectors * 512,
                operation: op,
                pid: 1,
                tid: 1,
                cpu: 0,
                comm: "same".into(),
            }));
            engine.ingest(StorageEvent::BlockComplete(BlockComplete {
                ts_ns: id * 10 + 1,
                request_id: id,
                device_major: 8,
                device_minor: minor,
                status: 0,
            }));
        }
        let mut a = AddressAccumulator::default();
        for io in engine.completed_ios() {
            a.observe(io);
        }
        let rows = a.finish();
        assert_eq!(
            rows.iter()
                .map(|r| (r.device.1, r.start_sector, r.end_sector, r.reads, r.writes))
                .collect::<Vec<_>>(),
            [
                (0, 0, 4, 1, 0),
                (0, 4, 6, 2, 0),
                (0, 6, 8, 2, 1),
                (0, 8, 12, 1, 0),
                (1, 0, 8, 0, 1)
            ]
        );
        assert_eq!(
            rows.iter()
                .filter(|r| r.repeated())
                .map(|r| r.end_sector - r.start_sector)
                .sum::<u64>(),
            4
        );
    }
}
