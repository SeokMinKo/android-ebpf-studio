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
    /// Exact empirical cumulative probability at each rendered value. The
    /// display may skip values, but ties always include their entire run.
    pub fn cdf_points(&self, limit: usize) -> Vec<[f64; 2]> {
        if self.values.is_empty() {
            return Vec::new();
        }
        let n = self.values.len();
        let samples = n.min(limit.max(2));
        let mut points = Vec::with_capacity(samples);
        for i in 0..samples {
            let index = if samples == 1 {
                0
            } else {
                i * (n - 1) / (samples - 1)
            };
            let value = self.values[index];
            if points.last().is_some_and(|p: &[f64; 2]| p[0] == value) {
                continue;
            }
            let count = self.values.partition_point(|v| *v <= value);
            points.push([value, count as f64 * 100. / n as f64]);
        }
        points
    }
    pub fn rank_points(&self, limit: usize) -> Vec<[f64; 2]> {
        let n = self.values.len();
        let samples = n.min(limit.max(2));
        (0..samples)
            .map(|i| {
                let index = if samples == 1 {
                    0
                } else {
                    i * (n - 1) / (samples - 1)
                };
                [(index + 1) as f64, self.values[index]]
            })
            .collect()
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
#[derive(Debug, Clone, Serialize)]
pub struct PayloadBin {
    pub lower: f64,
    pub upper: f64,
    pub read: u64,
    pub write: u64,
}
#[derive(Debug, Default, Clone, Serialize)]
pub struct AddressLocality {
    pub payload: Vec<PayloadBin>,
    pub reuse: MetricDistribution,
    /// sector, gap in ms, direction (0 Read / 1 Write).
    pub reuse_points: Vec<[f64; 3]>,
}
type LocalityRow = (u64, u64, IoOperation, Option<u64>);
#[derive(Debug, Default)]
pub struct LocalityAccumulator {
    rows: BTreeMap<(u32, u32), Vec<LocalityRow>>,
}
impl LocalityAccumulator {
    pub fn observe(&mut self, io: &CompletedIo) {
        if matches!(io.issue.operation, IoOperation::Read | IoOperation::Write) {
            self.rows
                .entry((io.issue.device_major, io.issue.device_minor))
                .or_default()
                .push((
                    io.issue.sector,
                    io.issue.bytes as u64,
                    io.issue.operation,
                    io.issue_timestamp(),
                ));
        }
    }
    pub fn finish(self) -> BTreeMap<(u32, u32), AddressLocality> {
        self.rows
            .into_iter()
            .map(|(device, mut rows)| {
                let mut sectors = Distribution::default();
                for r in &rows {
                    sectors.observe(Some(r.0 as f64));
                }
                sectors.finish();
                let mut result = AddressLocality {
                    payload: sectors
                        .histogram(16)
                        .into_iter()
                        .map(|b| PayloadBin {
                            lower: b.lower,
                            upper: b.upper,
                            read: 0,
                            write: 0,
                        })
                        .collect(),
                    ..Default::default()
                };
                for (sector, bytes, op, _) in &rows {
                    let index = result
                        .payload
                        .partition_point(|b| b.upper <= *sector as f64)
                        .min(result.payload.len() - 1);
                    let bin = &mut result.payload[index];
                    if *op == IoOperation::Read {
                        bin.read += bytes;
                    } else {
                        bin.write += bytes;
                    }
                }
                rows.sort_by_key(|r| r.3);
                let mut last: BTreeMap<(u64, bool), u64> = BTreeMap::new();
                for (sector, _, op, ts) in rows {
                    let write = op == IoOperation::Write;
                    let gap = ts.and_then(|ts| {
                        last.insert((sector, write), ts)
                            .map(|previous| (ts - previous) as f64 / 1e6)
                    });
                    result.reuse.observe(op, gap);
                    if let Some(gap) = gap {
                        result
                            .reuse_points
                            .push([sector as f64, gap, if write { 1. } else { 0. }]);
                    }
                }
                result.reuse.finish();
                (device, result)
            })
            .collect()
    }
}
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
    fn empirical_cdf_includes_ties_and_rank_preserves_endpoints() {
        let d = Distribution {
            values: vec![1., 1., 3., 7.],
            missing: 0,
        };
        assert_eq!(d.cdf_points(10), vec![[1., 50.], [3., 75.], [7., 100.]]);
        assert_eq!(d.cdf_points(2), vec![[1., 50.], [7., 100.]]);
        assert_eq!(d.rank_points(2), vec![[1., 1.], [4., 7.]]);
        assert!(Distribution::default().cdf_points(2).is_empty());
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
                cpu: None,
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
    #[test]
    fn locality_preserves_payload_and_splits_reuse_by_device_direction_and_start_lba() {
        let a = LocalityAccumulator {
            rows: BTreeMap::from([
                (
                    (8, 0),
                    vec![
                        (10, 1024, IoOperation::Read, Some(0)),
                        (10, 2048, IoOperation::Read, Some(2_000_000)),
                        (10, 4096, IoOperation::Write, Some(1_000_000)),
                        (10, 8192, IoOperation::Write, Some(4_000_000)),
                        (11, 512, IoOperation::Read, None),
                    ],
                ),
                (
                    (8, 1),
                    vec![(10, 65536, IoOperation::Read, Some(5_000_000))],
                ),
            ]),
        };
        let rows = a.finish();
        let d = &rows[&(8, 0)];
        assert_eq!(d.payload.iter().map(|b| b.read).sum::<u64>(), 3584);
        assert_eq!(d.payload.iter().map(|b| b.write).sum::<u64>(), 12288);
        assert_eq!(d.reuse.total.values, [2., 3.]);
        assert_eq!(d.reuse.total.missing, 3);
        assert_eq!(d.reuse.read.values, [2.]);
        assert_eq!(d.reuse.write.values, [3.]);
        assert!(rows[&(8, 1)].reuse.total.values.is_empty());
    }
}
