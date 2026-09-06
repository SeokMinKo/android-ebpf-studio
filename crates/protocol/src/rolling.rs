//! Fixed 64-observation rolling event rates. Each observation contributes its
//! payload and the gap from the previous same-device event. No service latency
//! is added to this elapsed-event clock.
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

pub const ROLLING_OBSERVATIONS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollingRate {
    pub payload_bytes: u64,
    pub duration_ns: u64,
    pub observations: usize,
}
impl RollingRate {
    pub fn mib_s(&self) -> Option<f64> {
        (self.duration_ns > 0)
            .then(|| self.payload_bytes as f64 * 1e9 / self.duration_ns as f64 / 1_048_576.)
    }
}

#[derive(Debug, Default)]
pub struct RollingRateAccumulator {
    samples: VecDeque<(Option<u64>, Option<u64>)>,
    duration: u128,
    bytes: u128,
    missing: usize,
}
impl RollingRateAccumulator {
    /// Missing time or payload invalidates a window until it has aged out.
    /// All 64 intervals must be observed; warm-up is never a measured zero.
    pub fn observe(&mut self, gap_ns: Option<u64>, payload: Option<u64>) -> Option<RollingRate> {
        self.samples.push_back((gap_ns, payload));
        self.duration += gap_ns.unwrap_or(0) as u128;
        self.bytes += payload.unwrap_or(0) as u128;
        self.missing += usize::from(gap_ns.is_none() || payload.is_none());
        if self.samples.len() > ROLLING_OBSERVATIONS {
            let (gap, payload) = self.samples.pop_front().unwrap();
            self.duration -= gap.unwrap_or(0) as u128;
            self.bytes -= payload.unwrap_or(0) as u128;
            self.missing -= usize::from(gap.is_none() || payload.is_none());
        }
        if self.samples.len() != ROLLING_OBSERVATIONS || self.missing > 0 {
            return None;
        }
        let rate = RollingRate {
            payload_bytes: u64::try_from(self.bytes).ok()?,
            duration_ns: u64::try_from(self.duration).ok()?,
            observations: self.samples.len(),
        };
        rate.mib_s().map(|_| rate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sixty_four_complete_intervals_keep_bytes_and_time_aligned() {
        let mut a = RollingRateAccumulator::default();
        assert!(a.observe(None, Some(999_999)).is_none());
        for _ in 0..63 {
            assert!(a.observe(Some(1_000_000), Some(1024)).is_none());
        }
        let rate = a.observe(Some(1_000_000), Some(1024)).unwrap();
        assert_eq!(rate.payload_bytes, 65536);
        assert_eq!(rate.duration_ns, 64_000_000);
        assert_eq!(rate.mib_s(), Some(0.9765625));
        let rate = a.observe(Some(2_000_000), Some(0)).unwrap();
        assert_eq!((rate.payload_bytes, rate.duration_ns), (64512, 65_000_000));
        assert!(a.observe(Some(1), None).is_none());
        for _ in 0..63 {
            assert!(a.observe(Some(1), Some(1)).is_none());
        }
        assert!(a.observe(Some(1), Some(1)).is_some());
    }
    #[test]
    fn zero_or_overflowing_denominators_do_not_become_rates() {
        for gap in [0, u64::MAX] {
            let mut a = RollingRateAccumulator::default();
            for _ in 0..64 {
                assert!(a.observe(Some(gap), Some(1024)).is_none());
            }
        }
    }
}
