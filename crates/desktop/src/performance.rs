use std::{collections::VecDeque, time::Duration};

use serde::Serialize;

pub const DEFAULT_SAMPLE_CAPACITY: usize = 600;
pub const UI_UPDATE_BUDGET: Duration = Duration::from_millis(33);

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct LatencySnapshot {
    pub samples: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
    pub over_budget: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UiPerformanceSnapshot {
    pub ui_update: LatencySnapshot,
    pub message_drain: LatencySnapshot,
    pub summary_rebuild: LatencySnapshot,
    pub explorer_rebuild: LatencySnapshot,
    pub pipeline_rebuild: LatencySnapshot,
    pub current_backlog: usize,
    pub peak_backlog: usize,
}

#[derive(Debug)]
struct LatencyWindow {
    values_us: VecDeque<u64>,
    capacity: usize,
    budget_us: u64,
    over_budget: u64,
}

impl LatencyWindow {
    fn new(capacity: usize, budget: Duration) -> Self {
        Self {
            values_us: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
            budget_us: duration_us(budget),
            over_budget: 0,
        }
    }

    fn observe(&mut self, elapsed: Duration) {
        let value = duration_us(elapsed);
        if self.values_us.len() == self.capacity {
            self.values_us.pop_front();
        }
        self.values_us.push_back(value);
        if value > self.budget_us {
            self.over_budget = self.over_budget.saturating_add(1);
        }
    }

    fn snapshot(&self) -> LatencySnapshot {
        if self.values_us.is_empty() {
            return LatencySnapshot::default();
        }
        let mut values = self.values_us.iter().copied().collect::<Vec<_>>();
        values.sort_unstable();
        LatencySnapshot {
            samples: values.len(),
            p50_ms: percentile_us(&values, 50) as f64 / 1_000.0,
            p95_ms: percentile_us(&values, 95) as f64 / 1_000.0,
            max_ms: values.last().copied().unwrap_or_default() as f64 / 1_000.0,
            over_budget: self.over_budget,
        }
    }
}

#[derive(Debug)]
pub struct UiPerformanceMonitor {
    ui_update: LatencyWindow,
    message_drain: LatencyWindow,
    summary_rebuild: LatencyWindow,
    explorer_rebuild: LatencyWindow,
    pipeline_rebuild: LatencyWindow,
    current_backlog: usize,
    peak_backlog: usize,
}

impl Default for UiPerformanceMonitor {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_SAMPLE_CAPACITY)
    }
}

impl UiPerformanceMonitor {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ui_update: LatencyWindow::new(capacity, UI_UPDATE_BUDGET),
            message_drain: LatencyWindow::new(capacity, Duration::from_millis(4)),
            summary_rebuild: LatencyWindow::new(capacity, Duration::from_millis(100)),
            explorer_rebuild: LatencyWindow::new(capacity, Duration::from_millis(100)),
            pipeline_rebuild: LatencyWindow::new(capacity, Duration::from_millis(100)),
            current_backlog: 0,
            peak_backlog: 0,
        }
    }

    pub fn observe_ui_update(&mut self, elapsed: Duration) {
        self.ui_update.observe(elapsed);
    }

    pub fn observe_message_drain(&mut self, elapsed: Duration, backlog: usize) {
        self.message_drain.observe(elapsed);
        self.current_backlog = backlog;
        self.peak_backlog = self.peak_backlog.max(backlog);
    }

    pub fn observe_summary_rebuild(&mut self, elapsed: Duration) {
        self.summary_rebuild.observe(elapsed);
    }

    pub fn observe_explorer_rebuild(&mut self, elapsed: Duration) {
        self.explorer_rebuild.observe(elapsed);
    }

    pub fn observe_pipeline_rebuild(&mut self, elapsed: Duration) {
        self.pipeline_rebuild.observe(elapsed);
    }

    pub fn snapshot(&self) -> UiPerformanceSnapshot {
        UiPerformanceSnapshot {
            ui_update: self.ui_update.snapshot(),
            message_drain: self.message_drain.snapshot(),
            summary_rebuild: self.summary_rebuild.snapshot(),
            explorer_rebuild: self.explorer_rebuild.snapshot(),
            pipeline_rebuild: self.pipeline_rebuild.snapshot(),
            current_backlog: self.current_backlog,
            peak_backlog: self.peak_backlog,
        }
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

fn duration_us(value: Duration) -> u64 {
    value.as_micros().min(u64::MAX as u128) as u64
}

fn percentile_us(sorted_values: &[u64], percentile: usize) -> u64 {
    let rank = sorted_values
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1)
        .min(sorted_values.len().saturating_sub(1));
    sorted_values[rank]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_window_is_bounded_and_uses_nearest_rank_percentiles() {
        let mut monitor = UiPerformanceMonitor::with_capacity(4);
        for millis in [1, 2, 3, 40, 50] {
            monitor.observe_ui_update(Duration::from_millis(millis));
        }

        let snapshot = monitor.snapshot().ui_update;
        assert_eq!(snapshot.samples, 4);
        assert_eq!(snapshot.p50_ms, 3.0);
        assert_eq!(snapshot.p95_ms, 50.0);
        assert_eq!(snapshot.max_ms, 50.0);
        assert_eq!(snapshot.over_budget, 2);
    }

    #[test]
    fn reset_clears_latency_and_backlog_history() {
        let mut monitor = UiPerformanceMonitor::with_capacity(2);
        monitor.observe_ui_update(Duration::from_millis(80));
        monitor.observe_message_drain(Duration::from_millis(5), 123);
        monitor.reset();

        assert_eq!(monitor.snapshot(), UiPerformanceSnapshot::default());
    }

    #[test]
    fn backlog_peak_does_not_fall_with_the_current_depth() {
        let mut monitor = UiPerformanceMonitor::with_capacity(2);
        monitor.observe_message_drain(Duration::from_millis(1), 200);
        monitor.observe_message_drain(Duration::from_millis(1), 5);

        let snapshot = monitor.snapshot();
        assert_eq!(snapshot.current_backlog, 5);
        assert_eq!(snapshot.peak_backlog, 200);
    }
}
