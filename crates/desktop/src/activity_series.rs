// Display resolution only: every level contains original samples, never means
// or synthetic zeroes. Analysis, interval filters and rankings use full bins.
struct ActivitySeries {
    levels: Vec<Vec<egui_plot::PlotPoint>>,
    y_bounds: [f64; 2],
}

impl ActivitySeries {
    fn new(points: Vec<egui_plot::PlotPoint>) -> Self {
        let y_bounds = points
            .iter()
            .fold([f64::INFINITY, f64::NEG_INFINITY], |[low, high], p| {
                [low.min(p.y), high.max(p.y)]
            });
        let mut levels = vec![points];
        while levels.last().unwrap().len() > 256 {
            let coarse = levels
                .last()
                .unwrap()
                .chunks(16)
                .flat_map(|chunk| {
                    let mut positions = vec![0, chunk.len() - 1];
                    positions.push(
                        (0..chunk.len())
                            .min_by(|&a, &b| chunk[a].y.total_cmp(&chunk[b].y))
                            .unwrap(),
                    );
                    positions.push(
                        (0..chunk.len())
                            .max_by(|&a, &b| chunk[a].y.total_cmp(&chunk[b].y))
                            .unwrap(),
                    );
                    positions.sort_unstable();
                    positions.dedup();
                    positions.into_iter().map(|i| chunk[i]).collect::<Vec<_>>()
                })
                .collect();
            levels.push(coarse);
        }
        Self { levels, y_bounds }
    }

    fn full(&self) -> &[egui_plot::PlotPoint] {
        &self.levels[0]
    }

    fn visible(&self, x: [f64; 2], columns: usize) -> &[egui_plot::PlotPoint] {
        let budget = columns.max(1).saturating_mul(4);
        for (i, level) in self.levels.iter().enumerate() {
            // Keep boundary neighbors so markers intersecting the clip edge do
            // not disappear. Samples stay ordered and preserve time gaps.
            let start = level.partition_point(|p| p.x < x[0]).saturating_sub(1);
            let end = level
                .partition_point(|p| p.x <= x[1])
                .saturating_add(1)
                .min(level.len());
            let points = &level[start.min(end)..end];
            if points.len() <= budget || i + 1 == self.levels.len() {
                return points;
            }
        }
        &[]
    }
}

#[cfg(test)]
mod activity_series_tests {
    use super::*;

    #[test]
    fn dense_render_keeps_original_extrema_endpoints_and_reveals_all_on_zoom() {
        let points: Vec<_> = (0..100_000)
            .map(|i| {
                egui_plot::PlotPoint::new(
                    i as f64 + 0.5,
                    match i {
                        12_345 => 999.0,
                        54_321 => -10.0,
                        _ => 2.0,
                    },
                )
            })
            .collect();
        let series = ActivitySeries::new(points.clone());
        let displayed = series.visible([0.0, 100_000.0], 800);
        assert!(displayed.len() <= 3_200);
        for index in [0, 12_345, 54_321, 99_999] {
            assert!(
                displayed.contains(&points[index]),
                "extremum/endpoint {index} lost"
            );
        }
        assert!(displayed.windows(2).all(|w| w[0].x < w[1].x));
        assert!(displayed.iter().all(|p| points[(p.x - 0.5) as usize] == *p));
        let zoom = series.visible([12_340.0, 12_350.0], 800);
        assert_eq!(zoom, &points[12_339..12_351]);
        assert_eq!(series.full(), points.as_slice());
    }

    #[test]
    fn sparse_data_and_gaps_are_not_interpolated_or_filled_with_zero() {
        let points = vec![
            egui_plot::PlotPoint::new(0.5, 3.0),
            egui_plot::PlotPoint::new(99.5, 7.0),
        ];
        let series = ActivitySeries::new(points.clone());
        assert_eq!(series.visible([0.0, 100.0], 800), points.as_slice());
        assert_eq!(series.y_bounds, [3.0, 7.0]);
        assert!(
            ActivitySeries::new(vec![])
                .visible([0.0, 1.0], 800)
                .is_empty()
        );
    }
}
