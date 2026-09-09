#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CategoryAxis {
    Command,
    Access,
    Size,
    Device,
    Process,
    File,
    Confidence,
}
impl CategoryAxis {
    fn label(self) -> &'static str {
        match self {
            Self::Command => "Command",
            Self::Access => "Access pattern",
            Self::Size => "Size class",
            Self::Device => "Device",
            Self::Process => "Process",
            Self::File => "File candidate set",
            Self::Confidence => "Attribution confidence",
        }
    }
    fn needs_graph(self) -> bool {
        matches!(self, Self::File | Self::Confidence)
    }
    fn key(self, io: &CompletedIo, graph: Option<&IoTransactionGraph>) -> String {
        match self {
            Self::Command => format!("{:?}", io.issue.operation),
            Self::Access => format!("{:?}", io.access_pattern),
            Self::Size => format!("{:?}", io.size_class),
            Self::Device => format!("{}:{}", io.issue.device_major, io.issue.device_minor),
            Self::Process => format!(
                "{}:{} / {} · PID {}",
                io.issue.device_major,
                io.issue.device_minor,
                io.issue.comm,
                identity_number(io.issuer_pid())
            ),
            Self::File => {
                let labels = graph
                    .map(block_file_origins)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|o| {
                        format!(
                            "{} [{}]",
                            o.path
                                .and_then(|p| p.path)
                                .unwrap_or_else(|| o.file.fallback_label()),
                            edge_confidence_label(o.confidence)
                        )
                    })
                    .collect::<std::collections::BTreeSet<_>>();
                format!(
                    "{}:{} / {}",
                    io.issue.device_major,
                    io.issue.device_minor,
                    if labels.is_empty() {
                        "<path unresolved>".into()
                    } else {
                        labels.into_iter().collect::<Vec<_>>().join(" | ")
                    }
                )
            }
            Self::Confidence => GroupBy::Confidence.key(io, graph),
        }
    }
}

// Category positions are built from the full filtered cohort, before sampling
// and before selection. A selected subset must never renumber its categories.
#[derive(Debug, Clone, Default)]
struct AxisCategories {
    labels: Vec<String>,
    positions: BTreeMap<String, usize>,
}
impl AxisCategories {
    fn build(engine: &AnalysisEngine, axis: AxisMetric) -> Self {
        let AxisMetric::Category(category) = axis else {
            return Self::default();
        };
        let labels: Vec<_> = engine
            .completed_ios()
            .iter()
            .map(|io| {
                let graph = category.needs_graph().then(|| engine.transaction_for(io));
                category.key(io, graph.as_ref())
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let positions = labels
            .iter()
            .enumerate()
            .map(|(i, label)| (label.clone(), i))
            .collect();
        Self { labels, positions }
    }
    fn value(
        &self,
        axis: AxisMetric,
        io: &CompletedIo,
        origin: u64,
        graph: Option<&IoTransactionGraph>,
    ) -> Option<f64> {
        if let AxisMetric::Category(category) = axis {
            self.positions
                .get(&category.key(io, graph))
                .map(|n| *n as f64)
        } else {
            axis.value(io, origin, graph)
        }
    }
    fn tick(&self, axis: AxisMetric, value: f64, step: f64) -> String {
        if axis == AxisMetric::AddressMB {
            return format!("{value:.6}").trim_end_matches('0').trim_end_matches('.').to_owned();
        }
        if axis == AxisMetric::TimeMs {
            return format!("{value:.9}").trim_end_matches('0').trim_end_matches('.').to_owned();
        }
        if matches!(axis, AxisMetric::Category(_)) {
            if (value - value.round()).abs() > 0.001 || value < 0. {
                return String::new();
            }
            self.labels
                .get(value.round() as usize)
                .map(|s| {
                    let short: String = s.chars().take(22).collect();
                    if s.chars().count() > 22 {
                        format!("{short}…")
                    } else {
                        short
                    }
                })
                .unwrap_or_default()
        } else {
            crate::graph_summary::summary_tick(value, step.abs()*4.)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CustomGeometry {
    #[default]
    Scatter,
    Line,
    Bar,
}
impl StudioApp {
    fn custom_geometry_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Draw as");
            for (value, label) in [
                (CustomGeometry::Scatter, "Scatter"),
                (CustomGeometry::Line, "Line"),
                (CustomGeometry::Bar, "Bar"),
            ] {
                ui.selectable_value(&mut self.custom_geometry, value, label);
            }
        });
        if self.custom_geometry != CustomGeometry::Scatter {
            ui.small("Lines follow ascending X within each color category. Bars represent individual displayed requests; equal X values overlap. Summary uses all original requests, without summing heights or display sampling.");
        }
    }
}

fn companion_distributions_ui(ui: &mut egui::Ui, s: &SelectionSummary) {
    if s.companion_distributions.is_empty() {
        return;
    }
    egui::CollapsingHeader::new("Paired distributions · current graph cohort").default_open(std::env::var_os("ANDROID_EBPF_QA_PAIRED_HISTOGRAM").is_some()).show(ui,|ui| {
        ui.small("Chunk, observed device QD and numeric graph axes use exactly this graph's I/O selection. Unmeasured values are counted separately. Each panel has its own direction, histogram, CDF and percentile controls.");
        for slot in 0..2 {ui.push_id(("companion",slot),|ui| {
            let id=ui.id().with("axis");
            let default=if slot==0 {AxisMetric::ChunkKiB.label()}else{AxisMetric::IssueQueueDepth.label()};
            let mut axis=ui.data_mut(|d|d.get_temp::<String>(id).unwrap_or(default.into()));
            if !s.companion_distributions.contains_key(&axis) {axis=s.companion_distributions.keys().next().unwrap().clone();}
            egui::ComboBox::from_id_salt("companion-axis").selected_text(&axis).show_ui(ui,|ui| {for key in s.companion_distributions.keys(){ui.selectable_value(&mut axis,key.clone(),key);}});
            ui.data_mut(|d|d.insert_temp(id,axis.clone()));
            metric_distribution_ui(ui,&s.companion_distributions[&axis],&axis);
        });}
    });
}

#[cfg(test)]
mod custom_axes_tests {
    use super::*;
    use android_ebpf_protocol::StorageEvent;
    #[test]
    fn category_selection_preserves_full_cohort_positions_and_device_identity() {
        let mut source = AnalysisEngine::new();
        for (id, pid, minor) in [(1, 1, 0), (2, 2, 0), (3, 1, 1)] {
            source.ingest(StorageEvent::BlockIssue(
                android_ebpf_protocol::BlockIssue {
                    ts_ns: id * 1000,
                    request_id: id,
                    device_major: 8,
                    device_minor: minor,
                    sector: 0,
                    sectors: 8,
                    bytes: 4096,
                    operation: IoOperation::Read,
                    pid,
                    tid: pid,
                    cpu: 0,
                    comm: "same".into(),
                },
            ));
            source.ingest(StorageEvent::BlockComplete(
                android_ebpf_protocol::BlockComplete {
                    cpu: None,
                    ts_ns: id * 1000 + 100,
                    request_id: id,
                    device_major: 8,
                    device_minor: minor,
                    status: 0,
                },
            ));
        }
        let x = AxisMetric::Category(CategoryAxis::Process);
        let labels = AxisCategories::build(&source, x);
        assert_eq!(labels.labels.len(), 3);
        let s = compute_selection(
            &source,
            SelectionRequest::Rectangle {
                min: [1.9, 0.],
                max: [2.1, 10.],
            },
            x,
            AxisMetric::ChunkKiB,
            0,
        );
        assert_eq!(s.keys.iter().map(|k| k.0).collect::<Vec<_>>(), [3]);
        assert_eq!(s.companion_distributions["Chunk (KiB)"].total.values, [4.]);
        assert_eq!(
            s.categories["Axis: Process"]
                .values()
                .map(|v| v.0)
                .sum::<u64>(),
            1
        );
        let y = AxisMetric::Category(CategoryAxis::Command);
        let s = compute_selection(
            &source,
            SelectionRequest::Rectangle {
                min: [f64::NEG_INFINITY; 2],
                max: [f64::INFINITY; 2],
            },
            x,
            y,
            0,
        );
        assert_eq!(s.keys.len(), 3);
        assert!(s.metric.total.values.is_empty());
        assert_eq!(s.metric.total.missing, 0);
        assert_eq!(s.categories["Axis: Command"]["Read"].0, 3);
        let same = compute_selection(
            &source,
            SelectionRequest::Rectangle {
                min: [f64::NEG_INFINITY; 2],
                max: [f64::INFINITY; 2],
            },
            y,
            y,
            0,
        );
        assert_eq!(same.categories["Axis: Command"]["Read"].0, 3);
    }
}

#[cfg(test)]
mod mb_tick_regression {
    use super::*;
    #[test]
    fn narrow_time_ticks_keep_adjacent_instants_distinct() {
        let categories=AxisCategories::default();
        let labels:Vec<_>=(7290..=7460).step_by(10).map(|v|categories.tick(AxisMetric::TimeMs,v as f64,10.)).collect();
        assert_eq!(labels.iter().collect::<std::collections::BTreeSet<_>>().len(),labels.len(),"distinct 10 ms ticks must not repeat");
    }
    #[test]
    fn adjacent_mb_ticks_do_not_collapse_to_one_abbreviation() {
        let categories = AxisCategories::default();
        assert_ne!(categories.tick(AxisMetric::AddressMB,45615.0,1.), categories.tick(AxisMetric::AddressMB,45616.0,1.));
        assert_eq!(categories.tick(AxisMetric::AddressMB,45615.000512,0.000512), "45615.000512");
        assert_eq!(categories.tick(AxisMetric::AddressMB,45615.0,1.), "45615");
    }
}
