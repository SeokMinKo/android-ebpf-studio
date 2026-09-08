impl StudioApp {
    fn poll_graph_summary(&mut self) {
        if self.selection.summary.is_some() || self.selection.pending.is_some() {
            self.selection.all_pending=None;
            return;
        }
        let signature = (self.analysis_generation, self.x_axis, self.y_axis);
        let live=self.is_running();
        if self.selection.all_summary.as_ref().is_some_and(|v| (v.1,v.2)!=(signature.1,signature.2) || (!live && v.0!=signature.0)) {
            self.selection.all_summary = None;
        }
        if self.selection.all_pending.as_ref().is_some_and(|(g,x,y,_)| (*x,*y)!=(signature.1,signature.2) || (!live && *g!=signature.0)) {
            self.selection.all_pending=None;
        }
        if let Some((g,x,y,rx)) = &self.selection.all_pending {
            match rx.try_recv() {
                Ok(summary) => {
                    if (*g,*x,*y) == signature || (live && (*x,*y)==(signature.1,signature.2)) {
                        self.selection.all_summary=Some((*g,*x,*y,summary));
                        self.selection.all_refresh=Some(Instant::now());
                    }
                    self.selection.all_pending=None;
                }
                Err(crossbeam_channel::TryRecvError::Disconnected) => self.selection.all_pending=None,
                Err(crossbeam_channel::TryRecvError::Empty) => {}
            }
        }
        let due=self.selection.all_summary.is_none() || (live
            && self.selection.all_summary.as_ref().is_some_and(|v|v.0!=signature.0)
            && self.selection.all_refresh.is_none_or(|t|t.elapsed()>=LIVE_ANALYSIS_REFRESH));
        if due && self.selection.all_pending.is_none() {
            let engine=self.analysis().select_completed(|_|true);
            let origin=self.time_origin();
            let bw=self.bandwidth_context(None);
            let width=self.window_width_ms;
            let (g,x,y)=signature;
            let (tx,rx)=bounded(1);
            let cancelled=Arc::new(AtomicBool::new(false));
            self.selection.all_pending=Some((g,x,y,SummaryWork {receiver:rx,cancelled:Arc::clone(&cancelled)}));
            std::thread::spawn(move || {
                let s=compute_graph_selection_cancellable(&engine,SelectionRequest::Rectangle {min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]},[x,y],origin,bw,width,Some(&cancelled));
                if !cancelled.load(Ordering::Relaxed) && let Some(s)=s {let _=tx.send(s);}
            });
        }
    }
}

#[cfg(test)]
mod summary_layout_tests {
    use super::*;
    #[test]
    fn wide_lba_histogram_tick_text_stays_within_the_summary_panel() {
        let mut metric=crate::graph_summary::MetricDistribution::default();
        metric.total.values=vec![2_629_824.,987_000_000.];
        for width in [280.,340.] {
            let ctx=egui::Context::default();
            let mut checked=0;
            for _ in 0..3 {
                let mut output=ctx.run_ui(egui::RawInput{screen_rect:Some(egui::Rect::from_min_size(egui::Pos2::ZERO,egui::vec2(width,1000.))),..Default::default()},|root| {
                    egui::CentralPanel::default().show(root,|ui|metric_distribution_ui(ui,&metric,"Sector"));
                });
                output.textures_delta.clear();
                for clipped in &output.shapes {
                    if let egui::Shape::Text(text)=&clipped.shape {
                        let label=text.galley.text();
                        if label.ends_with('M') || label.ends_with('G') {
                            checked+=1;
                            assert!(clipped.shape.visual_bounding_rect().right()<=clipped.clip_rect.right()+1.,"{width}px Summary clips {label}");
                        }
                    }
                }
            }
            assert!(checked>0,"must inspect rendered axis labels");
        }
    }
}

fn graph_distribution_ui(ui: &mut egui::Ui, summary: &SelectionSummary) {
    constrain_summary_width(ui);
    let Some(axis)=summary.metric_axis else {return;};
    ui.strong(format!("{} · distribution",axis.label()));
    if summary.timeline.is_some() {ui.small("Timeline cohort: measured issue-to-completion latency distribution and request categories. Unpaired completions remain in request/byte totals; their missing latency is excluded from percentiles.");}
    ui.small(if summary.window_series.as_ref().is_some_and(|s|s.metric.device_activity()) {"Full-source device activity, before display sampling. Exact nearest-rank percentiles of available activity samples."}else{"Retained graph cohort, before display sampling. Exact nearest-rank percentiles; unmeasured values are excluded."});
    match axis {
        AxisMetric::IssueQueueDepth=> {ui.small("Observed per-device requests in flight immediately after issue, before analysis filters. Perfetto reconstructs uniquely paired intervals; unpaired/sampled requests are absent. This is not hardware or unsampled device QD.");}
        AxisMetric::QueueDepth=> {ui.small("Legacy observed depth after completion across all devices. Use QD at issue for send-Q comparisons.");}
        AxisMetric::IssueGapMs|AxisMetric::CompletionGapMs=> {ui.small("Gap from the preceding same-device observed event before analysis filters. First event is unmeasured; sampled/lost events can enlarge gaps. Points are placed at completion time.");}
        AxisMetric::LatencyPerKiB=> {ui.small("Measured issue-to-completion latency / Read or Write size in KiB. Zero size and non-transfer commands are excluded.");}
        AxisMetric::RollingC2cBandwidth|AxisMetric::RollingD2dBandwidth=> {ui.small("64 consecutive same-device observed event gaps and their Read+Write payload, before analysis filters. Warm-up/missing gaps/unknown payload/zero duration are unavailable. Not unsampled kernel throughput. Points use completion time; Read/Write tabs group the terminal request operation, not separate payload rates. Filtered endpoints retain their original device-wide rolling context.");}
        _=>{}
    }
    if matches!(axis, AxisMetric::Sector | AxisMetric::AddressKiB | AxisMetric::AddressMB) {
        if summary.address_distributions.is_empty() {ui.label("No LBA samples in this cohort.");}
        let page=target_page(ui,"lba-distribution-device",summary.address_distributions.len());
        // Each device gets an independent distribution; numerical LBA equality
        // across devices does not imply the same storage location.
        for (device,dist) in summary.address_distributions.iter().skip(page*20).take(20) {
            ui.push_id(device,|ui| {
                ui.strong(format!("Device {}:{}",device.0,device.1));
                metric_distribution_ui(ui,dist,axis.label());
                ui.collapsing("LBA violin · binned density",|ui| violin_ui(ui,&dist.total,axis.label()));
                if let Some(locality)=summary.locality.get(device) {
                    egui::CollapsingHeader::new("Spatial payload / temporal reuse").default_open(std::env::var("ANDROID_EBPF_QA_LOCALITY").is_ok()).show(ui,|ui| {
                        constrain_summary_width(ui);
                        ui.add(egui::Label::new(RichText::new("Read / Write payload by starting LBA").strong()).wrap());
                        summary_plot(ui,ui.id().with("spatial-payload")).height(160.).legend(Legend::default())
                            .x_axis_label("Starting sector (512 B)").y_axis_label("Payload (MiB)")
                            .x_grid_spacer(summary_grid).x_axis_formatter(summary_axis_tick)
                            .show(ui,|plot| {
                                for (write,label,color) in [(false,"Read",accent()),(true,"Write",green())] {
                                    let bars=locality.payload.iter().map(|b| {
                                        let width=(b.upper-b.lower).max(1.);
                                        egui_plot::Bar::new((b.lower+b.upper)*0.5+if write {width*0.2}else{-width*0.2},if write {b.write}else{b.read} as f64/1_048_576.).width(width*0.4)
                                    }).collect();
                                    plot.bar_chart(egui_plot::BarChart::new(label,bars).color(color));
                                }
                            });
                        ui.small("Whole R/W payload goes to its starting-address bin; this is traffic locality, not unique occupied space. Discard/Flush/Other extents are excluded.");
                        ui.collapsing("Spatial payload values",|ui| {for b in &locality.payload {ui.label(format!("[{:.0}, {:.0}): R {} / W {} bytes",b.lower,b.upper,b.read,b.write));}ui.small("The final upper boundary is inclusive.");});
                        ui.add(egui::Label::new(RichText::new("Time until the same starting LBA is accessed again").strong()).wrap());
                        ui.small("Same device, same Read/Write direction and same starting sector within this graph cohort. Measured issue timestamps are sorted; first visits and missing timestamps are excluded. Partial range overlap alone is not a repeat here; use Address access counts for overlap.");
                        metric_distribution_ui(ui,&locality.reuse,"Same-LBA reuse gap (ms)");
                        summary_plot(ui,ui.id().with("temporal-locality")).height(140.).legend(Legend::default())
                            .x_axis_label("Starting sector (512 B)").y_axis_label("Reuse gap (ms)")
                            .x_grid_spacer(summary_grid).x_axis_formatter(summary_axis_tick)
                            .show(ui,|plot| {for (direction,label,color) in [(0.,"Read",accent()),(1.,"Write",green())] {
                                let rows:Vec<_>=locality.reuse_points.iter().filter(|r|r[2]==direction).collect();
                                let stride=rows.len().div_ceil(1000).max(1);
                                let points:Vec<[f64;2]>=rows.into_iter().step_by(stride).map(|r|[r[0],r[1]]).collect();
                                plot.points(Points::new(label,points).radius(2.).color(color));
                            }});
                        ui.small("Scatter draws at most 1,000 points per direction; histogram and CSV use all measured reuse gaps.");
                    });
                }
            });
        }
        ui.separator();
        ui.strong("Address access counts");
        ui.small("512-byte sector intervals [start, end). Read and Write counts per address, split by device. Partial overlaps are split; adjacent requests do not overlap.");
        let repeated:Vec<_>=summary.address_counts.iter().filter(|r|r.repeated()).collect();
        ui.label(format!("{} accessed ranges · {} ranges accessed more than once",summary.address_counts.len(),repeated.len()));
        let id=ui.id().with("only-repeated-addresses");
        let mut only_repeated=ui.data_mut(|d|d.get_temp::<bool>(id).unwrap_or(true));
        ui.checkbox(&mut only_repeated,"Only repeated address access");
        ui.data_mut(|d|d.insert_temp(id,only_repeated));
        let rows:Vec<_>=summary.address_counts.iter().filter(|r|!only_repeated||r.repeated()).collect();
        ui.collapsing("Read / Write counts by address",|ui| {
            for device in summary.address_distributions.keys() {
                studio_plot(ui.id().with(("address-repeat",device))).height(150.)
                    .grid_spacing(45.0..=120.0).x_axis_formatter(|mark,_|compact_tick(mark.value))
                    .x_axis_label(format!("Device {}:{} · sector",device.0,device.1))
                    .y_axis_label("Access count").legend(Legend::default())
                    .show(ui,|plot| {
                        for (label,color,write) in [("Read",accent(),false),("Write",green(),true)] {
                            let points:Vec<[f64;2]>=rows.iter().filter(|r| &r.device==device).flat_map(|r| {
                                let count=if write {r.writes}else{r.reads} as f64;
                                [[r.start_sector as f64,0.],[r.start_sector as f64,count],[r.end_sector as f64,count],[r.end_sector as f64,0.]]
                            }).collect();
                            plot.line(Line::new(label,points).color(color));
                        }
                    });
            }
        });
        let page=target_page(ui,"address-count-pages",rows.len());
        egui::Grid::new("address-counts").striped(true).show(ui,|ui| {
            for label in ["Device / LBA [start,end)","Read","Write"] {ui.strong(label);} ui.end_row();
            for r in rows.into_iter().skip(page*20).take(20) {
                ui.label(format!("{}:{} / {}–{}",r.device.0,r.device.1,r.start_sector,r.end_sector));
                ui.label(r.reads.to_string());ui.label(r.writes.to_string());ui.end_row();
            }
        });
    } else if let Some(series)=&summary.window_series {
        if series.metric==crate::window_series::WindowMetric::BurstPayload {
            ui.small("One final payload total per activity burst, not one sample per cumulative curve point. Bursts reset after device-wide Idle > 0.5 ms. First I/O payload is included. R/W filters affect payload, never device-wide burst boundaries.");
            if !series.activity_known {ui.colored_label(amber(),"Burst distribution unavailable: complete device activity is not proven.");}
        } else if series.metric.intervals() {
            ui.small("Each positive continuous interval contributes one duration sample, independent of I/O count. Analysis boundaries clip intervals. Read/Write durations are not defined separately for shared device activity.");
            if !series.activity_known {ui.colored_label(amber(),"Interval distribution unavailable: full device activity coverage is not proven. No zero-duration samples are invented.");}
        } else {ui.small(format!("{} time windows; each window contributes one sample. Empty windows are included, partial windows use their actual duration. Payload excludes non-R/W extents.",series.samples.len()));}
        metric_distribution_named_ui(ui,&summary.metric,axis.label(),series.metric.population());
    } else if matches!(axis,AxisMetric::Category(_)) {
        ui.small("Categorical axis: use count or payload shares below. Percentiles of category positions are not defined.");
    } else {
        metric_distribution_ui(ui,&summary.metric,axis.label());
    }
    companion_distributions_ui(ui,summary);
    category_distribution_ui(ui,summary);
    if ui.button("Export graph summary CSV").clicked()
        && let Some(path)=rfd::FileDialog::new().set_file_name("graph-summary.csv").save_file() {
        match write_graph_summary_csv(&path,summary) {
            Ok(()) => {ui.label(format!("Saved {}",path.display()));}
            Err(error) => {ui.colored_label(red(),error.to_string());}
        }
    }
}

fn category_distribution_ui(ui:&mut egui::Ui,s:&SelectionSummary) {
    egui::CollapsingHeader::new("Cohort categories · count / payload share").default_open(matches!(s.metric_axis,Some(AxisMetric::Category(_))) || std::env::var("ANDROID_EBPF_QA_SUMMARY_CATEGORIES").is_ok()).show(ui,|ui| {
        constrain_summary_width(ui);
        let id=ui.id().with("category-dimension");
        let mut dimension=ui.data_mut(|d|d.get_temp::<String>(id).unwrap_or_else(||std::env::var("ANDROID_EBPF_QA_CATEGORY").unwrap_or_else(|_|if let Some(AxisMetric::Category(c))=s.metric_axis {format!("Axis: {}",c.label())}else{"Command".into()})));
        egui::ComboBox::from_id_salt("category-dimension").selected_text(&dimension).show_ui(ui,|ui| {
            for key in s.categories.keys() {ui.selectable_value(&mut dimension,key.clone(),key);}
        });
        ui.data_mut(|d|d.insert_temp(id,dimension.clone()));
        let id=ui.id().with("category-weight");
        let mut payload=ui.data_mut(|d|d.get_temp::<bool>(id).unwrap_or(false));
        ui.horizontal(|ui| {ui.selectable_value(&mut payload,false,"I/O count");ui.selectable_value(&mut payload,true,"R/W payload bytes");});
        ui.data_mut(|d|d.insert_temp(id,payload));
        let Some(rows)=s.categories.get(&dimension) else {return;};
        let mut values:Vec<_>=rows.iter().map(|(k,v)|(k,if payload {v.1}else{v.0})).collect();
        values.sort_by(|a,b|b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        let total:u64=values.iter().map(|v|v.1).sum();
        ui.small(format!("Denominator: {total} {} across {} categories",if payload {"payload bytes"}else{"memberships"},values.len()));
        if dimension.contains("membership") {ui.colored_label(amber(),"One request can belong to multiple file candidates or layers. Shares use memberships, not unique global I/O; candidate payload is not exclusive attribution.");}
        else {ui.small("Each graph request belongs to one category. Payload excludes Discard/Flush/Other extents.");}
        if dimension=="Chunk size" {ui.small("Exact request bytes, without size-class grouping or KiB rounding. Use the shared Read/Write filter for direction-specific shares.");}
        if dimension=="Command / access / size" {let threshold=android_ebpf_protocol::LARGE_IO_BYTES/1024;ui.small(format!("Joint command, observed access pattern and size class. Small < {threshold} KiB; Large ≥ {threshold} KiB. Unknown access remains separate."));}
        if total==0 {ui.label("No values for this weighting.");return;}
        let mut pie:Vec<_>=values.iter().take(4).map(|(k,v)|((*k).clone(),*v)).collect();
        if values.len()>4 {pie.push((format!("Remaining {} categories",values.len()-4),values.iter().skip(4).map(|v|v.1).sum()));}
        // Long identities stay in the pageable table, while slice numbers give
        // stable non-hover references without widening the Summary panel.
        let labels:Vec<_>=pie.iter().enumerate().map(|(i,_)|format!("{}",i+1)).collect();
        selection_pie(ui,&pie.iter().map(|v|v.1).collect::<Vec<_>>(),&labels.iter().map(String::as_str).collect::<Vec<_>>());
        for (i,(label,_)) in pie.iter().enumerate() {ui.label(format!("{} · {label}",i+1));}
        let page=target_page(ui,"category-all-rows",values.len());
        for (label,value) in values.into_iter().skip(page*20).take(20) {ui.label(format!("{label}: {value} ({:.2}%)",value as f64*100./total as f64));}
    });
}

fn metric_distribution_ui(ui:&mut egui::Ui, metric:&crate::graph_summary::MetricDistribution, unit:&str) {
    metric_distribution_named_ui(ui,metric,unit,"I/O count");
}
fn metric_distribution_named_ui(ui:&mut egui::Ui, metric:&crate::graph_summary::MetricDistribution, unit:&str,sample_label:&str) {
    constrain_summary_width(ui);
    let id=ui.id().with("distribution-direction");
    let mut direction=ui.data_mut(|d|d.get_temp::<usize>(id).unwrap_or(0));
    ui.horizontal_wrapped(|ui| {
        for (i,label) in ["Total","Read","Write","Other"].iter().enumerate() {ui.selectable_value(&mut direction,i,*label);}
    });
    ui.data_mut(|d|d.insert_temp(id,direction));
    let d=[&metric.total,&metric.read,&metric.write,&metric.other][direction];
    distribution_ui(ui,d,unit,sample_label);
}
fn distribution_ui(ui:&mut egui::Ui,d:&crate::graph_summary::Distribution,unit:&str,sample_label:&str) {
    constrain_summary_width(ui);
    ui.label(format!("n={} · unmeasured={}",d.values.len(),d.missing));
    if d.values.is_empty() {ui.label("No measured samples; percentiles unavailable.");return;}
    let percentile_table = |ui:&mut egui::Ui| {
        egui::Grid::new(ui.id().with("metric-percentiles")).striped(true).show(ui,|ui| {
            for pair in [[0,90],[25,95],[50,99],[75,100]] {
                for p in pair {
                    ui.label(if p==0 {"Min".into()} else if p==100 {"Max".into()} else {format!("P{p}")});
                    let value=d.percentile(p).unwrap();
                    ui.label(if value.fract()==0. {format!("{value:.0}")} else {format!("{value:.4}")});
                }
                ui.end_row();
            }
        });
    };
    if unit=="Sector" || unit=="Address (KiB)" {ui.collapsing("Address percentiles",percentile_table);} else {percentile_table(ui);}
    let bins=d.histogram(16);
    summary_plot(ui,ui.id().with("metric-histogram")).height(160.).allow_zoom(false).allow_drag(false)
        .grid_spacing(35.0..=120.0).x_grid_spacer(summary_grid).x_axis_formatter(summary_axis_tick)
        .x_axis_label(unit).y_axis_label(sample_label).show(ui,|plot| {
            let bars=bins.iter().map(|b|egui_plot::Bar::new((b.lower+b.upper)*0.5,b.count as f64).width(b.plot_width())).collect();
            plot.bar_chart(egui_plot::BarChart::new(sample_label,bars).color(accent()));
        });
    ui.small("Equal-width bins [lower, upper); final bin includes maximum. Constant samples form one bin.");
    ui.collapsing("Histogram values",|ui| {
        for (i,b) in bins.iter().enumerate() {ui.label(format!("[{:.4}, {:.4}{}: {} ({:.1}%)",b.lower,b.upper,if i+1==bins.len(){"]"}else{")"},b.count,b.count as f64*100./d.values.len() as f64));}
    });
    let open=std::env::var("ANDROID_EBPF_QA_SUMMARY_CDF").is_ok();
    egui::CollapsingHeader::new("Cumulative distribution / sorted rank").default_open(open).show(ui,|ui| {
        let id=ui.id().with("cumulative-view");
        let mut rank=ui.data_mut(|d|d.get_temp::<bool>(id).unwrap_or_else(||std::env::var("ANDROID_EBPF_QA_SUMMARY_RANK").is_ok()));
        ui.horizontal(|ui| {ui.selectable_value(&mut rank,false,"CDF");ui.selectable_value(&mut rank,true,"Sorted rank");});
        ui.data_mut(|d|d.insert_temp(id,rank));
        let points=if rank {d.rank_points(512)}else{d.cdf_points(512)};
        summary_plot(ui,ui.id().with("cumulative-plot")).height(150.).allow_zoom(false).allow_drag(false)
            .x_axis_label(if rank {"Rank (1-based)"}else{unit})
            .y_axis_label(if rank {unit.to_owned()}else{format!("{sample_label} ≤ value (%)")})
            .x_grid_spacer(summary_grid).x_axis_formatter(summary_axis_tick)
            .show(ui,|plot| {plot.line(Line::new(if rank {"Sorted samples"}else{"Empirical CDF"},points).color(accent()));});
        ui.small("CDF includes all tied values. At most 512 original values are drawn; connecting lines interpolate the display. CSV contains every value, rank and exact cumulative count.");
    });
}

fn violin_ui(ui:&mut egui::Ui,d:&crate::graph_summary::Distribution,unit:&str) {
    let bins=d.histogram(24);
    let maximum=bins.iter().map(|b|b.count).max().unwrap_or(1).max(1) as f64;
    let mut shape:Vec<[f64;2]>=bins.iter().map(|b|[(b.lower+b.upper)*0.5,b.count as f64/maximum]).collect();
    shape.extend(bins.iter().rev().map(|b|[(b.lower+b.upper)*0.5,-(b.count as f64)/maximum]));
    summary_plot(ui,ui.id().with("violin")).height(130.).x_axis_label(unit).y_axis_label("Relative density")
        .grid_spacing(35.0..=120.0).x_grid_spacer(summary_grid).x_axis_formatter(summary_axis_tick)
        .allow_zoom(false).allow_drag(false).show(ui,|plot| {
            if shape.len()>2 {plot.polygon(egui_plot::Polygon::new("Mirrored histogram density",shape).fill_color(accent().gamma_multiply(0.35)));}
        });
    ui.small("Mirrored normalized histogram, no inferred kernel smoothing. Histogram table gives exact counts.");
}

fn constrain_summary_width(ui:&mut egui::Ui) {
    let width=(ui.clip_rect().right()-ui.max_rect().left()).min(ui.available_width()).max(64.);
    ui.set_max_width(width);
}
fn summary_plot(ui:&egui::Ui,id:impl egui::AsId)->egui_plot::Plot<'static> {
    studio_plot(id).width((ui.clip_rect().right()-ui.max_rect().left()).min(ui.available_width()).max(64.))
}
fn summary_axis_tick(mark:egui_plot::GridMark,range:&std::ops::RangeInclusive<f64>)->String {
    if mark.value>*range.end()-(range.end()-range.start())*0.06 {String::new()}else{compact_tick(mark.value)}
}

fn compact_tick(value:f64)->String {
    let scaled=|divisor:f64,suffix:&str| {let n=value/divisor;if n.fract()==0. {format!("{n:.0}{suffix}")}else{format!("{n:.1}{suffix}")}};
    if value.abs()>=1e9 {scaled(1e9,"G")}
    else if value.abs()>=1e6 {scaled(1e6,"M")}
    else if value.abs()>=1e3 {scaled(1e3,"k")}
    else if value.fract()==0. {format!("{value:.0}")}
    else {format!("{value:.2}")}
}

fn summary_grid(input:egui_plot::GridInput)->Vec<egui_plot::GridMark> {
    let range=input.bounds.1-input.bounds.0;
    if !range.is_finite() || range<=0. {return Vec::new();}
    let raw=range/4.;
    let power=10f64.powf(raw.log10().floor());
    let fraction=raw/power;
    let step=power*if fraction<1.5 {1.} else if fraction<3.5 {2.} else if fraction<7.5 {5.} else {10.};
    let first=(input.bounds.0/step).ceil()*step;
    (0..10).map(|i|first+i as f64*step).take_while(|v|*v<=input.bounds.1)
        .map(|value|egui_plot::GridMark{value,step_size:range}).collect()
}

fn write_graph_summary_csv(path:&std::path::Path,s:&SelectionSummary)->anyhow::Result<()> {
    let mut writer=csv::Writer::from_path(path)?;
    writer.write_record(["kind","metric","group","lower_or_percentile","upper","count_or_value","unit"])?;
    let metric=s.metric_axis.map_or("Unknown",AxisMetric::label);
    writer.write_record(["definition",metric,"all","histogram [lower,upper); final upper inclusive","","exact nearest-rank percentiles; retained graph cohort","not kernel aggregate"])?;
    writer.write_record(["population",metric,"all","","",&s.keys.len().to_string(),"full-resolution graph requests"])?;
    writer.write_record(["unplottable_source",metric,"all","","",&s.unplottable_rows.to_string(),"filtered source requests with missing axes"])?;
    if let Some(t)=&s.timeline {
        writer.write_record(["timeline_definition",t.mode.label(),"all","","","Issue/complete events, request lifetime only when issue measured. Rectangle selects completion endpoints and shown rows. Latency histogram excludes missing duration; request/byte totals retain unpaired completions.","timestamps ns; one unique request per row export"])?;
        for p in &t.points {writer.write_record(["timeline_request",t.mode.label(),&format!("{} / {:?}",t.lanes[p.row-1],p.key),&p.start_ns.map_or("unavailable".into(),|v|v.to_string()),&p.end_ns.to_string(),operation_label(p.operation),"issue/complete ns"])?;}
        if t.mode==TimelineMode::Cpus {for p in &t.points {
            if let (Some(row),Some(ts))=(p.issue_row,p.start_ns) {writer.write_record(["timeline_cpu_event","Issue",&format!("{} / {:?}",t.lanes[row-1],p.key),&ts.to_string(),"",operation_label(p.operation),"timestamp ns; measured CPU lane or explicitly unmeasured"])?;}
            writer.write_record(["timeline_cpu_event","Complete",&format!("{} / {:?}",t.lanes[p.row-1],p.key),&p.end_ns.to_string(),"",operation_label(p.operation),"timestamp ns; measured CPU lane or explicitly unmeasured"])?;
        }}
    }
    if let Some(b)=&s.host_bw {
        writer.write_record(["definition","Host BW","all",&b.start_ns.to_string(),&b.end_ns.to_string(),"Inclusive completion-counted full Read + Write payload; Discard/Flush/Other extents excluded; issue-to-completion activity union includes all operations and processes, clipped to range; multiple devices use any-device-active wall time","ns"])?;
        writer.write_record(["excluded_extent_bytes","Host BW","Other","","",&b.bytes.other.to_string(),"bytes, not transferred payload"])?;
        writer.write_record(["coverage","Host BW","all","","",&b.coverage,"detail cohort, not kernel throughput"])?;
        for (label,value) in [("analysis_time",Some(b.duration_ns)),("busy",b.busy_ns),("idle",b.idle_ns),("observed_busy_lower_bound",Some(b.observed_busy_ns))] {
            writer.write_record(["duration","Host BW",label,"","",&value.map_or("unavailable".into(),|v|v.to_string()),"ns"])?;
        }
        for (label,value) in [("Busy",b.busy_ns),("Idle",b.idle_ns)] {
            let percent=value.filter(|_|b.duration_ns>0).map(|ns|ns as f64*100./b.duration_ns as f64);
            writer.write_record(["device_time_share","Analysis wall time",label,"",&b.duration_ns.to_string(),&percent.map_or("unavailable".into(),|v|v.to_string()),"percent; denominator ns"])?;
        }
        for (i,label) in ["Total","Read","Write"].iter().enumerate() {
            writer.write_record(["bytes","Host BW",label,"","",&if s.keys.is_empty()&&s.unplottable_rows>0{"unavailable".into()}else{[b.bytes.total(),b.bytes.read,b.bytes.write][i].to_string()},"bytes"])?;
            for (metric,value) in [("Host BW with Idle",b.with_idle_mib_s[i]),("Host BW w/o Idle",b.without_idle_mib_s[i])] {
                writer.write_record(["bandwidth",metric,label,"","",&value.map_or("unavailable".into(),|v|v.to_string()),"MiB/s"])?;
            }
        }
    }
    if let Some(series)=&s.window_series {
        if series.metric==crate::window_series::WindowMetric::BurstPayload {
            writer.write_record(["burst_definition",metric,"all","500000","","Reset only after device-wide Idle > threshold; first I/O included; one final-total sample per burst; cumulative points count R/W completion payload","ns threshold; MiB uses1048576bytes"])?;
        }
        writer.write_record(["window_definition",metric,"all",&series.width_ns.to_string(),"",if series.metric==crate::window_series::WindowMetric::BurstPayload {"One activity burst per sample; device-wide activity separated by Idle >0.5ms, clipped to analysis boundaries; completion cohort (start,end]; final payload includes every R/W request. BW clock is the first-to-last selected burst envelope."}else if series.metric.intervals(){"One positive continuous interval per sample; device-wide union or complement clipped to analysis boundaries; completion cohort (start,end]. Full graph uses all analysis-range I/O; selected intervals use their completion cohort. BW clock is the first-to-last selected interval envelope."}else{"one sample per window; [start,end), final end inclusive; partial-window rates use actual duration; cumulative payload starts at analysis interval start"},"ns"])?;
        writer.write_record(["activity_known",metric,"all","","",&series.activity_known.to_string(),"coverage gate for activity metrics"])?;
        for sample in &series.samples {
            for (ts,bytes) in &sample.cumulative {for (i,direction) in ["Total","Read","Write"].iter().enumerate() {
                writer.write_record(["burst_cumulative",metric,direction,&sample.start_ns.to_string(),&ts.to_string(),&bytes[i].to_string(),"cumulative bytes; lower=burst start ns, upper=completion ns"])?;
            }}
            for (i,direction) in ["Total","Read","Write"].iter().enumerate() {
                writer.write_record([if series.metric.intervals(){"activity_interval"}else{"time_window"},metric,direction,&sample.start_ns.to_string(),&sample.end_ns.to_string(),&sample.values[i].map_or("unavailable".into(),|v|v.to_string()),metric])?;
                writer.write_record(["window_payload",metric,direction,&sample.start_ns.to_string(),&sample.end_ns.to_string(),&sample.payload[i].to_string(),"Read+Write bytes"])?;
                writer.write_record(["window_requests",metric,direction,&sample.start_ns.to_string(),&sample.end_ns.to_string(),&sample.requests[i].to_string(),"requests; Total includes all commands"])?;
            }
        }
    }
    let distributions:Vec<_>=if s.address_distributions.is_empty() {vec![("all".to_string(),&s.metric)]} else {s.address_distributions.iter().map(|(d,m)|(format!("{}:{}",d.0,d.1),m)).collect()};
    for (device,m) in distributions {
        for (direction,d) in [("Total",&m.total),("Read",&m.read),("Write",&m.write),("Other",&m.other)] {
            let group=format!("{device}/{direction}");
            for p in [0,25,50,75,90,95,99,100] {
                writer.write_record(["percentile",metric,&group,&p.to_string(),"",&d.percentile(p).map_or("unavailable".into(),|v|v.to_string()),metric])?;
            }
            for b in d.histogram(16) {
                writer.write_record(["histogram",metric,&group,&b.lower.to_string(),&b.upper.to_string(),&b.count.to_string(),s.window_series.as_ref().map_or("requests",|s|s.metric.population())])?;
            }
            writer.write_record(["missing",metric,&group,"","",&d.missing.to_string(),s.window_series.as_ref().map_or("requests",|s|s.metric.population())])?;
            for (i,value) in d.values.iter().enumerate() {
                writer.write_record(["sorted_rank",metric,&group,&(i+1).to_string(),"",&value.to_string(),metric])?;
                if i+1==d.values.len() || d.values[i+1]!=*value {
                    writer.write_record(["cdf",metric,&group,&value.to_string(),&(i+1).to_string(),&((i+1) as f64*100./d.values.len() as f64).to_string(),"percent; upper = cumulative count"])?;
                }
            }
        }
    }
    for (metric,m) in &s.companion_distributions {
        for (direction,d) in [("Total",&m.total),("Read",&m.read),("Write",&m.write),("Other",&m.other)] {
            for p in [0,25,50,75,90,95,99,100] {writer.write_record(["companion_percentile",metric,direction,&p.to_string(),"",&d.percentile(p).map_or("unavailable".into(),|v|v.to_string()),metric])?;}
            for b in d.histogram(16) {writer.write_record(["companion_histogram",metric,direction,&b.lower.to_string(),&b.upper.to_string(),&b.count.to_string(),"requests"])?;}
            writer.write_record(["companion_missing",metric,direction,"","",&d.missing.to_string(),"requests"])?;
        }
    }
    for r in &s.address_counts {
        for (direction,count) in [("Read",r.reads),("Write",r.writes)] {
            writer.write_record(["address_count","LBA",&format!("{}:{}/{direction}",r.device.0,r.device.1),&r.start_sector.to_string(),&r.end_sector.to_string(),&count.to_string(),"requests per sector; end exclusive"])?;
        }
    }
    for (dimension,rows) in &s.categories {
        for (weight,index) in [("membership_count",0),("payload_bytes",1)] {
            let total:u64=rows.values().map(|v|if index==0 {v.0}else{v.1}).sum();
            for (label,values) in rows {
                let value=if index==0 {values.0}else{values.1};
                writer.write_record(["category",dimension,label,weight,&total.to_string(),&value.to_string(),"category memberships; payload is Read + Write only"])?;
            }
        }
    }
    for (device,locality) in &s.locality {
        let device=format!("{}:{}",device.0,device.1);
        for b in &locality.payload {
            for (direction,value) in [("Read",b.read),("Write",b.write)] {
                writer.write_record(["spatial_payload","Starting sector",&format!("{device}/{direction}"),&b.lower.to_string(),&b.upper.to_string(),&value.to_string(),"payload bytes; last upper inclusive"])?;
            }
        }
        for r in &locality.reuse_points {
            writer.write_record(["temporal_reuse","Same-LBA reuse gap",&format!("{device}/{}",if r[2]==0. {"Read"}else{"Write"}),&r[0].to_string(),"",&r[1].to_string(),"ms; same starting sector and direction in cohort"])?;
        }
    }
    writer.flush()?;
    Ok(())
}
