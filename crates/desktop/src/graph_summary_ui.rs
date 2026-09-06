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
            let (g,x,y)=signature;
            let (tx,rx)=bounded(1);
            self.selection.all_pending=Some((g,x,y,rx));
            std::thread::spawn(move || {
                let mut s=compute_selection(&engine,SelectionRequest::Rectangle {min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]},x,y,origin);
                bw.attach(&mut s);
                let _=tx.send(s);
            });
        }
    }
}

fn graph_distribution_ui(ui: &mut egui::Ui, summary: &SelectionSummary) {
    let Some(axis)=summary.metric_axis else {return;};
    ui.strong(format!("{} · distribution",axis.label()));
    ui.small("Retained graph cohort, before display sampling. Exact nearest-rank percentiles; unmeasured values are excluded.");
    if matches!(axis, AxisMetric::Sector | AxisMetric::AddressKiB) {
        if summary.address_distributions.is_empty() {ui.label("No LBA samples in this cohort.");}
        let page=target_page(ui,"lba-distribution-device",summary.address_distributions.len());
        // Each device gets an independent distribution; numerical LBA equality
        // across devices does not imply the same storage location.
        for (device,dist) in summary.address_distributions.iter().skip(page*20).take(20) {
            ui.push_id(device,|ui| {
                ui.strong(format!("Device {}:{}",device.0,device.1));
                metric_distribution_ui(ui,dist,axis.label());
                ui.collapsing("LBA violin · binned density",|ui| violin_ui(ui,&dist.total,axis.label()));
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
    } else {
        metric_distribution_ui(ui,&summary.metric,axis.label());
    }
    if ui.button("Export graph summary CSV").clicked()
        && let Some(path)=rfd::FileDialog::new().set_file_name("graph-summary.csv").save_file() {
        match write_graph_summary_csv(&path,summary) {
            Ok(()) => {ui.label(format!("Saved {}",path.display()));}
            Err(error) => {ui.colored_label(red(),error.to_string());}
        }
    }
}

fn metric_distribution_ui(ui:&mut egui::Ui, metric:&crate::graph_summary::MetricDistribution, unit:&str) {
    let id=ui.id().with("distribution-direction");
    let mut direction=ui.data_mut(|d|d.get_temp::<usize>(id).unwrap_or(0));
    ui.horizontal_wrapped(|ui| {
        for (i,label) in ["Total","Read","Write","Other"].iter().enumerate() {ui.selectable_value(&mut direction,i,*label);}
    });
    ui.data_mut(|d|d.insert_temp(id,direction));
    let d=[&metric.total,&metric.read,&metric.write,&metric.other][direction];
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
    studio_plot(ui.id().with("metric-histogram")).height(160.).allow_zoom(false).allow_drag(false)
        .grid_spacing(35.0..=120.0).x_grid_spacer(summary_grid).x_axis_formatter(|mark,_| compact_tick(mark.value))
        .x_axis_label(unit).y_axis_label("I/O count").show(ui,|plot| {
            let bars=bins.iter().map(|b|egui_plot::Bar::new((b.lower+b.upper)*0.5,b.count as f64).width((b.upper-b.lower).max(b.lower.abs()*0.01).max(0.000001)*0.95)).collect();
            plot.bar_chart(egui_plot::BarChart::new("Requests",bars).color(accent()));
        });
    ui.small("Equal-width bins [lower, upper); final bin includes maximum. Constant samples form one bin.");
    ui.collapsing("Histogram values",|ui| {
        for (i,b) in bins.iter().enumerate() {ui.label(format!("[{:.4}, {:.4}{}: {} ({:.1}%)",b.lower,b.upper,if i+1==bins.len(){"]"}else{")"},b.count,b.count as f64*100./d.values.len() as f64));}
    });
}

fn violin_ui(ui:&mut egui::Ui,d:&crate::graph_summary::Distribution,unit:&str) {
    let bins=d.histogram(24);
    let maximum=bins.iter().map(|b|b.count).max().unwrap_or(1).max(1) as f64;
    let mut shape:Vec<[f64;2]>=bins.iter().map(|b|[(b.lower+b.upper)*0.5,b.count as f64/maximum]).collect();
    shape.extend(bins.iter().rev().map(|b|[(b.lower+b.upper)*0.5,-(b.count as f64)/maximum]));
    studio_plot(ui.id().with("violin")).height(130.).x_axis_label(unit).y_axis_label("Relative density")
        .grid_spacing(35.0..=120.0).x_grid_spacer(summary_grid).x_axis_formatter(|mark,_| compact_tick(mark.value))
        .allow_zoom(false).allow_drag(false).show(ui,|plot| {
            if shape.len()>2 {plot.polygon(egui_plot::Polygon::new("Mirrored histogram density",shape).fill_color(accent().gamma_multiply(0.35)));}
        });
    ui.small("Mirrored normalized histogram, no inferred kernel smoothing. Histogram table gives exact counts.");
}

fn compact_tick(value:f64)->String {
    if value.abs()>=1e9 {format!("{:.1}G",value/1e9)}
    else if value.abs()>=1e6 {format!("{:.1}M",value/1e6)}
    else if value.abs()>=1e3 {format!("{:.1}k",value/1e3)}
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
    if let Some(b)=&s.host_bw {
        writer.write_record(["definition","Host BW","all",&b.start_ns.to_string(),&b.end_ns.to_string(),"Inclusive completion-counted full bytes; issue-to-completion activity union clipped to range; all processes on selected devices; multiple devices use any-device-active wall time","ns"])?;
        writer.write_record(["coverage","Host BW","all","","",&b.coverage,"detail cohort, not kernel throughput"])?;
        for (label,value) in [("analysis_time",Some(b.duration_ns)),("busy",b.busy_ns),("idle",b.idle_ns),("observed_busy_lower_bound",Some(b.observed_busy_ns))] {
            writer.write_record(["duration","Host BW",label,"","",&value.map_or("unavailable".into(),|v|v.to_string()),"ns"])?;
        }
        for (i,label) in ["Total","Read","Write"].iter().enumerate() {
            writer.write_record(["bytes","Host BW",label,"","",&[b.bytes.total(),b.bytes.read,b.bytes.write][i].to_string(),"bytes"])?;
            for (metric,value) in [("Host BW with Idle",b.with_idle_mib_s[i]),("Host BW w/o Idle",b.without_idle_mib_s[i])] {
                writer.write_record(["bandwidth",metric,label,"","",&value.map_or("unavailable".into(),|v|v.to_string()),"MiB/s"])?;
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
                writer.write_record(["histogram",metric,&group,&b.lower.to_string(),&b.upper.to_string(),&b.count.to_string(),"requests"])?;
            }
            writer.write_record(["missing",metric,&group,"","",&d.missing.to_string(),"requests"])?;
        }
    }
    for r in &s.address_counts {
        for (direction,count) in [("Read",r.reads),("Write",r.writes)] {
            writer.write_record(["address_count","LBA",&format!("{}:{}/{direction}",r.device.0,r.device.1),&r.start_sector.to_string(),&r.end_sector.to_string(),&count.to_string(),"requests per sector; end exclusive"])?;
        }
    }
    writer.flush()?;
    Ok(())
}
