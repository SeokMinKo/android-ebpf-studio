fn compute_graph_selection(engine:&AnalysisEngine,request:SelectionRequest,x:AxisMetric,y:AxisMetric,origin:u64,mut bw:BandwidthContext,width_ms:u64)->SelectionSummary {
    if let AxisMetric::Timeline(mode)=y {return compute_timeline_selection(engine,request,mode,origin,bw);}
    let AxisMetric::Window(metric)=y else {
        let mut summary=compute_selection(engine,request,x,y,origin);bw.attach(&mut summary);return summary;
    };
    let started=Instant::now();
    let full_graph=matches!(request,SelectionRequest::Rectangle{min,max} if min==[f64::NEG_INFINITY;2] && max==[f64::INFINITY;2]);
    let series=crate::window_series::build(engine.completed_ios(),&bw.activity,&bw.devices,bw.range,width_ms.saturating_mul(1_000_000),metric);
    let point_index=if let SelectionRequest::Point(key)=request {engine.completed_ios().iter().find(|io|selection_key(io)==key).and_then(|io|series.index_at(io.completion.ts_ns))}else{None};
    let selected:Vec<bool>=series.samples.iter().enumerate().map(|(index,sample)| {
        let time=(sample.start_ns-origin) as f64/1e6+(sample.end_ns-sample.start_ns) as f64/2e6;
        match request {
            SelectionRequest::Rectangle{min,max}=>time>=min[0] && time<=max[0] &&
                sample.values[0].map_or(min[1]==f64::NEG_INFINITY&&max[1]==f64::INFINITY,|v|v>=min[1]&&v<=max[1]),
            SelectionRequest::Point(_)=>point_index==Some(index),
        }
    }).collect();
    let cohort=engine.select_completed(|io|if metric.intervals() && full_graph {io.completion.ts_ns>=bw.range.0 && io.completion.ts_ns<=bw.range.1}else{series.index_at(io.completion.ts_ns).is_some_and(|i|selected[i])});
    let mut summary=compute_selection(&cohort,SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]},AxisMetric::TimeMs,AxisMetric::ChunkKiB,origin);
    summary.source_rows=engine.completed_ios().len();summary.metric_axis=Some(y);summary.metric=Default::default();summary.bounds=None;
    let mut chosen=series;chosen.samples=std::mem::take(&mut chosen.samples).into_iter().zip(selected).filter_map(|(s,yes)|yes.then_some(s)).collect();
    if !(metric.intervals() && full_graph) {
        if let (Some(first),Some(last))=(chosen.samples.first(),chosen.samples.last()) {bw.range=(first.start_ns,last.end_ns);}
        else {bw.range.1=bw.range.0;}
    }
    for sample in &chosen.samples {
        summary.metric.total.observe(sample.values[0]);
        summary.metric.read.observe(sample.values[1]);summary.metric.write.observe(sample.values[2]);
        if metric==crate::window_series::WindowMetric::Iops {summary.metric.other.observe(sample.values[0].zip(sample.values[1]).zip(sample.values[2]).map(|((t,r),w)|(t-r-w).max(0.)));}
        if let Some(value)=sample.values[0] {
            let a=[(sample.start_ns-origin) as f64/1e6,if metric==crate::window_series::WindowMetric::BurstPayload {0.}else{value}];let b=[(sample.end_ns-origin) as f64/1e6,value];
            let bounds=summary.bounds.get_or_insert_with(||egui_plot::PlotBounds::from_min_max(a,b));
            bounds.extend_with(&egui_plot::PlotPoint::new(a[0],a[1]));bounds.extend_with(&egui_plot::PlotPoint::new(b[0],b[1]));
        }
    }
    summary.metric.finish();summary.window_series=Some(chosen);summary.elapsed=started.elapsed();bw.attach(&mut summary);summary
}

impl StudioApp {
    fn window_series_ui(&mut self,ui:&mut egui::Ui) {
        let intervals=matches!(self.y_axis,AxisMetric::Window(m) if m.intervals());
        let bursts=self.y_axis==AxisMetric::Window(crate::window_series::WindowMetric::BurstPayload);
        let mut width=self.window_width_ms;
        if !intervals {ui.horizontal_wrapped(|ui| {ui.label("Time window (ms)");ui.add(egui::DragValue::new(&mut width).range(1..=60_000).speed(10.));});}
        if width!=self.window_width_ms {self.window_width_ms=width;self.invalidate_query();self.rebuild_filtered();return;}
        self.axis_ranges_ui(ui);
        let origin=self.time_origin();let metric=self.y_axis;
        let Some(series)=self.selection.all_summary.as_ref().filter(|s|s.2==metric).and_then(|s|s.3.window_series.as_ref()) else {ui.spinner();ui.label("Building full-resolution time windows…");return;};
        if bursts {
            ui.small(format!("{} bursts · reset after device-wide Idle > 0.5 ms · first I/O included",series.samples.len()));
            ui.small("Curves show completion-counted cumulative R/W payload within each burst. Center markers show final burst totals; drag across markers or click a burst to select whole bursts. Summary gives one final-total sample per burst, including zero filtered payload.");
        } else if intervals {
            ui.small(format!("{} continuous intervals · one duration sample per interval · clipped at analysis boundaries",series.samples.len()));
            ui.small("Overlapping or touching activity is merged across selected devices. Idle is its complement. Click an interval or drag across centers to summarize whole intervals.");
        } else {
            ui.small(format!("{} windows · effective width {:.3} ms · final partial window uses its measured duration",series.samples.len(),series.width_ns as f64/1e6));
            ui.small("One statistical sample per window, including empty windows. Data is retained completion detail; zeros are not proof of unsampled inactivity. Click a window or drag across window centers to summarize whole windows.");
        }
        if series.metric.device_activity() || bursts {ui.colored_label(amber(),"Device-wide activity includes other processes and operations. Unknown coverage stays unavailable; eligible Perfetto activity is a reconstructed estimate.");}
        if series.samples.iter().all(|s|s.values[0].is_none()) {ui.label(if intervals && series.activity_known {"No positive-duration intervals of this kind in the analysis range."}else{"No measured samples: coverage is unknown or analysis duration is zero."});}
        let bounds_command=self.selection.bounds_command.take();let auto=std::mem::take(&mut self.selection.auto_bounds);
        let selecting=self.selection.enabled;let mut drag=self.selection.drag_start;let mut selected=None;
        let visible_clip=ui.clip_rect();
        let response=studio_plot("window-series").height(330.).x_axis_label(if bursts {"Time (ms) · markers at burst centers"}else if intervals {"Interval center (ms)"}else{"Time-window center (ms)"}).y_axis_label(metric.label())
            .legend(Legend::default()).allow_drag(!selecting).allow_boxed_zoom(!selecting)
            .x_axis_formatter(|m,_|compact_tick(m.value)).y_axis_formatter(|m,_|compact_tick(m.value))
            .show(ui,|plot| {
                if let Some(bounds)=bounds_command {plot.set_plot_bounds(bounds);}else if auto {plot.set_auto_bounds(true);}
                self.render_qa.plot_rect=Some(*plot.transform().frame());
                self.selection.current_bounds=Some(plot.plot_bounds());
                for (direction,label,color) in [(0,"Total",muted()),(1,"Read",accent()),(2,"Write",green())] {
                    if bursts {
                        for sample in &series.samples {
                            let mut points=vec![[(sample.start_ns-origin) as f64/1e6,0.]];let mut previous=0.;
                            for (ts,payload) in &sample.cumulative {
                                let time=(*ts-origin) as f64/1e6;let value=payload[direction] as f64/1_048_576.;
                                points.extend([[time,previous],[time,value]]);previous=value;
                            }
                            points.push([(sample.end_ns-origin) as f64/1e6,previous]);
                            plot.line(Line::new(label,points).color(color));
                        }
                    }
                    let points:Vec<_>=series.samples.iter().filter_map(|s|s.values[direction].map(|v|[(s.start_ns-origin) as f64/1e6+(s.end_ns-s.start_ns) as f64/2e6,v])).collect();
                    if direction==0 {self.render_qa.point_target=points.iter().map(|p|plot.screen_from_plot(egui_plot::PlotPoint::new(p[0],p[1]))).find(|pos|visible_clip.shrink(4.).contains(*pos));}
                    if !points.is_empty() {if !intervals {plot.line(Line::new(label,points.clone()).color(color));}plot.points(Points::new(label,points).radius(3.).color(color));}
                }
                if let Some(selected)=self.selection.summary.as_ref().and_then(|s|s.window_series.as_ref()) {
                    let points:Vec<_>=selected.samples.iter().filter_map(|s|s.values[0].map(|v|[(s.start_ns-origin) as f64/1e6+(s.end_ns-s.start_ns) as f64/2e6,v])).collect();
                    plot.points(Points::new(if intervals {"Selected intervals"}else{"Selected windows"},points).radius(6.).filled(false).color(amber()));
                }
                if selecting && plot.response().drag_started() && let Some(pos)=plot.response().interact_pointer_pos() {let p=plot.plot_from_screen(pos-plot.response().drag_delta());drag=Some([p.x,p.y]);}
                if selecting && let Some(start)=drag && let Some(pos)=plot.response().interact_pointer_pos() {
                    let p=plot.plot_from_screen(pos);let min=[start[0].min(p.x),start[1].min(p.y)];let max=[start[0].max(p.x),start[1].max(p.y)];
                    plot.polygon(egui_plot::Polygon::new("Window selection",vec![min,[max[0],min[1]],max,[min[0],max[1]]]).fill_color(accent().gamma_multiply(0.15)));
                    if plot.response().drag_stopped() {selected=Some(SelectionRequest::Rectangle{min,max});drag=None;}
                }
                if selecting && plot.response().clicked() && let Some(p)=plot.pointer_coordinate() {
                    let ts=origin.saturating_add((p.x.max(0.)*1e6) as u64);
                    if let Some(index)=series.index_at(ts) {let s=&series.samples[index];let center=(s.start_ns-origin) as f64/1e6+(s.end_ns-s.start_ns) as f64/2e6;selected=Some(SelectionRequest::Rectangle{min:[center,f64::NEG_INFINITY],max:[center,f64::INFINITY]});}
                }
            });
        qa_region(&mut self.render_qa,"Window trend",response.response.rect,ui.clip_rect());
        if self.render_qa.output.is_some() && self.render_qa.input_step==0 && self.render_qa.point_target.is_none() && std::env::var("ANDROID_EBPF_QA_GESTURE").as_deref()==Ok("point") {response.response.scroll_to_me(Some(egui::Align::Min));}
        self.selection.drag_start=drag;
        if let Some(request)=selected {self.begin_selection(request);}
    }
}

#[cfg(test)]
mod window_summary_tests {
    use super::*;
    use android_ebpf_protocol::{BlockIssue,BlockComplete,StorageEvent};
    use crate::window_series::WindowMetric;
    #[test]
    fn burst_summary_uses_final_totals_once_and_selection_exports_the_cumulative_curve() {
        let mut engine=AnalysisEngine::new();let mut activity=crate::host_bw::ActivityTimeline::default();activity.verified_complete=true;
        for (id,a,b) in [(1,0,1_000_000),(2,1_000_001,2_000_000),(3,3_000_000,4_000_000)] {
            engine.ingest(StorageEvent::BlockIssue(BlockIssue{ts_ns:a,request_id:id,device_major:8,device_minor:0,sector:id*8,sectors:2048,bytes:1_048_576,operation:IoOperation::Read,pid:1,tid:1,cpu:0,comm:"x".into()}));
            if let Some(io)=engine.ingest(StorageEvent::BlockComplete(BlockComplete{ts_ns:b,request_id:id,device_major:8,device_minor:0,status:0})) {activity.observe(&io);}
        }
        let context=||BandwidthContext{activity:Arc::new(activity.clone()),range:(0,4_000_000),devices:vec![(8,0)]};let axis=AxisMetric::Window(WindowMetric::BurstPayload);
        let full=compute_graph_selection(&engine,SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]},AxisMetric::TimeMs,axis,0,context(),1);
        assert_eq!(full.metric.total.values,[1.,2.]);assert_eq!(full.keys.len(),3);
        let selected=compute_graph_selection(&engine,SelectionRequest::Rectangle{min:[1.,0.],max:[1.,3.]},AxisMetric::TimeMs,axis,0,context(),1);
        assert_eq!(selected.keys.len(),2);assert_eq!(selected.metric.total.values,[2.]);assert_eq!(selected.bounds.unwrap().min()[1],0.);
        let path=std::env::temp_dir().join(format!("burst-{}.csv",uuid::Uuid::new_v4()));write_graph_summary_csv(&path,&selected).unwrap();
        let records=csv::Reader::from_path(&path).unwrap().records().collect::<Result<Vec<_>,_>>().unwrap();
        assert_eq!(records.iter().filter(|r|&r[0]=="burst_cumulative"&&&r[2]=="Total").map(|r|r[5].parse::<u64>().unwrap()).collect::<Vec<_>>(),[1_048_576,2_097_152]);
        assert!(records.iter().any(|r|&r[0]=="histogram"&&&r[6]=="activity bursts"));std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn interval_summary_weights_runs_once_and_keeps_other_process_activity_and_empty_idle_selection() {
        let mut engine=AnalysisEngine::new();let mut activity=crate::host_bw::ActivityTimeline::default();
        for (id,pid,a,b) in [(1,1,0,2),(2,2,1,5),(3,1,7,8),(4,1,7,8)] {
            engine.ingest(StorageEvent::BlockIssue(BlockIssue{ts_ns:a*1_000_000,request_id:id,device_major:8,device_minor:0,sector:id*8,sectors:2,bytes:1024,operation:IoOperation::Read,pid,tid:pid,cpu:0,comm:"same".into()}));
            if let Some(io)=engine.ingest(StorageEvent::BlockComplete(BlockComplete{ts_ns:b*1_000_000,request_id:id,device_major:8,device_minor:0,status:0})) {activity.observe(&io);}
        }
        activity.verified_complete=true;
        let context=||BandwidthContext{activity:Arc::new(activity.clone()),range:(0,10_000_000),devices:vec![(8,0)]};
        let all_request=SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]};
        let axis=AxisMetric::Window(WindowMetric::BusyRunMs);
        let all=compute_graph_selection(&engine,all_request,AxisMetric::TimeMs,axis,0,context(),100);
        assert_eq!(all.metric.total.values,[1.,5.]);assert_eq!(all.keys.len(),4);assert_eq!(all.host_bw.as_ref().unwrap().duration_ns,10_000_000);
        let filtered=engine.select_completed(|io|io.issue.pid==1);
        let f=compute_graph_selection(&filtered,all_request,AxisMetric::TimeMs,axis,0,context(),100);
        assert_eq!(f.metric.total.values,[1.,5.]);assert_eq!(f.keys.len(),3);assert_eq!(f.host_bw.as_ref().unwrap().busy_ns,Some(6_000_000));
        let selected=compute_graph_selection(&engine,SelectionRequest::Rectangle{min:[2.5,0.],max:[2.5,10.]},AxisMetric::TimeMs,axis,0,context(),100);
        assert_eq!(selected.metric.total.values,[5.]);assert_eq!(selected.keys.len(),2);assert_eq!(selected.host_bw.as_ref().unwrap().duration_ns,5_000_000);
        let idle=compute_graph_selection(&engine,SelectionRequest::Rectangle{min:[6.,0.],max:[6.,10.]},AxisMetric::TimeMs,AxisMetric::Window(WindowMetric::IdleGapMs),0,context(),100);
        assert_eq!(idle.metric.total.values,[2.]);assert!(idle.keys.is_empty());assert_eq!(idle.host_bw.as_ref().unwrap().idle_ns,Some(2_000_000));assert!(idle.bounds.is_some());
        let path=std::env::temp_dir().join(format!("interval-{}.csv",uuid::Uuid::new_v4()));write_graph_summary_csv(&path,&idle).unwrap();
        let records=csv::Reader::from_path(&path).unwrap().records().collect::<Result<Vec<_>,_>>().unwrap();
        assert!(records.iter().any(|r|&r[0]=="activity_interval"&&&r[2]=="Total"&&&r[3]=="5000000"&&&r[4]=="7000000"&&&r[5]=="2"));
        assert!(records.iter().any(|r|&r[0]=="histogram"&&&r[6]=="continuous intervals"));std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn window_summary_counts_windows_once_and_selection_snaps_to_the_drawn_window() {
        let mut engine=AnalysisEngine::new();let mut activity=crate::host_bw::ActivityTimeline::default();
        for id in 0..26 {
            let ts=if id==0 {1_000_000_000}else if id<25 {1_200_000_000+id*1000}else{2_400_000_000};
            engine.ingest(StorageEvent::BlockIssue(BlockIssue {ts_ns:ts-100,request_id:id,device_major:8,device_minor:0,sector:0,sectors:2048,bytes:1_048_576,operation:IoOperation::Read,pid:1,tid:1,cpu:0,comm:"dense".into()}));
            if let Some(io)=engine.ingest(StorageEvent::BlockComplete(BlockComplete{ts_ns:ts,request_id:id,device_major:8,device_minor:0,status:0})) {activity.observe(&io);}
        }
        activity.verified_complete=true;
        let context=||BandwidthContext{activity:Arc::new(activity.clone()),range:(0,2_500_000_000),devices:vec![(8,0)]};
        let axis=AxisMetric::Window(WindowMetric::Bandwidth);
        let all=compute_graph_selection(&engine,SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]},AxisMetric::TimeMs,axis,0,context(),1000);
        assert_eq!(all.keys.len(),26);assert_eq!(all.metric.total.values,[0.,2.,25.]);
        assert_eq!(all.metric.total.percentile(50),Some(2.));
        let at_boundary=compute_graph_selection(&engine,SelectionRequest::Point(selection_key(&engine.completed_ios()[0])),AxisMetric::TimeMs,axis,0,context(),1000);
        assert_eq!(at_boundary.keys.len(),25);assert_eq!(at_boundary.metric.total.values,[25.]);
        let selected=compute_graph_selection(&engine,SelectionRequest::Rectangle{min:[1400.,0.],max:[1600.,30.]},AxisMetric::TimeMs,axis,0,context(),1000);
        assert_eq!(selected.keys.len(),25);assert_eq!(selected.metric.total.values,[25.]);
        let bw=selected.host_bw.as_ref().unwrap();assert_eq!((bw.start_ns,bw.end_ns),(1_000_000_000,2_000_000_000));assert_eq!(bw.with_idle_mib_s[0],Some(25.));
        let empty=compute_graph_selection(&engine,SelectionRequest::Rectangle{min:[500.,0.],max:[500.,0.]},AxisMetric::TimeMs,axis,0,context(),1000);
        assert!(empty.keys.is_empty());assert_eq!(empty.metric.total.values,[0.]);assert_eq!(empty.host_bw.as_ref().unwrap().duration_ns,1_000_000_000);
        let mut unknown=context();Arc::make_mut(&mut unknown.activity).verified_complete=false;
        let unavailable=compute_graph_selection(&engine,SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]},AxisMetric::TimeMs,AxisMetric::Window(WindowMetric::IdleMs),0,unknown,1000);
        assert_eq!(unavailable.keys.len(),26);assert!(unavailable.metric.total.values.is_empty());assert_eq!(unavailable.metric.total.missing,3);
    }
}
