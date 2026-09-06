#[derive(Debug,Clone,Copy,PartialEq,Eq,serde::Serialize)]
enum TimelineMode { Commands, Requests, Cpus }
impl TimelineMode {
    fn label(self)->&'static str {match self {Self::Commands=>"Device / block command",Self::Requests=>"Request row",Self::Cpus=>"Device / observed CPU"}}
}
#[derive(Debug,Clone,serde::Serialize)]
struct TimelinePoint {
    key:IoSelectionKey,
    row:usize,
    issue_row:Option<usize>,
    start_ns:Option<u64>,
    end_ns:u64,
    operation:IoOperation,
    tooltip:String,
}
#[derive(Debug,Clone,serde::Serialize)]
struct TimelineView {
    mode:TimelineMode,
    origin:u64,
    lanes:Vec<String>,
    points:Vec<TimelinePoint>,
}
impl TimelinePoint {
    fn y(&self,mode:TimelineMode)->f64 {if mode==TimelineMode::Requests {-(self.row as f64)}else{self.row as f64}}
    fn issue_y(&self,mode:TimelineMode)->f64 {self.issue_row.map_or_else(||self.y(mode),|r|r as f64)}
    fn on_page(&self,first:usize,last:usize)->bool {(first..=last).contains(&self.row)||self.issue_row.is_some_and(|r|(first..=last).contains(&r))}
}
#[cfg(test)]
mod timeline_tests {
    use super::*;
    use android_ebpf_protocol::{BlockIssue,BlockComplete,StorageEvent,CompletionEvidence,CorrelationConfidence};
    fn fixture()->AnalysisEngine {
        let mut source=AnalysisEngine::new();
        for (id,minor,a,b,op) in [(1,0,1,5,IoOperation::Read),(2,1,2,4,IoOperation::Read),(3,0,3,6,IoOperation::Write)] {
            source.ingest(StorageEvent::BlockIssue(BlockIssue{ts_ns:a*1_000_000,request_id:id,device_major:8,device_minor:minor,sector:100,sectors:8,bytes:4096,operation:op,pid:1,tid:1,cpu:0,comm:"same".into()}));
            source.ingest(StorageEvent::BlockComplete(BlockComplete{cpu:None,ts_ns:b*1_000_000,request_id:id,device_major:8,device_minor:minor,status:0}));
        }
        let mut engine=AnalysisEngine::new();
        for original in source.completed_ios() {
            let mut io=original.clone();
            if io.issue.request_id==3 {io.device_latency_ns=None;io.evidence=Some(Box::new(CompletionEvidence{source:"fixture".into(),record_id:3,issue_record_candidates:vec![],issue_timestamp_ns:None,issuer_pid:None,issuer_tid:None,issuer_cpu:None,completion_status:None,process_name:None,timing_confidence:CorrelationConfidence::ContextOnly,reason:"issue not observed".into(),clock:0}));}
            engine.ingest(StorageEvent::ObservedBlockCompletion(io));
        }
        engine
    }
    fn context()->BandwidthContext {BandwidthContext{activity:Arc::new(crate::host_bw::ActivityTimeline::default()),range:(0,7_000_000),devices:vec![(8,0),(8,1)]}}
    #[test]
    fn unsupported_clock_is_not_placed_in_added_time_graphs() {
        let source=fixture();let mut engine=AnalysisEngine::new();
        let mut io=source.completed_ios().iter().find(|io|io.evidence.is_some()).unwrap().clone();
        io.evidence.as_mut().unwrap().clock=99;
        engine.ingest(StorageEvent::ObservedBlockCompletion(io));
        let request=SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]};
        assert_eq!(build_footprint(&engine,0,FootprintMode::Process,0).unique,0);
        for mode in [TimelineMode::Commands,TimelineMode::Requests,TimelineMode::Cpus] {
            assert!(build_timeline(&engine,mode,0).points.is_empty());
            let s=compute_timeline_selection(&engine,request,mode,0,context());
            assert!(s.keys.is_empty());assert_eq!(s.unplottable_rows,1);
        }
        let s=compute_graph_selection(&engine,request,AxisMetric::TimeMs,AxisMetric::Window(crate::window_series::WindowMetric::Iops),0,context(),1);
        assert!(s.keys.is_empty());assert_eq!(s.unplottable_rows,1);
        assert!(s.window_series.unwrap().samples.iter().all(|w|w.requests[0]==0));
    }
    #[test]
    fn cpu_timeline_keeps_phase_cpus_and_unknown_lane_distinct_including_across_pages() {
        let source=fixture();let mut engine=AnalysisEngine::new();
        for original in source.completed_ios() {let mut io=original.clone();io.completion.cpu=match io.issue.request_id {1=>Some(7),2=>Some(0),_=>None};engine.ingest(StorageEvent::ObservedBlockCompletion(io));}
        let view=build_timeline(&engine,TimelineMode::Cpus,0);
        assert_eq!(view.lanes,["Device 8:0 / CPU 0","Device 8:0 / CPU 7","Device 8:0 / CPU unmeasured","Device 8:1 / CPU 0"]);
        let p=&view.points[0];assert_eq!((p.issue_y(view.mode),p.y(view.mode)),(1.,2.));
        assert_eq!(view.points[2].issue_row,None);assert_eq!(view.points[2].row,3);
        let mut across=p.clone();across.issue_row=Some(1);across.row=41;
        assert!(across.on_page(1,40));assert!(across.on_page(41,80));assert!(!across.on_page(81,120));
        let s=compute_timeline_selection(&engine,SelectionRequest::Rectangle{min:[4.9,1.9],max:[5.1,2.1]},TimelineMode::Cpus,0,context());
        assert_eq!(s.keys.len(),1);assert!(s.keys.contains(&p.key));assert_eq!(s.metric.total.values,[4.]);
    }
    #[test]
    fn qa_preset_discards_old_axis_geometry_while_new_summary_is_loading() {
        let mut app=StudioApp::default();let point=egui::pos2(842_009.,-46_478_000_000.);
        app.render_qa.plot_rect=Some(egui::Rect::from_min_max(egui::pos2(0.,0.),egui::pos2(1200.,800.)));
        app.render_qa.point_target=Some(point);app.render_qa.stable_point=Some(point);
        app.render_qa.stable_rect=app.render_qa.plot_rect;app.render_qa.layout_stable_since=Some(Instant::now());
        app.apply_qa_preset();
        assert!(app.render_qa.plot_rect.is_none()&&app.render_qa.point_target.is_none()&&app.render_qa.stable_rect.is_none()&&app.render_qa.stable_point.is_none()&&app.render_qa.layout_stable_since.is_none());
    }
    #[test]
    fn command_lanes_separate_devices_and_gantt_rows_order_by_observed_start() {
        let engine=fixture();let commands=build_timeline(&engine,TimelineMode::Commands,0);
        assert_eq!(commands.lanes,["Device 8:0 / Read","Device 8:0 / Write","Device 8:1 / Read"]);
        let gantt=build_timeline(&engine,TimelineMode::Requests,0);
        assert_eq!(gantt.points.iter().map(|p|(p.key.0,p.row,p.start_ns,p.y(gantt.mode))).collect::<Vec<_>>(),[(1,1,Some(1_000_000),-1.),(2,2,Some(2_000_000),-2.),(3,3,None,-3.)]);
    }
    #[test]
    fn timeline_latency_excludes_missing_duration_but_retains_request_and_payload_cohort() {
        let engine=fixture();let full=compute_timeline_selection(&engine,SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]},TimelineMode::Requests,0,context());
        assert_eq!(full.keys.len(),3);assert_eq!(full.metric.total.values,[2.,4.]);assert_eq!(full.metric.total.missing,1);assert_eq!(full.read.bytes+full.write.bytes,12288);
        let path=std::env::temp_dir().join(format!("timeline-{}.csv",uuid::Uuid::new_v4()));write_graph_summary_csv(&path,&full).unwrap();
        let records=csv::Reader::from_path(&path).unwrap().records().collect::<Result<Vec<_>,_>>().unwrap();
        assert_eq!(records.iter().filter(|r|&r[0]=="timeline_request").count(),3);
        assert!(records.iter().any(|r|&r[0]=="timeline_request"&&&r[3]=="unavailable"&&&r[4]=="6000000"));std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn rectangle_uses_completion_and_signed_row_while_point_keeps_full_lifetime() {
        let engine=fixture();
        let one=compute_timeline_selection(&engine,SelectionRequest::Rectangle{min:[4.,-2.1],max:[5.,-1.9]},TimelineMode::Requests,0,context());
        assert_eq!(one.keys.iter().map(|k|k.0).collect::<Vec<_>>(),[2]);assert_eq!(one.metric.total.values,[2.]);
        let empty=compute_timeline_selection(&engine,SelectionRequest::Rectangle{min:[2.,-2.1],max:[3.,-1.9]},TimelineMode::Requests,0,context());assert!(empty.keys.is_empty());
        let point=compute_timeline_selection(&engine,SelectionRequest::Point((1,1_000_000,8,0)),TimelineMode::Requests,0,context());
        assert_eq!(point.keys.len(),1);let bounds=point.bounds.unwrap();assert_eq!(bounds.min(),[1.,-1.]);assert_eq!(bounds.max(),[5.,-1.]);
    }
}
fn build_timeline(engine:&AnalysisEngine,mode:TimelineMode,origin:u64)->TimelineView {
    let mut ordered:Vec<_>=engine.completed_ios().iter().filter(|io|io.completion_timestamp().is_some()).collect();
    ordered.sort_by_key(|io|(io.issue_timestamp().unwrap_or(io.completion.ts_ns),io.completion.ts_ns,selection_key(io)));
    let command_label=|io:&CompletedIo|format!("Device {}:{} / {}",io.issue.device_major,io.issue.device_minor,operation_label(io.issue.operation));
    let cpu_label=|io:&CompletedIo,cpu:Option<u32>|format!("Device {}:{} / CPU {}",io.issue.device_major,io.issue.device_minor,cpu.map_or("unmeasured".into(),|n|n.to_string()));
    let lanes:Vec<String>=match mode {
        TimelineMode::Commands=>ordered.iter().map(|io|command_label(io)).collect::<std::collections::BTreeSet<_>>().into_iter().collect(),
        TimelineMode::Requests=>(1..=ordered.len()).map(|i|format!("{i}")).collect(),
        TimelineMode::Cpus=>ordered.iter().flat_map(|io|std::iter::once(cpu_label(io,io.completion.cpu)).chain(io.issue_timestamp().filter(|a|*a<=io.completion.ts_ns).map(|_|cpu_label(io,io.issuer_cpu())))).collect::<std::collections::BTreeSet<_>>().into_iter().collect(),
    };
    let positions:BTreeMap<_,_>=lanes.iter().enumerate().map(|(i,s)|(s.clone(),i+1)).collect();
    let points=ordered.into_iter().enumerate().map(|(index,io)| {
        let start_ns=io.issue_timestamp().filter(|ts|*ts<=io.completion.ts_ns);
        let tooltip=format!("{} · device {}:{}\n{}\nLBA [{}, {}) · {} bytes\nIssue: {} ns · Complete: {} ns\nTiming: {:?}\nIssue CPU: {} · Completion CPU: {}\nSelect for Files / Processes / Investigate and I/O CSV",
            operation_label(io.issue.operation),io.issue.device_major,io.issue.device_minor,issuer_label(io.issuer_pid(),io.issuer_tid(),&io.issue.comm),
            io.issue.sector,io.issue.sector.saturating_add(io.issue.sectors as u64),io.issue.bytes,start_ns.map_or("unmeasured".into(),|v|v.to_string()),io.completion.ts_ns,io.timing_confidence(),identity_number(io.issuer_cpu()),identity_number(io.completion.cpu));
        TimelinePoint {key:selection_key(io),row:match mode {TimelineMode::Commands=>positions[&command_label(io)],TimelineMode::Requests=>index+1,TimelineMode::Cpus=>positions[&cpu_label(io,io.completion.cpu)]},issue_row:if mode==TimelineMode::Cpus {start_ns.map(|_|positions[&cpu_label(io,io.issuer_cpu())])}else{None},start_ns,end_ns:io.completion.ts_ns,operation:io.issue.operation,tooltip}
    }).collect();
    TimelineView {mode,origin,lanes,points}
}
fn compute_timeline_selection(engine:&AnalysisEngine,request:SelectionRequest,mode:TimelineMode,origin:u64,bw:BandwidthContext)->SelectionSummary {
    let started=Instant::now();
    let mut timeline=build_timeline(engine,mode,origin);
    timeline.points.retain(|p|match request {
        SelectionRequest::Point(key)=>p.key==key,
        SelectionRequest::Rectangle{min,max}=>{let x=p.end_ns.saturating_sub(origin) as f64/1e6;x>=min[0]&&x<=max[0]&&p.y(mode)>=min[1]&&p.y(mode)<=max[1]},
    });
    let keys:std::collections::HashSet<_>=timeline.points.iter().map(|p|p.key).collect();
    let cohort=engine.select_completed(|io|keys.contains(&selection_key(io)));
    let mut result=compute_selection(&cohort,SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]},AxisMetric::TimeMs,AxisMetric::ChunkKiB,origin);
    result.source_rows=engine.completed_ios().len();result.unplottable_rows=engine.completed_ios().iter().filter(|io|io.completion_timestamp().is_none()).count();result.metric_axis=Some(AxisMetric::DeviceLatencyMs);result.metric=Default::default();result.bounds=None;
    for io in cohort.completed_ios() {result.metric.observe(io.issue.operation,io.device_latency_ns.map(|n|n as f64/1e6));}
    result.metric.finish();
    for p in &timeline.points {
        let a=[p.start_ns.unwrap_or(p.end_ns).saturating_sub(origin) as f64/1e6,p.issue_y(mode)];
        let b=[p.end_ns.saturating_sub(origin) as f64/1e6,p.y(mode)];
        let bounds=result.bounds.get_or_insert_with(||egui_plot::PlotBounds::from_min_max(a,b));
        bounds.extend_with(&egui_plot::PlotPoint::new(a[0],a[1]));bounds.extend_with(&egui_plot::PlotPoint::new(b[0],b[1]));
    }
    result.timeline=Some(timeline);result.elapsed=started.elapsed();bw.attach(&mut result);result
}
impl StudioApp {
    fn timeline_ui(&mut self,ui:&mut egui::Ui) {
        self.axis_ranges_ui(ui);
        let Some(view)=self.selection.all_summary.as_ref().filter(|v|v.2==self.y_axis).and_then(|v|v.3.timeline.as_ref()) else {ui.spinner();ui.label("Building full-resolution timeline…");return;};
        let mode=view.mode;
        if mode==TimelineMode::Cpus {ui.small("CPU is measured independently at issue and completion. Unmeasured CPU has its own lane. Analysis CPU filtering uses issue CPU, matching the block issuer filter.");}
        ui.small(format!("{} I/O · {} rows · {} issue timestamps unmeasured",view.points.len(),view.lanes.len(),view.points.iter().filter(|p|p.start_ns.is_none()).count()));
        ui.small("Hollow marker = measured issue; filled marker = completion. Gantt lines show observed request lifetime. Missing issue has only a completion marker. Rectangle selects completion endpoints; click a segment or endpoint for one I/O.");
        ui.small("Summary covers the full filtered timeline, independent of page/display stride. Its histogram/percentiles summarize measured device latency; missing latency is counted separately. Other observed layers remain available in Investigate.");
        let id=ui.id().with(("timeline-page",format!("{:?}",view.mode)));
        let pages=view.lanes.len().div_ceil(40).max(1);
        let mut page=ui.data_mut(|d|d.get_temp::<usize>(id).unwrap_or_else(||std::env::var("ANDROID_EBPF_QA_TIMELINE_PAGE").ok().and_then(|s|s.parse::<usize>().ok()).unwrap_or(1).saturating_sub(1))).min(pages-1);
        if let Some(bounds)=self.selection.bounds_command {
            let first_row=if mode==TimelineMode::Requests {-bounds.max()[1]}else{bounds.min()[1]};
            page=(first_row.round().max(1.) as usize-1)/40;page=page.min(pages-1);
        }
        ui.horizontal(|ui| {
            let previous=ui.add_enabled(page>0,egui::Button::new("Previous rows"));qa_region(&mut self.render_qa,"timeline-previous",previous.rect,ui.clip_rect());if previous.clicked(){page-=1;}
            let mut number=page+1;ui.label("Page");if ui.add(egui::DragValue::new(&mut number).range(1..=pages)).changed(){page=number-1;}
            ui.label(format!("/ {pages}"));
            let next=ui.add_enabled(page+1<pages,egui::Button::new("Next rows"));qa_region(&mut self.render_qa,"timeline-next",next.rect,ui.clip_rect());if next.clicked(){page+=1;}
        });
        let page_changed=ui.data_mut(|d|d.get_temp::<usize>(id))!=Some(page);ui.data_mut(|d|d.insert_temp(id,page));
        let first=page*40+1;let last=((page+1)*40).min(view.lanes.len()).max(first);
        self.render_qa.lane_page=page;self.render_qa.lane_pages=pages;self.render_qa.lane_visible=view.lanes.iter().skip(page*40).take(40).cloned().collect();
        let visible:Vec<_>=view.points.iter().filter(|p|p.on_page(first,last)).collect();
        let operations=[IoOperation::Read,IoOperation::Write,IoOperation::Discard,IoOperation::Flush,IoOperation::Other];
        let mut drawn=Vec::new();
        for op in operations {let group:Vec<_>=visible.iter().copied().filter(|p|p.operation==op).collect();let stride=group.len().div_ceil(1500).max(1);drawn.extend(group.into_iter().step_by(stride));}
        if drawn.len()<visible.len(){ui.small(format!("Displaying {} of {} page I/O; Summary/selection use every original request.",drawn.len(),visible.len()));}
        let absolute=|ts:u64|ts.saturating_sub(view.origin) as f64/1e6;
        let selecting=self.selection.enabled;let mut drag=self.selection.drag_start;let mut selected=None;
        let bounds_command=self.selection.bounds_command.take();let auto=std::mem::take(&mut self.selection.auto_bounds);
        let visible_clip=ui.clip_rect();
        let response=studio_plot("request-timeline").height(430.).x_axis_label("Time (ms)").y_axis_label(view.mode.label())
            .allow_drag(!selecting).allow_boxed_zoom(!selecting).x_axis_formatter(|m,_|compact_tick(m.value))
            .y_axis_formatter(|m,_|{let n=m.value.abs().round();if (m.value.abs()-n).abs()<0.001&&n>=1. {view.lanes.get(n as usize-1).cloned().unwrap_or_default()}else{String::new()}})
            .y_grid_spacer(|_|{let mut marks:Vec<_>=(first..=last).map(|row|egui_plot::GridMark{value:if mode==TimelineMode::Requests {-(row as f64)}else{row as f64},step_size:(last-first+1) as f64}).collect();marks.sort_by(|a,b|a.value.total_cmp(&b.value));marks})
            .label_formatter(|hover|match hover {
                HoverPosition::NearDataPoint{plot_name,index,..}=>{
                    let issue=plot_name.ends_with(" issue");let label=plot_name.trim_end_matches(" issue").trim_end_matches(" complete");
                    drawn.iter().filter(|p|operation_label(p.operation)==label&&(!issue||p.start_ns.is_some())).nth(*index).map(|p|p.tooltip.clone())
                },_=>None
            })
            .show(ui,|plot| {
                if let Some(bounds)=bounds_command {plot.set_plot_bounds(bounds);}
                else if auto||page_changed {
                    let mut min=f64::INFINITY;let mut max=f64::NEG_INFINITY;
                    for p in &view.points {min=min.min(absolute(p.start_ns.unwrap_or(p.end_ns)));max=max.max(absolute(p.end_ns));}
                    if !min.is_finite(){min=0.;max=1.;}let pad=(max-min).max(1.)*0.03;
                    let (bottom,top)=if mode==TimelineMode::Requests {(-(last as f64)-0.5,-(first as f64)+0.5)}else{(first as f64-0.5,last as f64+0.5)};
                    plot.set_plot_bounds(egui_plot::PlotBounds::from_min_max([min-pad,bottom],[max+pad,top]));
                }
                self.render_qa.plot_rect=Some(*plot.transform().frame());self.selection.current_bounds=Some(plot.plot_bounds());
                self.render_qa.point_target=drawn.iter().map(|p|plot.screen_from_plot(egui_plot::PlotPoint::new(absolute(p.end_ns),p.y(mode)))).find(|p|visible_clip.shrink(4.).contains(*p));
                if std::env::var_os("ANDROID_EBPF_QA_ISSUE_POINT").is_some() {
                    self.render_qa.point_target=drawn.iter().filter_map(|p|p.start_ns.map(|a|plot.screen_from_plot(egui_plot::PlotPoint::new(absolute(a),p.issue_y(mode))))).find(|p|plot.transform().frame().shrink(3.).contains(*p)&&visible_clip.contains(*p));
                }
                if std::env::var("ANDROID_EBPF_QA_SEGMENT_POINT").is_ok() {
                    self.render_qa.point_target=drawn.iter().find_map(|p|p.start_ns.and_then(|a|{
                        let a=plot.screen_from_plot(egui_plot::PlotPoint::new(absolute(a),p.issue_y(mode)));let b=plot.screen_from_plot(egui_plot::PlotPoint::new(absolute(p.end_ns),p.y(mode)));
                        (a.distance(b)>40.).then_some(a.lerp(b,0.5))
                    }));
                }
                for (op,color) in [(IoOperation::Read,accent()),(IoOperation::Write,green()),(IoOperation::Discard,red()),(IoOperation::Flush,amber()),(IoOperation::Other,muted())] {
                    let group:Vec<_>=drawn.iter().copied().filter(|p|p.operation==op).collect();
                    if view.mode==TimelineMode::Requests {for p in &group {if let Some(a)=p.start_ns {
                        plot.line(Line::new("",vec![[absolute(a),p.y(mode)],[absolute(p.end_ns),p.y(mode)]]).allow_hover(false).color(color).width(3.));
                    }}}
                    plot.points(Points::new(format!("{} issue",operation_label(op)),group.iter().filter_map(|p|p.start_ns.map(|a|[absolute(a),p.issue_y(mode)])).collect::<Vec<_>>()).filled(false).radius(3.5).color(color));
                    plot.points(Points::new(format!("{} complete",operation_label(op)),group.iter().map(|p|[absolute(p.end_ns),p.y(mode)]).collect::<Vec<_>>()).radius(2.5).color(color));
                }
                if let Some(s)=&self.selection.summary {plot.points(Points::new("Selected",visible.iter().filter(|p|s.keys.contains(&p.key)).map(|p|[absolute(p.end_ns),p.y(mode)]).collect::<Vec<_>>()).allow_hover(false).filled(false).radius(6.).color(amber()));}
                if selecting&&plot.response().clicked()&&let Some(pos)=plot.pointer_coordinate() {
                    let screen=plot.screen_from_plot(pos);
                    selected=visible.iter().filter_map(|p|{
                        let b=plot.screen_from_plot(egui_plot::PlotPoint::new(absolute(p.end_ns),p.y(mode)));
                        let distance=if let Some(a)=p.start_ns {
                            let a=plot.screen_from_plot(egui_plot::PlotPoint::new(absolute(a),p.issue_y(mode)));
                            if view.mode==TimelineMode::Requests {egui::pos2(screen.x.clamp(a.x.min(b.x),a.x.max(b.x)),b.y).distance(screen)}else{a.distance(screen).min(b.distance(screen))}
                        }else{b.distance(screen)};
                        (distance<12.).then_some((distance,p.key))
                    }).min_by(|a,b|a.0.total_cmp(&b.0)).map(|(_,key)|SelectionRequest::Point(key));
                }
                if selecting&&plot.response().drag_started()&&let Some(pos)=plot.response().interact_pointer_pos() {let p=plot.plot_from_screen(pos-plot.response().drag_delta());drag=Some([p.x,p.y]);}
                if selecting&&let Some(a)=drag&&let Some(pos)=plot.response().interact_pointer_pos() {
                    let p=plot.plot_from_screen(pos);let min=[a[0].min(p.x),a[1].min(p.y)];let max=[a[0].max(p.x),a[1].max(p.y)];
                    plot.polygon(egui_plot::Polygon::new("Selected area",vec![min,[max[0],min[1]],max,[min[0],max[1]]]).fill_color(accent().gamma_multiply(0.15)));
                    if plot.response().drag_stopped(){selected=Some(SelectionRequest::Rectangle{min,max});drag=None;}
                }
            });
        qa_region(&mut self.render_qa,"Timeline",response.response.rect,ui.clip_rect());
        self.selection.drag_start=drag;if let Some(request)=selected{self.begin_selection(request);}
    }
}

