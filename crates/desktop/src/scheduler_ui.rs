// Scheduler delays have their own population. Never synthesize a CompletedIo
// to reuse request statistics: a task delay has no device, operation or payload.
#[cfg(test)]
mod scheduler_tests {
    use super::*;
    #[test]
    fn scheduler_probe_metadata_preserves_loss_status_live_and_reloaded() {
        let mut app=StudioApp{loss_status:"Kernel loss: 7".into(),..Default::default()};
        let path=std::env::temp_dir().join(format!("scheduler-source-{}.ndjson",uuid::Uuid::new_v4()));
        let mut lines=Vec::new();
        for (source,stage,status) in [("native","recording","Kernel loss: 7"),("scheduler_iowait","recording","Task delay probe attached"),("scheduler_iowait","complete","Task delay capture finished")] {
            let record=WireRecord::SourceInfo{schema_version:android_ebpf_protocol::SCHEMA_VERSION,source:source.into(),status:status.into(),metadata:serde_json::json!({"stage":stage})};
            lines.push(serde_json::to_string(&record).unwrap());app.ingest_record(record);
        }
        assert_eq!(app.loss_status,"Kernel loss: 7");
        std::fs::write(&path,lines.join("\n")+"\n").unwrap();
        let loaded=crate::session::load_analysis(&path).unwrap();
        assert_eq!(loaded.loss_status,"Kernel loss: 7");
        assert_eq!(loaded.source_info.len(),3);
        std::fs::remove_file(path).unwrap();
    }
    fn waits()->Vec<android_ebpf_protocol::SchedulerIoWait> {
        (0..200).map(|i|android_ebpf_protocol::SchedulerIoWait{ts_ns:100_000_000+i*10_000_000,delay_ns:(i%20)*1000,tid:if i%2==0{42}else{43},pid:if i%2==0{None}else{Some(40)},comm:if i%2==0{"Worker-A"}else{"worker-B"}.into(),cpu:Some((i%4) as u32),source:"fixture".into()}).collect()
    }
    #[test]
    fn scheduler_only_session_has_filters_and_shared_origin_without_block_statistics() {
        let mut app=StudioApp{y_axis:AxisMetric::SchedulerIoWait,..Default::default()};
        for w in waits(){app.analyzer.ingest(android_ebpf_protocol::StorageEvent::SchedulerIoWait(w));}
        assert_eq!(app.time_origin(),100_000_000);assert_eq!(app.analyzer.summary().completed_ios,0);
        app.render_qa.output=Some(PathBuf::from("unused-test-region-marker"));
        let ctx=egui::Context::default();let mut output=ctx.run_ui(Default::default(),|root|{egui::CentralPanel::default().show(root,|ui|app.filter_ui(ui));});output.textures_delta.clear();
        assert!(app.render_qa.regions.contains_key("analysis-filters"));
    }
    #[test]
    fn scheduler_switch_discards_previous_request_summary_work() {
        let mut app=StudioApp{y_axis:AxisMetric::SchedulerIoWait,..Default::default()};
        let (_tx,rx)=bounded(1);app.selection.all_pending=Some((0,AxisMetric::TimeMs,AxisMetric::Sector,SummaryWork {receiver:rx,cancelled:Arc::new(AtomicBool::new(false))}));
        let ctx=egui::Context::default();let mut output=ctx.run_ui(Default::default(),|root|app.selection_panel(root));output.textures_delta.clear();
        assert!(app.selection.all_pending.is_none(),"previous request-summary receiver cannot remain pending on scheduler view");
    }
    #[test]
    fn scheduler_native_ui_content_renders_empty_and_populated_without_request_summary() {
        for rows in [vec![],waits()] {
            let mut app=StudioApp{y_axis:AxisMetric::SchedulerIoWait,explorer_preset:ExplorerPreset::SchedulerIoWait,..Default::default()};
            app.scheduler.signature=Some((app.analysis_generation,app.query.clone()));
            app.scheduler.view=Some(Arc::new(build_scheduler_view(rows,&app.query,100_000_000,0)));
            let ctx=egui::Context::default();
            for _ in 0..3 {let mut output=ctx.run_ui(egui::RawInput{screen_rect:Some(egui::Rect::from_min_size(egui::Pos2::ZERO,egui::vec2(1600.,1000.))),..Default::default()},|root| {
                app.scheduler_panel(root);egui::CentralPanel::default().show(root,|ui|app.scheduler_trend_ui(ui));
            });output.textures_delta.clear();}
            assert!(app.selection.summary.is_none());
            assert_eq!(app.scheduler.view.as_ref().unwrap().distribution.values.len(),app.scheduler.view.as_ref().unwrap().rows.len());
        }
    }
    #[test]
    fn scheduler_filters_selection_percentiles_and_exports_share_one_population() {
        let all=build_scheduler_view(waits(),&AnalysisFilter::default(),100_000_000,0);
        assert_eq!(all.distribution.percentile(50),Some(9.));assert_eq!(all.distribution.percentile(95),Some(18.));
        assert_eq!(all.distribution.histogram(16).iter().map(|b|b.count).sum::<usize>(),200);
        for (q,count) in [(AnalysisFilter{process:"WORKER-a".into(),..Default::default()},100),(AnalysisFilter{tid:43,start_ms:10.,end_ms:30.,..Default::default()},2),(AnalysisFilter{pid:40,..Default::default()},100),(AnalysisFilter{pid:42,..Default::default()},0),(AnalysisFilter{cpu:Some(0),..Default::default()},50),(AnalysisFilter{device:"8:0".into(),..Default::default()},0)] {assert_eq!(build_scheduler_view(waits(),&q,100_000_000,0).rows.len(),count);}
        let selected=select_scheduler(&all,SchedulerSelection::Rectangle{min:[0.,0.],max:[100.,5.]});
        assert_eq!(selected.rows.len(),6);assert_eq!(selected.distribution.percentile(50),Some(2.));
        let point=select_scheduler(&all,SchedulerSelection::Point(0));assert_eq!(point.distribution.values,[0.]);
        let path=std::env::temp_dir().join(format!("scheduler-{}.csv",uuid::Uuid::new_v4()));write_scheduler_csv(&path,&selected,false).unwrap();
        let rows=csv::Reader::from_path(&path).unwrap().records().collect::<Result<Vec<_>,_>>().unwrap();assert_eq!(rows.len(),6);assert_eq!(&rows[0][2],"0");assert!(rows[0][5].is_empty());std::fs::remove_file(path).unwrap();
    }
}
#[derive(Clone,serde::Serialize)]
struct SchedulerView {
    rows:Vec<android_ebpf_protocol::SchedulerIoWait>,
    distribution:crate::graph_summary::Distribution,
    origin:u64,
    source_count:usize,
    dropped:usize,
    incompatible:bool,
}
#[derive(Clone,Copy)]
enum SchedulerSelection { Point(usize), Rectangle{min:[f64;2],max:[f64;2]} }
#[derive(Default)]
struct SchedulerState {
    signature:Option<(u64,AnalysisFilter)>,
    pending:Option<Receiver<SchedulerView>>,
    view:Option<Arc<SchedulerView>>,
    selected:Option<Arc<SchedulerView>>,
    selected_pending:Option<Receiver<SchedulerView>>,
    refreshed:Option<Instant>,
    applied:bool,
}
fn scheduler_block_filters(q:&AnalysisFilter)->bool {
    q.latency_range.is_some() || q.request_keys.is_some() || !q.file.is_empty() || !q.device.is_empty() || q.operation.is_some()
        || q.confidence.is_some() || q.min_bytes>0 || q.max_bytes>0 || q.access.is_some() || q.layer.is_some()
}
fn scheduler_xy(w:&android_ebpf_protocol::SchedulerIoWait,origin:u64)->[f64;2] {
    // Signed subtraction preserves timestamps preceding the common origin.
    [(i128::from(w.ts_ns)-i128::from(origin)) as f64/1e6,w.delay_ns as f64/1000.]
}
fn scheduler_distribution(rows:&[android_ebpf_protocol::SchedulerIoWait])->crate::graph_summary::Distribution {
    let mut d=crate::graph_summary::Distribution::default();
    for w in rows { d.observe(Some(w.delay_ns as f64/1000.)); }
    d.finish();d
}
fn build_scheduler_view(mut rows:Vec<android_ebpf_protocol::SchedulerIoWait>,q:&AnalysisFilter,origin:u64,dropped:usize)->SchedulerView {
    let source_count=rows.len();let incompatible=scheduler_block_filters(q);
    let process=q.process.to_lowercase();
    rows.retain(|w| {
        let t=scheduler_xy(w,origin)[0];
        !incompatible && t>=q.start_ms && (q.end_ms<=0. || t<=q.end_ms)
            && (q.pid==0 || w.pid==Some(q.pid)) && (q.tid==0 || w.tid==q.tid)
            && q.cpu.is_none_or(|cpu|w.cpu==Some(cpu)) && w.comm.to_lowercase().contains(&process)
    });
    rows.sort_by_key(|w|w.ts_ns);
    let distribution=scheduler_distribution(&rows);
    SchedulerView{rows,distribution,origin,source_count,dropped,incompatible}
}
fn select_scheduler(view:&SchedulerView,request:SchedulerSelection)->SchedulerView {
    let rows:Vec<_>=view.rows.iter().enumerate().filter(|(i,w)|match request {
        SchedulerSelection::Point(index)=>*i==index,
        SchedulerSelection::Rectangle{min,max}=>{let p=scheduler_xy(w,view.origin);p[0]>=min[0]&&p[0]<=max[0]&&p[1]>=min[1]&&p[1]<=max[1]},
    }).map(|(_,w)|w.clone()).collect();
    let distribution=scheduler_distribution(&rows);
    SchedulerView{rows,distribution,origin:view.origin,source_count:view.source_count,dropped:view.dropped,incompatible:view.incompatible}
}
fn write_scheduler_csv(path:&std::path::Path,view:&SchedulerView,summary:bool)->anyhow::Result<()> {
    let mut out=csv::Writer::from_path(path)?;
    if summary {
        out.write_record(["kind","lower_or_rank","upper","count_or_value","unit"])?;
        out.write_record(["population","retained scheduler task delay events","",&view.rows.len().to_string(),"events"])?;
        out.write_record(["retention_dropped","before analysis filters","",&view.dropped.to_string(),"events"])?;
        for p in [0,25,50,75,90,95,99,100] {out.write_record(["percentile",&p.to_string(),"",&view.distribution.percentile(p).map_or("unavailable".into(),|v|v.to_string()),"us"])?;}
        for b in view.distribution.histogram(16) {out.write_record(["histogram",&b.lower.to_string(),&b.upper.to_string(),&b.count.to_string(),"us; [lower,upper), final inclusive"])?;}
        for (i,v) in view.distribution.values.iter().enumerate() {out.write_record(["cdf_rank",&(i+1).to_string(),&view.distribution.values.partition_point(|n|n<=v).to_string(),&v.to_string(),"us; exact cumulative count in upper"])?;}
    } else {
        out.write_record(["timestamp_ns","time_ms","delay_ns","delay_us","task_tid","task_pid","task_comm","observer_cpu","source","origin_ns"])?;
        for w in &view.rows {let p=scheduler_xy(w,view.origin);out.write_record([w.ts_ns.to_string(),p[0].to_string(),w.delay_ns.to_string(),p[1].to_string(),w.tid.to_string(),w.pid.map_or(String::new(),|n|n.to_string()),w.comm.clone(),w.cpu.map_or(String::new(),|n|n.to_string()),w.source.clone(),view.origin.to_string()])?;}
    }
    out.flush()?;Ok(())
}
impl StudioApp {
    fn poll_scheduler(&mut self) {
        let changed=self.scheduler.signature.as_ref().is_none_or(|(g,q)|q!=&self.query || *g!=self.analysis_generation);
        let query_changed=self.scheduler.signature.as_ref().is_none_or(|(_,q)|q!=&self.query);
        let live=self.is_running();
        let due=query_changed || ((!live || self.scheduler.refreshed.is_none_or(|t|t.elapsed()>=LIVE_ANALYSIS_REFRESH)) && self.scheduler.selected.is_none() && !self.scheduler.applied);
        if changed && due {
            self.scheduler=SchedulerState::default();
            self.scheduler.signature=Some((self.analysis_generation,self.query.clone()));
            let rows=self.analyzer.scheduler_waits().to_vec();
            let origin=self.time_origin();
            let dropped=self.analyzer.scheduler_waits_dropped();let q=self.query.clone();
            let (tx,rx)=bounded(1);self.scheduler.pending=Some(rx);self.scheduler.refreshed=Some(Instant::now());
            self.selection.auto_bounds=true;
            std::thread::spawn(move||{let _=tx.send(build_scheduler_view(rows,&q,origin,dropped));});
        }
        if let Some(rx)=&self.scheduler.pending {match rx.try_recv() {
            Ok(v)=>{self.scheduler.view=Some(Arc::new(v));self.scheduler.pending=None;},
            Err(crossbeam_channel::TryRecvError::Disconnected)=>self.scheduler.pending=None,
            Err(crossbeam_channel::TryRecvError::Empty)=>{},
        }}
        if let Some(rx)=&self.scheduler.selected_pending {match rx.try_recv() {
            Ok(v)=>{self.scheduler.selected=Some(Arc::new(v));self.scheduler.selected_pending=None;},
            Err(crossbeam_channel::TryRecvError::Disconnected)=>self.scheduler.selected_pending=None,
            Err(crossbeam_channel::TryRecvError::Empty)=>{},
        }}
    }
    fn scheduler_panel(&mut self,ui:&mut egui::Ui) {
        self.poll_scheduler();
        let mut panel=egui::Panel::right("selection-summary").default_size(340.).size_range(260.0..=440.0).resizable(true);
        if ui.ctx().content_rect().width()<1100. {panel=panel.exact_size(280.);}
        panel.show(ui,|ui| {
            ui.heading("Graph summary");
            ui.horizontal(|ui| {
                ui.strong("Summary");
                let clear=ui.button("Clear selection");qa_region(&mut self.render_qa,"scheduler-clear",clear.rect,ui.clip_rect());
                if clear.clicked(){self.scheduler.selected=None;self.scheduler.selected_pending=None;}
            });
            if self.scheduler.pending.is_some()||self.scheduler.selected_pending.is_some(){ui.spinner();ui.label("Calculating scheduler samples…");}
            let Some(view)=self.scheduler.selected.as_ref().or(self.scheduler.view.as_ref()).cloned() else{return;};
            egui::ScrollArea::vertical().id_salt("scheduler-summary").show(ui,|ui| {
                ui.small(if self.scheduler.selected.is_some(){"Selected scheduler events"}else if self.scheduler.applied{"Applied scheduler event cohort"}else{"Full filtered scheduler graph"});
                if self.is_running(){ui.small("Live snapshot; selected/applied cohorts stay fixed until cleared or filters change.");}
                ui.heading(format!("{} wait events",view.rows.len()));
                ui.label("Scheduler I/O wait · microseconds");
                ui.small("Observed task delays from sched_stat_iowait. Exact nearest-rank percentiles of retained events, before display sampling.");
                if let Some(WireRecord::SourceInfo{status,metadata,..})=self.source_info.iter().rev().find(|r|matches!(r,WireRecord::SourceInfo{source,metadata,..} if source=="scheduler_iowait"&&metadata["stage"]=="recording")) {
                    ui.small(status);
                    if let Some(error)=metadata["stats_error"].as_str(){ui.colored_label(amber(),format!("Scheduler accounting could not be enabled: {error}"));}
                    if let Some(scope)=metadata["capture_filter_scope"].as_str(){ui.small(scope);}
                }
                if let Some(error)=self.source_info.iter().rev().find_map(|r|match r {WireRecord::SourceInfo{source,metadata,..} if source=="scheduler_iowait"=>metadata["stats_restore"]["Err"].as_str(),_=>None}) {ui.colored_label(amber(),format!("Scheduler accounting restoration failed: {error}"));}
                if view.dropped>0 {ui.colored_label(amber(),format!("{} earlier wait events removed by detail retention. Distribution covers retained events only; narrow and reload the original interval.",view.dropped));}
                if view.incompatible {ui.colored_label(amber(),"Block-only filters have no scheduler identity. Clear them to view wait events.");}
                if view.source_count==0 {ui.label("No scheduler I/O wait samples were captured. This does not mean zero wait. Kernel schedstats, tracepoint availability and collector support are required.");}
                distribution_ui(ui,&view.distribution,"Delay (us)","Wait events");
                if self.scheduler.selected.is_some() && ui.button("Apply selected scheduler events").clicked() {
                    self.scheduler.view=Some(view.clone());self.scheduler.selected=None;self.scheduler.applied=true;self.selection.auto_bounds=true;
                }
                if self.scheduler.applied && ui.button("Restore full filtered scheduler graph").clicked(){self.scheduler.signature=None;}
                for (summary,label) in [(false,"Export wait events CSV"),(true,"Export wait summary CSV")] {
                    if ui.button(label).clicked() && let Some(path)=rfd::FileDialog::new().set_file_name(if summary{"scheduler-summary.csv"}else{"scheduler-events.csv"}).save_file() {
                        let result=self.session_path.as_ref().map_or(Ok(()),|source|crate::session::ensure_distinct_export(source,&path)).and_then(|_|write_scheduler_csv(&path,&view,summary));
                        self.status=match result {Ok(())=>format!("Saved {}",path.display()),Err(e)=>e.to_string()};
                    }
                }
                ui.small("Task TID/comm identify the waiting task. PID is shown only when known. CPU is the observer CPU. Device, Read/Write, file path and payload are unmeasured for these events.");
            });
        });
    }
    fn scheduler_trend_ui(&mut self,ui:&mut egui::Ui) {
        self.poll_scheduler();
        ui.small("Process matches waiting-task comm; TID and time filters apply. CPU filters the observer. PID excludes unknown TGID. Events are plotted at scheduler accounting time, not an invented wait start.");
        if scheduler_block_filters(&self.query) {
            ui.colored_label(amber(),"Device / command / size / path / layer / request-selection filters cannot identify scheduler events.");
            if ui.button("Clear block-only filters").clicked() {
                self.query=AnalysisFilter{start_ms:self.query.start_ms,end_ms:self.query.end_ms,pid:self.query.pid,tid:self.query.tid,process:self.query.process.clone(),cpu:self.query.cpu,..Default::default()};self.invalidate_query();self.scheduler.signature=None;
            }
        }
        let Some(view)=self.scheduler.view.clone() else{ui.spinner();return;};
        let stride=view.rows.len().div_ceil(5000).max(1);
        let drawn:Vec<_>=view.rows.iter().enumerate().step_by(stride).collect();
        ui.small(format!("{} filtered / {} retained wait events · displaying {} · table and Summary use all cohort samples",view.rows.len(),view.source_count,drawn.len()));
        let selecting=self.selection.enabled;let mut drag=self.selection.drag_start;let mut request=None;
        let auto=std::mem::take(&mut self.selection.auto_bounds);let clip=ui.clip_rect();
        let response=studio_plot("scheduler-iowait").height(430.).x_axis_label("Time (ms)").y_axis_label("I/O wait delay (us)")
            .allow_drag(!selecting).allow_boxed_zoom(!selecting).label_formatter(|hover|match hover {
                HoverPosition::NearDataPoint{index,..}=>drawn.get(*index).map(|(_,w)|format!("{} · TID {} · PID {}\nDelay {} ns · event {} ns\nObserver CPU {}\n{}",w.comm,w.tid,identity_number(w.pid),w.delay_ns,w.ts_ns,identity_number(w.cpu),w.source)),_=>None,
            }).show(ui,|plot| {
                if auto {
                    let min=view.rows.first().map_or(0.,|w|scheduler_xy(w,view.origin)[0]);let max=view.rows.last().map_or(1.,|w|scheduler_xy(w,view.origin)[0]);let pad=(max-min).max(1.)*0.03;
                    let ymax=view.distribution.percentile(100).unwrap_or(1.).max(1.);
                    plot.set_plot_bounds(egui_plot::PlotBounds::from_min_max([min-pad,-ymax*0.03],[max+pad,ymax*1.05]));
                }
                self.render_qa.plot_rect=Some(*plot.transform().frame());
                self.render_qa.point_target=drawn.iter().map(|(_,w)|{let p=scheduler_xy(w,view.origin);plot.screen_from_plot(egui_plot::PlotPoint::new(p[0],p[1]))}).find(|p|plot.transform().frame().shrink(4.).contains(*p)&&clip.contains(*p));
                plot.points(Points::new("Task I/O wait",drawn.iter().map(|(_,w)|scheduler_xy(w,view.origin)).collect::<Vec<_>>()).color(accent()).radius(3.));
                if let Some(s)=&self.scheduler.selected {plot.points(Points::new("Selected",s.rows.iter().step_by(s.rows.len().div_ceil(5000).max(1)).map(|w|scheduler_xy(w,view.origin)).collect::<Vec<_>>()).allow_hover(false).filled(false).color(amber()).radius(6.));}
                if selecting && plot.response().clicked() && let Some(p)=plot.pointer_coordinate() {
                    let screen=plot.screen_from_plot(p);
                    request=view.rows.iter().enumerate().filter_map(|(i,w)|{let p=scheduler_xy(w,view.origin);let d=plot.screen_from_plot(egui_plot::PlotPoint::new(p[0],p[1])).distance(screen);(d<12.).then_some((d,i))}).min_by(|a,b|a.0.total_cmp(&b.0)).map(|(_,i)|SchedulerSelection::Point(i));
                }
                if selecting&&plot.response().drag_started()&&let Some(pos)=plot.response().interact_pointer_pos(){let p=plot.plot_from_screen(pos-plot.response().drag_delta());drag=Some([p.x,p.y]);}
                if selecting&&let Some(a)=drag&&let Some(pos)=plot.response().interact_pointer_pos(){let p=plot.plot_from_screen(pos);let min=[a[0].min(p.x),a[1].min(p.y)];let max=[a[0].max(p.x),a[1].max(p.y)];plot.polygon(egui_plot::Polygon::new("Selection",vec![min,[max[0],min[1]],max,[min[0],max[1]]]).fill_color(accent().gamma_multiply(0.15)));if plot.response().drag_stopped(){request=Some(SchedulerSelection::Rectangle{min,max});drag=None;}}
            });
        qa_region(&mut self.render_qa,"Scheduler trend",response.response.rect,ui.clip_rect());
        self.selection.drag_start=drag;
        if let Some(request)=request {let (tx,rx)=bounded(1);self.scheduler.selected_pending=Some(rx);let view=view.clone();std::thread::spawn(move||{let _=tx.send(select_scheduler(&view,request));});}
        ui.separator();ui.strong("Scheduler event details · current summary cohort");
        let table=self.scheduler.selected.as_ref().unwrap_or(&view);
        egui::ScrollArea::both().id_salt("scheduler-table").max_height(260.).show_rows(ui,20.,table.rows.len(),|ui,range| {
            for i in range {let w=&table.rows[i];ui.monospace(format!("{:.3} ms | {} ns wait | TID {} | PID {} | {} | CPU {} | {}",scheduler_xy(w,table.origin)[0],w.delay_ns,w.tid,identity_number(w.pid),w.comm,identity_number(w.cpu),w.source));}
        });
    }
}
