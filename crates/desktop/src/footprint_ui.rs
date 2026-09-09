#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum FootprintMode {
    #[default]
    Combined,
    FilePath,
    Process,
    FileProcess,
}

#[cfg(test)]
mod footprint_tests {
    use super::*;
    use android_ebpf_protocol::{BlockComplete,BlockIssue,StorageEvent,RequestOrigin,IoOrigin,FileIdentity,PathSnapshot,PathSource};
    fn fixture()->AnalysisEngine {
        let mut engine=AnalysisEngine::new();
        for (id,pid,minor) in [(1,10,0),(2,11,0),(3,10,1)] {
            engine.ingest(StorageEvent::BlockIssue(BlockIssue{ts_ns:id*1_000_000,request_id:id,device_major:8,device_minor:minor,sector:100,sectors:8,bytes:4096,operation:IoOperation::Read,pid,tid:pid,cpu:0,comm:"same-name".into()}));
            engine.ingest(StorageEvent::BlockComplete(BlockComplete{cpu:None,ts_ns:id*1_000_000+500_000,request_id:id,device_major:8,device_minor:minor,status:0}));
        }
        engine
    }
    #[test]
    fn connected_coordinates_preserve_measured_lifetime_and_never_fabricate_missing_start() {
        let source=fixture();let mut engine=AnalysisEngine::new();
        for (index,original) in source.completed_ios().iter().enumerate() {
            let mut io=original.clone();
            if index==1 {io.evidence=Some(Box::new(android_ebpf_protocol::CompletionEvidence {
                source:"fixture".into(),record_id:2,issue_record_candidates:vec![],issue_timestamp_ns:None,issuer_pid:None,issuer_tid:None,issuer_cpu:None,completion_status:None,process_name:None,timing_confidence:android_ebpf_protocol::CorrelationConfidence::ContextOnly,reason:"no issue event".into(),clock:0,
            }));}
            engine.ingest(StorageEvent::ObservedBlockCompletion(io));
        }
        let view=build_footprint(&engine,0,FootprintMode::Combined,0);
        assert_eq!(view.lanes.len(),2);assert_eq!(view.unique,3);
        let points:Vec<_>=view.lanes.values().flatten().collect();
        assert_eq!(points.iter().filter(|p|p.issue_ms.is_some()).count(),2);
        assert!(points.iter().any(|p|p.issue_ms==Some(1.)&&p.point.coordinates==[1.5,100.]&&p.end_sector==108.));
        assert!(points.iter().any(|p|p.issue_ms.is_none()&&p.point.coordinates==[2.5,100.]));
        assert!(view.min[0]<1.&&view.max[0]>3.5);
        let s=compute_selection(&engine,SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]},AxisMetric::TimeMs,AxisMetric::Sector,0);
        assert_eq!(s.keys.len(),3);assert_eq!(s.metric.total.values,[100.;3]);assert_eq!(s.read.bytes,3*4096);
    }
    #[test]
    fn process_lanes_keep_same_name_pids_and_devices_separate_and_reset_caches() {
        let engine=fixture();
        let view=build_footprint(&engine,0,FootprintMode::Process,0);
        assert_eq!(view.lanes.len(),3);
        assert_eq!(view.unique,3);
        assert_eq!(view.memberships,3);
        assert!(view.lanes.keys().any(|n|n.contains("8:1")&&n.contains("PID 10")));
        let missing=build_footprint(&engine,0,FootprintMode::FileProcess,0);
        assert!(missing.lanes.keys().all(|n|n.contains("unproven")));
        let mut app=StudioApp{analyzer:engine,..Default::default()};
        app.footprint.view=Some(view);
        app.query.pid=11;app.invalidate_query();app.rebuild_filtered();
        assert!(app.footprint.view.is_none());
        assert_eq!(build_footprint(app.analysis(),1,FootprintMode::Process,0).unique,1);
        app.query=AnalysisFilter::default();app.invalidate_query();app.rebuild_filtered();
        assert_eq!(build_footprint(app.analysis(),1,FootprintMode::Process,0).unique,3);
    }
    #[test]
    fn multi_origin_lanes_duplicate_membership_but_never_global_io_or_bytes() {
        let mut engine=fixture();
        for inode in [42,43] {
            engine.ingest(StorageEvent::RequestOrigin(RequestOrigin {
                ts_ns:1_100_000,request_id:1,origin_id:inode,
                file:FileIdentity{fs_device_major:8,fs_device_minor:0,inode,inode_generation:None,mount_id:None},
                path:Some(PathSnapshot{path:Some(format!("/data/{inode}")),source:PathSource::ProcFd,captured_ts_ns:1_100_000,deleted:false}),
                origin:IoOrigin::Unknown,operation:IoOperation::Read,bytes:Some(4096),pid:10,tid:10,
                file_origin_confidence:EdgeConfidence::Exact,request_lifetime_confidence:EdgeConfidence::Probable,incomplete:false,
            }));
        }
        let view=build_footprint(&engine,0,FootprintMode::FilePath,0);
        assert_eq!(view.unique,3);
        assert_eq!(view.memberships,4);
        assert!(view.lanes.keys().any(|n|n.contains("/data/42")&&n.contains("Probable")));
        let s=compute_selection(&engine,SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]},AxisMetric::TimeMs,AxisMetric::Sector,0);
        assert_eq!(s.keys.len(),3);assert_eq!(s.read.bytes,3*4096);
        assert_eq!(s.categories["File candidate membership"].values().map(|v|v.0).sum::<u64>(),4);
        assert_eq!(s.categories["Process"].values().map(|v|v.0).sum::<u64>(),3);
        assert_eq!(s.categories["File candidate membership"].values().map(|v|v.1).sum::<u64>(),4*4096);
    }
}
impl FootprintMode {
    fn label(self)->&'static str {match self {
        Self::Combined=>"Combined",Self::FilePath=>"FilePath lanes",
        Self::Process=>"Block issuer Process lanes",Self::FileProcess=>"File I/O Process candidate lanes",
    }}
}
#[derive(Default)]
struct FootprintState {
    mode:FootprintMode,
    connected:bool,
    view:Option<FootprintView>,
    pending:Option<Receiver<FootprintView>>,
    fit:bool,
}
struct FootprintView {
    generation:u64,
    mode:FootprintMode,
    lanes:BTreeMap<String,Vec<FootprintPoint>>,
    min:[f64;2],
    max:[f64;2],
    unique:usize,
    memberships:usize,
    built:Instant,
}
struct FootprintPoint {
    point:ExplorerPoint,
    issue_ms:Option<f64>,
    end_sector:f64,
    operation:IoOperation,
}

fn footprint_groups(io:&CompletedIo,graph:&IoTransactionGraph,mode:FootprintMode)->Vec<String> {
    let device=format!("Device {}:{}",io.issue.device_major,io.issue.device_minor);
    let mut names=std::collections::BTreeSet::new();
    match mode {
        FootprintMode::Combined=>{names.insert(device.clone());}
        FootprintMode::Process=>{names.insert(format!("{device} | {} · PID {}",if io.issue.comm.is_empty(){"<name unavailable>"}else{&io.issue.comm},identity_number(io.issuer_pid())));}
        FootprintMode::FilePath=>{
            for origin in block_file_origins(graph) {
                let path=origin.path.as_ref().and_then(|p|p.path.as_deref()).filter(|s|!s.is_empty()).unwrap_or("<path unresolved>");
                names.insert(format!("{device} | {path} | {} | {}",origin.file.fallback_label(),edge_confidence_label(origin.confidence)));
            }
        }
        FootprintMode::FileProcess=>{
            for node in graph.nodes.iter().filter(|n|n.kind==IoNodeKind::FileOperation) {
                // A related FileOperation is a candidate, not proof that the
                // block issuer is the originating process (notably writeback).
                names.insert(format!("{device} | file-process candidate PID {} / TID {} | {}",node.pid,node.tid,node.name));
            }
        }
    }
    if names.is_empty() {names.insert(format!("{device} | {}",if mode==FootprintMode::FileProcess{"<originating process unproven / async writeback>"}else{"<path unresolved>"}));}
    names.into_iter().collect()
}

fn build_footprint(engine:&AnalysisEngine,generation:u64,mode:FootprintMode,origin:u64)->FootprintView {
    let mut view=FootprintView{generation,mode,lanes:BTreeMap::new(),min:[f64::INFINITY;2],max:[f64::NEG_INFINITY;2],unique:0,memberships:0,built:Instant::now()};
    for io in engine.completed_ios() {
        let Some(completion)=io.completion_timestamp() else {continue;};
        let time=completion.saturating_sub(origin) as f64/1e6;
        let issue_ms=io.issue_timestamp().filter(|ts|*ts<=io.completion.ts_ns).map(|ts|ts.saturating_sub(origin) as f64/1e6);
        let sector=io.issue.sector as f64;
        let end=io.issue.sector.saturating_add(io.issue.sectors as u64) as f64;
        let graph=engine.transaction_for(io);
        let names=footprint_groups(io,&graph,mode);
        let tooltip=format!("{}\nBlock issuer: {}\nDevice {}:{}\nLBA [{}, {}) · {} bytes\nIssue: {:?} ns · Complete: {} ns\n{}\n{}",
            operation_label(io.issue.operation),issuer_label(io.issuer_pid(),io.issuer_tid(),&io.issue.comm),io.issue.device_major,io.issue.device_minor,
            io.issue.sector,io.issue.sector.saturating_add(io.issue.sectors as u64),io.issue.bytes,io.issue_timestamp(),io.completion.ts_ns,
            file_origin_tooltip(&block_file_origins(&graph)),if names.len()>1{"Repeated display across candidate lanes; counted once in global Summary."}else{"Block issuer and original file process are distinct roles."});
        for name in names {
            view.lanes.entry(name).or_default().push(FootprintPoint{point:ExplorerPoint{coordinates:[time,sector],file_tooltip:Some(tooltip.clone()),request:selection_key(io)},issue_ms,end_sector:end,operation:io.issue.operation});
            view.memberships+=1;
        }
        view.unique+=1;
        view.min[0]=view.min[0].min(issue_ms.unwrap_or(time));view.max[0]=view.max[0].max(time);
        view.min[1]=view.min[1].min(sector);view.max[1]=view.max[1].max(end);
    }
    if view.unique==0 {view.min=[0.;2];view.max=[1.;2];}
    for axis in 0..2 {let pad=(view.max[axis]-view.min[axis]).max(1.)*0.03;view.min[axis]-=pad;view.max[axis]+=pad;}
    view
}

impl StudioApp {
    fn connected_footprint(&self)->bool {(self.footprint.connected||self.explorer_preset==ExplorerPreset::ConnectedFootprint) && self.x_axis==AxisMetric::TimeMs && matches!(self.y_axis,AxisMetric::Sector|AxisMetric::AddressKiB|AxisMetric::AddressMB)}
    fn footprint_controls(&mut self,ui:&mut egui::Ui) {
        if self.x_axis!=AxisMetric::TimeMs || !matches!(self.y_axis,AxisMetric::Sector|AxisMetric::AddressKiB|AxisMetric::AddressMB) {return;}
        let before=self.footprint.mode;
        ui.horizontal_wrapped(|ui| {
            let mut connected=self.connected_footprint();
            if ui.checkbox(&mut connected,"Connect issue to completion").changed() {
                self.explorer_preset=if connected {ExplorerPreset::ConnectedFootprint}else{ExplorerPreset::LbaDistribution};self.footprint.fit=true;
            }
            self.footprint.connected=connected;
            ui.label("Footprint layout");
            egui::ComboBox::from_id_salt("footprint-layout").selected_text(self.footprint.mode.label()).show_ui(ui,|ui| {
                for mode in [FootprintMode::Combined,FootprintMode::FilePath,FootprintMode::Process,FootprintMode::FileProcess] {ui.selectable_value(&mut self.footprint.mode,mode,mode.label());}
            });
            if ui.button("Fit all lanes").clicked(){self.footprint.fit=true;}
        });
        if before!=self.footprint.mode {self.footprint.view=None;self.footprint.pending=None;self.footprint.fit=true;}
    }

    fn footprint_lanes_ui(&mut self,ui:&mut egui::Ui) {
        let connected=self.connected_footprint();
        if let Some(rx)=&self.footprint.pending && let Ok(view)=rx.try_recv() {
            if view.mode==self.footprint.mode {self.footprint.view=Some(view);}
            self.footprint.pending=None;
        }
        let stale=self.footprint.view.as_ref().is_none_or(|v|v.generation!=self.analysis_generation && (!self.is_running()||v.built.elapsed()>=LIVE_ANALYSIS_REFRESH));
        if stale && self.footprint.pending.is_none() {
            let engine=self.analysis().select_completed(|_|true);
            let (g,mode,origin)=(self.analysis_generation,self.footprint.mode,self.time_origin());
            let (tx,rx)=bounded(1);self.footprint.pending=Some(rx);
            std::thread::spawn(move||{let _=tx.send(build_footprint(&engine,g,mode,origin));});
        }
        let Some(view)=&self.footprint.view else {ui.spinner();ui.label("Building full-resolution footprint groups…");return;};
        ui.label(format!("{} unique I/O · {} lane memberships · {} groups",view.unique,view.memberships,view.lanes.len()));
        ui.small("Each lane includes its device identity. File candidates and async writeback are not proven original-process attribution. Repeated memberships never increase the global Summary count/bytes. All groups are accessible with the page control.");
        if connected {ui.small("Hollow start = measured issue; filled end = completion. Horizontal line = observed lifetime at starting LBA; vertical line = address extent. Missing issue keeps only completion/extent. Click a segment or endpoint to inspect one I/O. Rectangle selects completion endpoints, preserving completion-counted Summary/BW.");}
        let page_id=ui.id().with("footprint-page");
        let mut page=ui.data_mut(|d|d.get_temp::<usize>(page_id).unwrap_or(0));
        let pages=view.lanes.len().div_ceil(4).max(1);page=page.min(pages-1);
        ui.horizontal(|ui| {
            let previous=ui.add_enabled(page>0,egui::Button::new("Previous lanes"));
            qa_region(&mut self.render_qa,"previous-lanes",previous.rect,ui.clip_rect());
            if previous.clicked(){page-=1;}
            ui.label(format!("{} / {}",page+1,pages));
            let next=ui.add_enabled(page+1<pages,egui::Button::new("Next lanes"));
            qa_region(&mut self.render_qa,"next-lanes",next.rect,ui.clip_rect());
            if next.clicked(){page+=1;}
        });
        self.render_qa.lane_page=page;self.render_qa.lane_pages=pages;
        self.render_qa.lane_visible=view.lanes.keys().skip(page*4).take(4).cloned().collect();
        ui.data_mut(|d|d.insert_temp(page_id,page));
        let divisor=match self.y_axis { AxisMetric::AddressKiB=>2.0, AxisMetric::AddressMB=>1_000_000.0/512.0, _=>1.0 };
        let fit=self.footprint.fit;
        let mut select=None;
        let mut filter=None;
        let mut area_keys=None;
        let selecting=self.selection.enabled;
        let bounds_command=self.selection.bounds_command.take();
        let storage_y_max=(self.explorer_preset==ExplorerPreset::LbaDistribution).then(||self.storage_range.y_max(self.y_axis)).flatten();
        ui.small("Drag a rectangle to summarize I/O in that lane. Disable Select points / area to pan linked axes.");
        for (name,points) in view.lanes.iter().skip(page*4).take(4) {
            ui.push_id(name,|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(name);ui.label(format!("n={}",points.len()));
                    if ui.button("Analyze this lane").clicked(){filter=Some(points.iter().map(|p|p.point.request).collect());}
                });
                let step=points.len().div_ceil(3000).max(1);
                let drag_id=ui.id().with("lane-drag");
                let mut drag=ui.data_mut(|d|d.get_temp::<[f64;2]>(drag_id));
                let lane_plot=studio_plot(ui.id().with("lane"));
                let lane_plot=if let Some(max)=storage_y_max {lane_plot.default_y_bounds(0.,max)}else{lane_plot};
                lane_plot.height(if view.mode==FootprintMode::Combined {330.}else{175.}).link_axis("footprint-shared-axes",[true,true])
                    .allow_drag(false)
                    .allow_boxed_zoom(!selecting).boxed_zoom_pointer_button(egui::PointerButton::Primary)
                    .y_axis_formatter(|m,_|compact_tick(m.value))
                    .y_grid_spacer(summary_grid)
                    .link_cursor("footprint-shared-cursor",[true,true]).x_axis_label(if connected {"Issue to completion time (ms)"}else{"Completion time (ms)"}).y_axis_label(self.y_axis.label()).legend(Legend::default())
                    .label_formatter(|hover|match hover {
                        HoverPosition::NearDataPoint{plot_name,index,..}=>points.iter().filter(|p|operation_label(p.operation)==*plot_name).step_by(step).nth(*index).and_then(|p|p.point.file_tooltip.clone()),
                        _=>None,
                    }).show(ui,|plot| {
                        if fit {plot.set_plot_bounds(egui_plot::PlotBounds::from_min_max([view.min[0],if storage_y_max.is_some(){0.}else{view.min[1]/divisor}],[view.max[0],storage_y_max.unwrap_or(view.max[1]/divisor)]));}
                        if let Some(bounds)=bounds_command {plot.set_plot_bounds(bounds);}
                        self.selection.current_bounds=Some(plot.plot_bounds());
                        if page==0 && name==view.lanes.first_key_value().unwrap().0 {
                            self.render_qa.plot_rect=Some(*plot.transform().frame());
                            self.render_qa.point_target=points.first().map(|p|plot.screen_from_plot(egui_plot::PlotPoint::new(p.point.coordinates[0],p.point.coordinates[1]/divisor)));
                            if connected && std::env::var("ANDROID_EBPF_QA_SEGMENT_POINT").is_ok() {
                                self.render_qa.point_target=points.iter().step_by(step).filter_map(|p|p.issue_ms.map(|start|(start,p))).find_map(|(start,p)| {
                                    let a=plot.screen_from_plot(egui_plot::PlotPoint::new(start,p.point.coordinates[1]/divisor));let b=plot.screen_from_plot(egui_plot::PlotPoint::new(p.point.coordinates[0],p.point.coordinates[1]/divisor));
                                    (a.distance(b)>40.).then_some(a.lerp(b,0.5))
                                });
                            }
                        }
                        if selecting && plot.response().drag_started() && let Some(pos)=plot.response().interact_pointer_pos() {
                            let p=plot.plot_from_screen(pos-plot.response().drag_delta()); drag=Some([p.x,p.y]);
                        }
                        if selecting && let Some(start)=drag && let Some(pos)=plot.response().interact_pointer_pos() {
                            let p=plot.plot_from_screen(pos);
                            let (min,max)=([start[0].min(p.x),start[1].min(p.y)],[start[0].max(p.x),start[1].max(p.y)]);
                            plot.polygon(egui_plot::Polygon::new("Selection area",vec![min,[max[0],min[1]],max,[min[0],max[1]]]).fill_color(accent().gamma_multiply(0.15)).stroke(Stroke::new(1.5,accent())));
                            if plot.response().drag_stopped() {
                                area_keys=Some((SelectionRequest::Rectangle{min,max},points.iter().filter(|p|{let [x,y]=p.point.coordinates;x>=min[0]&&x<=max[0]&&y/divisor>=min[1]&&y/divisor<=max[1]}).map(|p|p.point.request).collect::<std::collections::HashSet<_>>()));
                                drag=None;
                            }
                        }
                        for (op,color) in [(IoOperation::Read,accent()),(IoOperation::Write,green()),(IoOperation::Flush,amber()),(IoOperation::Discard,red()),(IoOperation::Other,muted())] {
                            let coords:Vec<_>=points.iter().filter(|p|p.operation==op).step_by(step).map(|p|[p.point.coordinates[0],p.point.coordinates[1]/divisor]).collect();
                            plot.points(Points::new(operation_label(op),coords).color(color).radius(2.5));
                        }
                        for op in [IoOperation::Read,IoOperation::Write,IoOperation::Flush,IoOperation::Discard,IoOperation::Other] {
                          for p in points.iter().filter(|p|p.operation==op).step_by(step) {
                            if connected && let Some(start)=p.issue_ms {
                                let color=match p.operation {IoOperation::Read=>accent(),IoOperation::Write=>green(),IoOperation::Discard=>red(),IoOperation::Flush=>amber(),IoOperation::Other=>muted()};
                                plot.line(Line::new("",vec![[start,p.point.coordinates[1]/divisor],[p.point.coordinates[0],p.point.coordinates[1]/divisor]]).allow_hover(false).color(color));
                                plot.points(Points::new("",vec![[start,p.point.coordinates[1]/divisor]]).allow_hover(false).filled(false).radius(3.5).color(color));
                            }
                            plot.line(Line::new("",vec![[p.point.coordinates[0],p.point.coordinates[1]/divisor],[p.point.coordinates[0],p.end_sector/divisor]]).allow_hover(false).color(if p.operation==IoOperation::Write{green()}else{accent()}));
                          }
                        }
                        if let Some(summary)=&self.selection.summary {
                            plot.points(Points::new("Selected",points.iter().filter(|p|summary.keys.contains(&p.point.request)).map(|p|[p.point.coordinates[0],p.point.coordinates[1]/divisor]).collect::<Vec<_>>()).filled(false).allow_hover(false).radius(5.).color(amber()));
                        }
                        if selecting && plot.response().clicked() && let Some(pos)=plot.pointer_coordinate() {
                            let screen=plot.screen_from_plot(pos);
                            select=points.iter().filter_map(|p|{
                                let end=plot.screen_from_plot(egui_plot::PlotPoint::new(p.point.coordinates[0],p.point.coordinates[1]/divisor));
                                let distance=if connected && let Some(start)=p.issue_ms {let start=plot.screen_from_plot(egui_plot::PlotPoint::new(start,p.point.coordinates[1]/divisor));egui::pos2(screen.x.clamp(start.x.min(end.x),start.x.max(end.x)),end.y).distance(screen)}else{end.distance(screen)};
                                (distance<16.).then_some((distance,p.point.request))
                            }).min_by(|a,b|a.0.total_cmp(&b.0)).map(|v|v.1);
                        }
                    });
                ui.data_mut(|d|{if let Some(drag)=drag {d.insert_temp(drag_id,drag);}else{d.remove::<[f64;2]>(drag_id);}});
                if step>1 {ui.small(format!("Display stride {step}; Summary and lane filtering use all {} I/O",points.len()));}
            });
        }
        self.footprint.fit=false;
        if let Some(keys)=filter {self.query.request_keys=Some(keys);self.invalidate_query();self.rebuild_filtered();}
        if let Some(key)=select {self.begin_selection(SelectionRequest::Point(key));}
        if let Some((request,keys))=area_keys {
            let bw=self.bandwidth_context(Some(request));
            let engine=self.analysis().select_completed(|io|keys.contains(&selection_key(io)));
            // Replace any older worker receiver. A late result cannot replace
            // this lane's cohort, even when the old worker is still finishing.
            self.selection.queued=None;
            self.selection.discard_pending=false;
            self.selection.requested_at=Some(Instant::now());
            let (tx,rx)=bounded(1);self.selection.pending=Some(rx);
            let (x,y,origin)=(self.x_axis,self.y_axis,self.time_origin());
            std::thread::spawn(move||{let mut s=compute_selection(&engine,SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]},x,y,origin);bw.attach(&mut s);let _=tx.send(s);});
        }
    }
}
