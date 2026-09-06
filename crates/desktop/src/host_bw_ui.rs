struct BandwidthContext {
    activity:Arc<crate::host_bw::ActivityTimeline>,
    range:(u64,u64),
    devices:Vec<crate::host_bw::Device>,
}
impl BandwidthContext {
    fn attach(self,s:&mut SelectionSummary) {
        s.host_bw=Some(crate::host_bw::calculate(&self.activity,self.range,crate::host_bw::TransferBytes{read:s.read.bytes,write:s.write.bytes,other:s.other_bytes},self.devices));
    }
}
impl StudioApp {
    fn bandwidth_context(&self,request:Option<SelectionRequest>)->BandwidthContext {
        let origin=self.time_origin();
        let mut range=self.reanalysis.window.or(self.activity.range).unwrap_or((origin,origin));
        let absolute=|ms:f64|origin.saturating_add((ms.max(0.)*1e6) as u64);
        range.0=range.0.max(absolute(self.query.start_ms));
        if self.query.end_ms>0. {range.1=range.1.min(absolute(self.query.end_ms));}
        match request {
            Some(SelectionRequest::Rectangle{min,max})=> {
                let axis=if self.x_axis==AxisMetric::TimeMs {Some(0)}else if self.y_axis==AxisMetric::TimeMs {Some(1)}else{None};
                if let Some(axis)=axis {
                    if min[axis].is_finite(){range.0=range.0.max(absolute(min[axis]));}
                    if max[axis].is_finite(){range.1=range.1.min(absolute(max[axis]));}
                }
            }
            Some(SelectionRequest::Point(key))=> {
                if let Some(io)=self.analysis().completed_ios().iter().find(|io|selection_key(io)==key) {
                    range=(io.start_timestamp().max(range.0),io.completion.ts_ns.min(range.1));
                }
            }
            None=>{}
        }
        range.1=range.1.max(range.0);
        let devices=self.activity.devices.keys().copied().filter(|d|self.query.device.is_empty()||format!("{}:{}",d.0,d.1)==self.query.device).collect();
        BandwidthContext{activity:Arc::clone(&self.activity),range,devices}
    }
}

fn host_bw_ui(ui:&mut egui::Ui,s:&SelectionSummary) {
    let Some(b)=&s.host_bw else {return;};
    ui.strong("Host BW · MiB/s");
    if b.estimated {ui.colored_label(amber(),"Reconstructed estimate · block trace, Probable request matching");}
    ui.small("Completion-counted Read + Write payload from this graph cohort. Detail-based BW is not the unsampled kernel throughput.");
    egui::Grid::new("host-bw-rates").num_columns(3).striped(true).show(ui,|ui| {
        ui.label("");ui.strong("with Idle");ui.strong("w/o Idle");ui.end_row();
        for (i,label) in ["Total","Read","Write"].iter().enumerate() {
            ui.label(*label);
            for value in [b.with_idle_mib_s[i],b.without_idle_mib_s[i]] {ui.label(value.map_or("—".into(),|v|format!("{v:.4}")));}
            ui.end_row();
        }
    });
    ui.label(format!("Bytes: Total {} · Read {} · Write {}",format_bytes(b.bytes.total()),format_bytes(b.bytes.read),format_bytes(b.bytes.write)));
    if b.bytes.other>0 {ui.small(format!("Excluded non-R/W command extents: {} (for example, Discard ranges)",format_bytes(b.bytes.other)));}
    ui.label(format!("Analysis time: {}",format_latency(Some(b.duration_ns))));
    ui.label(format!("Active/Busy: {} · Idle: {}",format_latency(b.busy_ns),format_latency(b.idle_ns)));
    if b.busy_ns.is_none() {
        ui.small(format!("Observed active-time lower bound: {}",format_latency(Some(b.observed_busy_ns))));
        ui.colored_label(amber(),format!("w/o Idle unavailable: {}",b.coverage));
    }
    ui.collapsing("BW definitions & coverage",|ui| {
        ui.label(format!("Range: {}–{} ns",b.start_ns,b.end_ns));
        ui.label("with Idle = bytes / analysis time. w/o Idle = same bytes / active time. Total = Read + Write payload. Discard/Flush/Other command extents are excluded from bytes; their observed execution still contributes to device active time. Total, Read and Write use the same denominator.");
        ui.label("Active time is the union of measured issue-to-completion intervals for all observed processes and operations on the selected devices. Process/FilePath filters change the numerator, never erase other processes' device activity.");
        ui.label("Completed requests in the inclusive analysis interval contribute their full bytes, even if issued before Start. Activity intervals are clipped to the interval; requests completing later still contribute activity. A point uses that request's observed span. Adjacent inclusive selections can share an endpoint request.");
        ui.label("Multiple devices: sum selected request bytes and use wall-clock union of activity (any device busy), not summed device-seconds. Stacked block-device observations may represent the same physical transfer; select one device to avoid that interpretation.");
        ui.label(format!("Devices: {}",b.devices.iter().map(|d|format!("{}:{}",d.0,d.1)).collect::<Vec<_>>().join(", ")));
        ui.label(&b.coverage);
        ui.label("MiB/s uses 1,048,576 bytes/MiB. — means unknown coverage or zero denominator, not zero throughput.");
    });
}

#[cfg(test)]
mod bandwidth_ui_tests {
    use super::*;
    use android_ebpf_protocol::{BlockIssue,BlockComplete,StorageEvent};
    #[test]
    fn filter_area_reset_and_csv_share_explicit_clock_and_device_wide_activity() {
        let mut app=StudioApp::default();
        for (id,pid,a,b) in [(1,10,0,2),(2,11,2,8),(3,10,9,10)] {
            for event in [StorageEvent::BlockIssue(BlockIssue{ts_ns:a*1_000_000_000,request_id:id,device_major:8,device_minor:0,sector:id*8,sectors:2048,bytes:1_048_576,operation:IoOperation::Read,pid,tid:pid,cpu:0,comm:"shared-name".into()}),StorageEvent::BlockComplete(BlockComplete{ts_ns:b*1_000_000_000,request_id:id,device_major:8,device_minor:0,status:0})] {
                if let Some(io)=app.analyzer.ingest(event) {Arc::make_mut(&mut app.activity).observe(&io);}
            }
        }
        // Fixture provenance is fully known; production coverage is not inferred.
        Arc::make_mut(&mut app.activity).verified_complete=true;
        app.query.pid=10;app.invalidate_query();app.rebuild_filtered();
        let rect=SelectionRequest::Rectangle{min:[1000.,0.],max:[8500.,f64::INFINITY]};
        let mut s=compute_selection(app.analysis(),rect,AxisMetric::TimeMs,AxisMetric::Sector,0);
        app.x_axis=AxisMetric::TimeMs;app.y_axis=AxisMetric::Sector;
        app.bandwidth_context(Some(rect)).attach(&mut s);
        let b=s.host_bw.as_ref().unwrap();
        assert_eq!(s.keys.len(),1);assert_eq!(b.duration_ns,7_500_000_000);
        assert_eq!(b.busy_ns,Some(7_000_000_000));assert_eq!(b.idle_ns,Some(500_000_000));
        assert_eq!(b.without_idle_mib_s[1],Some(1./7.));
        let path=std::env::temp_dir().join(format!("bw-{}.csv",uuid::Uuid::new_v4()));
        write_graph_summary_csv(&path,&s).unwrap();
        let records=csv::Reader::from_path(&path).unwrap().records().collect::<Result<Vec<_>,_>>().unwrap();
        assert!(records.iter().any(|r|&r[1]=="Host BW w/o Idle"&&&r[2]=="Read"&&r[5].parse::<f64>().unwrap()==1./7.&&&r[6]=="MiB/s"));
        std::fs::remove_file(path).unwrap();
        app.query=AnalysisFilter::default();app.invalidate_query();app.rebuild_filtered();
        assert_eq!(app.analysis().completed_ios().len(),3);
        assert_eq!(app.bandwidth_context(None).range,(0,10_000_000_000));
    }
}
