#[derive(Default)]
struct RawLogState {
    identity: Option<(PathBuf, IoSelectionKey)>,
    pending: Option<Receiver<Result<String, String>>>,
    text: Option<String>,
}

fn raw_record_matches(record: &WireRecord, io: &CompletedIo) -> bool {
    use android_ebpf_protocol::StorageEvent;
    let same = |id, major, minor| {
        id == io.issue.request_id
            && major == io.issue.device_major
            && minor == io.issue.device_minor
    };
    match record {
        WireRecord::Event { event, .. } => match event {
            StorageEvent::BlockIssue(e) => {
                same(e.request_id, e.device_major, e.device_minor) && e.ts_ns == io.issue.ts_ns
            }
            StorageEvent::BlockInsert(e) => {
                same(e.request_id, e.device_major, e.device_minor)
                    && io
                        .insert
                        .as_ref()
                        .is_some_and(|insert| insert.ts_ns == e.ts_ns)
            }
            StorageEvent::BlockComplete(e) => {
                same(e.request_id, e.device_major, e.device_minor) && e.ts_ns == io.completion.ts_ns
            }
            StorageEvent::ObservedBlockCompletion(e) => {
                selection_key(e) == selection_key(io) && e.completion.ts_ns == io.completion.ts_ns
            }
            _ => false,
        },
        _ => false,
    }
}

fn read_request_raw_log(path: &std::path::Path, io: &CompletedIo) -> anyhow::Result<String> {
    use std::io::BufRead;
    let mut text = format!(
        "Session: {}\nRequest key: {:?}\nMarked lines are exact stored request records. Unmarked adjacent lines are context only.\n\n",
        path.display(),
        selection_key(io)
    );
    let mut previous = VecDeque::new();
    let mut after = 0usize;
    let mut matches = 0;
    let mut shown = 0;
    let mut last_shown = 0;
    for (index, line) in std::io::BufReader::new(std::fs::File::open(path)?)
        .lines()
        .enumerate()
    {
        let line = line?;
        let number = index + 1;
        let matched =
            serde_json::from_str::<WireRecord>(&line).is_ok_and(|r| raw_record_matches(&r, io));
        if matched {
            matches += 1;
        }
        if shown < 100 && (matched || after > 0) {
            if matched {
                for (n, old) in &previous {
                    if *n > last_shown {
                        text.push_str(&format!("  {n}: {old}\n"));
                        shown += 1;
                    }
                }
            }
            text.push_str(&format!(
                "{} {number}: {line}\n",
                if matched { ">" } else { " " }
            ));
            shown += 1;
            last_shown = number;
        }
        after = if matched { 3 } else { after.saturating_sub(1) };
        previous.push_back((number, line));
        if previous.len() > 3 {
            previous.pop_front();
        }
    }
    text.push_str(&format!(
        "\nMatched session records: {matches}. Display capped at 100 context lines.\n"
    ));
    if matches == 0 {
        text.push_str("No exact stored record found. The retained analysis projection below is not a substitute for an original source record.\n");
    }
    if let Some(evidence) = io.evidence.as_ref() {
        if let Some(raw) = crate::perfetto_session::raw_trace_path(path) {
            let decoded = crate::perfetto::decode(std::fs::File::open(&raw)?);
            text.push_str(&format!("\nDecoded original Perfetto block events: {}\nRecord IDs are trace-local, not kernel request IDs. Issue candidates are correlation evidence, not proven ownership.\n",raw.display()));
            let mut found = false;
            for event in &decoded.events {
                let completion = event.record_id == evidence.record_id
                    && event.kind == crate::perfetto::BlockKind::Complete
                    && event.timestamp_ns == io.completion.ts_ns
                    && crate::perfetto_projection::device_numbers(event.device_encoded)
                        == (io.issue.device_major, io.issue.device_minor);
                let candidate = evidence.issue_record_candidates.contains(&event.record_id);
                if completion || candidate {
                    found |= completion;
                    text.push_str(&format!(
                        "{}\n{}\n",
                        if completion {
                            "Exact completion record"
                        } else {
                            "Issue candidate record"
                        },
                        serde_json::to_string_pretty(event)?
                    ));
                }
            }
            if !found {
                text.push_str(
                    "Matching completion record unavailable in this raw trace / bounded decoder.\n",
                );
            }
            text.push_str(&format!(
                "Decode quality: {}\n",
                serde_json::to_string(&decoded.quality)?
            ));
        } else {
            text.push_str("Original Perfetto trace unavailable beside this saved session. Raw record IDs remain in the projection.\n");
        }
    }
    text.push_str(&format!(
        "\nRetained analysis projection (derived fields included):\n{}\n",
        serde_json::to_string_pretty(io)?
    ));
    Ok(text)
}

#[cfg(test)]
mod raw_log_tests {
    use super::*;
    use android_ebpf_protocol::{BlockComplete, BlockIssue, SCHEMA_VERSION, StorageEvent};
    #[test]
    fn reused_request_id_matches_only_exact_lifetime_and_exports_original_lines() {
        let mut engine = AnalysisEngine::new();
        let mut records = Vec::new();
        for start in [10, 30] {
            for event in [
                StorageEvent::BlockIssue(BlockIssue {
                    ts_ns: start,
                    request_id: 1,
                    device_major: 8,
                    device_minor: 0,
                    sector: 0,
                    sectors: 8,
                    bytes: 4096,
                    operation: IoOperation::Read,
                    pid: 1,
                    tid: 1,
                    cpu: 0,
                    comm: "request".into(),
                }),
                StorageEvent::BlockComplete(BlockComplete {
                    cpu: None,
                    ts_ns: start + 5,
                    request_id: 1,
                    device_major: 8,
                    device_minor: 0,
                    status: 0,
                }),
            ] {
                engine.ingest(event.clone());
                records.push(WireRecord::Event {
                    schema_version: SCHEMA_VERSION,
                    sequence: records.len() as u64,
                    event,
                });
            }
        }
        let io = engine.completed_ios().last().unwrap();
        assert_eq!(
            records
                .iter()
                .map(|r| raw_record_matches(r, io))
                .collect::<Vec<_>>(),
            [false, false, true, true]
        );
        let path =
            std::env::temp_dir().join(format!("raw-evidence-{}.ndjson", uuid::Uuid::new_v4()));
        let original = records
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, &original).unwrap();
        let result = read_request_raw_log(&path, io).unwrap();
        assert_eq!(result.lines().filter(|s| s.starts_with("> ")).count(), 2);
        assert!(result.contains(&format!("> 3: {}", original.lines().nth(2).unwrap())));
        assert!(result.contains("Matched session records: 2"));
        std::fs::remove_file(path).unwrap();
    }
}

impl StudioApp {
    fn raw_log_ui(&mut self, ui: &mut egui::Ui, io: &CompletedIo) {
        egui::CollapsingHeader::new("Raw Log · selected request / source records").default_open(std::env::var_os("ANDROID_EBPF_QA_RAW_LOG").is_some()).show(ui,|ui| {
            let identity=self.session_path.clone().map(|p|(p,selection_key(io)));
            if self.raw_log.identity!=identity {self.raw_log=RawLogState{identity:identity.clone(),..Default::default()};}
            let result=self.raw_log.pending.as_ref().and_then(|rx|match rx.try_recv(){Ok(v)=>Some(v),Err(crossbeam_channel::TryRecvError::Disconnected)=>Some(Err("Raw log worker stopped".into())),Err(crossbeam_channel::TryRecvError::Empty)=>None});
            if let Some(result)=result {self.raw_log.text=Some(result.unwrap_or_else(|e|format!("Raw log unavailable: {e}")));self.raw_log.pending=None;}
            ui.small("Read the saved request's original NDJSON lines and neighboring context. Perfetto sessions also show matching decoded raw completion and candidate issue records. Reading runs in the background.");
            let qa_auto=std::env::var_os("ANDROID_EBPF_QA_RAW_LOG").is_some() && self.raw_log.text.is_none() && self.raw_log.pending.is_none();
            if (ui.add_enabled(identity.is_some() && self.raw_log.pending.is_none(),egui::Button::new("Load source records")).clicked() || qa_auto) && let Some((path,_))=identity {
                let io=io.clone();let(tx,rx)=bounded(1);self.raw_log.pending=Some(rx);
                std::thread::spawn(move||{let _=tx.send(read_request_raw_log(&path,&io).map_err(|e|e.to_string()));});
            }
            if self.raw_log.pending.is_some(){ui.spinner();ui.ctx().request_repaint_after(Duration::from_millis(100));}
            if self.session_path.is_none(){ui.label("Save this session before reading original source records.");}
            if let Some(text)=self.raw_log.text.as_ref() {
                ui.horizontal(|ui| {
                    if ui.button("Copy raw evidence").clicked(){ui.ctx().copy_text(text.clone());}
                    if ui.button("Export raw evidence text").clicked() && let Some(path)=rfd::FileDialog::new().set_file_name("request-raw-log.txt").save_file() {self.status=match std::fs::write(path,text){Ok(())=>"Raw evidence exported".into(),Err(e)=>e.to_string()};}
                });
                egui::ScrollArea::both().id_salt("raw-request-log").max_height(360.).show(ui,|ui|{ui.add(egui::Label::new(RichText::new(text).monospace()).selectable(true));});
            }
        });
    }
}
