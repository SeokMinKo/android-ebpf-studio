impl StudioApp {
    fn recover_perfetto(&mut self, from_phone: bool) {
        if self.is_running() {
            return;
        }
        let Some(original) = self.session_path.clone() else {
            return;
        };
        self.phase = CapturePhase::Analyzing;
        self.status = if from_phone {
            "Recovering the original phone's Perfetto trace…"
        } else {
            "Reanalyzing saved raw trace…"
        }
        .into();
        let client = self.adb.clone();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = if from_phone {
                crate::perfetto_session::recover_from_phone(client, &original)
            } else {
                crate::perfetto_session::reanalyze_saved_trace(&original)
            };
            match result {
                Ok(path) => {
                    let loaded = session::load_analysis(&path)
                        .map(Box::new)
                        .map_err(|e| e.to_string());
                    let _ = tx.send(HostMessage::SessionLoaded(path, loaded));
                }
                Err(error) => {
                    let _=tx.send(HostMessage::SessionLoaded(original,Err(format!("Recovery failed: {error}. Original session preserved; reconnect its phone or reanalyze an available saved raw trace."))));
                }
            }
        });
    }
    fn export_perfetto_raw(&mut self) {
        if self.is_running() || self.raw_export_pending {
            return;
        }
        let Some(source) = self.session_path.clone() else {
            return;
        };
        if self.render_qa.output.is_some()
            && let Some(destination) = std::env::var_os("ANDROID_EBPF_QA_EXPORT_RAW")
        {
            self.start_raw_trace_export(source, PathBuf::from(destination));
            return;
        }
        let Some(destination) = rfd::FileDialog::new()
            .add_filter("Perfetto raw trace", &["pftrace"])
            .set_file_name("android-storage.pftrace")
            .save_file()
        else {
            return;
        };
        self.start_raw_trace_export(source, destination);
    }
    fn start_raw_trace_export(&mut self, source: PathBuf, destination: PathBuf) {
        if self.raw_export_pending {
            return;
        }
        self.raw_export_pending = true;
        self.status = "Exporting Perfetto raw trace…".into();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = crate::perfetto_session::export_raw_trace(&source, &destination)
                .map_err(|e| e.to_string());
            let _ = tx.send(HostMessage::RawTraceExported(result));
        });
    }
    fn perfetto_recovery_ui(&mut self, ui: &mut egui::Ui) {
        let raw = self
            .session_path
            .as_deref()
            .and_then(crate::perfetto_session::raw_trace_path)
            .is_some();
        let manifest = self
            .session_path
            .as_deref()
            .and_then(crate::perfetto_session::recovery_manifest)
            .is_some();
        if !raw && !manifest {
            return;
        }
        ui.strong("Recover preserved Perfetto data");
        ui.label("Recovery creates a new analysis session. The original session stays available. Phone recovery always targets the device recorded in this session, regardless of the current device selection.");
        ui.horizontal_wrapped(|ui| {
            let recover =
                ui.add_enabled(manifest, egui::Button::new("Recover from original phone"));
            self.render_qa
                .inspector_buttons
                .insert("Recover from original phone".into(), recover.rect.center());
            if recover.clicked() {
                self.recover_perfetto(true);
            }
            let local = ui.add_enabled(raw, egui::Button::new("Reanalyze saved raw trace"));
            self.render_qa
                .inspector_buttons
                .insert("Reanalyze saved raw trace".into(), local.rect.center());
            if local.clicked() {
                self.recover_perfetto(false);
            }
        });
    }
}
