fn main() -> eframe::Result {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let options = eframe::NativeOptions {
        persist_window: std::env::var_os("ANDROID_EBPF_QA_OUTPUT").is_none(),
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1500.0, 940.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Android eBPF Storage Studio",
        options,
        Box::new(|cc| Ok(Box::new(android_ebpf_studio::app::StudioApp::new(cc)))),
    )
}
