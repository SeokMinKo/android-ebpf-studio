fn main() -> eframe::Result {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([1400.0, 900.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Android eBPF Storage Studio",
        options,
        Box::new(|_| Ok(Box::new(android_ebpf_studio::app::StudioApp::default()))),
    )
}
