fn main() -> eframe::Result {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let mut options = eframe::NativeOptions {
        renderer: if cfg!(target_os = "windows") {
            eframe::Renderer::Wgpu
        } else {
            eframe::Renderer::Glow
        },
        persist_window: std::env::var_os("ANDROID_EBPF_QA_OUTPUT").is_none(),
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1500.0, 940.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };
    // The Windows OpenGL initialization path can fault inside ControlLib.dll
    // before an app frame. Use the native D3D12 path without changing drivers.
    if cfg!(target_os = "windows")
        && let eframe::egui_wgpu::WgpuSetup::CreateNew(setup) = &mut options.wgpu_options.wgpu_setup
    {
        setup.instance_descriptor.backends = eframe::wgpu::Backends::DX12;
    }
    tracing::info!(renderer = %options.renderer, "Starting native renderer");
    eframe::run_native(
        "Android eBPF Storage Studio",
        options,
        Box::new(|cc| Ok(Box::new(android_ebpf_studio::app::StudioApp::new(cc)))),
    )
}
