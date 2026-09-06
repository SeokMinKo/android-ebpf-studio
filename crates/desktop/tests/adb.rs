use android_ebpf_studio::adb::{AdbCommandBuilder, DeviceState, parse_devices};

#[test]
fn root_requires_actual_uid_not_successful_adb_exit_text() {
    use android_ebpf_studio::adb::is_root_uid;
    assert!(is_root_uid("0\r\n"));
    assert!(!is_root_uid("2000\r\n"));
    assert!(!is_root_uid(
        "adbd cannot run as root in production builds\r\n"
    ));
    assert!(!is_root_uid(""));
}

#[test]
fn parses_only_structured_adb_device_rows() {
    let output = concat!(
        "List of devices attached\n",
        "R3CN123456 device product:qssi model:SM_S938N device:pa3q transport_id:1\n",
        "192.168.0.5:5555 unauthorized transport_id:2\n",
        "\n"
    );

    let devices = parse_devices(output);
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].serial, "R3CN123456");
    assert_eq!(devices[0].model.as_deref(), Some("SM_S938N"));
    assert_eq!(devices[0].state, DeviceState::Device);
    assert_eq!(devices[1].state, DeviceState::Unauthorized);
}

#[test]
fn every_target_command_binds_the_selected_serial() {
    let builder = AdbCommandBuilder::new("192.168.0.5:5555").unwrap();
    let command = builder.shell(&["getprop", "ro.product.model"]);

    assert_eq!(command.program, "adb");
    assert_eq!(
        command.args,
        [
            "-s",
            "192.168.0.5:5555",
            "shell",
            "getprop",
            "ro.product.model"
        ]
    );
}

#[test]
fn rejects_serials_that_could_be_shell_arguments() {
    assert!(AdbCommandBuilder::new("-d").is_err());
    assert!(AdbCommandBuilder::new("serial;whoami").is_err());
    assert!(AdbCommandBuilder::new("serial with spaces").is_err());
}

#[test]
fn privileged_commands_quote_values_and_stay_bound_to_target() {
    use android_ebpf_studio::adb::RootMethod;
    let builder = AdbCommandBuilder::new("second-phone").unwrap();
    for method in [RootMethod::Shell, RootMethod::SuCommand, RootMethod::SuUid] {
        let spec = builder.root_shell(method, &["printf", "a'$(id); b"]);
        assert_eq!(&spec.args[..3], &["-s", "second-phone", "shell"]);
        assert_eq!(spec.args.len(), 4);
        assert!(spec.args[3].contains("printf"));
        assert!(spec.args[3].contains("'\"'\"'"));
    }
}

#[test]
fn root_is_not_enough_for_full_tracing_and_abi_is_checked() {
    use android_ebpf_studio::adb::PreflightReport;
    let mut report = PreflightReport {
        root: true,
        ..Default::default()
    };
    assert!(!report.full_ebpf_ready());
    report.tracefs = true;
    report.block_issue = true;
    report.block_complete = true;
    report.abi = "x86_64".into();
    assert!(!report.full_ebpf_ready());
    report.abi = "arm64-v8a".into();
    assert!(report.full_ebpf_ready());
}
