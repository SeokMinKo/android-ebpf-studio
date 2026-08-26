use android_ebpf_studio::adb::{AdbCommandBuilder, DeviceState, parse_devices};

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
