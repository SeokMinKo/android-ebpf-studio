use android_ebpf_agent::trace_format::{
    parse_layout, parse_pipeline_layout, parse_raw_syscall_layout,
};
use android_ebpf_types::OFFSET_MISSING;

const FORMAT: &str = r#"
name: block_rq_issue
ID: 1223
format:
        field:unsigned short common_type; offset:0; size:2; signed:0;
        field:dev_t dev; offset:8; size:4; signed:0;
        field:sector_t sector; offset:16; size:8; signed:0;
        field:unsigned int nr_sector; offset:24; size:4; signed:0;
        field:unsigned int bytes; offset:28; size:4; signed:0;
        field:char rwbs[8]; offset:32; size:8; signed:1;
        field:void * rq; offset:56; size:8; signed:0;
"#;

#[test]
fn parses_kernel_tracepoint_offsets_by_field_name() {
    let layout = parse_layout(FORMAT).unwrap();
    assert_eq!(layout.dev_offset, 8);
    assert_eq!(layout.sector_offset, 16);
    assert_eq!(layout.nr_sector_offset, 24);
    assert_eq!(layout.bytes_offset, 28);
    assert_eq!(layout.rwbs_offset, 32);
    assert_eq!(layout.request_offset, 56);
    assert_eq!(layout.status_offset, OFFSET_MISSING);
}

#[test]
fn parses_raw_syscall_enter_and_exit_layouts() {
    let enter = concat!(
        "field:long id; offset:8; size:8; signed:1;\n",
        "field:unsigned long args[6]; offset:16; size:48; signed:0;\n"
    );
    let exit = concat!(
        "field:long id; offset:8; size:8; signed:1;\n",
        "field:long ret; offset:16; size:8; signed:1;\n"
    );
    let layout = parse_raw_syscall_layout(enter, exit).unwrap();
    assert_eq!(layout.enter_id_offset, 8);
    assert_eq!(layout.enter_args_offset, 16);
    assert_eq!(layout.exit_ret_offset, 16);
}

#[test]
fn mandatory_storage_fields_are_required() {
    let error = parse_layout("field:dev_t dev; offset:8; size:4; signed:0;")
        .expect_err("sector and length are mandatory");
    assert!(error.to_string().contains("sector"));
}

#[test]
fn parses_ufs_pipeline_layout_with_dynamic_state() {
    let format = concat!(
        "field:__data_loc char[] str; offset:8; size:4; signed:1;\n",
        "field:unsigned int tag; offset:12; size:4; signed:0;\n",
        "field:int transfer_len; offset:20; size:4; signed:1;\n",
        "field:u64 lba; offset:32; size:8; signed:0;\n",
        "field:u8 opcode; offset:40; size:1; signed:0;\n",
        "field:int status; offset:44; size:4; signed:1;\n"
    );
    let layout = parse_pipeline_layout(
        format,
        &["tag"],
        &["lba"],
        &["transfer_len"],
        &["opcode"],
        &["status"],
        &["str"],
    )
    .unwrap();
    assert_eq!(layout.key_offset, 12);
    assert_eq!(layout.key_size, 4);
    assert_eq!(layout.sector_offset, 32);
    assert_eq!(layout.bytes_offset, 20);
    assert_eq!(layout.operation_offset, 40);
    assert_eq!(layout.status_offset, 44);
    assert_eq!(layout.state_offset, 8);
}

#[test]
fn rejects_pipeline_key_sizes_the_bpf_reader_cannot_decode() {
    let format = "field:u16 tag; offset:8; size:2; signed:0;\n";
    let error = parse_pipeline_layout(format, &["tag"], &[], &[], &[], &[], &[])
        .expect_err("only 32-bit and 64-bit stage keys are supported");
    assert!(error.to_string().contains("4 or 8 bytes"));
}
