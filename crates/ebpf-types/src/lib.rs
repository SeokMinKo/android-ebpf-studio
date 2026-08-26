#![no_std]

pub const OFFSET_MISSING: u16 = u16::MAX;
pub const KIND_BLOCK_ISSUE: u8 = 1;
pub const KIND_BLOCK_COMPLETE: u8 = 2;
pub const KIND_BLOCK_INSERT: u8 = 3;
pub const KIND_FILE_IO: u8 = 4;
pub const KIND_PIPELINE: u8 = 5;
pub const LAYER_FILESYSTEM: u8 = 1;
pub const LAYER_SCSI: u8 = 2;
pub const LAYER_UFS: u8 = 3;
pub const LAYER_UIC: u8 = 4;
pub const PHASE_BEGIN: u8 = 1;
pub const PHASE_END: u8 = 2;
pub const PHASE_INSTANT: u8 = 3;
pub const OP_READ: u8 = 1;
pub const OP_WRITE: u8 = 2;
pub const OP_FLUSH: u8 = 3;
pub const OP_DISCARD: u8 = 4;
pub const OP_OTHER: u8 = 255;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TraceLayout {
    pub dev_offset: u16,
    pub sector_offset: u16,
    pub nr_sector_offset: u16,
    pub bytes_offset: u16,
    pub rwbs_offset: u16,
    pub request_offset: u16,
    pub status_offset: u16,
    pub reserved: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RawSyscallLayout {
    pub enter_id_offset: u16,
    pub enter_args_offset: u16,
    pub exit_ret_offset: u16,
    pub reserved: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PipelineTraceLayout {
    pub key_offset: u16,
    pub sector_offset: u16,
    pub bytes_offset: u16,
    pub operation_offset: u16,
    pub status_offset: u16,
    pub state_offset: u16,
    pub key_size: u8,
    pub reserved: [u8; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FileStart {
    pub start_ts_ns: u64,
    pub requested_bytes: u64,
    pub fd: i32,
    pub operation: u8,
    pub reserved: [u8; 3],
    pub pid: u32,
    pub tid: u32,
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelEvent {
    pub ts_ns: u64,
    pub start_ts_ns: u64,
    pub request_id: u64,
    pub sector: u64,
    pub requested_bytes: u64,
    pub return_value: i64,
    pub device: u32,
    pub sectors: u32,
    pub bytes: u32,
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub status: i32,
    pub fd: i32,
    pub kind: u8,
    pub operation: u8,
    pub correlation_exact: u8,
    pub pipeline_layer: u8,
    pub pipeline_phase: u8,
    pub reserved: u8,
    pub comm: [u8; 16],
}
