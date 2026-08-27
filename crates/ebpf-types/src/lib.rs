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
pub const LAYER_SCHEDULER: u8 = 5;
pub const PHASE_BEGIN: u8 = 1;
pub const PHASE_END: u8 = 2;
pub const PHASE_INSTANT: u8 = 3;
pub const OP_READ: u8 = 1;
pub const OP_WRITE: u8 = 2;
pub const OP_FLUSH: u8 = 3;
pub const OP_DISCARD: u8 = 4;
pub const OP_OTHER: u8 = 255;
pub const MODE_BASIC: u8 = 1;
pub const MODE_BALANCED: u8 = 2;
pub const MODE_DEEP: u8 = 3;
pub const MODE_RAW_ALL: u8 = 4;
pub const HISTOGRAM_BUCKETS: usize = 32;
pub const STACK_ID_UNAVAILABLE: u64 = u64::MAX;

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
pub struct FilterKey {
    pub generation: u64,
    pub value: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RawFilterConfig {
    pub generation: u64,
    pub total_latency_ns: u64,
    pub queue_latency_ns: u64,
    pub device_latency_ns: u64,
    pub min_bytes: u32,
    pub max_bytes: u32,
    pub pid_count: u16,
    pub tid_count: u16,
    pub uid_count: u16,
    pub device_count: u16,
    pub operation_count: u16,
    pub sample_rate_permyriad: u16,
    pub mode: u8,
    pub match_all: u8,
    pub include_errors: u8,
    pub include_correlation_failures: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockStart {
    pub insert_ts_ns: u64,
    pub issue_ts_ns: u64,
    pub request_id: u64,
    pub sector: u64,
    pub device: u32,
    pub sectors: u32,
    pub bytes: u32,
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub operation: u8,
    pub correlation_exact: u8,
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelAggregate {
    pub generation: u64,
    pub first_ts_ns: u64,
    pub last_ts_ns: u64,
    pub observed: u64,
    pub bytes: u64,
    pub failed: u64,
    pub filter_passed: u64,
    pub filter_suppressed: u64,
    pub detail_emitted: u64,
    pub suppressed_fast: u64,
    pub sampled: u64,
    pub forced_error: u64,
    pub ring_reserve_failures: u64,
    pub map_insert_failures: u64,
    pub expired: u64,
    pub key_reused: u64,
    pub total_latency: [u64; HISTOGRAM_BUCKETS],
    pub queue_latency: [u64; HISTOGRAM_BUCKETS],
    pub device_latency: [u64; HISTOGRAM_BUCKETS],
    pub io_size: [u64; HISTOGRAM_BUCKETS],
    pub queue_depth: [u64; HISTOGRAM_BUCKETS],
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
    pub kernel_stack_id: u64,
    pub user_stack_id: u64,
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
