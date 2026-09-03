#![no_std]
#![no_main]

use android_ebpf_types::{
    BlockStart, FileIdentityLayout, FileStart, FilterKey, HISTOGRAM_BUCKETS, KIND_BLOCK_COMPLETE,
    KIND_BLOCK_INSERT, KIND_BLOCK_ISSUE, KIND_FILE_IO, KIND_PIPELINE, KIND_REQUEST_ORIGIN,
    KernelAggregate, KernelEvent, KernelFileOrigin, LAYER_FILESYSTEM, LAYER_SCHEDULER, LAYER_SCSI,
    LAYER_UFS, LAYER_UIC, MODE_BALANCED, MODE_BASIC, MODE_DEEP, MODE_RAW_ALL, OFFSET_MISSING,
    OP_DISCARD, OP_FLUSH, OP_OTHER, OP_READ, OP_WRITE, ORIGIN_FILE, ORIGIN_INCOMPLETE,
    ORIGIN_INODE_GENERATION_VALID, ORIGIN_WRITEBACK, PHASE_BEGIN, PHASE_END, PHASE_INSTANT,
    PipelineTraceLayout, RawFilterConfig, RawSyscallLayout, STACK_ID_UNAVAILABLE, TraceLayout,
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_kernel,
    },
    macros::{btf_tracepoint, fentry, fexit, map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, RingBuf, StackTrace},
    programs::tracing::StackIdContext,
    programs::{BtfTracePointContext, FEntryContext, FExitContext, TracePointContext},
};

const MAX_REQUEST_ORIGINS: u8 = 8;

#[map]
static ISSUE_LAYOUT: Array<TraceLayout> = Array::with_max_entries(1, 0);

#[map]
static COMPLETE_LAYOUT: Array<TraceLayout> = Array::with_max_entries(1, 0);

#[map]
static INSERT_LAYOUT: Array<TraceLayout> = Array::with_max_entries(1, 0);

#[map]
static RAW_SYSCALL_LAYOUT: Array<RawSyscallLayout> = Array::with_max_entries(1, 0);

#[map]
static FILE_IDENTITY_LAYOUT: Array<FileIdentityLayout> = Array::with_max_entries(1, 0);

#[map]
static EXACT_ATTRIBUTION_ENABLED: Array<u8> = Array::with_max_entries(1, 0);

#[map]
static UFS_LAYOUT: Array<PipelineTraceLayout> = Array::with_max_entries(1, 0);

#[map]
static SCSI_START_LAYOUT: Array<PipelineTraceLayout> = Array::with_max_entries(1, 0);

#[map]
static SCSI_DONE_LAYOUT: Array<PipelineTraceLayout> = Array::with_max_entries(1, 0);

#[map]
static FS_START_LAYOUT: Array<PipelineTraceLayout> = Array::with_max_entries(1, 0);

#[map]
static FS_DONE_LAYOUT: Array<PipelineTraceLayout> = Array::with_max_entries(1, 0);

#[map]
static FILE_STARTS: HashMap<u64, FileStart> = HashMap::with_max_entries(32_768, 0);

#[map]
static ACTIVE_FILE_ORIGINS: HashMap<u64, KernelFileOrigin> = HashMap::with_max_entries(32_768, 0);

#[map]
static BIO_FILE_ORIGINS: HashMap<u64, KernelFileOrigin> = HashMap::with_max_entries(65_536, 0);

#[map]
static REQUEST_ORIGIN_COUNTS: HashMap<u64, u8> = HashMap::with_max_entries(65_536, 0);

#[map]
static FILTER_ACTIVE: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static FILTER_CONFIGS: HashMap<u64, RawFilterConfig> = HashMap::with_max_entries(64, 0);

#[map]
static FILTER_PIDS: HashMap<FilterKey, u8> = HashMap::with_max_entries(4096, 0);

#[map]
static FILTER_TIDS: HashMap<FilterKey, u8> = HashMap::with_max_entries(4096, 0);

#[map]
static FILTER_UIDS: HashMap<FilterKey, u8> = HashMap::with_max_entries(4096, 0);

#[map]
static FILTER_DEVICES: HashMap<FilterKey, u8> = HashMap::with_max_entries(4096, 0);

#[map]
static FILTER_OPERATIONS: HashMap<FilterKey, u8> = HashMap::with_max_entries(256, 0);

#[map]
static BLOCK_STARTS: HashMap<u64, BlockStart> = HashMap::with_max_entries(65_536, 0);

#[map]
static AGGREGATES: PerCpuArray<KernelAggregate> = PerCpuArray::with_max_entries(1, 0);

#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(16_384, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

#[tracepoint]
pub fn block_rq_issue(ctx: TracePointContext) -> u32 {
    handle_block(ctx, KIND_BLOCK_ISSUE, &ISSUE_LAYOUT).unwrap_or(0)
}

#[tracepoint]
pub fn block_rq_complete(ctx: TracePointContext) -> u32 {
    handle_block(ctx, KIND_BLOCK_COMPLETE, &COMPLETE_LAYOUT).unwrap_or(0)
}

#[tracepoint]
pub fn block_rq_insert(ctx: TracePointContext) -> u32 {
    handle_block(ctx, KIND_BLOCK_INSERT, &INSERT_LAYOUT).unwrap_or(0)
}

#[tracepoint]
pub fn raw_sys_enter(ctx: TracePointContext) -> u32 {
    capture_sys_enter(ctx).unwrap_or(0)
}

#[tracepoint]
pub fn raw_sys_exit(ctx: TracePointContext) -> u32 {
    capture_sys_exit(ctx).unwrap_or(0)
}

#[fentry(function = "vfs_read")]
pub fn exact_vfs_read(ctx: FEntryContext) -> u32 {
    capture_active_file(ctx, OP_READ).unwrap_or(0)
}

#[fexit(function = "vfs_read")]
pub fn exact_vfs_read_exit(ctx: FExitContext) -> u32 {
    clear_active_file(ctx).unwrap_or(0)
}

#[fentry(function = "vfs_write")]
pub fn exact_vfs_write(ctx: FEntryContext) -> u32 {
    capture_active_file(ctx, OP_WRITE).unwrap_or(0)
}

#[fexit(function = "vfs_write")]
pub fn exact_vfs_write_exit(ctx: FExitContext) -> u32 {
    clear_active_file(ctx).unwrap_or(0)
}

#[fentry(function = "write_cache_pages")]
pub fn exact_write_cache_pages(ctx: FEntryContext) -> u32 {
    capture_writeback_mapping(ctx).unwrap_or(0)
}

#[fexit(function = "write_cache_pages")]
pub fn exact_write_cache_pages_exit(ctx: FExitContext) -> u32 {
    clear_active_file(ctx).unwrap_or(0)
}

#[fentry(function = "f2fs_write_data_pages")]
pub fn exact_f2fs_write_data_pages(ctx: FEntryContext) -> u32 {
    capture_writeback_mapping(ctx).unwrap_or(0)
}

#[fexit(function = "f2fs_write_data_pages")]
pub fn exact_f2fs_write_data_pages_exit(ctx: FExitContext) -> u32 {
    clear_active_file(ctx).unwrap_or(0)
}

#[fentry(function = "submit_bio")]
pub fn exact_submit_bio(ctx: FEntryContext) -> u32 {
    bind_active_file_to_bio(ctx).unwrap_or(0)
}

#[fentry(function = "submit_bio_noacct")]
pub fn exact_submit_bio_noacct(ctx: FEntryContext) -> u32 {
    bind_active_file_to_bio(ctx).unwrap_or(0)
}

#[fentry(function = "blk_mq_bio_to_request")]
pub fn exact_bio_to_request(ctx: FEntryContext) -> u32 {
    let request_ptr: u64 = ctx.arg(0);
    let bio_ptr: u64 = ctx.arg(1);
    link_bio_ptrs(request_ptr, bio_ptr, true).unwrap_or(0)
}

#[btf_tracepoint(function = "block_bio_backmerge")]
pub fn exact_block_bio_backmerge(ctx: BtfTracePointContext) -> u32 {
    let request_ptr: u64 = ctx.arg(1);
    let bio_ptr: u64 = ctx.arg(2);
    link_bio_ptrs(request_ptr, bio_ptr, false).unwrap_or(0)
}

#[btf_tracepoint(function = "block_bio_frontmerge")]
pub fn exact_block_bio_frontmerge(ctx: BtfTracePointContext) -> u32 {
    let request_ptr: u64 = ctx.arg(1);
    let bio_ptr: u64 = ctx.arg(2);
    link_bio_ptrs(request_ptr, bio_ptr, false).unwrap_or(0)
}

fn capture_active_file(ctx: FEntryContext, operation: u8) -> Result<u32, i32> {
    if !exact_attribution_enabled() {
        return Ok(0);
    }
    let config = active_filter().unwrap_or(RawFilterConfig {
        mode: MODE_RAW_ALL,
        match_all: 1,
        ..RawFilterConfig::default()
    });
    if config.mode != MODE_DEEP && config.mode != MODE_RAW_ALL {
        return Ok(0);
    }
    let file_ptr: u64 = ctx.arg(0);
    let requested_bytes: u64 = ctx.arg(2);
    if file_ptr == 0 {
        return Ok(0);
    }
    let layout = FILE_IDENTITY_LAYOUT.get(0).ok_or(1_i32)?;
    let inode_ptr = read_kernel_u64(file_ptr, layout.file_inode_offset)?;
    if inode_ptr == 0 {
        return Ok(0);
    }
    let superblock_ptr = read_kernel_u64(inode_ptr, layout.inode_superblock_offset)?;
    if superblock_ptr == 0 {
        return Ok(0);
    }
    let inode = read_kernel_u64(inode_ptr, layout.inode_number_offset)?;
    let fs_device = read_kernel_u32(superblock_ptr, layout.superblock_device_offset)?;
    let mut origin_flags = ORIGIN_FILE;
    let inode_generation = if layout.inode_generation_offset == OFFSET_MISSING {
        0
    } else {
        origin_flags |= ORIGIN_INODE_GENERATION_VALID;
        read_kernel_u32(inode_ptr, layout.inode_generation_offset)?
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    if !matches_filter(
        pid,
        tid,
        bpf_get_current_uid_gid() as u32,
        0,
        requested_bytes.min(u32::MAX as u64) as u32,
        operation,
    ) {
        return Ok(0);
    }
    let origin = KernelFileOrigin {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        requested_bytes,
        inode,
        mount_id: 0,
        fs_device,
        inode_generation,
        pid,
        tid,
        origin_flags,
        operation,
        reserved: [0; 3],
    };
    ACTIVE_FILE_ORIGINS
        .insert(&pid_tgid, &origin, 0)
        .map_err(|_| 2_i32)?;
    Ok(0)
}

fn clear_active_file(_ctx: FExitContext) -> Result<u32, i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = ACTIVE_FILE_ORIGINS.remove(&pid_tgid);
    Ok(0)
}

fn capture_writeback_mapping(ctx: FEntryContext) -> Result<u32, i32> {
    if !exact_attribution_enabled() {
        return Ok(0);
    }
    let config = active_filter().unwrap_or(RawFilterConfig {
        mode: MODE_RAW_ALL,
        ..RawFilterConfig::default()
    });
    if config.mode != MODE_DEEP && config.mode != MODE_RAW_ALL {
        return Ok(0);
    }
    let layout = FILE_IDENTITY_LAYOUT.get(0).ok_or(1_i32)?;
    if layout.address_space_host_offset == OFFSET_MISSING {
        return Ok(0);
    }
    let mapping_ptr: u64 = ctx.arg(0);
    if mapping_ptr == 0 {
        return Ok(0);
    }
    let inode_ptr = read_kernel_u64(mapping_ptr, layout.address_space_host_offset)?;
    if inode_ptr == 0 {
        return Ok(0);
    }
    let superblock_ptr = read_kernel_u64(inode_ptr, layout.inode_superblock_offset)?;
    if superblock_ptr == 0 {
        return Ok(0);
    }
    let mut origin_flags = ORIGIN_WRITEBACK;
    let inode_generation = if layout.inode_generation_offset == OFFSET_MISSING {
        0
    } else {
        origin_flags |= ORIGIN_INODE_GENERATION_VALID;
        read_kernel_u32(inode_ptr, layout.inode_generation_offset)?
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let origin = KernelFileOrigin {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        requested_bytes: 0,
        inode: read_kernel_u64(inode_ptr, layout.inode_number_offset)?,
        mount_id: 0,
        fs_device: read_kernel_u32(superblock_ptr, layout.superblock_device_offset)?,
        inode_generation,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        origin_flags,
        operation: OP_WRITE,
        reserved: [0; 3],
    };
    ACTIVE_FILE_ORIGINS
        .insert(&pid_tgid, &origin, 0)
        .map_err(|_| 2_i32)?;
    Ok(0)
}

fn bind_active_file_to_bio(ctx: FEntryContext) -> Result<u32, i32> {
    if !exact_attribution_enabled() {
        return Ok(0);
    }
    let bio_ptr: u64 = ctx.arg(0);
    if bio_ptr == 0 {
        return Ok(0);
    }
    // A bio pointer may be reused after completion. Observing a new submit is
    // the lifecycle boundary that invalidates any stale association.
    let _ = BIO_FILE_ORIGINS.remove(&bio_ptr);
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(origin) = (unsafe { ACTIVE_FILE_ORIGINS.get(&pid_tgid) }) else {
        return Ok(0);
    };
    BIO_FILE_ORIGINS
        .insert(&bio_ptr, origin, 0)
        .map_err(|_| 2_i32)?;
    Ok(0)
}

fn link_bio_ptrs(request_ptr: u64, bio_ptr: u64, new_request: bool) -> Result<u32, i32> {
    if !exact_attribution_enabled() {
        return Ok(0);
    }
    if request_ptr == 0 || bio_ptr == 0 {
        return Ok(0);
    }
    if new_request {
        // blk_mq_bio_to_request initializes a fresh request from this bio, so
        // it is also the safe boundary for request-pointer reuse.
        let _ = REQUEST_ORIGIN_COUNTS.remove(&request_ptr);
    }
    let Some(origin) = (unsafe { BIO_FILE_ORIGINS.get(&bio_ptr) }) else {
        return Ok(0);
    };
    let mut retained = *origin;
    let count = unsafe { REQUEST_ORIGIN_COUNTS.get(&request_ptr) }
        .copied()
        .unwrap_or(0);
    if count > MAX_REQUEST_ORIGINS {
        let _ = BIO_FILE_ORIGINS.remove(&bio_ptr);
        return Ok(0);
    }
    if count == MAX_REQUEST_ORIGINS {
        retained.origin_flags |= ORIGIN_INCOMPLETE;
    }
    let next = count.saturating_add(1);
    REQUEST_ORIGIN_COUNTS
        .insert(&request_ptr, &next, 0)
        .map_err(|_| 2_i32)?;
    let event = KernelEvent {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        request_id: request_ptr,
        origin_id: bio_ptr,
        inode: retained.inode,
        mount_id: retained.mount_id,
        fs_device: retained.fs_device,
        bytes: retained.requested_bytes.min(u32::MAX as u64) as u32,
        inode_generation: retained.inode_generation,
        origin_flags: retained.origin_flags,
        pid: retained.pid,
        tid: retained.tid,
        kind: KIND_REQUEST_ORIGIN,
        operation: retained.operation,
        correlation_exact: 1,
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
        ..KernelEvent::default()
    };
    let config = active_filter().unwrap_or(RawFilterConfig {
        mode: MODE_RAW_ALL,
        ..RawFilterConfig::default()
    });
    submit_event(event, config.generation)?;
    let _ = BIO_FILE_ORIGINS.remove(&bio_ptr);
    Ok(0)
}

fn read_kernel_u64(base: u64, offset: u16) -> Result<u64, i32> {
    let address = base.checked_add(u64::from(offset)).ok_or(1_i32)?;
    unsafe { bpf_probe_read_kernel(address as *const u64) }
}

fn read_kernel_u32(base: u64, offset: u16) -> Result<u32, i32> {
    let address = base.checked_add(u64::from(offset)).ok_or(1_i32)?;
    unsafe { bpf_probe_read_kernel(address as *const u32) }
}

fn exact_attribution_enabled() -> bool {
    EXACT_ATTRIBUTION_ENABLED.get(0).copied() == Some(1)
}

#[tracepoint]
pub fn ufs_command(ctx: TracePointContext) -> u32 {
    // A task tag is controller-local and reusable. Until a controller identity
    // is captured alongside it, the pair is measured but cannot be advertised
    // as an exact globally scoped correlation key.
    emit_pipeline_dynamic(ctx, LAYER_UFS, &UFS_LAYOUT, false).unwrap_or(0)
}

#[tracepoint]
pub fn scsi_dispatch_start(ctx: TracePointContext) -> u32 {
    emit_pipeline(ctx, LAYER_SCSI, PHASE_BEGIN, &SCSI_START_LAYOUT, true).unwrap_or(0)
}

#[tracepoint]
pub fn scsi_dispatch_done(ctx: TracePointContext) -> u32 {
    emit_pipeline(ctx, LAYER_SCSI, PHASE_END, &SCSI_DONE_LAYOUT, true).unwrap_or(0)
}

#[tracepoint]
pub fn fs_data_start(ctx: TracePointContext) -> u32 {
    emit_pipeline(ctx, LAYER_FILESYSTEM, PHASE_BEGIN, &FS_START_LAYOUT, false).unwrap_or(0)
}

#[tracepoint]
pub fn fs_data_done(ctx: TracePointContext) -> u32 {
    emit_pipeline(ctx, LAYER_FILESYSTEM, PHASE_END, &FS_DONE_LAYOUT, false).unwrap_or(0)
}

#[tracepoint]
pub fn ufs_context(ctx: TracePointContext) -> u32 {
    emit_context(ctx, LAYER_UIC).unwrap_or(0)
}

#[tracepoint]
pub fn fs_context(ctx: TracePointContext) -> u32 {
    emit_context(ctx, LAYER_FILESYSTEM).unwrap_or(0)
}

#[tracepoint]
pub fn sched_context(ctx: TracePointContext) -> u32 {
    emit_context(ctx, LAYER_SCHEDULER).unwrap_or(0)
}

fn emit_context(_ctx: TracePointContext, layer: u8) -> Result<u32, i32> {
    let config = active_filter().unwrap_or(RawFilterConfig {
        mode: MODE_RAW_ALL,
        match_all: 1,
        ..RawFilterConfig::default()
    });
    if config.mode < MODE_DEEP {
        return Ok(0);
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    if !matches_filter(pid, tid, bpf_get_current_uid_gid() as u32, 0, 0, OP_OTHER) {
        return Ok(0);
    }
    let event = KernelEvent {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        start_ts_ns: 0,
        request_id: 0,
        sector: 0,
        requested_bytes: 0,
        return_value: 0,
        kernel_stack_id: STACK_ID_UNAVAILABLE,
        user_stack_id: STACK_ID_UNAVAILABLE,
        device: 0,
        sectors: 0,
        bytes: 0,
        pid,
        tid,
        cpu: unsafe { bpf_get_smp_processor_id() },
        status: 0,
        fd: -1,
        kind: KIND_PIPELINE,
        operation: OP_OTHER,
        correlation_exact: 0,
        pipeline_layer: layer,
        pipeline_phase: PHASE_INSTANT,
        reserved: 0,
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
        ..KernelEvent::default()
    };
    submit_event(event, config.generation)?;
    Ok(0)
}

fn emit_pipeline_dynamic(
    ctx: TracePointContext,
    layer: u8,
    layouts: &Array<PipelineTraceLayout>,
    exact: bool,
) -> Result<u32, i32> {
    let layout = layouts.get(0).ok_or(1_i32)?;
    let phase = if layout.state_offset == OFFSET_MISSING {
        PHASE_INSTANT
    } else {
        let location = read_u32(&ctx, layout.state_offset)?;
        let offset = (location & 0xffff) as usize;
        match read_u8_at(&ctx, offset)? {
            b's' | b'S' => PHASE_BEGIN,
            b'c' | b'C' => PHASE_END,
            _ => PHASE_INSTANT,
        }
    };
    emit_pipeline(ctx, layer, phase, layouts, exact)
}

fn emit_pipeline(
    ctx: TracePointContext,
    layer: u8,
    phase: u8,
    layouts: &Array<PipelineTraceLayout>,
    exact: bool,
) -> Result<u32, i32> {
    let config = active_filter().unwrap_or(RawFilterConfig {
        mode: MODE_RAW_ALL,
        match_all: 1,
        ..RawFilterConfig::default()
    });
    if config.mode < MODE_DEEP {
        return Ok(0);
    }
    let layout = layouts.get(0).ok_or(1_i32)?;
    let request_id = if layout.key_size == 8 {
        read_u64(&ctx, layout.key_offset)?
    } else {
        read_u32(&ctx, layout.key_offset)? as u64
    };
    let sector = if layout.sector_offset == OFFSET_MISSING {
        0
    } else {
        read_u64(&ctx, layout.sector_offset)?
    };
    let bytes = if layout.bytes_offset == OFFSET_MISSING {
        0
    } else {
        read_u32(&ctx, layout.bytes_offset)?
    };
    let operation = if layout.operation_offset == OFFSET_MISSING {
        OP_OTHER
    } else {
        read_u8(&ctx, layout.operation_offset)?
    };
    let status = if layout.status_offset == OFFSET_MISSING {
        0
    } else {
        read_i32(&ctx, layout.status_offset)?
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    if !matches_filter(pid, tid, uid, 0, bytes, operation) {
        return Ok(0);
    }
    let event = KernelEvent {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        start_ts_ns: 0,
        request_id,
        sector,
        requested_bytes: 0,
        return_value: 0,
        kernel_stack_id: STACK_ID_UNAVAILABLE,
        user_stack_id: STACK_ID_UNAVAILABLE,
        device: 0,
        sectors: 0,
        bytes,
        pid,
        tid,
        cpu: unsafe { bpf_get_smp_processor_id() },
        status,
        fd: -1,
        kind: KIND_PIPELINE,
        operation,
        correlation_exact: u8::from(exact),
        pipeline_layer: layer,
        pipeline_phase: phase,
        reserved: u8::from(layout.status_offset != OFFSET_MISSING)
            | (u8::from(layout.operation_offset != OFFSET_MISSING) << 1),
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
        ..KernelEvent::default()
    };
    submit_event(event, config.generation)?;
    Ok(0)
}

fn handle_block(
    ctx: TracePointContext,
    kind: u8,
    layouts: &Array<TraceLayout>,
) -> Result<u32, i32> {
    let layout = layouts.get(0).ok_or(1_i32)?;
    let device = read_u32(&ctx, layout.dev_offset)?;
    let sector = read_u64(&ctx, layout.sector_offset)?;
    let sectors = read_u32(&ctx, layout.nr_sector_offset)?;
    let bytes = if layout.bytes_offset == OFFSET_MISSING {
        sectors.saturating_mul(512)
    } else {
        read_u32(&ctx, layout.bytes_offset)?
    };
    let operation = if layout.rwbs_offset == OFFSET_MISSING {
        OP_OTHER
    } else {
        decode_operation(read_u8(&ctx, layout.rwbs_offset)?)
    };
    let (request_id, correlation_exact) = if layout.request_offset == OFFSET_MISSING {
        (fallback_request_id(device, sector, sectors, operation), 0)
    } else {
        (read_u64(&ctx, layout.request_offset)?, 1)
    };
    let status = if layout.status_offset == OFFSET_MISSING {
        0
    } else {
        read_i32(&ctx, layout.status_offset)?
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let mut event = KernelEvent {
        ts_ns,
        start_ts_ns: 0,
        request_id,
        sector,
        requested_bytes: 0,
        return_value: 0,
        kernel_stack_id: STACK_ID_UNAVAILABLE,
        user_stack_id: STACK_ID_UNAVAILABLE,
        device,
        sectors,
        bytes,
        pid,
        tid,
        cpu: unsafe { bpf_get_smp_processor_id() },
        status,
        fd: -1,
        kind,
        operation,
        correlation_exact,
        pipeline_layer: 0,
        pipeline_phase: 0,
        reserved: 0,
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
        ..KernelEvent::default()
    };
    let config = active_filter().unwrap_or(RawFilterConfig {
        mode: MODE_RAW_ALL,
        match_all: 1,
        ..RawFilterConfig::default()
    });
    match kind {
        KIND_BLOCK_INSERT => {
            if !matches_filter(pid, tid, uid, device, bytes, operation) {
                aggregate_filter_suppressed(config.generation);
                return Ok(0);
            }
            let start = BlockStart {
                insert_ts_ns: ts_ns,
                issue_ts_ns: 0,
                request_id,
                sector,
                device,
                sectors,
                bytes,
                pid,
                tid,
                cpu: event.cpu,
                operation,
                correlation_exact,
                comm: event.comm,
            };
            if BLOCK_STARTS.insert(&request_id, &start, 0).is_err() {
                aggregate_map_failure(config.generation);
            }
            if config.mode == MODE_DEEP || config.mode == MODE_RAW_ALL {
                submit_event(event, config.generation)?;
            }
        }
        KIND_BLOCK_ISSUE => {
            if !matches_filter(pid, tid, uid, device, bytes, operation) {
                let _ = BLOCK_STARTS.remove(&request_id);
                aggregate_filter_suppressed(config.generation);
                return Ok(0);
            }
            let prior = unsafe { BLOCK_STARTS.get(&request_id) }.copied();
            if prior.is_some_and(|value| value.issue_ts_ns != 0) {
                aggregate_key_reused(config.generation);
            }
            let start = BlockStart {
                insert_ts_ns: prior.map_or(0, |value| value.insert_ts_ns),
                issue_ts_ns: ts_ns,
                request_id,
                sector,
                device,
                sectors,
                bytes,
                pid,
                tid,
                cpu: event.cpu,
                operation,
                correlation_exact,
                comm: event.comm,
            };
            if BLOCK_STARTS.insert(&request_id, &start, 0).is_err() {
                aggregate_map_failure(config.generation);
                return Ok(0);
            }
            aggregate_filter_passed(config.generation);
            if config.mode == MODE_DEEP || config.mode == MODE_RAW_ALL {
                submit_event(event, config.generation)?;
            }
        }
        KIND_BLOCK_COMPLETE => {
            let _ = REQUEST_ORIGIN_COUNTS.remove(&request_id);
            let Some(start) = unsafe { BLOCK_STARTS.get(&request_id) }.copied() else {
                aggregate_expired(config.generation);
                return Ok(0);
            };
            let _ = BLOCK_STARTS.remove(&request_id);
            if start.issue_ts_ns == 0 || ts_ns < start.issue_ts_ns {
                aggregate_expired(config.generation);
                return Ok(0);
            }
            let device_latency = ts_ns.saturating_sub(start.issue_ts_ns);
            let queue_latency = if start.insert_ts_ns == 0 {
                0
            } else {
                start.issue_ts_ns.saturating_sub(start.insert_ts_ns)
            };
            let total_latency = if start.insert_ts_ns == 0 {
                device_latency
            } else {
                ts_ns.saturating_sub(start.insert_ts_ns)
            };
            aggregate_completion(
                config.generation,
                ts_ns,
                start.bytes,
                status,
                total_latency,
                queue_latency,
                device_latency,
            );
            let sampled = config.sample_rate_permyriad != 0
                && request_id % 10_000 < config.sample_rate_permyriad as u64;
            let slow = total_latency >= config.total_latency_ns
                || (queue_latency != 0 && queue_latency >= config.queue_latency_ns)
                || device_latency >= config.device_latency_ns;
            let forced_error = config.include_errors != 0 && status != 0;
            let detail = match config.mode {
                MODE_BASIC => false,
                MODE_BALANCED => slow || sampled || forced_error,
                MODE_DEEP | MODE_RAW_ALL => true,
                _ => false,
            };
            if detail {
                aggregate_detail(config.generation, sampled, forced_error);
                if config.mode == MODE_DEEP {
                    event.start_ts_ns = if start.insert_ts_ns == 0 {
                        start.issue_ts_ns
                    } else {
                        start.insert_ts_ns
                    };
                    event.kernel_stack_id = ctx
                        .get_stackid(&STACK_TRACES, 0)
                        .map_or(STACK_ID_UNAVAILABLE, |value| value as u64);
                }
                if config.mode == MODE_BALANCED {
                    if start.insert_ts_ns != 0 {
                        submit_event(
                            block_event_from_start(&start, KIND_BLOCK_INSERT),
                            config.generation,
                        )?;
                    }
                    submit_event(
                        block_event_from_start(&start, KIND_BLOCK_ISSUE),
                        config.generation,
                    )?;
                }
                submit_event(event, config.generation)?;
            } else {
                aggregate_suppressed_fast(config.generation);
            }
        }
        _ => {}
    }
    Ok(0)
}

fn block_event_from_start(start: &BlockStart, kind: u8) -> KernelEvent {
    KernelEvent {
        ts_ns: if kind == KIND_BLOCK_INSERT {
            start.insert_ts_ns
        } else {
            start.issue_ts_ns
        },
        start_ts_ns: 0,
        request_id: start.request_id,
        sector: start.sector,
        requested_bytes: 0,
        return_value: 0,
        kernel_stack_id: STACK_ID_UNAVAILABLE,
        user_stack_id: STACK_ID_UNAVAILABLE,
        device: start.device,
        sectors: start.sectors,
        bytes: start.bytes,
        pid: start.pid,
        tid: start.tid,
        cpu: start.cpu,
        status: 0,
        fd: -1,
        kind,
        operation: start.operation,
        correlation_exact: start.correlation_exact,
        pipeline_layer: 0,
        pipeline_phase: 0,
        reserved: 0,
        comm: start.comm,
        ..KernelEvent::default()
    }
}

fn submit_event(event: KernelEvent, generation: u64) -> Result<(), i32> {
    let Some(mut entry) = EVENTS.reserve::<KernelEvent>(0) else {
        aggregate_reserve_failure(generation);
        return Err(2_i32);
    };
    entry.write(event);
    entry.submit(0);
    Ok(())
}

fn aggregate_mut(generation: u64) -> Option<&'static mut KernelAggregate> {
    let pointer = AGGREGATES.get_ptr_mut(0)?;
    let aggregate = unsafe { &mut *pointer };
    if aggregate.generation != generation {
        *aggregate = KernelAggregate {
            generation,
            ..KernelAggregate::default()
        };
    }
    Some(aggregate)
}

fn aggregate_filter_passed(generation: u64) {
    if let Some(value) = aggregate_mut(generation) {
        value.filter_passed = value.filter_passed.saturating_add(1);
    }
}

fn aggregate_filter_suppressed(generation: u64) {
    if let Some(value) = aggregate_mut(generation) {
        value.filter_suppressed = value.filter_suppressed.saturating_add(1);
    }
}

fn aggregate_map_failure(generation: u64) {
    if let Some(value) = aggregate_mut(generation) {
        value.map_insert_failures = value.map_insert_failures.saturating_add(1);
    }
}

fn aggregate_key_reused(generation: u64) {
    if let Some(value) = aggregate_mut(generation) {
        value.key_reused = value.key_reused.saturating_add(1);
    }
}

fn aggregate_expired(generation: u64) {
    if let Some(value) = aggregate_mut(generation) {
        value.expired = value.expired.saturating_add(1);
    }
}

fn aggregate_reserve_failure(generation: u64) {
    if let Some(value) = aggregate_mut(generation) {
        value.ring_reserve_failures = value.ring_reserve_failures.saturating_add(1);
    }
}

fn aggregate_suppressed_fast(generation: u64) {
    if let Some(value) = aggregate_mut(generation) {
        value.suppressed_fast = value.suppressed_fast.saturating_add(1);
    }
}

fn aggregate_detail(generation: u64, sampled: bool, forced_error: bool) {
    if let Some(value) = aggregate_mut(generation) {
        value.detail_emitted = value.detail_emitted.saturating_add(1);
        value.sampled = value.sampled.saturating_add(sampled as u64);
        value.forced_error = value.forced_error.saturating_add(forced_error as u64);
    }
}

fn aggregate_completion(
    generation: u64,
    ts_ns: u64,
    bytes: u32,
    status: i32,
    total_latency: u64,
    queue_latency: u64,
    device_latency: u64,
) {
    if let Some(value) = aggregate_mut(generation) {
        if value.first_ts_ns == 0 {
            value.first_ts_ns = ts_ns;
        }
        value.last_ts_ns = ts_ns;
        value.observed = value.observed.saturating_add(1);
        value.bytes = value.bytes.saturating_add(bytes as u64);
        value.failed = value.failed.saturating_add((status != 0) as u64);
        value.total_latency[histogram_index(total_latency)] =
            value.total_latency[histogram_index(total_latency)].saturating_add(1);
        value.queue_latency[histogram_index(queue_latency)] =
            value.queue_latency[histogram_index(queue_latency)].saturating_add(1);
        value.device_latency[histogram_index(device_latency)] =
            value.device_latency[histogram_index(device_latency)].saturating_add(1);
        value.io_size[histogram_index(bytes as u64)] =
            value.io_size[histogram_index(bytes as u64)].saturating_add(1);
    }
}

fn histogram_index(value: u64) -> usize {
    let index = if value == 0 {
        0
    } else {
        63_u32.saturating_sub(value.leading_zeros()) as usize
    };
    if index >= HISTOGRAM_BUCKETS {
        HISTOGRAM_BUCKETS - 1
    } else {
        index
    }
}

fn capture_sys_enter(ctx: TracePointContext) -> Result<u32, i32> {
    let layout = RAW_SYSCALL_LAYOUT.get(0).ok_or(1_i32)?;
    let syscall = read_i64(&ctx, layout.enter_id_offset)?;
    // arm64 Linux syscall numbers: read, write, pread64, pwrite64.
    let operation = match syscall {
        63 | 67 => OP_READ,
        64 | 68 => OP_WRITE,
        _ => return Ok(0),
    };
    let fd = read_i64(&ctx, layout.enter_args_offset)? as i32;
    let requested_bytes = read_u64_at(&ctx, layout.enter_args_offset as usize + 16)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    if !matches_filter(
        pid,
        tid,
        uid,
        0,
        requested_bytes.min(u32::MAX as u64) as u32,
        operation,
    ) {
        return Ok(0);
    }
    let start = FileStart {
        start_ts_ns: unsafe { bpf_ktime_get_ns() },
        requested_bytes,
        fd,
        operation,
        reserved: [0; 3],
        pid,
        tid,
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
    };
    FILE_STARTS
        .insert(&pid_tgid, &start, 0)
        .map_err(|_| 2_i32)?;
    Ok(0)
}

fn active_filter() -> Option<RawFilterConfig> {
    let generation = FILTER_ACTIVE.get(0).copied()?;
    if generation == 0 {
        return None;
    }
    unsafe { FILTER_CONFIGS.get(&generation) }.copied()
}

fn matches_filter(pid: u32, tid: u32, uid: u32, device: u32, bytes: u32, operation: u8) -> bool {
    let Some(config) = active_filter() else {
        return true;
    };
    if config.min_bytes != 0 && bytes < config.min_bytes {
        return false;
    }
    if config.max_bytes != 0 && bytes > config.max_bytes {
        return false;
    }
    if config.pid_count != 0 && !filter_contains(&FILTER_PIDS, config.generation, pid as u64) {
        return false;
    }
    if config.tid_count != 0 && !filter_contains(&FILTER_TIDS, config.generation, tid as u64) {
        return false;
    }
    if config.uid_count != 0 && !filter_contains(&FILTER_UIDS, config.generation, uid as u64) {
        return false;
    }
    if config.device_count != 0
        && !filter_contains(&FILTER_DEVICES, config.generation, device as u64)
    {
        return false;
    }
    if config.operation_count != 0
        && !filter_contains(&FILTER_OPERATIONS, config.generation, operation as u64)
    {
        return false;
    }
    true
}

fn filter_contains(map: &HashMap<FilterKey, u8>, generation: u64, value: u64) -> bool {
    let key = FilterKey { generation, value };
    unsafe { map.get(&key) }.is_some()
}

fn capture_sys_exit(ctx: TracePointContext) -> Result<u32, i32> {
    let layout = RAW_SYSCALL_LAYOUT.get(0).ok_or(1_i32)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let start = unsafe { FILE_STARTS.get(&pid_tgid) }
        .copied()
        .ok_or(0_i32)?;
    let _ = FILE_STARTS.remove(&pid_tgid);
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let return_value = read_i64(&ctx, layout.exit_ret_offset)?;
    let config = active_filter().unwrap_or(RawFilterConfig {
        mode: MODE_RAW_ALL,
        match_all: 1,
        ..RawFilterConfig::default()
    });
    let latency = ts_ns.saturating_sub(start.start_ts_ns);
    let sampled = config.sample_rate_permyriad != 0
        && pid_tgid % 10_000 < config.sample_rate_permyriad as u64;
    let detail = match config.mode {
        MODE_BASIC => false,
        MODE_BALANCED => {
            latency >= config.total_latency_ns
                || sampled
                || (config.include_errors != 0 && return_value < 0)
        }
        MODE_DEEP | MODE_RAW_ALL => true,
        _ => false,
    };
    if !detail {
        return Ok(0);
    }
    let event = KernelEvent {
        ts_ns,
        start_ts_ns: start.start_ts_ns,
        request_id: pid_tgid,
        sector: 0,
        requested_bytes: start.requested_bytes,
        return_value,
        kernel_stack_id: if config.mode == MODE_DEEP {
            ctx.get_stackid(&STACK_TRACES, 0)
                .map_or(STACK_ID_UNAVAILABLE, |value| value as u64)
        } else {
            STACK_ID_UNAVAILABLE
        },
        user_stack_id: if config.mode == MODE_DEEP {
            ctx.get_stackid(&STACK_TRACES, 1 << 8)
                .map_or(STACK_ID_UNAVAILABLE, |value| value as u64)
        } else {
            STACK_ID_UNAVAILABLE
        },
        device: 0,
        sectors: 0,
        bytes: 0,
        pid: start.pid,
        tid: start.tid,
        cpu: unsafe { bpf_get_smp_processor_id() },
        status: 0,
        fd: start.fd,
        kind: KIND_FILE_IO,
        operation: start.operation,
        correlation_exact: 0,
        pipeline_layer: 0,
        pipeline_phase: 0,
        reserved: 0,
        comm: start.comm,
        ..KernelEvent::default()
    };
    submit_event(event, config.generation)?;
    Ok(0)
}

fn read_u8(ctx: &TracePointContext, offset: u16) -> Result<u8, i32> {
    unsafe { ctx.read_at(offset as usize) }
}

fn read_u8_at(ctx: &TracePointContext, offset: usize) -> Result<u8, i32> {
    unsafe { ctx.read_at(offset) }
}

fn read_u32(ctx: &TracePointContext, offset: u16) -> Result<u32, i32> {
    unsafe { ctx.read_at(offset as usize) }
}

fn read_i32(ctx: &TracePointContext, offset: u16) -> Result<i32, i32> {
    unsafe { ctx.read_at(offset as usize) }
}

fn read_i64(ctx: &TracePointContext, offset: u16) -> Result<i64, i32> {
    unsafe { ctx.read_at(offset as usize) }
}

fn read_u64(ctx: &TracePointContext, offset: u16) -> Result<u64, i32> {
    unsafe { ctx.read_at(offset as usize) }
}

fn read_u64_at(ctx: &TracePointContext, offset: usize) -> Result<u64, i32> {
    unsafe { ctx.read_at(offset) }
}

fn decode_operation(first: u8) -> u8 {
    match first {
        b'R' => OP_READ,
        b'W' => OP_WRITE,
        b'F' => OP_FLUSH,
        b'D' => OP_DISCARD,
        _ => OP_OTHER,
    }
}

fn fallback_request_id(device: u32, sector: u64, sectors: u32, operation: u8) -> u64 {
    let mut value = sector ^ ((device as u64) << 32) ^ ((sectors as u64) << 8);
    value ^= operation as u64;
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51afd7ed558ccd);
    value ^ (value >> 33)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
