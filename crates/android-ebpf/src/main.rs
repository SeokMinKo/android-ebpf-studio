#![no_std]
#![no_main]

use android_ebpf_types::{
    FileStart, KIND_BLOCK_COMPLETE, KIND_BLOCK_INSERT, KIND_BLOCK_ISSUE, KIND_FILE_IO, KernelEvent,
    OFFSET_MISSING, OP_DISCARD, OP_FLUSH, OP_OTHER, OP_READ, OP_WRITE, RawSyscallLayout,
    TraceLayout,
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_smp_processor_id, bpf_ktime_get_ns,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::TracePointContext,
};

#[map]
static ISSUE_LAYOUT: Array<TraceLayout> = Array::with_max_entries(1, 0);

#[map]
static COMPLETE_LAYOUT: Array<TraceLayout> = Array::with_max_entries(1, 0);

#[map]
static INSERT_LAYOUT: Array<TraceLayout> = Array::with_max_entries(1, 0);

#[map]
static RAW_SYSCALL_LAYOUT: Array<RawSyscallLayout> = Array::with_max_entries(1, 0);

#[map]
static FILE_STARTS: HashMap<u64, FileStart> = HashMap::with_max_entries(32_768, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

#[tracepoint]
pub fn block_rq_issue(ctx: TracePointContext) -> u32 {
    emit(ctx, KIND_BLOCK_ISSUE, &ISSUE_LAYOUT).unwrap_or(0)
}

#[tracepoint]
pub fn block_rq_complete(ctx: TracePointContext) -> u32 {
    emit(ctx, KIND_BLOCK_COMPLETE, &COMPLETE_LAYOUT).unwrap_or(0)
}

#[tracepoint]
pub fn block_rq_insert(ctx: TracePointContext) -> u32 {
    emit(ctx, KIND_BLOCK_INSERT, &INSERT_LAYOUT).unwrap_or(0)
}

#[tracepoint]
pub fn raw_sys_enter(ctx: TracePointContext) -> u32 {
    capture_sys_enter(ctx).unwrap_or(0)
}

#[tracepoint]
pub fn raw_sys_exit(ctx: TracePointContext) -> u32 {
    capture_sys_exit(ctx).unwrap_or(0)
}

fn emit(ctx: TracePointContext, kind: u8, layouts: &Array<TraceLayout>) -> Result<u32, i32> {
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
    let event = KernelEvent {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        start_ts_ns: 0,
        request_id,
        sector,
        requested_bytes: 0,
        return_value: 0,
        device,
        sectors,
        bytes,
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        cpu: unsafe { bpf_get_smp_processor_id() },
        status,
        fd: -1,
        kind,
        operation,
        correlation_exact,
        reserved: 0,
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
    };
    let mut entry = EVENTS.reserve::<KernelEvent>(0).ok_or(2_i32)?;
    entry.write(event);
    entry.submit(0);
    Ok(0)
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
    let start = FileStart {
        start_ts_ns: unsafe { bpf_ktime_get_ns() },
        requested_bytes,
        fd,
        operation,
        reserved: [0; 3],
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
    };
    FILE_STARTS
        .insert(&pid_tgid, &start, 0)
        .map_err(|_| 2_i32)?;
    Ok(0)
}

fn capture_sys_exit(ctx: TracePointContext) -> Result<u32, i32> {
    let layout = RAW_SYSCALL_LAYOUT.get(0).ok_or(1_i32)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let start = unsafe { FILE_STARTS.get(&pid_tgid) }
        .copied()
        .ok_or(0_i32)?;
    let _ = FILE_STARTS.remove(&pid_tgid);
    let event = KernelEvent {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        start_ts_ns: start.start_ts_ns,
        request_id: pid_tgid,
        sector: 0,
        requested_bytes: start.requested_bytes,
        return_value: read_i64(&ctx, layout.exit_ret_offset)?,
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
        reserved: 0,
        comm: start.comm,
    };
    let mut entry = EVENTS.reserve::<KernelEvent>(0).ok_or(2_i32)?;
    entry.write(event);
    entry.submit(0);
    Ok(0)
}

fn read_u8(ctx: &TracePointContext, offset: u16) -> Result<u8, i32> {
    unsafe { ctx.read_at(offset as usize) }
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
