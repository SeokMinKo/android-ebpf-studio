//! Read counters only from program FDs owned by this capture. Keep FD clones
//! through detach so the final health record includes the last callbacks.
use android_ebpf_protocol::ProbeHealth;
use aya::{Ebpf, programs::ProgramFd};
use aya_obj::generated::{bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, bpf_prog_info};
use std::{
    collections::BTreeMap,
    mem::{offset_of, size_of},
    os::fd::{AsFd, AsRawFd},
};

pub fn owned_programs(bpf: &Ebpf) -> Vec<(String, ProgramFd)> {
    bpf.programs()
        .filter_map(|(name, program)| {
            program
                .fd()
                .ok()
                .and_then(|fd| fd.try_clone().ok())
                .map(|fd| (format!("runtime.{name}"), fd))
        })
        .collect()
}

#[repr(C)]
struct InfoQuery {
    fd: u32,
    info_len: u32,
    info: u64,
}

fn recursion_misses(fd: &ProgramFd) -> Option<u64> {
    // Zeroed pointer/length fields request metadata only, never program code.
    let mut info: bpf_prog_info = unsafe { std::mem::zeroed() };
    let mut query = InfoQuery {
        fd: fd.as_fd().as_raw_fd() as u32,
        info_len: size_of::<bpf_prog_info>() as u32,
        info: (&mut info as *mut bpf_prog_info) as u64,
    };
    // The kernel writes only within the supplied info_len. Older kernels may
    // return a shorter structure; absence must not become a measured zero.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET_INFO_BY_FD as libc::c_uint,
            &mut query as *mut InfoQuery,
            size_of::<InfoQuery>(),
        )
    };
    if result != 0
        || (query.info_len as usize)
            < offset_of!(bpf_prog_info, recursion_misses) + size_of::<u64>()
    {
        return None;
    }
    Some(info.recursion_misses)
}

pub fn observe(programs: &[(String, ProgramFd)], health: &mut BTreeMap<String, ProbeHealth>) {
    for (name, fd) in programs {
        let entry = health.entry(name.clone()).or_default();
        if let Some(value) = recursion_misses(fd) {
            // Preserve the observed cumulative lower bound even when a later
            // info query fails; these are probe calls, not unique lost requests.
            entry.recursion_misses = Some(entry.recursion_misses.unwrap_or(0).max(value));
        }
    }
}
