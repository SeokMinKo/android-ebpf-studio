use android_ebpf_protocol::SchedulerIoWait;
use android_ebpf_types::{KIND_SCHEDULER_IO_WAIT, KernelEvent};

pub fn from_kernel(event: &KernelEvent) -> Option<SchedulerIoWait> {
    if event.kind != KIND_SCHEDULER_IO_WAIT || event.tid == 0 || event.tid > i32::MAX as u32 {
        return None;
    }
    let end = event
        .comm
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(event.comm.len());
    Some(SchedulerIoWait {
        ts_ns: event.ts_ns,
        delay_ns: event.requested_bytes,
        tid: event.tid,
        pid: None,
        comm: String::from_utf8_lossy(&event.comm[..end]).into_owned(),
        cpu: Some(event.cpu),
        source: "eBPF sched_stat_iowait".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_delay_and_task_identity_without_using_observer_pid_or_request_fields() {
        for delay in [0, 1, 1_000_000_000] {
            let mut event = KernelEvent {
                kind: KIND_SCHEDULER_IO_WAIT,
                ts_ns: 123,
                requested_bytes: delay,
                tid: 42,
                pid: 999,
                cpu: 0,
                request_id: 888,
                device: 2048,
                bytes: 4096,
                ..Default::default()
            };
            event.comm[..5].copy_from_slice(b"task\0");
            let wait = from_kernel(&event).unwrap();
            assert_eq!(
                (wait.ts_ns, wait.delay_ns, wait.tid, wait.pid, wait.cpu),
                (123, delay, 42, None, Some(0))
            );
            assert_eq!(wait.comm, "task");
            event.tid = 0;
            assert!(from_kernel(&event).is_none());
            event.tid = u32::MAX;
            assert!(from_kernel(&event).is_none());
        }
        assert!(from_kernel(&KernelEvent::default()).is_none());
    }
}
