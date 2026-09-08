//! Prefer raw block tracepoints only after all target layouts validate.
use android_ebpf_types::RawBlockLayout;
use anyhow::{Context, Result};
use aya::{Ebpf, Pod, maps::Array, programs::RawTracePoint};
#[repr(transparent)]
#[derive(Clone, Copy)]
struct LayoutValue(RawBlockLayout);
unsafe impl Pod for LayoutValue {}
/// None means attached. Some reason means no raw programs remain attached and
/// the caller may safely use the generic path. Rollback errors are fatal.
pub fn attach(bpf: &mut Ebpf) -> Result<Option<String>> {
    let mut loaded = Vec::new();
    let attempt = (|| -> Result<()> {
        let bytes = std::fs::read("/sys/kernel/btf/vmlinux")?;
        let l = android_ebpf_agent::block_btf::parse(&bytes).map_err(anyhow::Error::msg)?;
        let layout = RawBlockLayout {
            request_queue: l.request_queue,
            request_flags: l.request_flags,
            request_bytes: l.request_bytes,
            request_sector: l.request_sector,
            queue_disk: l.queue_disk,
            disk_major: l.disk_major,
            disk_minor: l.disk_minor,
            reserved: 0,
        };
        let mut map = Array::<_, LayoutValue>::try_from(
            bpf.map_mut("RAW_BLOCK_LAYOUT")
                .context("raw layout map unavailable")?,
        )?;
        map.set(0, LayoutValue(layout), 0)?;
        for name in ["raw_block_complete", "raw_block_insert", "raw_block_issue"] {
            let p: &mut RawTracePoint = bpf
                .program_mut(name)
                .with_context(|| format!("missing {name}"))?
                .try_into()?;
            p.load()?;
            loaded.push(name);
        }
        // Completion and insert must be ready before issue events are admitted.
        for (name, event) in [
            ("raw_block_complete", "block_rq_complete"),
            ("raw_block_insert", "block_rq_insert"),
            ("raw_block_issue", "block_rq_issue"),
        ] {
            let p: &mut RawTracePoint = bpf
                .program_mut(name)
                .context("loaded raw program disappeared")?
                .try_into()?;
            p.attach(event)?;
        }
        Ok(())
    })();
    match attempt {
        Ok(()) => Ok(None),
        Err(error) => {
            for name in loaded.into_iter().rev() {
                let p: &mut RawTracePoint = bpf
                    .program_mut(name)
                    .context("rollback program missing")?
                    .try_into()?;
                p.unload().with_context(|| {
                    format!("cannot roll back {name}; refusing duplicate generic capture")
                })?;
            }
            Ok(Some(format!("{error:#}")))
        }
    }
}
