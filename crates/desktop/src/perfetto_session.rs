//! Shared live/recovery projection and lossless raw trace export.
use crate::{
    adb::AdbClient,
    perfetto::{self, DecodedTrace},
    perfetto_capture::PerfettoCapture,
    perfetto_projection::Projection,
    session,
};
use android_ebpf_protocol::{
    ProbeCapabilities, SCHEMA_VERSION, StorageEvent, WireRecord, write_record,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

/// Derive the visible warning from saved evidence as well as new captures.
/// Kernel counters do not include loss in Perfetto's central service buffers.
pub fn source_status(source: &str, status: &str, metadata: &serde_json::Value) -> String {
    if source != "perfetto" || metadata["stage"] != "complete" {
        return status.into();
    }
    let Ok(quality) = serde_json::from_value::<perfetto::TraceQuality>(metadata["quality"].clone())
    else {
        return format!("{status} · Trace quality unavailable (missing or incompatible metadata)");
    };
    let mut notices = Vec::new();
    let service_loss: Vec<_> = quality
        .service_loss_counters
        .iter()
        .filter(|(_, value)| **value > 0)
        .map(|(name, value)| {
            if let Some((buffer, counter)) =
                name.strip_prefix("buffer_").and_then(|s| s.split_once('_'))
            {
                format!("buffer {buffer}: {value} {}", counter.replace('_', " "))
            } else {
                format!("{value} {}", name.replace('_', " "))
            }
        })
        .collect();
    if !service_loss.is_empty() {
        notices.push(format!(
            "Service loss detected: {}",
            service_loss.join(", ")
        ));
    } else if !quality.service_stats_seen {
        notices.push("Service loss counters unavailable".into());
    }
    if quality.lost_bundles > 0 {
        notices.push(format!("Lost ftrace bundles: {}", quality.lost_bundles));
    }
    if quality.parse_errors > 0 {
        notices.push(format!("Trace parse errors: {}", quality.parse_errors));
    }
    if quality.truncated {
        notices.push("Raw trace truncated".into());
    }
    if quality.projection_limited {
        notices.push("Analysis projection limit reached; raw trace preserved".into());
    }
    if quality.final_flush_outcome == Some(2) {
        notices.push("Final trace flush failed".into());
    }
    if !notices.is_empty() {
        let status = status
            .strip_suffix(" · quality details in Diagnostics")
            .unwrap_or(status);
        format!("{status}\n{}", notices.join(" · "))
    } else {
        status.into()
    }
}

pub fn project_records(
    decoded: &DecodedTrace,
    raw_trace: &str,
    mut emit: impl FnMut(WireRecord) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let analysis = perfetto::analyze(decoded);
    let unresolved = analysis
        .completions
        .iter()
        .filter(|o| o.device_latency_ns.is_none())
        .count();
    let status = format!(
        "Perfetto · {} I/O · {} timing unresolved · kernel loss {} · FilePath unresolved · quality details in Diagnostics",
        analysis.completions.len(),
        unresolved,
        decoded
            .quality
            .kernel_lost_events()
            .map_or("unavailable".into(), |n| n.to_string())
    );
    let mut devices = std::collections::BTreeMap::<_, crate::host_bw::DeviceCoverage>::new();
    for o in &analysis.completions {
        let device = crate::perfetto_projection::device_numbers(o.device_encoded);
        let row = devices
            .entry(device)
            .or_insert_with(|| crate::host_bw::DeviceCoverage {
                device,
                ..Default::default()
            });
        row.completions += 1;
        row.unresolved += u64::from(o.issue_timestamp_ns.is_none());
    }
    let records: std::collections::HashMap<_, _> =
        decoded.events.iter().map(|e| (e.record_id, e)).collect();
    for (ids, requeue) in [
        (&analysis.unmatched_issue_records, false),
        (&analysis.unpaired_requeue_records, true),
    ] {
        for id in ids {
            if let Some(e) = records.get(id) {
                let device = crate::perfetto_projection::device_numbers(e.device_encoded);
                let row = devices
                    .entry(device)
                    .or_insert_with(|| crate::host_bw::DeviceCoverage {
                        device,
                        ..Default::default()
                    });
                if requeue {
                    row.requeues += 1;
                } else {
                    row.unmatched += 1;
                }
            }
        }
    }
    let metadata = serde_json::json!({"stage":"complete","raw_trace":raw_trace,"quality":decoded.quality,"block_activity_devices":devices.values().collect::<Vec<_>>(),"block_records":decoded.events.len(),"completion_observations":analysis.completions.len(),"scheduler_iowait_events":decoded.scheduler_waits.len(),"scheduler_iowait_scope":"independent task delay events; absence is not measured zero; kernel schedstats/event support required","unresolved_timing":unresolved,"unmatched_issues":analysis.unmatched_issue_records.len(),"orphan_inserts":analysis.orphan_insert_records.len(),"unpaired_requeues":analysis.unpaired_requeue_records.len(),"correlation_limit_hits":analysis.correlation_limit_hits,"file_path":"Unresolved: Perfetto block tracepoints expose no file/inode mapping"});
    emit(WireRecord::SourceInfo {
        schema_version: SCHEMA_VERSION,
        source: "perfetto".into(),
        status,
        metadata,
    })?;
    let capabilities: ProbeCapabilities = serde_json::from_value(
        serde_json::json!({"bpf_syscall":false,"btf":false,"ring_buffer":false,"block_issue":decoded.events.iter().any(|e|e.kind==perfetto::BlockKind::Issue),"block_complete":!analysis.completions.is_empty(),"block_insert":decoded.events.iter().any(|e|e.kind==perfetto::BlockKind::Insert),"file_io":false,"exact_request_correlation":false,"exact_file_attribution":false}),
    )?;
    emit(WireRecord::Capabilities {
        schema_version: SCHEMA_VERSION,
        capabilities,
    })?;
    let projection = Projection::new(decoded).with_analysis(&analysis);
    for (idx, observation) in analysis.completions.iter().enumerate() {
        let io = projection.completion(observation)?;
        emit(WireRecord::Event {
            schema_version: SCHEMA_VERSION,
            sequence: idx as u64 + 1,
            event: StorageEvent::ObservedBlockCompletion(io),
        })?;
    }
    for (idx, wait) in decoded.scheduler_waits.iter().enumerate() {
        emit(WireRecord::Event {
            schema_version: SCHEMA_VERSION,
            sequence: (analysis.completions.len() + idx + 1) as u64,
            event: StorageEvent::SchedulerIoWait(wait.clone()),
        })?;
    }
    let count = (analysis.completions.len() + decoded.scheduler_waits.len()) as u64;
    emit(WireRecord::Footer {
        schema_version: SCHEMA_VERSION,
        events_seen: count,
        events_persisted: count,
        events_dropped: 0,
        events_rejected: 0,
        graceful: Some(
            !decoded.quality.truncated
                && decoded.quality.ftrace_end_seen
                && !decoded.quality.projection_limited,
        ),
    })?;
    Ok(())
}

/// Resolve only the studio-owned relative location, never a path supplied by
/// untrusted session metadata. Original NDJSON and raw trace remain untouched.
pub fn raw_trace_path(session: &Path) -> Option<PathBuf> {
    let path = session.parent()?.join("perfetto/capture.pftrace");
    path.is_file().then_some(path)
}
pub fn recovery_manifest(session: &Path) -> Option<PathBuf> {
    let path = session.parent()?.join("perfetto/perfetto-owner.json");
    path.is_file().then_some(path)
}

pub fn export_raw_trace(session: &Path, destination: &Path) -> anyhow::Result<PathBuf> {
    let source = raw_trace_path(session)
        .ok_or_else(|| anyhow::anyhow!("No saved Perfetto raw trace beside this session"))?;
    session::ensure_distinct_export(session, destination)?;
    session::ensure_distinct_export(&source, destination)?;
    let before = std::fs::metadata(&source)?;
    let mut input = std::fs::File::open(&source)?;
    // create_new rejects existing files, including hard-link aliases of source.
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|e| {
            anyhow::anyhow!("Choose a new export filename; no existing file was replaced: {e}")
        })?;
    let result = (|| -> anyhow::Result<()> {
        let bytes = std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        let after = std::fs::metadata(&source)?;
        anyhow::ensure!(
            bytes == before.len()
                && before.len() == after.len()
                && before.modified()? == after.modified()?,
            "Raw trace changed during export; retry after capture finishes"
        );
        Ok(())
    })();
    result.map_err(|e| {
        anyhow::anyhow!(
            "{e}. Incomplete export preserved at {}; original trace is unchanged",
            destination.display()
        )
    })?;
    Ok(destination.into())
}

fn write_recovered_session(
    decoded: &DecodedTrace,
    original: &Path,
    method: &str,
) -> anyhow::Result<PathBuf> {
    let parent = original
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Session directory unavailable"))?;
    let output = parent.join(format!("capture-recovered-{}.ndjson", uuid::Uuid::new_v4()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)?;
    let mut writer = std::io::BufWriter::new(file);
    // Preserve acquisition scope from the original header. Reanalysis cannot
    // infer an unfiltered capture recipe from zero loss in raw data alone.
    // Only scan a bounded header, never duplicate the full event decode here.
    if let Ok(original_file) = std::fs::File::open(original) {
        let mut scope = None;
        android_ebpf_protocol::SessionReader::default().visit(
            std::io::Read::take(std::io::BufReader::new(original_file), 256 * 1024),
            |record| {
                if let WireRecord::SourceInfo {
                    source, metadata, ..
                } = &record
                    && source == "perfetto"
                    && metadata["stage"] == "recording"
                {
                    scope = Some(record);
                }
                Ok(())
            },
        )?;
        if let Some(record) = scope {
            write_record(&mut writer, &record)?;
        }
    }
    let result = project_records(decoded, "perfetto/capture.pftrace", |mut record| {
        if let WireRecord::SourceInfo {
            status, metadata, ..
        } = &mut record
        {
            *status = format!("{method} · {status}");
            metadata["recovery"] = serde_json::json!({"method":method,"previous_session":original.file_name(),"original_preserved":true});
        }
        write_record(&mut writer, &record)?;
        Ok(())
    });
    // Flush the accepted prefix even if projection fails. It remains a distinct
    // partial session, never a replacement for the original recording.
    writer.flush()?;
    writer.get_ref().sync_all()?;
    result.map_err(|e| {
        anyhow::anyhow!(
            "{e}. Partial recovered session saved at {}",
            output.display()
        )
    })?;
    Ok(output)
}

pub fn reanalyze_saved_trace(original: &Path) -> anyhow::Result<PathBuf> {
    let raw = raw_trace_path(original).ok_or_else(|| {
        anyhow::anyhow!(
            "No saved raw trace. Reconnect the original phone and use Recover from phone"
        )
    })?;
    let before = std::fs::metadata(&raw)?;
    let decoded = perfetto::decode(std::io::BufReader::new(std::fs::File::open(&raw)?));
    let after = std::fs::metadata(&raw)?;
    anyhow::ensure!(
        before.len() == after.len() && before.modified()? == after.modified()?,
        "Raw trace changed while decoding; retry after capture stops"
    );
    write_recovered_session(&decoded, original, "Reanalyzed saved raw trace")
}

pub fn recover_from_phone(client: AdbClient, original: &Path) -> anyhow::Result<PathBuf> {
    let manifest = recovery_manifest(original)
        .ok_or_else(|| anyhow::anyhow!("No Perfetto recovery manifest beside this session"))?;
    let mut capture = PerfettoCapture::recover(client, &manifest)?;
    let decoded = capture.recover_and_pull()?;
    write_recovered_session(&decoded, original, "Recovered from original phone")
}
