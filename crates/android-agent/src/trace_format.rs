use std::collections::HashMap;

use android_ebpf_types::{OFFSET_MISSING, RawSyscallLayout, TraceLayout};
use anyhow::{Context, Result, bail};

pub fn parse_layout(input: &str) -> Result<TraceLayout> {
    let mut offsets = HashMap::new();
    for line in input.lines() {
        let line = line.trim();
        let Some(declaration) = line.strip_prefix("field:") else {
            continue;
        };
        let Some((field_declaration, rest)) = declaration.split_once(';') else {
            continue;
        };
        let Some(name) = field_declaration.split_whitespace().last() else {
            continue;
        };
        let name = name
            .trim_start_matches('*')
            .split('[')
            .next()
            .unwrap_or(name);
        let offset = rest
            .split(';')
            .find_map(|part| part.trim().strip_prefix("offset:"))
            .with_context(|| format!("field {name} has no offset"))?
            .trim()
            .parse::<u16>()
            .with_context(|| format!("field {name} offset is not a u16"))?;
        offsets.insert(name.to_owned(), offset);
    }

    Ok(TraceLayout {
        dev_offset: required(&offsets, "dev")?,
        sector_offset: required(&offsets, "sector")?,
        nr_sector_offset: required(&offsets, "nr_sector")?,
        bytes_offset: optional(&offsets, &["bytes", "nr_bytes"]),
        rwbs_offset: optional(&offsets, &["rwbs"]),
        request_offset: optional(&offsets, &["rq", "request"]),
        status_offset: optional(&offsets, &["error", "status"]),
        reserved: 0,
    })
}

pub fn parse_raw_syscall_layout(enter: &str, exit: &str) -> Result<RawSyscallLayout> {
    let enter = parse_offsets(enter)?;
    let exit = parse_offsets(exit)?;
    Ok(RawSyscallLayout {
        enter_id_offset: required(&enter, "id")?,
        enter_args_offset: required(&enter, "args")?,
        exit_ret_offset: required(&exit, "ret")?,
        reserved: 0,
    })
}

fn parse_offsets(input: &str) -> Result<HashMap<String, u16>> {
    let mut offsets = HashMap::new();
    for line in input.lines() {
        let line = line.trim();
        let Some(declaration) = line.strip_prefix("field:") else {
            continue;
        };
        let Some((field_declaration, rest)) = declaration.split_once(';') else {
            continue;
        };
        let Some(name) = field_declaration.split_whitespace().last() else {
            continue;
        };
        let name = name
            .trim_start_matches('*')
            .split('[')
            .next()
            .unwrap_or(name);
        let offset = rest
            .split(';')
            .find_map(|part| part.trim().strip_prefix("offset:"))
            .with_context(|| format!("field {name} has no offset"))?
            .trim()
            .parse::<u16>()
            .with_context(|| format!("field {name} offset is not a u16"))?;
        offsets.insert(name.to_owned(), offset);
    }
    Ok(offsets)
}

fn required(offsets: &HashMap<String, u16>, name: &str) -> Result<u16> {
    offsets
        .get(name)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("mandatory tracepoint field `{name}` is missing"))
}

fn optional(offsets: &HashMap<String, u16>, aliases: &[&str]) -> u16 {
    aliases
        .iter()
        .find_map(|name| offsets.get(*name).copied())
        .unwrap_or(OFFSET_MISSING)
}

pub fn validate_pair(issue: &TraceLayout, complete: &TraceLayout) -> Result<bool> {
    let issue_has_request = issue.request_offset != OFFSET_MISSING;
    let complete_has_request = complete.request_offset != OFFSET_MISSING;
    if issue_has_request != complete_has_request {
        bail!("request pointer is present in only one block tracepoint")
    }
    Ok(issue_has_request)
}
