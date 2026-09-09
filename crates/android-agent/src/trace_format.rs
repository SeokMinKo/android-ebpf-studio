use std::collections::HashMap;

use android_ebpf_types::{
    BioRemapLayout, F2fsFolioLayout, FileExtentLayout, OFFSET_MISSING, PipelineTraceLayout,
    RawSyscallLayout, SchedulerWaitLayout, TraceLayout,
};
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
        exit_id_offset: required(&exit, "id")?,
    })
}

pub fn parse_scheduler_wait_layout(input: &str) -> Result<SchedulerWaitLayout> {
    let fields = parse_fields(input)?;
    let field = |name: &str, size: u16| -> Result<u16> {
        let (offset, actual_size) = fields
            .get(name)
            .copied()
            .with_context(|| format!("sched_stat_iowait missing `{name}`"))?;
        if actual_size != size || offset.checked_add(size).is_none() {
            bail!(
                "sched_stat_iowait `{name}` needs {size} bytes at a valid offset; got {actual_size}"
            )
        }
        Ok(offset)
    };
    // Kernel sched_stat_template uses a fixed char comm[TASK_COMM_LEN].
    // __data_loc/pointer formats have another size and are not guessed.
    Ok(SchedulerWaitLayout {
        pid_offset: field("pid", 4)?,
        delay_offset: field("delay", 8)?,
        comm_offset: field("comm", 16)?,
        reserved: 0,
    })
}

pub fn parse_pipeline_layout(
    input: &str,
    key_aliases: &[&str],
    sector_aliases: &[&str],
    bytes_aliases: &[&str],
    operation_aliases: &[&str],
    status_aliases: &[&str],
    state_aliases: &[&str],
) -> Result<PipelineTraceLayout> {
    let fields = parse_fields(input)?;
    let (key_offset, key_size) = key_aliases
        .iter()
        .find_map(|name| fields.get(*name).copied())
        .ok_or_else(|| anyhow::anyhow!("mandatory pipeline correlation field is missing"))?;
    if !matches!(key_size, 4 | 8) {
        bail!("pipeline correlation field must be 4 or 8 bytes, got {key_size}")
    }
    Ok(PipelineTraceLayout {
        key_offset,
        sector_offset: optional_fields(&fields, sector_aliases),
        bytes_offset: optional_fields(&fields, bytes_aliases),
        operation_offset: optional_fields(&fields, operation_aliases),
        status_offset: optional_fields(&fields, status_aliases),
        state_offset: optional_fields(&fields, state_aliases),
        key_size: u8::try_from(key_size)
            .context("pipeline correlation field size does not fit u8")?,
        reserved: [0; 3],
    })
}

pub fn parse_f2fs_extent_layout(input: &str) -> Result<FileExtentLayout> {
    let fields = parse_fields(input)?;
    let required_field = |aliases: &[&str], size: u16| -> Result<u16> {
        let (name, (offset, actual_size)) = aliases
            .iter()
            .find_map(|name| fields.get(*name).copied().map(|field| (*name, field)))
            .with_context(|| {
                format!(
                    "mandatory f2fs extent field `{}` is missing",
                    aliases.join("/")
                )
            })?;
        if actual_size != size {
            bail!("f2fs extent field `{name}` must be {size} bytes, got {actual_size}")
        }
        Ok(offset)
    };
    let (physical_name, (physical_block_offset, physical_block_size)) = ["m_pblk", "pblk"]
        .iter()
        .find_map(|name| fields.get(*name).copied().map(|field| (*name, field)))
        .context("mandatory f2fs extent field `m_pblk/pblk` is missing")?;
    if !matches!(physical_block_size, 4 | 8) {
        bail!("f2fs extent field `{physical_name}` must be 4 or 8 bytes, got {physical_block_size}")
    }
    Ok(FileExtentLayout {
        dev_offset: required_field(&["dev"], 4)?,
        inode_offset: required_field(&["ino", "inode"], 8)?,
        physical_block_offset,
        block_count_offset: required_field(&["m_len", "len"], 4)?,
        result_offset: required_field(&["ret"], 4)?,
        physical_block_size: u8::try_from(physical_block_size)?,
        reserved: 0,
    })
}

pub fn parse_bio_remap_layout(input: &str) -> Result<BioRemapLayout> {
    let fields = parse_fields(input)?;
    let required = |name: &str, size: u16| -> Result<u16> {
        let (offset, actual_size) = fields
            .get(name)
            .copied()
            .with_context(|| format!("mandatory bio remap field `{name}` is missing"))?;
        if actual_size != size {
            bail!("bio remap field `{name}` must be {size} bytes, got {actual_size}")
        }
        Ok(offset)
    };
    Ok(BioRemapLayout {
        device_offset: required("dev", 4)?,
        sector_offset: required("sector", 8)?,
        sectors_offset: required("nr_sector", 4)?,
        old_device_offset: required("old_dev", 4)?,
        old_sector_offset: required("old_sector", 8)?,
        reserved: [0; 3],
    })
}

pub fn parse_f2fs_folio_layout(input: &str) -> Result<F2fsFolioLayout> {
    let fields = parse_fields(input)?;
    let required = |aliases: &[&str], expected_sizes: &[u16]| -> Result<(u16, u16)> {
        let (name, field) = aliases
            .iter()
            .find_map(|name| fields.get(*name).copied().map(|field| (*name, field)))
            .with_context(|| {
                format!(
                    "mandatory f2fs folio field `{}` is missing",
                    aliases.join("/")
                )
            })?;
        if !expected_sizes.contains(&field.1) {
            bail!(
                "f2fs folio field `{name}` must have size {:?}, got {}",
                expected_sizes,
                field.1
            )
        }
        Ok(field)
    };
    let (dev_offset, _) = required(&["dev"], &[4])?;
    let (inode_offset, _) = required(&["ino", "inode"], &[8])?;
    let (physical_block_offset, physical_block_size) =
        required(&["new_blkaddr", "new_blk"], &[4, 8])?;
    let (data_type_offset, _) = required(&["type"], &[4])?;
    Ok(F2fsFolioLayout {
        dev_offset,
        inode_offset,
        physical_block_offset,
        data_type_offset,
        physical_block_size: u8::try_from(physical_block_size)?,
        reserved: [0; 3],
    })
}

fn parse_offsets(input: &str) -> Result<HashMap<String, u16>> {
    Ok(parse_fields(input)?
        .into_iter()
        .map(|(name, (offset, _))| (name, offset))
        .collect())
}

fn parse_fields(input: &str) -> Result<HashMap<String, (u16, u16)>> {
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
        let size = rest
            .split(';')
            .find_map(|part| part.trim().strip_prefix("size:"))
            .with_context(|| format!("field {name} has no size"))?
            .trim()
            .parse::<u16>()
            .with_context(|| format!("field {name} size is not a u16"))?;
        offsets.insert(name.to_owned(), (offset, size));
    }
    Ok(offsets)
}

fn optional_fields(offsets: &HashMap<String, (u16, u16)>, aliases: &[&str]) -> u16 {
    aliases
        .iter()
        .find_map(|name| offsets.get(*name).map(|(offset, _)| *offset))
        .unwrap_or(OFFSET_MISSING)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_f2fs_extent_without_request_pointer() {
        let format = r#"
field:dev_t dev; offset:8; size:4; signed:0;
field:ino_t ino; offset:16; size:8; signed:0;
field:block_t m_pblk; offset:28; size:4; signed:0;
field:unsigned int m_len; offset:32; size:4; signed:0;
field:int ret; offset:52; size:4; signed:1;
"#;

        assert_eq!(
            parse_f2fs_extent_layout(format).unwrap(),
            FileExtentLayout {
                dev_offset: 8,
                inode_offset: 16,
                physical_block_offset: 28,
                block_count_offset: 32,
                result_offset: 52,
                physical_block_size: 4,
                reserved: 0,
            }
        );
    }

    #[test]
    fn parses_android_bio_remap_layout() {
        let format = r#"
field:dev_t dev; offset:8; size:4; signed:0;
field:sector_t sector; offset:16; size:8; signed:0;
field:unsigned int nr_sector; offset:24; size:4; signed:0;
field:dev_t old_dev; offset:28; size:4; signed:0;
field:sector_t old_sector; offset:32; size:8; signed:0;
"#;
        assert_eq!(
            parse_bio_remap_layout(format).unwrap(),
            BioRemapLayout {
                device_offset: 8,
                sector_offset: 16,
                sectors_offset: 24,
                old_device_offset: 28,
                old_sector_offset: 32,
                reserved: [0; 3],
            }
        );
    }

    #[test]
    fn parses_v2602da_f2fs_submit_folio_write_layout() {
        let format = r#"
field:dev_t dev; offset:8; size:4; signed:0;
field:ino_t ino; offset:16; size:8; signed:0;
field:unsigned long index; offset:24; size:8; signed:0;
field:block_t old_blkaddr; offset:32; size:4; signed:0;
field:block_t new_blkaddr; offset:36; size:4; signed:0;
field:enum req_op op; offset:40; size:4; signed:0;
field:int type; offset:52; size:4; signed:1;
"#;
        assert_eq!(
            parse_f2fs_folio_layout(format).unwrap(),
            F2fsFolioLayout {
                dev_offset: 8,
                inode_offset: 16,
                physical_block_offset: 36,
                data_type_offset: 52,
                physical_block_size: 4,
                reserved: [0; 3],
            }
        );
    }
}
