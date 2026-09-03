use std::{collections::BTreeMap, fs, path::Path};

use android_ebpf_types::{FileIdentityLayout, OFFSET_MISSING};
use anyhow::{Context, Result, anyhow, bail};

const BTF_MAGIC: u16 = 0xeb9f;
const BTF_KIND_STRUCT: u32 = 4;

pub fn file_identity_layout_from_sysfs(path: &Path) -> Result<FileIdentityLayout> {
    let bytes = fs::read(path).with_context(|| format!("failed to read BTF {}", path.display()))?;
    parse_file_identity_layout(&bytes)
}

fn parse_file_identity_layout(bytes: &[u8]) -> Result<FileIdentityLayout> {
    if bytes.len() < 24 {
        bail!("BTF header is truncated");
    }
    let little = match u16::from_le_bytes([bytes[0], bytes[1]]) {
        BTF_MAGIC => true,
        _ if u16::from_be_bytes([bytes[0], bytes[1]]) == BTF_MAGIC => false,
        _ => bail!("invalid BTF magic"),
    };
    let u32_at = |offset: usize| -> Result<u32> {
        let raw: [u8; 4] = bytes
            .get(offset..offset + 4)
            .ok_or_else(|| anyhow!("BTF record is truncated"))?
            .try_into()
            .expect("four-byte slice");
        Ok(if little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    };
    let header_len = u32_at(4)? as usize;
    let type_start = header_len
        .checked_add(u32_at(8)? as usize)
        .ok_or_else(|| anyhow!("BTF type offset overflow"))?;
    let type_end = type_start
        .checked_add(u32_at(12)? as usize)
        .ok_or_else(|| anyhow!("BTF type length overflow"))?;
    let string_start = header_len
        .checked_add(u32_at(16)? as usize)
        .ok_or_else(|| anyhow!("BTF string offset overflow"))?;
    let string_end = string_start
        .checked_add(u32_at(20)? as usize)
        .ok_or_else(|| anyhow!("BTF string length overflow"))?;
    if type_end > bytes.len() || string_end > bytes.len() {
        bail!("BTF sections exceed input");
    }
    let strings = &bytes[string_start..string_end];
    let string_at = |offset: u32| -> Result<&str> {
        let value = strings
            .get(offset as usize..)
            .ok_or_else(|| anyhow!("invalid BTF string offset {offset}"))?;
        let end = value
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| anyhow!("unterminated BTF string"))?;
        std::str::from_utf8(&value[..end]).context("BTF name is not UTF-8")
    };

    let mut fields = BTreeMap::<(String, String), u16>::new();
    let mut cursor = type_start;
    while cursor < type_end {
        let name_offset = u32_at(cursor)?;
        let info = u32_at(cursor + 4)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let kind_flag = info >> 31 != 0;
        cursor += 12;
        let extra_size = btf_extra_size(kind, vlen)?;
        if cursor + extra_size > type_end {
            bail!("BTF type payload is truncated");
        }
        if kind == BTF_KIND_STRUCT {
            let struct_name = string_at(name_offset)?;
            if matches!(
                struct_name,
                "file" | "inode" | "super_block" | "address_space"
            ) {
                for member_index in 0..vlen {
                    let member = cursor + member_index * 12;
                    let member_name = string_at(u32_at(member)?)?;
                    let raw_offset = u32_at(member + 8)?;
                    let bit_offset = if kind_flag {
                        raw_offset & 0x00ff_ffff
                    } else {
                        raw_offset
                    };
                    if bit_offset % 8 != 0 || bit_offset / 8 > u16::MAX as u32 {
                        bail!("unsupported BTF field offset {struct_name}.{member_name}");
                    }
                    fields.insert(
                        (struct_name.into(), member_name.into()),
                        (bit_offset / 8) as u16,
                    );
                }
            }
        }
        cursor += extra_size;
    }

    let required = |owner: &str, member: &str| -> Result<u16> {
        fields
            .get(&(owner.into(), member.into()))
            .copied()
            .ok_or_else(|| anyhow!("BTF field {owner}.{member} is missing"))
    };
    Ok(FileIdentityLayout {
        file_inode_offset: required("file", "f_inode")?,
        inode_superblock_offset: required("inode", "i_sb")?,
        inode_number_offset: required("inode", "i_ino")?,
        inode_generation_offset: fields
            .get(&("inode".into(), "i_generation".into()))
            .copied()
            .unwrap_or(OFFSET_MISSING),
        superblock_device_offset: required("super_block", "s_dev")?,
        address_space_host_offset: fields
            .get(&("address_space".into(), "host".into()))
            .copied()
            .unwrap_or(OFFSET_MISSING),
        reserved: [0; 2],
    })
}

fn btf_extra_size(kind: u32, vlen: usize) -> Result<usize> {
    let size = match kind {
        1 => 4,
        2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0,
        3 => 12,
        4 | 5 => 12 * vlen,
        6 => 8 * vlen,
        13 => 8 * vlen,
        14 => 4,
        15 => 12 * vlen,
        17 => 4,
        19 => 12 * vlen,
        _ => bail!("unsupported BTF kind {kind}"),
    };
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn synthetic_btf() -> Vec<u8> {
        let names = [
            "",
            "file",
            "f_inode",
            "inode",
            "i_sb",
            "i_ino",
            "i_generation",
            "super_block",
            "s_dev",
            "address_space",
            "host",
        ];
        let mut strings = Vec::new();
        let mut offsets = BTreeMap::new();
        for name in names {
            offsets.insert(name, strings.len() as u32);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let mut types = Vec::new();
        for (owner, members) in [
            ("file", vec![("f_inode", 32_u32)]),
            (
                "inode",
                vec![
                    ("i_sb", 64_u32),
                    ("i_ino", 128_u32),
                    ("i_generation", 192_u32),
                ],
            ),
            ("super_block", vec![("s_dev", 40_u32)]),
            ("address_space", vec![("host", 48_u32)]),
        ] {
            push_u32(&mut types, offsets[owner]);
            push_u32(&mut types, (BTF_KIND_STRUCT << 24) | members.len() as u32);
            push_u32(&mut types, 256);
            for (member, bit_offset) in members {
                push_u32(&mut types, offsets[member]);
                push_u32(&mut types, 1);
                push_u32(&mut types, bit_offset);
            }
        }
        let mut output = Vec::new();
        output.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        output.extend_from_slice(&[1, 0]);
        push_u32(&mut output, 24);
        push_u32(&mut output, 0);
        push_u32(&mut output, types.len() as u32);
        push_u32(&mut output, types.len() as u32);
        push_u32(&mut output, strings.len() as u32);
        output.extend_from_slice(&types);
        output.extend_from_slice(&strings);
        output
    }

    #[test]
    fn resolves_file_identity_offsets_from_target_btf() {
        let layout = parse_file_identity_layout(&synthetic_btf()).unwrap();
        assert_eq!(layout.file_inode_offset, 4);
        assert_eq!(layout.inode_superblock_offset, 8);
        assert_eq!(layout.inode_number_offset, 16);
        assert_eq!(layout.inode_generation_offset, 24);
        assert_eq!(layout.superblock_device_offset, 5);
        assert_eq!(layout.address_space_host_offset, 6);
    }

    #[test]
    fn parses_running_kernel_btf_when_exposed() {
        let path = Path::new("/sys/kernel/btf/vmlinux");
        if path.is_file() {
            let layout = file_identity_layout_from_sysfs(path).unwrap();
            assert_ne!(layout.file_inode_offset, OFFSET_MISSING);
            assert_ne!(layout.inode_superblock_offset, OFFSET_MISSING);
            assert_ne!(layout.inode_number_offset, OFFSET_MISSING);
            assert_ne!(layout.superblock_device_offset, OFFSET_MISSING);
        }
    }
}
