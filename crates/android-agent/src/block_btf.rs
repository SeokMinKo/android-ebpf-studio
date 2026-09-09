//! Fail-closed layout discovery for a future raw block tracepoint path.
//! This module does not attach probes or change attribution confidence.
#[derive(Debug, PartialEq, Eq)]
pub struct BlockLayout {
    pub request_queue: u16,
    pub request_flags: u16,
    pub request_bytes: u16,
    pub request_sector: u16,
    pub queue_disk: u16,
    pub disk_major: u16,
    pub disk_minor: u16,
}
struct Ty<'a> {
    name: &'a str,
    kind: u32,
    size: u32,
    flag: bool,
    data: Vec<u32>,
}
struct Btf<'a> {
    types: Vec<Ty<'a>>,
    strings: &'a [u8],
}
fn name(strings: &[u8], offset: u32) -> Result<&str, String> {
    let tail = strings
        .get(offset as usize..)
        .ok_or("invalid string offset")?;
    let end = tail
        .iter()
        .position(|x| *x == 0)
        .ok_or("unterminated string")?;
    std::str::from_utf8(&tail[..end]).map_err(|_| "invalid UTF-8".into())
}
impl<'a> Btf<'a> {
    fn read(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() < 24 || bytes[2] != 1 {
            return Err("unsupported BTF header".into());
        }
        let little = match &bytes[..2] {
            [0x9f, 0xeb] => true,
            [0xeb, 0x9f] => false,
            _ => return Err("invalid magic".into()),
        };
        let word = |p: usize| -> Result<u32, String> {
            let a: [u8; 4] = bytes
                .get(p..p.checked_add(4).ok_or("offset overflow")?)
                .ok_or("truncated BTF")?
                .try_into()
                .map_err(|_| "word")?;
            Ok(if little {
                u32::from_le_bytes(a)
            } else {
                u32::from_be_bytes(a)
            })
        };
        let header = word(4)? as usize;
        if header < 24 {
            return Err("short header".into());
        }
        let start = header.checked_add(word(8)? as usize).ok_or("overflow")?;
        let end = start.checked_add(word(12)? as usize).ok_or("overflow")?;
        let ss = header.checked_add(word(16)? as usize).ok_or("overflow")?;
        let se = ss.checked_add(word(20)? as usize).ok_or("overflow")?;
        if start < header || end > bytes.len() || ss < end {
            return Err("invalid sections".into());
        }
        let strings = bytes.get(ss..se).ok_or("invalid strings")?;
        let mut types = vec![Ty {
            name: "",
            kind: 0,
            size: 0,
            flag: false,
            data: vec![],
        }];
        let mut p = start;
        while p < end {
            if end - p < 12 {
                return Err("truncated type".into());
            }
            let n = name(strings, word(p)?)?;
            let info = word(p + 4)?;
            let k = info >> 24 & 31;
            let v = (info & 65535) as usize;
            let size = word(p + 8)?;
            p += 12;
            let words = match k {
                1 | 14 | 17 => 1,
                2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0,
                3 => 3,
                4 | 5 | 15 | 19 => 3 * v,
                6 | 13 => 2 * v,
                _ => return Err("unsupported kind".into()),
            };
            if words * 4 > end - p {
                return Err("truncated payload".into());
            }
            let mut data = Vec::with_capacity(words);
            for i in 0..words {
                data.push(word(p + i * 4)?);
            }
            p += words * 4;
            types.push(Ty {
                name: n,
                kind: k,
                size,
                flag: info >> 31 != 0,
                data,
            });
        }
        Ok(Self { types, strings })
    }
    fn ty(&self, id: u32) -> Result<&Ty<'a>, String> {
        self.types.get(id as usize).ok_or("invalid type id".into())
    }
    fn base(&self, mut id: u32) -> Result<&Ty<'a>, String> {
        for _ in 0..32 {
            let t = self.ty(id)?;
            if !matches!(t.kind, 8..=11 | 18) {
                return Ok(t);
            }
            id = t.size;
        }
        Err("cyclic type aliases".into())
    }
    fn named(&self, n: &str, kind: u32) -> Result<&Ty<'a>, String> {
        let mut a = self.types.iter().filter(|t| t.name == n && t.kind == kind);
        let t = a.next().ok_or_else(|| format!("missing {n}"))?;
        if a.next().is_some() {
            return Err(format!("ambiguous {n}"));
        }
        Ok(t)
    }
    fn integer(&self, id: u32, width: u32) -> Result<(), String> {
        let t = self.base(id)?;
        if t.kind != 1 || t.size != width || t.data[0] & 0x00ff_ffff != width * 8 {
            return Err("unexpected integer width/offset".into());
        }
        Ok(())
    }
    fn pointer(&self, id: u32, to: &str) -> Result<&Ty<'a>, String> {
        let t = self.base(id)?;
        if t.kind != 2 {
            return Err("expected pointer".into());
        }
        let b = self.base(t.size)?;
        if (to.is_empty() && t.size != 0) || (!to.is_empty() && (b.kind != 4 || b.name != to)) {
            return Err("pointer target mismatch".into());
        }
        Ok(b)
    }
    fn field(
        &self,
        t: &Ty<'a>,
        field: &str,
        width: u32,
        target: Option<&str>,
    ) -> Result<u16, String> {
        let mut found = None;
        for m in t.data.as_chunks::<3>().0 {
            if name(self.strings, m[0])? != field {
                continue;
            }
            if found.is_some() {
                return Err("ambiguous field".into());
            }
            let bit = if t.flag {
                if m[2] >> 24 != 0 {
                    return Err("bitfield unsupported".into());
                }
                m[2] & 0xffffff
            } else {
                m[2]
            };
            if bit % 8 != 0 || bit / 8 >= u16::MAX as u32 || bit / 8 + width > t.size {
                return Err("field outside structure".into());
            }
            if let Some(to) = target {
                self.pointer(m[1], to)?;
            } else {
                self.integer(m[1], width)?;
            }
            found = Some((bit / 8) as u16);
        }
        found.ok_or_else(|| format!("missing {}.{field}", t.name))
    }
    fn callback(&self, n: &str, complete: bool) -> Result<&Ty<'a>, String> {
        let t = self.named(n, 8)?;
        let ptr = self.base(t.size)?;
        if ptr.kind != 2 {
            return Err("callback pointer missing".into());
        }
        let proto = self.base(ptr.size)?;
        let count = if complete { 4 } else { 2 };
        if proto.kind != 13 || proto.size != 0 || proto.data.len() != count * 2 {
            return Err("callback signature mismatch".into());
        }
        self.pointer(proto.data[1], "")?;
        let request = self.pointer(proto.data[3], "request")?;
        if complete {
            self.integer(proto.data[5], 1)?;
            self.integer(proto.data[7], 4)?;
        }
        Ok(request)
    }
    fn field_target(&self, owner: &Ty<'a>, field: &str, target: &str) -> Result<&Ty<'a>, String> {
        self.field(owner, field, 8, Some(target))?;
        for m in owner.data.as_chunks::<3>().0 {
            if name(self.strings, m[0])? == field {
                return self.pointer(m[1], target);
            }
        }
        Err("missing pointer field".into())
    }
}
pub fn parse(bytes: &[u8]) -> Result<BlockLayout, String> {
    let b = Btf::read(bytes)?;
    let mut layout = None;
    for (n, c) in [
        ("btf_trace_block_rq_issue", false),
        ("btf_trace_block_rq_insert", false),
        ("btf_trace_block_rq_complete", true),
    ] {
        // Follow each callback's concrete types; unrelated compilation units
        // can legitimately define different structures with the same name.
        let request = b.callback(n, c)?;
        let queue = b.field_target(request, "q", "request_queue")?;
        let disk = b.field_target(queue, "disk", "gendisk")?;
        let current = BlockLayout {
            request_queue: b.field(request, "q", 8, Some("request_queue"))?,
            request_flags: b.field(request, "cmd_flags", 4, None)?,
            request_bytes: b.field(request, "__data_len", 4, None)?,
            request_sector: b.field(request, "__sector", 8, None)?,
            queue_disk: b.field(queue, "disk", 8, Some("gendisk"))?,
            disk_major: b.field(disk, "major", 4, None)?,
            disk_minor: b.field(disk, "first_minor", 4, None)?,
        };
        if layout.as_ref().is_some_and(|previous| previous != &current) {
            return Err("block callback layouts disagree".into());
        }
        layout = Some(current);
    }
    layout.ok_or("missing block callbacks".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut strings = vec![0_u8];
        let mut types = Vec::<u8>::new();
        fn name(s: &mut Vec<u8>, v: &str) -> u32 {
            let n = s.len() as u32;
            s.extend(v.as_bytes());
            s.push(0);
            n
        }
        fn word(b: &mut Vec<u8>, v: u32) {
            b.extend(v.to_le_bytes());
        }
        fn ty(t: &mut Vec<u8>, s: &mut Vec<u8>, n: &str, k: u32, size: u32, extra: &[u32]) {
            word(t, name(s, n));
            let count = match k {
                4 => extra.len() / 3,
                13 => extra.len() / 2,
                _ => 0,
            };
            word(t, (k << 24) | count as u32);
            word(t, size);
            for x in extra {
                word(t, *x);
            }
        }
        ty(&mut types, &mut strings, "u32", 1, 4, &[32]); // 1
        ty(&mut types, &mut strings, "u64", 1, 8, &[64]); // 2
        ty(&mut types, &mut strings, "u8", 1, 1, &[8]); // 3
        ty(&mut types, &mut strings, "", 2, 5, &[]); // 4 request pointer
        let fields = [
            ("q", 6, 0),
            ("cmd_flags", 1, 24),
            ("__data_len", 1, 44),
            ("__sector", 2, 48),
        ];
        let mut extra = Vec::new();
        for (n, t, o) in fields {
            extra.extend([name(&mut strings, n), t, o * 8]);
        }
        ty(&mut types, &mut strings, "request", 4, 280, &extra); // 5
        ty(&mut types, &mut strings, "", 2, 7, &[]); // 6 queue pointer
        let disk = name(&mut strings, "disk");
        ty(
            &mut types,
            &mut strings,
            "request_queue",
            4,
            1128,
            &[disk, 8, 104 * 8],
        ); // 7
        ty(&mut types, &mut strings, "", 2, 9, &[]); // 8 disk pointer
        let major = name(&mut strings, "major");
        let minor = name(&mut strings, "first_minor");
        ty(
            &mut types,
            &mut strings,
            "gendisk",
            4,
            704,
            &[major, 1, 0, minor, 1, 32],
        ); // 9
        ty(&mut types, &mut strings, "", 2, 0, &[]); // 10 void pointer
        ty(&mut types, &mut strings, "", 13, 0, &[0, 10, 0, 4]); // 11
        ty(&mut types, &mut strings, "", 2, 11, &[]); // 12
        ty(
            &mut types,
            &mut strings,
            "btf_trace_block_rq_issue",
            8,
            12,
            &[],
        ); // 13
        ty(
            &mut types,
            &mut strings,
            "btf_trace_block_rq_insert",
            8,
            12,
            &[],
        ); // 14
        ty(
            &mut types,
            &mut strings,
            "",
            13,
            0,
            &[0, 10, 0, 4, 0, 3, 0, 1],
        ); // 15
        ty(&mut types, &mut strings, "", 2, 15, &[]); // 16
        ty(
            &mut types,
            &mut strings,
            "btf_trace_block_rq_complete",
            8,
            16,
            &[],
        ); // 17
        let mut out = vec![0x9f, 0xeb, 1, 0];
        for x in [
            24,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ] {
            word(&mut out, x);
        }
        out.extend(types);
        out.extend(strings);
        out
    }

    #[test]
    fn follows_callback_type_instead_of_unrelated_same_name() {
        let mut b = fixture();
        let old_len = u32::from_le_bytes(b[12..16].try_into().unwrap());
        let insert = 24 + old_len as usize;
        let parsed = Btf::read(&b).unwrap();
        let request_name = parsed
            .strings
            .windows(8)
            .position(|v| v == b"request\0")
            .unwrap() as u32;
        let mut duplicate = Vec::new();
        for word in [request_name, 4_u32 << 24, 1] {
            duplicate.extend(word.to_le_bytes());
        }
        b.splice(insert..insert, duplicate);
        b[12..16].copy_from_slice(&(old_len + 12).to_le_bytes());
        b[16..20].copy_from_slice(&(old_len + 12).to_le_bytes());
        assert_eq!(parse(&b).unwrap().request_sector, 48);
    }

    #[test]
    fn resolves_layout_and_callbacks() {
        let r = parse(&fixture()).unwrap();
        assert_eq!(r.request_sector, 48);
        assert_eq!(r.request_bytes, 44);
        assert_eq!(r.request_flags, 24);
        assert_eq!(r.queue_disk, 104);
        assert_eq!(r.disk_minor, 4);
    }
    #[test]
    fn rejects_truncation() {
        let b = fixture();
        for end in [0, 8, 23, b.len() - 1] {
            assert!(parse(&b[..end]).is_err());
        }
    }
    #[test]
    fn rejects_wrong_callback() {
        let mut b = fixture();
        let offset = 24 + 16 + 16 + 16 + 12 + 60 + 12 + 24 + 12 + 36 + 12; // type 11 header
        b[offset + 24..offset + 28].copy_from_slice(&1_u32.to_le_bytes());
        assert!(parse(&b).is_err());
    }
    #[test]
    fn rejects_integer_bit_offset() {
        let mut b = fixture();
        b[36..40].copy_from_slice(&((8_u32 << 16) | 32).to_le_bytes());
        assert!(parse(&b).is_err());
    }
    #[test]
    fn rejects_wrong_width() {
        let mut b = fixture();
        b[24 + 8..24 + 12].copy_from_slice(&8_u32.to_le_bytes());
        assert!(parse(&b).is_err());
    }
    #[test]
    fn rejects_field_outside_struct() {
        let mut b = fixture();
        let request = 24 + 16 + 16 + 16 + 12;
        b[request + 8..request + 12].copy_from_slice(&32_u32.to_le_bytes());
        assert!(parse(&b).is_err());
    }
    #[test]
    #[ignore = "requires an explicitly supplied target BTF file"]
    fn target_btf_when_requested() {
        {
            let p = std::env::var("BLOCK_BTF_TEST_FILE").expect("target BTF file required");
            let r = parse(&std::fs::read(p).unwrap()).unwrap();
            assert!(r.request_sector > 0);
        }
    }
}
