use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const BLOCK: usize = 512;

pub fn extract_tar(data: &[u8], dest: &Path) -> Result<Vec<PathBuf>, String> {
    fs::create_dir_all(dest).map_err(|e| format!("create {:?}: {e}", dest))?;
    let dest = dest
        .canonicalize()
        .map_err(|e| format!("canon {:?}: {e}", dest))?;

    let mut out = Vec::new();
    let mut pos = 0;
    let mut long_name: Option<String> = None;

    while pos + BLOCK <= data.len() {
        let header = &data[pos..pos + BLOCK];
        if header.iter().all(|b| *b == 0) {
            pos += BLOCK;
            continue;
        }
        let size = parse_octal(&header[124..136])?;
        let typeflag = header[156];
        let mut name = read_name(header)?;
        if let Some(prefix) = read_prefix(header)? {
            if !name.is_empty() {
                name = format!("{prefix}/{name}");
            } else {
                name = prefix;
            }
        }
        if let Some(ln) = long_name.take() {
            name = ln;
        }

        pos += BLOCK;
        let body_end = pos + size as usize;
        if body_end > data.len() {
            return Err("tar truncated body".into());
        }
        let body = &data[pos..body_end];

        match typeflag {
            b'L' => {
                let parsed = cstr(body);
                long_name = Some(parsed);
            }
            b'x' | b'X' => {
                if let Some(path) = parse_pax_path(body) {
                    long_name = Some(path);
                }
            }
            0 | b'0' => {
                let target = safe_join(&dest, &name)?;
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| format!("mkdir {:?}: {e}", parent))?;
                }
                let mut f =
                    fs::File::create(&target).map_err(|e| format!("create {:?}: {e}", target))?;
                f.write_all(body)
                    .map_err(|e| format!("write {:?}: {e}", target))?;
                out.push(target);
            }
            b'5' => {
                let target = safe_join(&dest, &name)?;
                fs::create_dir_all(&target).map_err(|e| format!("mkdir {:?}: {e}", target))?;
            }
            _ => {}
        }

        pos = body_end;
        let pad = (BLOCK - (size as usize % BLOCK)) % BLOCK;
        pos += pad;
    }
    Ok(out)
}

fn parse_octal(b: &[u8]) -> Result<u64, String> {
    let s = std::str::from_utf8(b)
        .map_err(|_| "tar non-utf8 octal".to_string())?
        .trim_end_matches('\0')
        .trim_end_matches(' ')
        .trim_start_matches(' ');
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| format!("bad octal {s:?}"))
}

fn read_name(header: &[u8]) -> Result<String, String> {
    Ok(cstr(&header[0..100]))
}

fn read_prefix(header: &[u8]) -> Result<Option<String>, String> {
    if &header[257..263] == b"ustar\x00" || &header[257..263] == b"ustar " {
        let p = cstr(&header[345..500]);
        if !p.is_empty() {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|x| *x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn parse_pax_path(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    for record in iter_pax_records(text) {
        if let Some(v) = record.strip_prefix("path=") {
            return Some(v.to_string());
        }
    }
    None
}

fn iter_pax_records(s: &str) -> impl Iterator<Item = &str> {
    struct It<'a> {
        s: &'a str,
    }
    impl<'a> Iterator for It<'a> {
        type Item = &'a str;
        fn next(&mut self) -> Option<&'a str> {
            let s = self.s.trim_start();
            if s.is_empty() {
                return None;
            }
            let space = s.find(' ')?;
            let len: usize = s[..space].parse().ok()?;
            if len == 0 || len > s.len() {
                return None;
            }
            let record_with_nl = &s[space + 1..len - 1];
            self.s = &s[len..];
            Some(record_with_nl)
        }
    }
    It { s }
}

fn safe_join(dest: &Path, name: &str) -> Result<PathBuf, String> {
    let rel = PathBuf::from(name);
    for c in rel.components() {
        match c {
            Component::Normal(_) => {}
            Component::CurDir => {}
            _ => return Err(format!("refusing unsafe path {name:?}")),
        }
    }
    let joined = dest.join(&rel);
    if !joined.starts_with(dest) {
        return Err(format!("refusing path that escapes dest {name:?}"));
    }
    Ok(joined)
}

pub fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, body) in entries {
        append_regular_entry(&mut out, name, body);
    }
    out.extend(std::iter::repeat(0u8).take(BLOCK * 2));
    out
}

pub fn build_tar_pax(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, body) in entries {
        if name.len() > 100 {
            append_pax_path_header(&mut out, name);
        }
        append_regular_entry(&mut out, name, body);
    }
    out.extend(std::iter::repeat(0u8).take(BLOCK * 2));
    out
}

fn append_regular_entry(out: &mut Vec<u8>, name: &str, body: &[u8]) {
    let mut header = [0u8; BLOCK];
    let nb = name.as_bytes();
    let n = nb.len().min(100);
    header[..n].copy_from_slice(&nb[..n]);
    fill_common_header(&mut header, body.len(), b'0');
    finalize_checksum(&mut header);
    out.extend_from_slice(&header);
    out.extend_from_slice(body);
    let pad = (BLOCK - (body.len() % BLOCK)) % BLOCK;
    out.extend(std::iter::repeat(0u8).take(pad));
}

fn append_pax_path_header(out: &mut Vec<u8>, path: &str) {
    let record_body = pax_path_record(path);
    let mut header = [0u8; BLOCK];
    let pax_name = b"PaxHeaders/vetpkg";
    header[..pax_name.len()].copy_from_slice(pax_name);
    fill_common_header(&mut header, record_body.len(), b'x');
    finalize_checksum(&mut header);
    out.extend_from_slice(&header);
    out.extend_from_slice(&record_body);
    let pad = (BLOCK - (record_body.len() % BLOCK)) % BLOCK;
    out.extend(std::iter::repeat(0u8).take(pad));
}

fn pax_path_record(path: &str) -> Vec<u8> {
    let suffix = format!(" path={}\n", path);
    let mut len = suffix.len() + 1;
    loop {
        let prefix = len.to_string();
        let total = prefix.len() + suffix.len();
        if total == len {
            let mut record = Vec::with_capacity(total);
            record.extend_from_slice(prefix.as_bytes());
            record.extend_from_slice(suffix.as_bytes());
            return record;
        }
        len = total;
    }
}

fn fill_common_header(header: &mut [u8; BLOCK], size: usize, typeflag: u8) {
    let mode = b"0000644";
    header[100..107].copy_from_slice(mode);
    header[107] = 0;
    let zero7 = b"0000000";
    header[108..115].copy_from_slice(zero7);
    header[115] = 0;
    header[116..123].copy_from_slice(zero7);
    header[123] = 0;
    let sz = format!("{:011o}", size);
    let szb = sz.as_bytes();
    header[124..124 + szb.len()].copy_from_slice(szb);
    header[135] = 0;
    let mt = b"00000000000";
    header[136..147].copy_from_slice(mt);
    header[147] = 0;
    header[148..156].fill(b' ');
    header[156] = typeflag;
    header[257..263].copy_from_slice(b"ustar\x00");
    header[263..265].copy_from_slice(b"00");
}

fn finalize_checksum(header: &mut [u8; BLOCK]) {
    let mut sum: u32 = 0;
    for b in header.iter() {
        sum = sum.wrapping_add(*b as u32);
    }
    let csum = format!("{:06o}", sum);
    header[148..148 + csum.len()].copy_from_slice(csum.as_bytes());
    header[154] = 0;
    header[155] = b' ';
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::TempDir;

    #[test]
    fn round_trip_simple() {
        let tar = build_tar(&[("a.txt", b"hello"), ("b.txt", b"world!")]);
        let td = TempDir::new("vetpkg-tar").unwrap();
        let files = extract_tar(&tar, td.path()).unwrap();
        assert_eq!(files.len(), 2);
        let a = fs::read(td.path().join("a.txt")).unwrap();
        assert_eq!(a, b"hello");
        let b = fs::read(td.path().join("b.txt")).unwrap();
        assert_eq!(b, b"world!");
    }

    #[test]
    fn path_traversal_refused() {
        let tar = build_tar(&[("../escape.txt", b"bad")]);
        let td = TempDir::new("vetpkg-tar").unwrap();
        let r = extract_tar(&tar, td.path());
        assert!(r.is_err());
    }

    #[test]
    fn pax_path_record_parses() {
        let body = b"38 path=long-name-from-pax/example.js\n";
        assert_eq!(
            parse_pax_path(body),
            Some("long-name-from-pax/example.js".to_string())
        );
    }
}
