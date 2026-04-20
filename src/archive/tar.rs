use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const BLOCK: usize = 512;

/// Hard caps on tarball extraction. A legitimate npm package (even sharp
/// with its prebuilds) has under 10 000 entries and weighs a few dozen MB.
/// These ceilings protect against tarbombs without affecting real traffic.
pub const MAX_TAR_ENTRIES: usize = 100_000;
pub const MAX_TAR_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_TAR_ENTRY_BYTES: u64 = 256 * 1024 * 1024;

pub fn extract_tar(data: &[u8], dest: &Path) -> Result<Vec<PathBuf>, String> {
    fs::create_dir_all(dest).map_err(|e| format!("create {:?}: {e}", dest))?;
    let dest = dest
        .canonicalize()
        .map_err(|e| format!("canon {:?}: {e}", dest))?;

    let mut out = Vec::new();
    let mut pos = 0;
    let mut long_name: Option<String> = None;
    let mut entries_seen: usize = 0;
    let mut total_bytes: u64 = 0;

    while pos + BLOCK <= data.len() {
        let header = &data[pos..pos + BLOCK];
        if header.iter().all(|b| *b == 0) {
            pos += BLOCK;
            continue;
        }
        entries_seen += 1;
        if entries_seen > MAX_TAR_ENTRIES {
            return Err(format!(
                "tar entries exceed {MAX_TAR_ENTRIES} — refusing tarbomb"
            ));
        }
        let size = parse_octal(&header[124..136])?;
        if size > MAX_TAR_ENTRY_BYTES {
            return Err(format!(
                "tar entry {size} bytes exceeds {MAX_TAR_ENTRY_BYTES}"
            ));
        }
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_TAR_TOTAL_BYTES {
            return Err(format!(
                "tar total bytes exceed {MAX_TAR_TOTAL_BYTES} — refusing tarbomb"
            ));
        }
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

        // `size` is bounded above by MAX_TAR_ENTRY_BYTES (256 MB) so the
        // `as usize` cast is safe on 32-bit targets too (256 MB < 2 GB).
        pos += BLOCK;
        let body_end = pos
            .checked_add(size as usize)
            .ok_or_else(|| "tar body_end overflow".to_string())?;
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
            // b'1' hardlink, b'2' symlink, b'3'/b'4' char/block device,
            // b'6' FIFO — silently dropped. A security-focused extraction
            // refuses to materialize these types; legitimate npm tarballs
            // never contain them.
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
    // PAX record format (POSIX.1-2001): "<len> <key>=<value>\n"
    // where <len> is the total byte length of the record INCLUDING the
    // length digits, the space, and the trailing newline. A malicious
    // tarball can set a `len` so small or so large that naïve slicing
    // panics — every bounds check below is load-bearing.
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
            // `len` must be at least space + 2 (the space itself plus the
            // trailing newline) and must not exceed the remaining bytes;
            // must also be large enough for s[space+1..len-1] to be a
            // valid (possibly empty) range.
            if len > s.len() || space + 2 > len {
                return None;
            }
            // Guard against non-char boundary panics in case of a
            // multi-byte UTF-8 character straddling the declared end.
            if !s.is_char_boundary(space + 1) || !s.is_char_boundary(len - 1) {
                return None;
            }
            // Strictly require the record to end with the canonical '\n'
            // to prevent adjacent-record smuggling via miscounted len.
            if s.as_bytes()[len - 1] != b'\n' {
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

    #[test]
    fn pax_record_with_corrupt_length_does_not_panic() {
        // `len` claimed as 2, but a real record needs at least space+2.
        // Before the fix, `s[space+1..len-1]` would compute `[2..1]` and
        // panic. With the fix it yields None and terminates iteration.
        let body = b"2 ab\n";
        assert_eq!(parse_pax_path(body), None);
    }

    #[test]
    fn pax_record_without_trailing_newline_rejected() {
        // `len=3` points at 'b' (not '\n') — defeats the smuggling path
        // where a malicious tar appends a second path= record.
        let body = b"3 abc";
        assert_eq!(parse_pax_path(body), None);
    }

    #[test]
    fn tar_entry_count_cap_enforced() {
        // Construct a tar with MAX_TAR_ENTRIES + 5 empty files. Whichever
        // cap fires first is acceptable — the point is that the extractor
        // refuses to run past its stated limits, not which limit wins.
        let entries: Vec<(&str, &[u8])> = (0..MAX_TAR_ENTRIES + 5)
            .map(|_| ("x", b"" as &[u8]))
            .collect();
        let tar = build_tar(&entries);
        let td = TempDir::new("vetpkg-tar-bomb").unwrap();
        let err = extract_tar(&tar, td.path()).unwrap_err();
        assert!(
            err.contains("MAX_TAR_ENTRIES") || err.contains("tarbomb") || err.contains("total"),
            "expected tarbomb rejection, got: {err}"
        );
    }
}
