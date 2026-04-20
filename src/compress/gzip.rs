use super::deflate;

pub fn gunzip(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 18 {
        return Err("gzip input too small".into());
    }
    if data[0..2] != [0x1f, 0x8b] {
        return Err("not a gzip stream".into());
    }
    if data[2] != 8 {
        return Err("gzip method is not DEFLATE".into());
    }
    let flags = data[3];
    let mut pos = 10;
    if flags & 0x04 != 0 {
        if pos + 2 > data.len() {
            return Err("gzip truncated (FEXTRA)".into());
        }
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
        if pos > data.len() {
            return Err("gzip truncated (FEXTRA body)".into());
        }
    }
    if flags & 0x08 != 0 {
        pos = skip_zero_terminated(data, pos)?;
    }
    if flags & 0x10 != 0 {
        pos = skip_zero_terminated(data, pos)?;
    }
    if flags & 0x02 != 0 {
        if pos + 2 > data.len() {
            return Err("gzip truncated (FHCRC)".into());
        }
        pos += 2;
    }
    if pos + 8 > data.len() {
        return Err("gzip truncated".into());
    }
    let payload = &data[pos..data.len() - 8];
    let raw = deflate::inflate(payload)?;
    let crc = u32::from_le_bytes(
        data[data.len() - 8..data.len() - 4]
            .try_into()
            .map_err(|_| "gzip crc slice".to_string())?,
    );
    let isize = u32::from_le_bytes(
        data[data.len() - 4..]
            .try_into()
            .map_err(|_| "gzip isize slice".to_string())?,
    );
    if (raw.len() as u32) != isize {
        return Err(format!(
            "gzip ISIZE mismatch: expected {} got {}",
            isize,
            raw.len()
        ));
    }
    if crc32(&raw) != crc {
        return Err("gzip CRC32 mismatch".into());
    }
    Ok(raw)
}

fn skip_zero_terminated(data: &[u8], mut pos: usize) -> Result<usize, String> {
    while pos < data.len() {
        if data[pos] == 0 {
            return Ok(pos + 1);
        }
        pos += 1;
    }
    Err("gzip truncated (FNAME/FCOMMENT)".into())
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for n in 0..256u32 {
        let mut c = n;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb88320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        table[n as usize] = c;
    }
    let mut c = 0xffff_ffffu32;
    for b in data {
        c = table[((c ^ *b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xffff_ffff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"abc"), 0x352441c2);
    }

    #[test]
    fn rejects_non_gzip() {
        let data = vec![0u8; 32];
        assert!(gunzip(&data).is_err());
    }

    #[test]
    fn rejects_non_deflate_method() {
        let mut data = vec![0x1f, 0x8b, 0x07];
        data.extend_from_slice(&[0u8; 32]);
        assert!(gunzip(&data).is_err());
    }

    #[test]
    fn gunzip_real_gzip_output() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        if Command::new("gzip")
            .arg("--version")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            eprintln!("skipping: gzip not on PATH");
            return;
        }
        let payload = b"vetpkg gzip end-to-end test payload \
                        with some repeated repeated repeated repeated content\n";
        let mut child = Command::new("gzip")
            .arg("-c")
            .arg("-n")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(payload).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        let decoded = gunzip(&out.stdout).unwrap();
        assert_eq!(decoded, payload);
    }
}
