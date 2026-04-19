//! Pure-Rust DEFLATE (RFC 1951) decompression. Decompression only.
//!
//! Bit order reference: within a byte, bits are consumed LSB first (so the
//! first bit of the stream lives at bit 0 of byte 0). Huffman codes are
//! packed MSB-first: reconstruct a code by shifting left and OR-ing each
//! successive bit read from the stream. Length/distance extra bits are
//! packed LSB-first (plain N-bit integer as read).

const MAX_INPUT: usize = 512 * 1024 * 1024;
const MAX_OUTPUT: usize = 512 * 1024 * 1024;

pub fn inflate(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() > MAX_INPUT {
        return Err(format!("deflate input too large: {} bytes", data.len()));
    }
    let mut r = BitReader::new(data);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let bfinal = r.read_bits(1)?;
        let btype = r.read_bits(2)?;
        match btype {
            0 => inflate_stored(&mut r, &mut out)?,
            1 => inflate_fixed(&mut r, &mut out)?,
            2 => inflate_dynamic(&mut r, &mut out)?,
            _ => return Err("deflate: reserved block type 3".into()),
        }
        if out.len() > MAX_OUTPUT {
            return Err(format!("deflate output exceeded {MAX_OUTPUT} bytes"));
        }
        if bfinal == 1 {
            break;
        }
    }
    Ok(out)
}

pub fn inflate_available() -> bool {
    true
}

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bits(&mut self, n: u8) -> Result<u32, String> {
        debug_assert!(n <= 32);
        let mut result = 0u32;
        for i in 0..n {
            if self.byte_pos >= self.data.len() {
                return Err("deflate: unexpected EOF reading bits".into());
            }
            let bit = (self.data[self.byte_pos] >> self.bit_pos) & 1;
            result |= (bit as u32) << i;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }
        Ok(result)
    }

    fn align_to_byte(&mut self) {
        if self.bit_pos != 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }

    fn read_u16_le_aligned(&mut self) -> Result<u16, String> {
        self.align_to_byte();
        if self.byte_pos + 2 > self.data.len() {
            return Err("deflate: truncated u16 in stored block".into());
        }
        let lo = self.data[self.byte_pos] as u16;
        let hi = self.data[self.byte_pos + 1] as u16;
        self.byte_pos += 2;
        Ok(lo | (hi << 8))
    }

    fn read_raw_bytes_aligned(&mut self, n: usize) -> Result<&'a [u8], String> {
        debug_assert_eq!(self.bit_pos, 0);
        if self.byte_pos + n > self.data.len() {
            return Err("deflate: truncated stored block payload".into());
        }
        let slice = &self.data[self.byte_pos..self.byte_pos + n];
        self.byte_pos += n;
        Ok(slice)
    }
}

fn inflate_stored(r: &mut BitReader, out: &mut Vec<u8>) -> Result<(), String> {
    let len = r.read_u16_le_aligned()? as usize;
    let nlen = r.read_u16_le_aligned()?;
    if (len as u16) != !nlen {
        return Err(format!(
            "deflate: stored block LEN/NLEN mismatch ({} vs {})",
            len, nlen
        ));
    }
    let slice = r.read_raw_bytes_aligned(len)?;
    out.extend_from_slice(slice);
    Ok(())
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

const CODE_LEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

struct HuffmanTable {
    counts: [u32; 16],
    symbols: Vec<u16>,
    max_len: u8,
}

impl HuffmanTable {
    fn build(code_lengths: &[u8]) -> Result<Self, String> {
        let mut counts = [0u32; 16];
        for &len in code_lengths {
            if len > 15 {
                return Err(format!("deflate: code length {len} exceeds 15"));
            }
            counts[len as usize] += 1;
        }
        counts[0] = 0;

        let total_nonzero: u32 = counts.iter().sum();
        if total_nonzero > 0 {
            let kraft: u64 = counts
                .iter()
                .enumerate()
                .skip(1)
                .take(15)
                .map(|(len, &c)| (c as u64) << (15 - len))
                .sum();
            let budget: u64 = 1 << 15;
            if kraft > budget {
                return Err("deflate: oversubscribed Huffman code".into());
            }
        }

        let mut offsets = [0usize; 16];
        let mut offset = 0usize;
        for len in 1..=15 {
            offsets[len] = offset;
            offset += counts[len] as usize;
        }
        let mut symbols = vec![0u16; total_nonzero.max(1) as usize];
        let mut used = [0usize; 16];
        for (sym, &len) in code_lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let len = len as usize;
            let slot = offsets[len] + used[len];
            if slot >= symbols.len() {
                return Err("deflate: Huffman table overflow".into());
            }
            symbols[slot] = sym as u16;
            used[len] += 1;
        }

        let max_len = (1..=15u8)
            .rev()
            .find(|l| counts[*l as usize] > 0)
            .unwrap_or(0);

        Ok(Self {
            counts,
            symbols,
            max_len,
        })
    }

    fn decode(&self, r: &mut BitReader) -> Result<u16, String> {
        if self.max_len == 0 {
            return Err("deflate: empty Huffman table".into());
        }
        let mut code = 0u32;
        let mut first = 0u32;
        let mut index = 0usize;
        for len in 1..=self.max_len {
            let bit = r.read_bits(1)?;
            code = (code << 1) | bit;
            let count = self.counts[len as usize];
            if code < first + count {
                let slot = index + (code - first) as usize;
                if slot >= self.symbols.len() {
                    return Err("deflate: Huffman decode out of range".into());
                }
                return Ok(self.symbols[slot]);
            }
            index += count as usize;
            first = (first + count) << 1;
        }
        Err("deflate: Huffman code exceeded 15 bits".into())
    }
}

fn fixed_literal_lengths() -> [u8; 288] {
    let mut out = [0u8; 288];
    out[0..=143].fill(8);
    out[144..=255].fill(9);
    out[256..=279].fill(7);
    out[280..=287].fill(8);
    out
}

fn fixed_dist_lengths() -> [u8; 30] {
    [5u8; 30]
}

fn inflate_fixed(r: &mut BitReader, out: &mut Vec<u8>) -> Result<(), String> {
    let lit = HuffmanTable::build(&fixed_literal_lengths())?;
    let dist = HuffmanTable::build(&fixed_dist_lengths())?;
    inflate_block(r, out, &lit, &dist)
}

fn inflate_dynamic(r: &mut BitReader, out: &mut Vec<u8>) -> Result<(), String> {
    let hlit = r.read_bits(5)? as usize + 257;
    let hdist = r.read_bits(5)? as usize + 1;
    let hclen = r.read_bits(4)? as usize + 4;
    if hlit > 286 {
        return Err(format!("deflate: HLIT {hlit} > 286"));
    }
    if hdist > 30 {
        return Err(format!("deflate: HDIST {hdist} > 30"));
    }

    let mut code_len_lengths = [0u8; 19];
    for i in 0..hclen {
        code_len_lengths[CODE_LEN_ORDER[i]] = r.read_bits(3)? as u8;
    }
    let code_len_table = HuffmanTable::build(&code_len_lengths)?;

    let total = hlit + hdist;
    let mut lengths = vec![0u8; total];
    let mut i = 0;
    while i < total {
        let sym = code_len_table.decode(r)?;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                if i == 0 {
                    return Err("deflate: code 16 at start of code-length stream".into());
                }
                let repeat = r.read_bits(2)? as usize + 3;
                let prev = lengths[i - 1];
                for _ in 0..repeat {
                    if i >= total {
                        return Err("deflate: code 16 overflows".into());
                    }
                    lengths[i] = prev;
                    i += 1;
                }
            }
            17 => {
                let repeat = r.read_bits(3)? as usize + 3;
                for _ in 0..repeat {
                    if i >= total {
                        return Err("deflate: code 17 overflows".into());
                    }
                    lengths[i] = 0;
                    i += 1;
                }
            }
            18 => {
                let repeat = r.read_bits(7)? as usize + 11;
                for _ in 0..repeat {
                    if i >= total {
                        return Err("deflate: code 18 overflows".into());
                    }
                    lengths[i] = 0;
                    i += 1;
                }
            }
            _ => return Err(format!("deflate: invalid code-length symbol {sym}")),
        }
    }

    let lit = HuffmanTable::build(&lengths[..hlit])?;
    let dist = HuffmanTable::build(&lengths[hlit..])?;
    inflate_block(r, out, &lit, &dist)
}

fn inflate_block(
    r: &mut BitReader,
    out: &mut Vec<u8>,
    lit: &HuffmanTable,
    dist: &HuffmanTable,
) -> Result<(), String> {
    loop {
        let sym = lit.decode(r)?;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Ok(()),
            257..=285 => {
                let idx = (sym - 257) as usize;
                let mut length = LENGTH_BASE[idx] as usize;
                let extra = LENGTH_EXTRA[idx];
                if extra > 0 {
                    length += r.read_bits(extra)? as usize;
                }
                let dsym = dist.decode(r)?;
                if dsym > 29 {
                    return Err(format!("deflate: distance symbol {dsym} > 29"));
                }
                let didx = dsym as usize;
                let mut distance = DIST_BASE[didx] as usize;
                let dextra = DIST_EXTRA[didx];
                if dextra > 0 {
                    distance += r.read_bits(dextra)? as usize;
                }
                if distance == 0 || distance > out.len() {
                    return Err(format!(
                        "deflate: distance {} out of window (have {} bytes)",
                        distance,
                        out.len()
                    ));
                }
                let start = out.len() - distance;
                for k in 0..length {
                    let b = out[start + k];
                    out.push(b);
                }
            }
            _ => return Err(format!("deflate: invalid literal/length symbol {sym}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored_block(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x01);
        let len = bytes.len() as u16;
        let nlen = !len;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn decompresses_stored_block() {
        let payload = b"hello world";
        let stream = stored_block(payload);
        let got = inflate(&stream).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn stored_block_len_nlen_mismatch_errors() {
        let mut stream = stored_block(b"abcd");
        stream[3] ^= 0x01;
        assert!(inflate(&stream).is_err());
    }

    #[test]
    fn availability_flag_true() {
        assert!(inflate_available());
    }

    #[test]
    fn reports_reserved_block_type() {
        let bad = vec![0b0000_0111u8];
        let err = inflate(&bad).unwrap_err();
        assert!(err.contains("reserved"));
    }

    #[test]
    fn huffman_table_detects_oversubscribe() {
        let mut lens = vec![0u8; 4];
        lens[0] = 1;
        lens[1] = 1;
        lens[2] = 1;
        assert!(HuffmanTable::build(&lens).is_err());
    }

    #[test]
    fn decompresses_real_gzip_from_command() {
        if !has_gzip_on_path() {
            eprintln!("skipping: gzip not on PATH");
            return;
        }
        let payload = b"The quick brown fox jumps over the lazy dog.\n\
                        The quick brown fox jumps over the lazy dog.\n\
                        The quick brown fox jumps over the lazy dog.\n\
                        The quick brown fox jumps over the lazy dog.\n";
        let gzipped = gzip_via_command(payload);
        let raw_deflate = strip_gzip_frame(&gzipped);
        let decompressed = inflate(&raw_deflate).unwrap();
        assert_eq!(decompressed, payload);
    }

    fn has_gzip_on_path() -> bool {
        std::process::Command::new("gzip")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn gzip_via_command(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new("gzip")
            .arg("-c")
            .arg("-n")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(data).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        out.stdout
    }

    fn strip_gzip_frame(data: &[u8]) -> Vec<u8> {
        assert_eq!(&data[0..2], &[0x1f, 0x8b]);
        assert_eq!(data[2], 8);
        let flags = data[3];
        let mut pos = 10usize;
        if flags & 0x04 != 0 {
            let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2 + xlen;
        }
        if flags & 0x08 != 0 {
            while data[pos] != 0 {
                pos += 1;
            }
            pos += 1;
        }
        if flags & 0x10 != 0 {
            while data[pos] != 0 {
                pos += 1;
            }
            pos += 1;
        }
        if flags & 0x02 != 0 {
            pos += 2;
        }
        data[pos..data.len() - 8].to_vec()
    }
}
