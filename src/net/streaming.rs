//! Streaming forward for tarball passthrough.
//!
//! Given an upstream URL and a writable sink (typically a client TcpStream),
//! fetches the upstream body and pipes it to the sink in fixed-size chunks,
//! bounding memory usage at O(chunk_size) regardless of tarball size.
//!
//! For localhost HTTP (tests + local mock), goes through a direct TcpStream.
//! For HTTPS, spawns curl with piped stdout and pumps its stdout → sink.

use crate::platform::{is_safe_url, resolve_curl, sanitize_curl_env};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

pub const STREAM_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct StreamStats {
    pub bytes: u64,
    pub upstream_status: u16,
}

pub fn stream_forward<W: Write>(
    url: &str,
    writer: &mut W,
    timeout_secs: u32,
) -> Result<StreamStats, String> {
    if url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
        || url.starts_with("http://[::1]")
    {
        return stream_from_localhost(url, writer);
    }
    stream_from_curl(url, writer, timeout_secs)
}

fn stream_from_localhost<W: Write>(url: &str, writer: &mut W) -> Result<StreamStats, String> {
    let rest = url.strip_prefix("http://").ok_or("bad url scheme")?;
    let (hostport, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let hostport = hostport
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(hostport);
    let (host, port) = match hostport.rfind(':') {
        Some(idx) => (
            hostport[..idx].to_string(),
            hostport[idx + 1..]
                .parse::<u16>()
                .map_err(|_| format!("bad port in {url}"))?,
        ),
        None => (hostport.to_string(), 80),
    };
    let mut stream =
        TcpStream::connect((host.as_str(), port)).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;

    let (status, body_reader) = read_response_head(&mut stream)?;
    pump(body_reader, writer, status)
}

fn stream_from_curl<W: Write>(
    url: &str,
    writer: &mut W,
    timeout_secs: u32,
) -> Result<StreamStats, String> {
    if !is_safe_url(url) {
        return Err("refusing unsafe URL".into());
    }
    if std::env::var_os("VETPKG_NO_EXTERNAL_NETWORK").is_some() {
        return Err(format!(
            "VETPKG_NO_EXTERNAL_NETWORK is set; refusing to contact {url}"
        ));
    }
    let curl = resolve_curl()?;
    let mut cmd = Command::new(curl);
    sanitize_curl_env(&mut cmd);
    let mut child = cmd
        .arg("-sS")
        .arg("-i")
        .arg("-L")
        .arg("--max-redirs")
        .arg("5")
        .arg("--connect-timeout")
        .arg("10")
        .arg("--max-time")
        .arg(timeout_secs.to_string())
        .arg("--")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("curl spawn failed: {e}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "curl stdout closed".to_string())?;
    let mut reader = std::io::BufReader::new(stdout);
    let (status, body_rest) = read_response_head(&mut reader)?;
    let stats = pump(body_rest, writer, status)?;
    let _ = child.wait();
    Ok(stats)
}

struct BodyReader<R: Read> {
    carried: Vec<u8>,
    inner: R,
}

fn read_response_head<R: Read>(mut reader: R) -> Result<(u16, BodyReader<R>), String> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut scratch = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut scratch)
            .map_err(|e| format!("upstream read: {e}"))?;
        if n == 0 {
            return Err("upstream closed before headers".into());
        }
        buf.extend_from_slice(&scratch[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            let head_end = pos + 4;
            let head = &buf[..pos];
            let mut iter = head.split(|b| *b == b'\n');
            let status_line = iter.next().unwrap_or(&[]);
            let status_line = std::str::from_utf8(status_line)
                .map_err(|_| "non-utf8 status line".to_string())?
                .trim_end_matches('\r');
            let status = parse_status_code(status_line)?;
            let rest_bytes = buf[head_end..].to_vec();
            return Ok((
                status,
                BodyReader {
                    carried: rest_bytes,
                    inner: reader,
                },
            ));
        }
        if buf.len() > 256 * 1024 {
            return Err("response headers exceed 256KB".into());
        }
    }
}

fn find_double_crlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_code(line: &str) -> Result<u16, String> {
    let mut parts = line.split_whitespace();
    let _v = parts.next().ok_or_else(|| "no version".to_string())?;
    let code = parts.next().ok_or_else(|| "no status code".to_string())?;
    code.parse().map_err(|_| format!("bad status: {line}"))
}

fn pump<R: Read, W: Write>(
    mut body: BodyReader<R>,
    writer: &mut W,
    status: u16,
) -> Result<StreamStats, String> {
    // Security posture: body bytes are forwarded to the writer ONLY on a
    // 2xx upstream status. On any other status (redirects are followed
    // earlier by curl; what reaches us is the final status), we drain but
    // discard the body so the caller can report the actual error without
    // the client having received a partial success body.
    let forward = (200..300).contains(&status);
    let mut bytes: u64 = 0;
    if !body.carried.is_empty() {
        if forward {
            writer
                .write_all(&body.carried)
                .map_err(|e| format!("sink write: {e}"))?;
        }
        bytes += body.carried.len() as u64;
    }
    let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
    // Total payload cap — bytes cannot exceed MAX_FORWARD_BYTES even if
    // the upstream Content-Length (or chunked body) claims otherwise.
    const MAX_FORWARD_BYTES: u64 = 512 * 1024 * 1024;
    loop {
        let n = body
            .inner
            .read(&mut buf)
            .map_err(|e| format!("upstream read: {e}"))?;
        if n == 0 {
            break;
        }
        bytes = bytes.saturating_add(n as u64);
        if bytes > MAX_FORWARD_BYTES {
            return Err(format!(
                "upstream body exceeded MAX_FORWARD_BYTES ({MAX_FORWARD_BYTES})"
            ));
        }
        if forward {
            writer
                .write_all(&buf[..n])
                .map_err(|e| format!("sink write: {e}"))?;
        }
    }
    if forward {
        writer.flush().map_err(|e| format!("sink flush: {e}"))?;
    }
    Ok(StreamStats {
        bytes,
        upstream_status: status,
    })
}

pub fn write_http_ok_chunked_start<W: Write>(w: &mut W, content_type: &str) -> io::Result<()> {
    write!(w, "HTTP/1.1 200 OK\r\n")?;
    write!(w, "Content-Type: {}\r\n", content_type)?;
    write!(w, "Transfer-Encoding: chunked\r\n")?;
    write!(w, "Connection: close\r\n\r\n")?;
    Ok(())
}

pub fn write_chunk<W: Write>(w: &mut W, chunk: &[u8]) -> io::Result<()> {
    if chunk.is_empty() {
        return Ok(());
    }
    write!(w, "{:x}\r\n", chunk.len())?;
    w.write_all(chunk)?;
    write!(w, "\r\n")
}

pub fn write_chunked_end<W: Write>(w: &mut W) -> io::Result<()> {
    write!(w, "0\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn chunk_format_is_correct() {
        let mut out = Vec::new();
        write_http_ok_chunked_start(&mut out, "application/octet-stream").unwrap();
        write_chunk(&mut out, b"abcde").unwrap();
        write_chunked_end(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Transfer-Encoding: chunked\r\n"));
        assert!(s.contains("\r\n5\r\nabcde\r\n0\r\n\r\n"));
    }

    #[test]
    fn empty_chunk_is_skipped() {
        let mut out = Vec::new();
        write_chunk(&mut out, b"").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn pump_writes_all_bytes() {
        let body_bytes = vec![b'x'; 250_000];
        let mut sink: Vec<u8> = Vec::new();
        let body = BodyReader {
            carried: body_bytes[..1024].to_vec(),
            inner: Cursor::new(body_bytes[1024..].to_vec()),
        };
        let stats = pump(body, &mut sink, 200).unwrap();
        assert_eq!(stats.bytes as usize, 250_000);
        assert_eq!(sink.len(), 250_000);
        assert_eq!(stats.upstream_status, 200);
    }
}
