use crate::platform::{is_safe_header_value, is_safe_url, resolve_curl};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HttpClientResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpClientResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == n)
            .map(|(_, v)| v.as_str())
    }
}

pub fn http_get(url: &str, headers: &[(&str, &str)]) -> Result<HttpClientResponse, String> {
    http_get_with_timeout(url, headers, 30)
}

pub fn http_get_with_timeout(
    url: &str,
    headers: &[(&str, &str)],
    timeout_secs: u32,
) -> Result<HttpClientResponse, String> {
    validate_url(url)?;
    for (k, v) in headers {
        validate_header(k, v)?;
    }
    let curl = resolve_curl()?;
    let mut cmd = Command::new(&curl);
    cmd.arg("-sS")
        .arg("-i")
        .arg("-L")
        .arg("--max-redirs")
        .arg("5")
        .arg("--connect-timeout")
        .arg("10")
        .arg("--max-time")
        .arg(timeout_secs.to_string());
    for (k, v) in headers {
        cmd.arg("-H").arg(format!("{}: {}", k, v));
    }
    cmd.arg("--").arg(url);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let out = cmd
        .output()
        .map_err(|e| format!("curl spawn failed: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("curl exit {:?}: {}", out.status.code(), err));
    }
    parse_curl_output(&out.stdout)
}

fn validate_url(url: &str) -> Result<(), String> {
    if !is_safe_url(url) {
        return Err(format!("refusing unsafe URL: {url:?}"));
    }
    Ok(())
}

fn validate_header(k: &str, v: &str) -> Result<(), String> {
    if !is_safe_header_value(k) || !is_safe_header_value(v) {
        return Err("refusing header with CR/LF/NUL".into());
    }
    if k.contains(':') {
        return Err("header name cannot contain ':'".into());
    }
    Ok(())
}

fn parse_curl_output(out: &[u8]) -> Result<HttpClientResponse, String> {
    let mut pos = 0;
    loop {
        let (status, headers, header_end) = parse_response_head(out, pos)?;
        pos = header_end;
        let is_100 = status == 100;
        let is_redirect = (300..400).contains(&status);
        let peek_next = out[pos..].starts_with(b"HTTP/");
        if (is_100 || is_redirect) && peek_next {
            continue;
        }
        let body = out[pos..].to_vec();
        return Ok(HttpClientResponse {
            status,
            headers,
            body,
        });
    }
}

type ResponseHead = (u16, Vec<(String, String)>, usize);

fn parse_response_head(out: &[u8], start: usize) -> Result<ResponseHead, String> {
    let end = find_double_crlf(&out[start..])
        .map(|p| start + p + 4)
        .ok_or_else(|| "curl output missing header terminator".to_string())?;
    let head = std::str::from_utf8(&out[start..end - 4])
        .map_err(|_| "curl output headers not utf-8".to_string())?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "empty status line".to_string())?;
    let status = parse_status_line(status_line)?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some(colon) = line.find(':') {
            headers.push((
                line[..colon].trim().to_string(),
                line[colon + 1..].trim().to_string(),
            ));
        }
    }
    Ok((status, headers, end))
}

fn find_double_crlf(s: &[u8]) -> Option<usize> {
    s.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status_line(line: &str) -> Result<u16, String> {
    let mut parts = line.split_whitespace();
    let _v = parts.next().ok_or_else(|| "no version".to_string())?;
    let code = parts.next().ok_or_else(|| "no status code".to_string())?;
    code.parse().map_err(|_| format!("bad status: {line}"))
}

pub fn http_get_plain_local(
    host: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<HttpClientResponse, String> {
    if host != "127.0.0.1" && host != "localhost" && host != "::1" {
        return Err("plain connector only for localhost".into());
    }
    let mut stream = TcpStream::connect((host, port)).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("timeout: {e}"))?;
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (k, v) in headers {
        validate_header(k, v)?;
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    parse_curl_output(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn spawn_mock(body: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            s.write_all(resp.as_bytes()).unwrap();
        });
        port
    }

    #[test]
    fn plain_localhost_get_works() {
        let port = spawn_mock("hello");
        let r = http_get_plain_local("127.0.0.1", port, "/", &[]).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(&r.body, b"hello");
    }

    #[test]
    fn rejects_unsafe_url() {
        let r = http_get("file:///etc/passwd", &[]);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_crlf_in_header() {
        assert!(validate_header("X", "a\r\nSet-Cookie: bad").is_err());
    }

    #[test]
    fn parses_multi_phase_with_redirect() {
        let out = b"HTTP/1.1 301 Moved\r\nLocation: /new\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        let r = parse_curl_output(out).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
    }
}
