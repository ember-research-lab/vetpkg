use crate::json::{parse, JsonValue};
use crate::platform::{is_safe_header_value, is_safe_url, resolve_curl, sanitize_curl_env};
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
    let mut cmd = Command::new(curl);
    sanitize_curl_env(&mut cmd);
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

pub fn fetch_json(
    url: &str,
    headers: &[(&str, &str)],
    timeout_secs: u32,
) -> Result<JsonValue, String> {
    let resp = fetch(url, headers, timeout_secs, &[])?;
    if resp.status >= 400 {
        return Err(format!("upstream {url} returned HTTP {}", resp.status));
    }
    let body =
        std::str::from_utf8(&resp.body).map_err(|_| "upstream body not utf-8".to_string())?;
    parse(body).map_err(|e| format!("upstream body parse error: {e}"))
}

pub fn post_json(
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    timeout_secs: u32,
) -> Result<JsonValue, String> {
    let extra = [
        ("-X".to_string(), "POST".to_string()),
        ("--data-binary".to_string(), "@-".to_string()),
    ];
    let resp = fetch_with_stdin(url, headers, timeout_secs, &extra, body)?;
    if resp.status >= 400 {
        return Err(format!("upstream {url} returned HTTP {}", resp.status));
    }
    let body_s =
        std::str::from_utf8(&resp.body).map_err(|_| "upstream body not utf-8".to_string())?;
    parse(body_s).map_err(|e| format!("upstream body parse error: {e}"))
}

fn fetch(
    url: &str,
    headers: &[(&str, &str)],
    timeout_secs: u32,
    extra_args: &[(String, String)],
) -> Result<HttpClientResponse, String> {
    if is_localhost_http(url) {
        let (host, port, path) = split_localhost_http_url(url)?;
        return http_get_plain_local(&host, port, &path, headers);
    }
    enforce_external_network_guard(url)?;
    http_get_via_curl(url, headers, timeout_secs, extra_args, None)
}

fn fetch_with_stdin(
    url: &str,
    headers: &[(&str, &str)],
    timeout_secs: u32,
    extra_args: &[(String, String)],
    body: &[u8],
) -> Result<HttpClientResponse, String> {
    if is_localhost_http(url) {
        let (host, port, path) = split_localhost_http_url(url)?;
        return http_post_plain_local(&host, port, &path, headers, body);
    }
    enforce_external_network_guard(url)?;
    http_get_via_curl(url, headers, timeout_secs, extra_args, Some(body))
}

fn http_get_via_curl(
    url: &str,
    headers: &[(&str, &str)],
    timeout_secs: u32,
    extra_args: &[(String, String)],
    stdin_body: Option<&[u8]>,
) -> Result<HttpClientResponse, String> {
    validate_url(url)?;
    for (k, v) in headers {
        validate_header(k, v)?;
    }
    let curl = resolve_curl()?;
    let mut cmd = Command::new(curl);
    sanitize_curl_env(&mut cmd);
    cmd.arg("-sS")
        .arg("-i")
        .arg("-L")
        .arg("--max-redirs")
        .arg("5")
        .arg("--connect-timeout")
        .arg("10")
        .arg("--max-time")
        .arg(timeout_secs.to_string());
    for (a, b) in extra_args {
        cmd.arg(a).arg(b);
    }
    for (k, v) in headers {
        cmd.arg("-H").arg(format!("{}: {}", k, v));
    }
    cmd.arg("--").arg(url);
    if stdin_body.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("curl spawn failed: {e}"))?;
    if let Some(body) = stdin_body {
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(body)
                .map_err(|e| format!("curl stdin write: {e}"))?;
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("curl wait: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("curl exit {:?}: {}", out.status.code(), err));
    }
    parse_curl_output(&out.stdout)
}

fn enforce_external_network_guard(url: &str) -> Result<(), String> {
    if std::env::var_os("VETPKG_NO_EXTERNAL_NETWORK").is_some() {
        return Err(format!(
            "VETPKG_NO_EXTERNAL_NETWORK is set; refusing to contact {url}"
        ));
    }
    Ok(())
}

fn is_localhost_http(url: &str) -> bool {
    url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost")
        || url.starts_with("http://[::1]")
}

fn split_localhost_http_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "expected http:// prefix".to_string())?;
    let (hostport, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let hostport = hostport
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(hostport);
    let (host, port) = match hostport.rfind(':') {
        Some(idx) => {
            let host = &hostport[..idx];
            let port: u16 = hostport[idx + 1..]
                .parse()
                .map_err(|_| format!("bad port in {url}"))?;
            (host.to_string(), port)
        }
        None => (hostport.to_string(), 80),
    };
    Ok((host, port, path.to_string()))
}

pub fn http_post_plain_local(
    host: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<HttpClientResponse, String> {
    if host != "127.0.0.1" && host != "localhost" && host != "::1" {
        return Err("plain connector only for localhost".into());
    }
    let mut stream = TcpStream::connect((host, port)).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("timeout: {e}"))?;
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        validate_header(k, v)?;
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    stream
        .write_all(body)
        .map_err(|e| format!("write body: {e}"))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    parse_curl_output(&buf)
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

    #[test]
    fn split_localhost_url_parses_correctly() {
        let (h, p, path) = split_localhost_http_url("http://127.0.0.1:9451/npm/express").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 9451);
        assert_eq!(path, "/npm/express");

        let (h, p, path) = split_localhost_http_url("http://localhost:80").unwrap();
        assert_eq!(h, "localhost");
        assert_eq!(p, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn classifies_localhost_vs_external() {
        assert!(is_localhost_http("http://127.0.0.1:9451/x"));
        assert!(is_localhost_http("http://localhost/x"));
        assert!(is_localhost_http("http://[::1]:9451/x"));
        assert!(!is_localhost_http("https://registry.npmjs.org"));
        assert!(!is_localhost_http("http://registry.npmjs.org"));
    }

    #[test]
    fn fetch_json_on_localhost_parses_response() {
        let port = spawn_mock(r#"{"name":"ok","count":3}"#);
        let url = format!("http://127.0.0.1:{port}/");
        let v = fetch_json(&url, &[], 5).unwrap();
        assert_eq!(v.get("name").unwrap().as_str(), Some("ok"));
        assert_eq!(v.get("count").unwrap().as_f64(), Some(3.0));
    }

    #[test]
    fn fetch_json_surfaces_http_error_status() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut _buf = [0u8; 1024];
            let _ = s.read(&mut _buf);
            s.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ).unwrap();
        });
        let url = format!("http://127.0.0.1:{port}/");
        let r = fetch_json(&url, &[], 5);
        assert!(r.is_err());
    }

    #[test]
    fn external_network_guard_blocks_when_set() {
        std::env::set_var("VETPKG_NO_EXTERNAL_NETWORK", "1");
        let r = fetch("https://registry.npmjs.org/express", &[], 5, &[]);
        std::env::remove_var("VETPKG_NO_EXTERNAL_NETWORK");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("VETPKG_NO_EXTERNAL_NETWORK"));
    }

    #[test]
    fn post_json_round_trips_on_localhost() {
        use std::net::{Shutdown, TcpListener};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let body = br#"{"echo":"ok"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
            s.write_all(body).unwrap();
            let _ = s.shutdown(Shutdown::Write);
            let mut discard = Vec::new();
            let _ = s.read_to_end(&mut discard);
        });
        let url = format!("http://127.0.0.1:{port}/v1/query");
        let v = post_json(&url, &[("Content-Type", "application/json")], b"{}", 5).unwrap();
        assert_eq!(v.get("echo").unwrap().as_str(), Some("ok"));
    }
}
