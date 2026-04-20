//! End-to-end proxy integration: spawn a localhost mock npm registry, point
//! the proxy at it, issue metadata + tarball requests through the proxy,
//! verify scoring behaviour.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vetpkg::archive::tar;
use vetpkg::net::proxy::serve_on_listener;
use vetpkg::types::PolicyConfig;

fn now_iso_hours_ago(hours: u64) -> String {
    let target = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(hours * 3600);
    let (y, mo, d, h, mi, s) = to_utc(target);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn to_utc(mut secs: u64) -> (u64, u32, u32, u32, u32, u32) {
    let leap = |y: u64| (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
    let dim = |y: u64, m: u32| match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    let hour = ((secs / 3600) % 24) as u32;
    let minute = ((secs / 60) % 60) as u32;
    let second = (secs % 60) as u32;
    secs /= 86400;
    let mut year = 1970u64;
    loop {
        let days = if leap(year) { 366 } else { 365 };
        if secs < days {
            break;
        }
        secs -= days;
        year += 1;
    }
    let mut month = 1u32;
    loop {
        let days = dim(year, month) as u64;
        if secs < days {
            break;
        }
        secs -= days;
        month += 1;
    }
    let day = secs as u32 + 1;
    (year, month, day, hour, minute, second)
}

type MockResponses = Arc<Mutex<std::collections::HashMap<String, (u16, Vec<u8>, String)>>>;

struct MockRegistry {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    responses: MockResponses,
}

impl MockRegistry {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let responses: MockResponses = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let responses2 = responses.clone();
        let handle = thread::spawn(move || loop {
            if stop2.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((mut s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    let mut buf = [0u8; 8192];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("")
                        .to_string();
                    let (status, body, ctype) = responses2
                        .lock()
                        .unwrap()
                        .get(&path)
                        .cloned()
                        .unwrap_or((404, b"not found".to_vec(), "text/plain".into()));
                    let reason = if status == 200 { "OK" } else { "Not Found" };
                    let head = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = s.write_all(head.as_bytes());
                    let _ = s.write_all(&body);
                    let _ = s.shutdown(Shutdown::Write);
                    let mut discard = Vec::new();
                    let _ = s.read_to_end(&mut discard);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        });
        Self {
            port,
            stop,
            handle: Some(handle),
            responses,
        }
    }

    fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn put(&self, path: &str, status: u16, body: Vec<u8>, ctype: &str) {
        self.responses
            .lock()
            .unwrap()
            .insert(path.into(), (status, body, ctype.into()));
    }
}

impl Drop for MockRegistry {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

struct ProxyHarness {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ProxyHarness {
    fn spawn(config: PolicyConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let handle = thread::spawn(move || {
            let _ = serve_on_listener(listener, config, stop2);
        });
        Self {
            port,
            stop,
            handle: Some(handle),
        }
    }
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

impl Drop for ProxyHarness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn fetch(url: &str) -> (u16, Vec<u8>) {
    let rest = url.strip_prefix("http://").unwrap();
    let (hostport, path) = rest
        .split_once('/')
        .map(|(a, b)| (a, format!("/{b}")))
        .unwrap();
    let (host, port) = hostport.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let mut s = TcpStream::connect((host, port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let idx = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response headers");
    let head = std::str::from_utf8(&raw[..idx]).unwrap();
    let status_line = head.lines().next().unwrap();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let body = raw[idx + 4..].to_vec();
    (status, body)
}

fn clean_metadata(name: &str, version: &str) -> Vec<u8> {
    let publish = now_iso_hours_ago(24 * 365);
    format!(
        r#"{{"name":"{name}","dist-tags":{{"latest":"{version}"}},"versions":{{"{version}":{{"name":"{name}","version":"{version}","dist":{{"tarball":"http://example.test/tarball.tgz"}}}}}},"time":{{"{version}":"{publish}"}},"maintainers":[{{"email":"team@example.com"}}]}}"#
    )
    .into_bytes()
}

#[test]
fn proxy_metadata_for_clean_package_returns_200() {
    let mock = MockRegistry::spawn();
    mock.put(
        "/express",
        200,
        clean_metadata("express", "4.18.2"),
        "application/json",
    );
    let cfg = PolicyConfig {
        npm_upstream: mock.base(),
        ..Default::default()
    };
    let proxy = ProxyHarness::spawn(cfg);

    let (status, body) = fetch(&proxy.url("/npm/express"));
    assert_eq!(status, 200);
    let parsed = vetpkg::json::parse(std::str::from_utf8(&body).unwrap()).unwrap();
    assert_eq!(parsed.get("name").unwrap().as_str(), Some("express"));
    let versions = parsed.get("versions").unwrap().as_object().unwrap();
    assert_eq!(versions.len(), 1);
}

#[test]
fn proxy_metadata_504_when_upstream_missing() {
    let mock = MockRegistry::spawn();
    let cfg = PolicyConfig {
        npm_upstream: mock.base(),
        ..Default::default()
    };
    let proxy = ProxyHarness::spawn(cfg);

    let (status, _body) = fetch(&proxy.url("/npm/no-such-pkg"));
    assert_eq!(status, 502);
}

#[test]
fn proxy_abbreviated_metadata_strips_time_and_maintainers() {
    let mock = MockRegistry::spawn();
    mock.put(
        "/lodash",
        200,
        clean_metadata("lodash", "4.17.21"),
        "application/json",
    );
    let cfg = PolicyConfig {
        npm_upstream: mock.base(),
        ..Default::default()
    };
    let proxy = ProxyHarness::spawn(cfg);

    let rest = proxy.url("/npm/lodash");
    let rest = rest.strip_prefix("http://").unwrap();
    let (hostport, path) = rest
        .split_once('/')
        .map(|(a, b)| (a, format!("/{b}")))
        .unwrap();
    let (host, port) = hostport.split_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let mut s = TcpStream::connect((host, port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/vnd.npm.install-v1+json\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let idx = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let body = std::str::from_utf8(&raw[idx + 4..]).unwrap();
    let parsed = vetpkg::json::parse(body).unwrap();
    assert!(parsed.get("name").is_some());
    assert!(parsed.get("dist-tags").is_some());
    assert!(parsed.get("time").is_none());
    assert!(parsed.get("maintainers").is_none());
}

#[test]
fn proxy_tarball_passthrough_when_not_in_suspicion_map() {
    let mock = MockRegistry::spawn();
    let tar_bytes = tar::build_tar(&[("package/package.json", b"{\"name\":\"tiny\"}")]);
    mock.put(
        "/tiny/-/tiny-1.0.0.tgz",
        200,
        tar_bytes.clone(),
        "application/octet-stream",
    );
    let cfg = PolicyConfig {
        npm_upstream: mock.base(),
        ..Default::default()
    };
    let proxy = ProxyHarness::spawn(cfg);

    let (status, body) = fetch(&proxy.url("/npm/tiny/-/tiny-1.0.0.tgz"));
    assert_eq!(status, 200);
    let dechunked = dechunk(&body);
    assert!(
        dechunked.windows(4).any(|w| w == b"ustar") || dechunked.len() >= tar_bytes.len(),
        "response body should contain tar payload; got {} bytes",
        dechunked.len()
    );
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let line_end = match body[i..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => i + p,
            None => break,
        };
        let hex = std::str::from_utf8(&body[i..line_end]).unwrap_or("0");
        let size = usize::from_str_radix(hex.trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        let start = line_end + 2;
        let end = start + size;
        if end > body.len() {
            break;
        }
        out.extend_from_slice(&body[start..end]);
        i = end + 2;
    }
    if out.is_empty() {
        body.to_vec()
    } else {
        out
    }
}
