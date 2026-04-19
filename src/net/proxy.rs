//! Request-serving proxy wired to the TierOrchestrator + upstream fetchers.
//!
//! Shape:
//!   GET /npm/{name}                        → metadata (fetch + score + filter)
//!   GET /npm/{name}/-/{file}.tgz           → tarball   (SuspicionMap → stream or analyze)
//!   GET /pip/…                             → 501 (Phase 4 adapter present; proxy-side wiring pending)
//!   GET /cargo/…                           → 501 (same reason)
//!   GET /health, /status                   → lightweight JSON
//!
//! Scoring on the metadata hot path: we score only the dist-tags.latest
//! version for per-request cost control. Older versions are still caught
//! when their tarball URL is requested — that path runs Tier 1 + Tier 2 on
//! any (package, version) whose Tier 0 score fell in the suspicion window.

use crate::adapter::npm;
use crate::engine::suspicion_map::in_suspicion_window;
use crate::engine::TierOrchestrator;
use crate::json::to_json_string;
use crate::net::http_server::{read_request, HttpResponse};
use crate::net::package_path::{parse_npm_path, upstream_npm_path};
use crate::net::streaming::stream_forward;
use crate::signals::binary_blob::BlobInventory;
use crate::signals::build_diff::BuildScriptCache;
use crate::types::{PolicyConfig, Verdict};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

const MAX_CONCURRENT: usize = 32;
const METADATA_TIMEOUT_SECS: u32 = 15;
const TARBALL_TIMEOUT_SECS: u32 = 60;
const MAX_TARBALL_BYTES: usize = 200 * 1024 * 1024;

pub struct ProxyContext {
    pub orch: TierOrchestrator,
    pub config: PolicyConfig,
}

impl ProxyContext {
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            orch: TierOrchestrator::new(config.clone()),
            config,
        }
    }
}

pub fn serve(config: PolicyConfig) -> Result<u8, String> {
    let addr = format!("127.0.0.1:{}", config.port);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("bind {addr}: {e}"))?;
    listener
        .set_nonblocking(false)
        .map_err(|e| format!("listener config: {e}"))?;
    eprintln!(
        "vetpkg {} listening on http://{}",
        env!("CARGO_PKG_VERSION"),
        addr
    );
    eprintln!("  npm    /npm/*     active");
    eprintln!("  pip    /pip/*     adapter ready, proxy route pending");
    eprintln!("  cargo  /cargo/*   adapter ready, proxy route pending");

    let ctx = Arc::new(ProxyContext::new(config));
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stop = Arc::new(AtomicBool::new(false));

    for incoming in listener.incoming() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let permit = sem.acquire();
        let ctx = ctx.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            let _permit = permit;
            let _ = handle_connection(stream, &ctx, &stop);
        });
    }
    Ok(0)
}

pub fn serve_on_listener(
    listener: TcpListener,
    config: PolicyConfig,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let ctx = Arc::new(ProxyContext::new(config));
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("listener config: {e}"))?;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .map_err(|e| format!("stream config: {e}"))?;
                let permit = sem.acquire();
                let ctx = ctx.clone();
                let stop = stop.clone();
                thread::spawn(move || {
                    let _permit = permit;
                    let _ = handle_connection(stream, &ctx, &stop);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                eprintln!("accept error: {e}");
            }
        }
    }
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    ctx: &ProxyContext,
    _stop: &AtomicBool,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let req = match read_request(&stream) {
        Ok(r) => r,
        Err(e) => {
            let resp = HttpResponse::new(400, "Bad Request", format!("bad: {e}\n").into_bytes())
                .header("Content-Type", "text/plain");
            return resp.write_to(&mut stream);
        }
    };
    if req.method != "GET" {
        let resp = HttpResponse::new(405, "Method Not Allowed", b"method not allowed\n".to_vec())
            .header("Content-Type", "text/plain");
        return resp.write_to(&mut stream);
    }

    let accept = req.header("Accept").map(|s| s.to_string());
    if req.path == "/" || req.path == "/health" {
        let resp = HttpResponse::new(200, "OK", b"vetpkg: up\n".to_vec())
            .header("Content-Type", "text/plain");
        return resp.write_to(&mut stream);
    }
    if req.path == "/status" {
        let resp = HttpResponse::new(200, "OK", b"{\"status\":\"ok\"}\n".to_vec())
            .header("Content-Type", "application/json");
        return resp.write_to(&mut stream);
    }

    if req.path.starts_with("/npm/") {
        return match parse_npm_path(&req.path) {
            None => {
                let resp =
                    HttpResponse::new(400, "Bad Request", b"invalid npm package path\n".to_vec())
                        .header("Content-Type", "text/plain");
                resp.write_to(&mut stream)
            }
            Some(p) if p.tarball.is_none() => {
                serve_npm_metadata(&mut stream, ctx, &p.package, accept.as_deref())
            }
            Some(p) => serve_npm_tarball(&mut stream, ctx, &p.package, &p.tarball.unwrap()),
        };
    }
    if req.path.starts_with("/pip/") {
        let resp = HttpResponse::new(
            501,
            "Not Implemented",
            b"pip proxy routes: adapter ready, proxy wiring pending\n".to_vec(),
        )
        .header("Content-Type", "text/plain");
        return resp.write_to(&mut stream);
    }
    if req.path.starts_with("/cargo/") {
        let resp = HttpResponse::new(
            501,
            "Not Implemented",
            b"cargo proxy routes: adapter ready, proxy wiring pending\n".to_vec(),
        )
        .header("Content-Type", "text/plain");
        return resp.write_to(&mut stream);
    }

    let resp = HttpResponse::new(404, "Not Found", b"no such route\n".to_vec())
        .header("Content-Type", "text/plain");
    resp.write_to(&mut stream)
}

fn serve_npm_metadata(
    stream: &mut TcpStream,
    ctx: &ProxyContext,
    package: &str,
    accept: Option<&str>,
) -> std::io::Result<()> {
    let upstream_url = format!(
        "{}{}",
        ctx.config.npm_upstream.trim_end_matches('/'),
        upstream_npm_path(package)
    );
    let metadata = match crate::net::http_client::fetch_json(
        &upstream_url,
        &[("Accept", npm::FULL_CONTENT_TYPE)],
        METADATA_TIMEOUT_SECS,
    ) {
        Ok(v) => v,
        Err(e) => {
            let resp = HttpResponse::new(
                502,
                "Bad Gateway",
                format!("upstream fetch failed: {e}\n").into_bytes(),
            )
            .header("Content-Type", "text/plain");
            return resp.write_to(stream);
        }
    };

    let mut filtered = metadata.clone();
    let mut blocked: Vec<String> = Vec::new();

    let latest = metadata
        .get("dist-tags")
        .and_then(|t| t.get("latest"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if let Some(ver) = latest {
        if let Some(intel) = npm::intel_for_version(package, &metadata, &ver) {
            let result = ctx.orch.score_tier0(&intel);
            let log = ctx.orch.log_line(package, &ver, &result);
            eprintln!("{log}");
            if matches!(result.verdict, Verdict::Block) {
                blocked.push(ver);
            }
        }
    }

    for v in &blocked {
        filtered = npm::strip_version(&filtered, v);
    }

    let body = if npm::wants_abbreviated(accept) {
        let abbr = npm::to_abbreviated(&filtered);
        to_json_string(&abbr).into_bytes()
    } else {
        to_json_string(&filtered).into_bytes()
    };
    let content_type = if npm::wants_abbreviated(accept) {
        npm::ABBREVIATED_CONTENT_TYPE
    } else {
        npm::FULL_CONTENT_TYPE
    };
    let resp = HttpResponse::new(200, "OK", body).header("Content-Type", content_type);
    resp.write_to(stream)
}

fn serve_npm_tarball(
    stream: &mut TcpStream,
    ctx: &ProxyContext,
    package: &str,
    tarball_filename: &str,
) -> std::io::Result<()> {
    let version = version_from_tarball(package, tarball_filename);
    let upstream_url = format!(
        "{}{}/-/{}",
        ctx.config.npm_upstream.trim_end_matches('/'),
        upstream_npm_path(package),
        tarball_filename
    );

    let tier0 = version
        .as_deref()
        .and_then(|v| ctx.orch.suspicion.get(package, v));

    let needs_analysis = tier0
        .as_ref()
        .map(|r| {
            in_suspicion_window(
                r.score,
                ctx.config.allow_threshold,
                ctx.config.block_threshold,
            )
        })
        .unwrap_or(false);

    if !needs_analysis {
        return stream_tarball_forward(stream, &upstream_url);
    }

    let mut buffered = Vec::new();
    let stats = match stream_forward(&upstream_url, &mut buffered, TARBALL_TIMEOUT_SECS) {
        Ok(s) => s,
        Err(e) => {
            let resp = HttpResponse::new(
                502,
                "Bad Gateway",
                format!("tarball fetch failed: {e}\n").into_bytes(),
            )
            .header("Content-Type", "text/plain");
            return resp.write_to(stream);
        }
    };
    if buffered.len() > MAX_TARBALL_BYTES {
        let resp = HttpResponse::new(
            413,
            "Payload Too Large",
            b"tarball exceeds 200MB safety cap\n".to_vec(),
        )
        .header("Content-Type", "text/plain");
        return resp.write_to(stream);
    }
    let _ = stats;

    let analysis = analyze_tarball_bytes(&buffered, package, version.as_deref(), ctx);
    match analysis {
        AnalysisOutcome::Block(reason) => {
            eprintln!("[vetpkg] BLOCK {package}/{tarball_filename}: {reason}");
            let resp = HttpResponse::new(
                403,
                "Forbidden",
                format!("vetpkg blocked {package}/{tarball_filename}: {reason}\n").into_bytes(),
            )
            .header("Content-Type", "text/plain");
            resp.write_to(stream)
        }
        AnalysisOutcome::Allow => {
            let resp = HttpResponse::new(200, "OK", buffered)
                .header("Content-Type", "application/octet-stream");
            resp.write_to(stream)
        }
    }
}

enum AnalysisOutcome {
    Allow,
    Block(String),
}

fn analyze_tarball_bytes(
    bytes: &[u8],
    package: &str,
    version: Option<&str>,
    ctx: &ProxyContext,
) -> AnalysisOutcome {
    let Some(version) = version else {
        return AnalysisOutcome::Allow;
    };
    let decoded = match crate::compress::gzip::gunzip(bytes) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[vetpkg] gunzip failed for {package}@{version}: {e}");
            return AnalysisOutcome::Allow;
        }
    };
    let td = match crate::platform::TempDir::new("vetpkg-analysis") {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[vetpkg] tempdir create failed: {e}");
            return AnalysisOutcome::Allow;
        }
    };
    if let Err(e) = crate::archive::tar::extract_tar(&decoded, td.path()) {
        eprintln!("[vetpkg] tar extract failed for {package}@{version}: {e}");
        return AnalysisOutcome::Allow;
    }

    let result = match ctx.orch.score_tarball(
        package,
        version,
        td.path(),
        &BlobInventory::default(),
        &BuildScriptCache::default(),
        false,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[vetpkg] tier analysis failed for {package}@{version}: {e}");
            return AnalysisOutcome::Allow;
        }
    };
    eprintln!("{}", ctx.orch.log_line(package, version, &result));
    if matches!(result.verdict, Verdict::Block) {
        AnalysisOutcome::Block(format!(
            "combined score {:.2} (t0={:.2} t1={:.2} t2={:.2})",
            result.score, result.tier0_score, result.tier1_score, result.tier2_score
        ))
    } else {
        AnalysisOutcome::Allow
    }
}

fn stream_tarball_forward(stream: &mut TcpStream, url: &str) -> std::io::Result<()> {
    write!(stream, "HTTP/1.1 200 OK\r\n")?;
    write!(stream, "Content-Type: application/octet-stream\r\n")?;
    write!(stream, "Transfer-Encoding: chunked\r\n")?;
    write!(stream, "Connection: close\r\n\r\n")?;
    let mut writer = ChunkedWriter { stream };
    if let Err(e) = stream_forward(url, &mut writer, TARBALL_TIMEOUT_SECS) {
        eprintln!("[vetpkg] tarball stream failed for {url}: {e}");
    }
    writer.end()
}

struct ChunkedWriter<'a> {
    stream: &'a mut TcpStream,
}

impl<'a> Write for ChunkedWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        write!(self.stream, "{:x}\r\n", buf.len())?;
        self.stream.write_all(buf)?;
        write!(self.stream, "\r\n")?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl<'a> ChunkedWriter<'a> {
    fn end(&mut self) -> std::io::Result<()> {
        write!(self.stream, "0\r\n\r\n")
    }
}

fn version_from_tarball(package: &str, tarball_filename: &str) -> Option<String> {
    let base = tarball_filename.strip_suffix(".tgz")?;
    let name_no_scope = package.rsplit('/').next().unwrap_or(package);
    let prefix = format!("{name_no_scope}-");
    base.strip_prefix(&prefix).map(|s| s.to_string())
}

struct Semaphore {
    mu: Mutex<usize>,
    cv: Condvar,
    max: usize,
}

impl Semaphore {
    fn new(max: usize) -> Self {
        Self {
            mu: Mutex::new(0),
            cv: Condvar::new(),
            max,
        }
    }
    fn acquire(self: &Arc<Self>) -> Permit {
        let mut guard = self.mu.lock().unwrap();
        while *guard >= self.max {
            guard = self.cv.wait(guard).unwrap();
        }
        *guard += 1;
        Permit { sem: self.clone() }
    }
}

pub struct Permit {
    sem: Arc<Semaphore>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut g = self.sem.mu.lock().unwrap();
        if *g > 0 {
            *g -= 1;
        }
        self.sem.cv.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn version_extract() {
        assert_eq!(
            version_from_tarball("express", "express-4.18.2.tgz"),
            Some("4.18.2".into())
        );
        assert_eq!(
            version_from_tarball("@vercel/next", "next-14.0.0.tgz"),
            Some("14.0.0".into())
        );
        assert_eq!(version_from_tarball("express", "unrelated.tgz"), None);
    }

    fn client_request(port: u16, path: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(
            s,
            "GET {} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
            path
        )
        .unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();
        buf
    }

    #[test]
    fn proxy_static_routes_still_work() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let handle = thread::spawn(move || {
            let _ = serve_on_listener(listener, PolicyConfig::default(), stop2);
        });

        let r = client_request(port, "/health");
        assert!(r.contains("200 OK"));
        let r = client_request(port, "/pip/requests");
        assert!(r.contains("501"));
        let r = client_request(port, "/cargo/serde");
        assert!(r.contains("501"));
        let r = client_request(port, "/nope");
        assert!(r.contains("404"));
        let r = client_request(port, "/npm/UPPERCASE");
        assert!(r.contains("400"));

        stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(("127.0.0.1", port));
        let _ = handle.join();
    }

    #[test]
    fn semaphore_limits_and_releases() {
        let sem = Arc::new(Semaphore::new(2));
        let p1 = sem.acquire();
        let p2 = sem.acquire();
        assert_eq!(*sem.mu.lock().unwrap(), 2);
        drop(p1);
        assert_eq!(*sem.mu.lock().unwrap(), 1);
        drop(p2);
        assert_eq!(*sem.mu.lock().unwrap(), 0);
    }
}
