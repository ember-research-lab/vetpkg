//! Phase 1 Task 4: OSV on-demand API integration via localhost mock.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vetpkg::adapter::osv::{CacheEntry, OsvClient, DEFAULT_CACHE_TTL};
use vetpkg::types::Severity;

struct MockOsv {
    port: u16,
    stop: Arc<AtomicBool>,
    hits: Arc<AtomicUsize>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockOsv {
    fn spawn(response_json: String, status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(AtomicUsize::new(0));
        let stop2 = stop.clone();
        let hits2 = hits.clone();
        let handle = thread::spawn(move || loop {
            if stop2.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((mut s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf);
                    hits2.fetch_add(1, Ordering::Relaxed);
                    let reason = if status == 200 {
                        "OK"
                    } else {
                        "Service Unavailable"
                    };
                    let header = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response_json.len()
                    );
                    let _ = s.write_all(header.as_bytes());
                    let _ = s.write_all(response_json.as_bytes());
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
            hits,
            handle: Some(handle),
        }
    }

    fn api_base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn hit_count(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }
}

impl Drop for MockOsv {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn sample_response() -> String {
    r#"{
        "vulns": [
            {
                "id": "GHSA-wf5p-g6vw-rhxx",
                "summary": "axios SSRF",
                "database_specific": {"severity": "HIGH"}
            }
        ]
    }"#
    .to_string()
}

#[test]
fn queries_and_extracts_high_severity() {
    let mock = MockOsv::spawn(sample_response(), 200);
    let client = OsvClient::new(mock.api_base());
    let advs = client.query("npm", "axios", "1.14.1").unwrap();
    assert_eq!(advs.len(), 1);
    assert_eq!(advs[0].id, "GHSA-wf5p-g6vw-rhxx");
    assert_eq!(advs[0].severity, Severity::High);
}

#[test]
fn no_vulns_yields_empty_list() {
    let mock = MockOsv::spawn(r#"{"vulns":[]}"#.to_string(), 200);
    let client = OsvClient::new(mock.api_base());
    let advs = client.query("npm", "express", "4.18.2").unwrap();
    assert!(advs.is_empty());
}

#[test]
fn cache_hits_within_ttl_avoid_upstream() {
    let mock = MockOsv::spawn(sample_response(), 200);
    let client = OsvClient::new(mock.api_base());
    let mut cache: HashMap<String, CacheEntry> = HashMap::new();
    let _ = client
        .query_cached(&mut cache, "npm", "axios", "1.14.1")
        .unwrap();
    let _ = client
        .query_cached(&mut cache, "npm", "axios", "1.14.1")
        .unwrap();
    assert_eq!(mock.hit_count(), 1);
}

#[test]
fn expired_cache_reissues_fetch() {
    let mock = MockOsv::spawn(sample_response(), 200);
    let mut client = OsvClient::new(mock.api_base());
    client.ttl = Duration::from_millis(10);
    let mut cache: HashMap<String, CacheEntry> = HashMap::new();
    let _ = client
        .query_cached(&mut cache, "npm", "axios", "1.14.1")
        .unwrap();
    let key = vetpkg::adapter::osv::cache_key("npm", "axios", "1.14.1");
    if let Some(entry) = cache.get_mut(&key) {
        entry.cached_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(3600);
    }
    let _ = client
        .query_cached(&mut cache, "npm", "axios", "1.14.1")
        .unwrap();
    assert_eq!(mock.hit_count(), 2);
}

#[test]
fn upstream_failure_uses_stale_cache() {
    let mock = MockOsv::spawn(r#"{"error":"down"}"#.to_string(), 503);
    let client = OsvClient::new(mock.api_base());
    let mut cache: HashMap<String, CacheEntry> = HashMap::new();
    cache.insert(
        vetpkg::adapter::osv::cache_key("npm", "axios", "1.14.1"),
        CacheEntry {
            advisories: vec![vetpkg::types::Advisory {
                id: "GHSA-cache-hit".into(),
                severity: Severity::Critical,
                summary: "stale".into(),
            }],
            cached_at: 0,
        },
    );
    let advs = client
        .query_cached(&mut cache, "npm", "axios", "1.14.1")
        .unwrap();
    assert_eq!(advs.len(), 1);
    assert_eq!(advs[0].id, "GHSA-cache-hit");
}

#[test]
fn default_ttl_is_one_hour() {
    assert_eq!(DEFAULT_CACHE_TTL, Duration::from_secs(3600));
}
