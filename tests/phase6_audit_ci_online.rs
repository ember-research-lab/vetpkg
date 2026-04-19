//! audit-ci --online: tag-mutation detection through a mocked GitHub API.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use vetpkg::ci::Severity;
use vetpkg::cli::audit_ci::{audit, AuditOptions};
use vetpkg::platform::TempDir;

type Responses = Arc<Mutex<std::collections::HashMap<String, (u16, String)>>>;

struct MockGitHub {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    responses: Responses,
}

impl MockGitHub {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let responses: Responses = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let stop2 = stop.clone();
        let responses2 = responses.clone();
        let handle = thread::spawn(move || loop {
            if stop2.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((mut s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    let mut buf = [0u8; 4096];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let path = String::from_utf8_lossy(&buf[..n])
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("")
                        .to_string();
                    let (status, body) = responses2
                        .lock()
                        .unwrap()
                        .get(&path)
                        .cloned()
                        .unwrap_or((404, r#"{"message":"not found"}"#.into()));
                    let reason = if status == 200 { "OK" } else { "Not Found" };
                    let head = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = s.write_all(head.as_bytes());
                    let _ = s.write_all(body.as_bytes());
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
    fn set(&self, path: &str, status: u16, body: &str) {
        self.responses
            .lock()
            .unwrap()
            .insert(path.into(), (status, body.to_string()));
    }
}

impl Drop for MockGitHub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn write_workflow(root: &std::path::Path, content: &str) {
    let p = root.join(".github/workflows/ci.yml");
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, content).unwrap();
}

#[test]
fn first_scan_establishes_baseline() {
    let td = TempDir::new("online-first").unwrap();
    write_workflow(
        td.path(),
        "jobs:\n  b:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n",
    );
    let gh = MockGitHub::spawn();
    gh.set(
        "/repos/actions/checkout/git/ref/tags/v4",
        200,
        r#"{"ref":"refs/tags/v4","object":{"sha":"abc123def","type":"commit"}}"#,
    );
    let cache = td.path().join("ci_cache.json");
    let opts = AuditOptions {
        path: td.path().to_path_buf(),
        online: true,
        github_api_base: Some(gh.base()),
        cache_path: Some(cache.clone()),
        ..Default::default()
    };
    let report = audit(&opts).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.message.contains("baseline established")),
        "{:#?}",
        report.findings
    );
    assert!(cache.exists());
}

#[test]
fn mismatch_fires_critical() {
    let td = TempDir::new("online-mismatch").unwrap();
    write_workflow(
        td.path(),
        "jobs:\n  b:\n    runs-on: x\n    steps:\n      - uses: tj-actions/changed-files@v41\n",
    );
    let gh = MockGitHub::spawn();
    gh.set(
        "/repos/tj-actions/changed-files/git/ref/tags/v41",
        200,
        r#"{"ref":"refs/tags/v41","object":{"sha":"9d8b7e1","type":"commit"}}"#,
    );
    let cache = td.path().join("ci_cache.json");
    fs::write(
        &cache,
        r#"{"tj-actions/changed-files@v41":{"action":"tj-actions/changed-files","tag":"v41","sha":"a3e4c2f","checked_at":0}}"#,
    )
    .unwrap();
    let opts = AuditOptions {
        path: td.path().to_path_buf(),
        online: true,
        github_api_base: Some(gh.base()),
        cache_path: Some(cache),
        ..Default::default()
    };
    let report = audit(&opts).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.severity == Severity::Critical
                && f.message.contains("may have been hijacked")),
        "{:#?}",
        report.findings
    );
}

#[test]
fn annotated_tag_two_hop_resolves() {
    let td = TempDir::new("online-annotated").unwrap();
    write_workflow(
        td.path(),
        "jobs:\n  b:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n",
    );
    let gh = MockGitHub::spawn();
    gh.set(
        "/repos/actions/checkout/git/ref/tags/v4",
        200,
        r#"{"ref":"refs/tags/v4","object":{"sha":"tagobj99","type":"tag"}}"#,
    );
    gh.set(
        "/repos/actions/checkout/git/tags/tagobj99",
        200,
        r#"{"tag":"v4","object":{"sha":"real_commit","type":"commit"}}"#,
    );
    let cache_path = td.path().join("ci_cache.json");
    fs::write(
        &cache_path,
        r#"{"actions/checkout@v4":{"action":"actions/checkout","tag":"v4","sha":"real_commit","checked_at":0}}"#,
    )
    .unwrap();
    let opts = AuditOptions {
        path: td.path().to_path_buf(),
        online: true,
        github_api_base: Some(gh.base()),
        cache_path: Some(cache_path),
        ..Default::default()
    };
    let report = audit(&opts).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.message.contains("baseline verified")),
        "{:#?}",
        report.findings
    );
}

#[test]
fn online_failure_degrades_to_low_severity() {
    let td = TempDir::new("online-fail").unwrap();
    write_workflow(
        td.path(),
        "jobs:\n  b:\n    runs-on: x\n    steps:\n      - uses: ghost/action@v1\n",
    );
    let gh = MockGitHub::spawn();
    let cache = td.path().join("ci_cache.json");
    let opts = AuditOptions {
        path: PathBuf::from(td.path()),
        online: true,
        github_api_base: Some(gh.base()),
        cache_path: Some(cache),
        ..Default::default()
    };
    let report = audit(&opts).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.message.contains("online check failed")),
        "{:#?}",
        report.findings
    );
}
