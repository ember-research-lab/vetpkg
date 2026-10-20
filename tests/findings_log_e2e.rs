//! A Warn verdict served through the proxy must reach
//! `~/.ember/vetpkg/findings.jsonl` (the suite contract ember-agent-monitor
//! reads). Own test binary + single test: it points HOME at a temp dir for
//! the whole process, which is only safe with no sibling tests.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use vetpkg::net::proxy::serve_on_listener;
use vetpkg::types::PolicyConfig;

#[test]
fn warn_verdict_through_proxy_is_written_to_findings_log() {
    let home = std::env::temp_dir().join(format!("vetpkg-findings-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    std::env::set_var("HOME", &home);

    // One-shot mock registry: typosquat-shaped name, old publish, one version.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let up_port = upstream.local_addr().unwrap().port();
    let body = r#"{"name":"requets","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"requets","version":"1.0.0","dist":{"tarball":"http://example.test/t.tgz"}}},"time":{"1.0.0":"2020-01-01T00:00:00Z"},"maintainers":[{"email":"a@example.com"}]}"#;
    std::thread::spawn(move || {
        for _ in 0..2 {
            if let Ok((mut s, _)) = upstream.accept() {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        }
    });

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = PolicyConfig {
        npm_upstream: format!("http://127.0.0.1:{up_port}"),
        ..Default::default()
    };
    let stop = Arc::new(AtomicBool::new(false));
    std::thread::spawn(move || {
        let _ = serve_on_listener(listener, cfg, stop);
    });

    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET /npm/requets HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);

    let log = home.join(".ember/vetpkg/findings.jsonl");
    let mut text = String::new();
    for _ in 0..50 {
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if !text.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        text.contains(r#""package":"requets""#),
        "findings log: {text:?}"
    );
    assert!(text.contains(r#""ecosystem":"npm""#), "{text:?}");
    let _ = std::fs::remove_dir_all(&home);
}
