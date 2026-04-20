use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use vetpkg::adapter::npm::intel_for_version;
use vetpkg::engine::SecurityEngine;
use vetpkg::json::{parse, to_json_string, JsonValue};
use vetpkg::net::proxy::serve_on_listener;
use vetpkg::types::{PolicyConfig, Verdict};

#[test]
fn json_parses_1_5mb_under_budget() {
    let count = 15_000;
    let mut arr = Vec::with_capacity(count);
    for i in 0..count {
        let obj = JsonValue::Object(vec![
            ("name".into(), JsonValue::Str(format!("pkg-{i}"))),
            ("version".into(), JsonValue::Str("1.2.3".into())),
            (
                "nested".into(),
                JsonValue::Array(vec![
                    JsonValue::Number(i as f64),
                    JsonValue::Bool(i % 2 == 0),
                    JsonValue::Null,
                    JsonValue::Str("value with \"escapes\" and \n newlines".into()),
                ]),
            ),
        ]);
        arr.push(obj);
    }
    let big = to_json_string(&JsonValue::Array(arr));
    assert!(
        big.len() > 1_500_000 && big.len() < 1_800_000,
        "fixture should be ~1.5MB, got {}",
        big.len()
    );

    let budget = if cfg!(debug_assertions) {
        Duration::from_millis(400)
    } else {
        Duration::from_millis(100)
    };
    let start = Instant::now();
    let parsed = parse(&big).expect("parse");
    let elapsed = start.elapsed();
    assert_eq!(parsed.as_array().unwrap().len(), count);
    assert!(
        elapsed < budget,
        "parse of {} bytes took {:?}, exceeds {:?} budget (debug={})",
        big.len(),
        elapsed,
        budget,
        cfg!(debug_assertions)
    );
}

#[test]
fn axios_fixture_scores_block() {
    let text = std::fs::read_to_string("tests/fixtures/axios_full.json")
        .expect("axios fixture must exist");
    let metadata = parse(&text).expect("fixture must parse");

    let latest = metadata
        .get("dist-tags")
        .and_then(|t| t.get("latest"))
        .and_then(|v| v.as_str())
        .expect("latest version present")
        .to_string();

    let mut intel = intel_for_version("axios", &metadata, &latest).expect("intel");

    intel.prior_maintainers = vec!["original@axios.io".into()];
    intel.prior_dependencies = vec!["follow-redirects".into(), "form-data".into()];
    intel.age_hours = Some(2.0);

    let engine = SecurityEngine::new(PolicyConfig::default());
    let score = engine.score(&intel);
    assert!(
        score.score >= 0.6,
        "axios fixture expected Block, got {:.3} with signals {:?}",
        score.score,
        score.signals
    );
    assert_eq!(engine.verdict(score.score), Verdict::Block);
}

#[test]
fn clean_package_scores_allow() {
    let metadata = parse(
        r#"{
        "name": "express",
        "dist-tags": {"latest": "4.18.2"},
        "versions": {
            "4.18.2": {
                "name": "express",
                "version": "4.18.2",
                "dependencies": {"body-parser": "1.20.1"},
                "scripts": {"test": "mocha"}
            }
        },
        "time": {"4.18.2": "2023-01-01T00:00:00Z"},
        "maintainers": [{"name": "dougwilson", "email": "doug@somethingdoug.com"}]
    }"#,
    )
    .unwrap();
    let intel = intel_for_version("express", &metadata, "4.18.2").unwrap();
    let engine = SecurityEngine::new(PolicyConfig::default());
    let score = engine.score(&intel);
    assert!(
        score.score < 0.3,
        "express expected Allow, got {:.3} with signals {:?}",
        score.score,
        score.signals
    );
    assert_eq!(engine.verdict(score.score), Verdict::Allow);
}

#[test]
fn proxy_never_contacts_external_hosts() {
    // Verify the VETPKG_NO_EXTERNAL_NETWORK guard is honored by the proxy:
    // when set, a request that would require upstream fetch must be refused
    // with a clear error rather than silently contacting the registry.
    std::env::set_var("VETPKG_NO_EXTERNAL_NETWORK", "1");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let handle = thread::spawn(move || {
        let _ = serve_on_listener(listener, PolicyConfig::default(), stop2);
    });

    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET /npm/express HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).unwrap();
    assert!(
        buf.contains("VETPKG_NO_EXTERNAL_NETWORK") || buf.contains("refusing to contact"),
        "proxy should refuse upstream fetch under guard, got: {buf}"
    );

    stop.store(true, Ordering::Relaxed);
    let _ = TcpStream::connect(("127.0.0.1", port));
    let _ = handle.join();
    std::env::remove_var("VETPKG_NO_EXTERNAL_NETWORK");
}
