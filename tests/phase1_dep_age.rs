//! Phase 1 Task 3: dep age auto-resolution against a localhost-only mock
//! npm registry. No real upstream is ever contacted.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use vetpkg::adapter::npm::{resolve_dep_ages_from_registry, DEFAULT_DEP_AGE_TIMEOUT_SECS};
use vetpkg::types::{Ecosystem, PackageIntel};

struct MockRegistry {
    port: u16,
    stop: Arc<AtomicBool>,
    fetch_log: Arc<std::sync::Mutex<Vec<String>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockRegistry {
    fn spawn(responses: HashMap<String, (u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let fetch_log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let fetch_log2 = fetch_log.clone();

        let handle = thread::spawn(move || loop {
            if stop2.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((mut s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    let mut buf = [0u8; 4096];
                    let n = match s.read(&mut buf) {
                        Ok(n) => n,
                        Err(_) => continue,
                    };
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req.lines().next().and_then(|line| {
                        let mut parts = line.split_whitespace();
                        parts.next();
                        parts.next().map(|p| p.to_string())
                    });
                    if let Some(p) = &path {
                        fetch_log2.lock().unwrap().push(p.clone());
                    }
                    let (status, body) = path
                        .and_then(|p| responses.get(&p).cloned())
                        .unwrap_or((404, "{}".into()));
                    let reason = if status == 200 { "OK" } else { "Not Found" };
                    let header = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                    s.write_all(header.as_bytes()).unwrap();
                    s.write_all(body.as_bytes()).unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(_) => thread::sleep(std::time::Duration::from_millis(10)),
            }
        });
        Self {
            port,
            stop,
            fetch_log,
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn fetches(&self) -> Vec<String> {
        self.fetch_log.lock().unwrap().clone()
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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn iso_from_hours_ago(hours: u64) -> String {
    let target = now_unix().saturating_sub(hours * 3600);
    let (year, month, day, hour, minute, second) = unix_to_utc(target);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn unix_to_utc(mut secs: u64) -> (u64, u32, u32, u32, u32, u32) {
    let is_leap = |y: u64| (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
    let days_in_month = |y: u64, m: u32| -> u32 {
        match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if is_leap(y) {
                    29
                } else {
                    28
                }
            }
            _ => 0,
        }
    };
    let hour = ((secs / 3600) % 24) as u32;
    let minute = ((secs / 60) % 60) as u32;
    let second = (secs % 60) as u32;
    secs /= 86400;
    let mut year: u64 = 1970;
    loop {
        let days = if is_leap(year) { 366 } else { 365 };
        if secs < days {
            break;
        }
        secs -= days;
        year += 1;
    }
    let mut month: u32 = 1;
    loop {
        let days = days_in_month(year, month) as u64;
        if secs < days {
            break;
        }
        secs -= days;
        month += 1;
    }
    let day = secs as u32 + 1;
    (year, month, day, hour, minute, second)
}

fn metadata_json(name: &str, latest: &str, published_hours_ago: u64) -> String {
    format!(
        r#"{{"name":"{name}","dist-tags":{{"latest":"{latest}"}},"time":{{"{latest}":"{}"}}}}"#,
        iso_from_hours_ago(published_hours_ago)
    )
}

#[test]
fn resolves_age_for_fresh_new_dep() {
    let mut responses = HashMap::new();
    responses.insert(
        "/proto-loader".into(),
        (200, metadata_json("proto-loader", "0.0.1", 2)),
    );
    let mock = MockRegistry::spawn(responses);

    let mut intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "axios".into(),
        version: "1.14.1".into(),
        prior_dependencies: vec!["follow-redirects".into()],
        dependencies: vec!["follow-redirects".into(), "proto-loader".into()],
        ..Default::default()
    };
    resolve_dep_ages_from_registry(
        &mock.base_url(),
        &mut intel,
        5,
        DEFAULT_DEP_AGE_TIMEOUT_SECS,
    );
    let age = intel.dep_ages.get("proto-loader").copied().unwrap();
    assert!(
        (1.0..=4.0).contains(&age),
        "expected ~2h, got {age}h; fetches: {:?}",
        mock.fetches()
    );
    assert_eq!(mock.fetches(), vec!["/proto-loader".to_string()]);
}

#[test]
fn respects_max_fetches_cap() {
    let mut responses = HashMap::new();
    for i in 0..10 {
        let name = format!("new-dep-{i}");
        responses.insert(format!("/{name}"), (200, metadata_json(&name, "1.0.0", 24)));
    }
    let mock = MockRegistry::spawn(responses);

    let deps: Vec<String> = (0..10).map(|i| format!("new-dep-{i}")).collect();
    let mut intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "consumer".into(),
        version: "1.0.0".into(),
        prior_dependencies: vec![],
        dependencies: deps,
        ..Default::default()
    };
    resolve_dep_ages_from_registry(&mock.base_url(), &mut intel, 5, 3);
    assert_eq!(intel.dep_ages.len(), 5);
    assert_eq!(mock.fetches().len(), 5);
}

#[test]
fn missing_dep_does_not_crash_other_lookups() {
    let mut responses = HashMap::new();
    responses.insert(
        "/good-dep".into(),
        (200, metadata_json("good-dep", "1.0.0", 10)),
    );
    let mock = MockRegistry::spawn(responses);

    let mut intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "consumer".into(),
        version: "1.0.0".into(),
        prior_dependencies: vec![],
        dependencies: vec!["missing-dep".into(), "good-dep".into()],
        ..Default::default()
    };
    resolve_dep_ages_from_registry(&mock.base_url(), &mut intel, 5, 3);
    assert!(intel.dep_ages.contains_key("good-dep"));
    assert!(!intel.dep_ages.contains_key("missing-dep"));
}

#[test]
fn scoped_dep_name_url_encoded() {
    let mut responses = HashMap::new();
    responses.insert(
        "/@scope%2fpkg".into(),
        (200, metadata_json("@scope/pkg", "1.0.0", 5)),
    );
    let mock = MockRegistry::spawn(responses);

    let mut intel = PackageIntel {
        ecosystem: Some(Ecosystem::Npm),
        name: "consumer".into(),
        version: "1.0.0".into(),
        prior_dependencies: vec![],
        dependencies: vec!["@scope/pkg".into()],
        ..Default::default()
    };
    resolve_dep_ages_from_registry(&mock.base_url(), &mut intel, 5, 3);
    assert!(intel.dep_ages.contains_key("@scope/pkg"));
    assert_eq!(mock.fetches(), vec!["/@scope%2fpkg".to_string()]);
}
