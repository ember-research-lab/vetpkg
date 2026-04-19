//! Shared state between metadata handler (Tier 0) and tarball handler.
//!
//! Metadata scoring writes entries with score in the annotation window
//! [warn_threshold, block_threshold). Tarball handler reads them to decide
//! whether to stream-forward (fast path) or buffer+inspect (slow path).
//!
//! TTL is 30 minutes by default. Cleanup thread sweeps every 60s.

use crate::types::Signal;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_TTL: Duration = Duration::from_secs(30 * 60);
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Tier0Result {
    pub score: f64,
    pub signals: Vec<Signal>,
    pub cached_at: Instant,
}

pub type Key = (String, String);

pub struct SuspicionMap {
    inner: Arc<RwLock<HashMap<Key, Tier0Result>>>,
    ttl: Duration,
}

impl SuspicionMap {
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    pub fn insert(&self, pkg: &str, ver: &str, result: Tier0Result) {
        let mut guard = self.inner.write().expect("suspicion map poisoned");
        guard.insert((pkg.to_string(), ver.to_string()), result);
    }

    pub fn get(&self, pkg: &str, ver: &str) -> Option<Tier0Result> {
        let guard = self.inner.read().expect("suspicion map poisoned");
        let entry = guard.get(&(pkg.to_string(), ver.to_string()))?.clone();
        if entry.cached_at.elapsed() > self.ttl {
            return None;
        }
        Some(entry)
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("suspicion map poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn sweep(&self) -> usize {
        let mut guard = self.inner.write().expect("suspicion map poisoned");
        let before = guard.len();
        let ttl = self.ttl;
        guard.retain(|_, v| v.cached_at.elapsed() <= ttl);
        before - guard.len()
    }

    pub fn start_sweeper(
        &self,
        interval: Duration,
        stop: Arc<AtomicBool>,
    ) -> thread::JoinHandle<()> {
        let inner = self.inner.clone();
        let ttl = self.ttl;
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(interval);
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                if let Ok(mut guard) = inner.write() {
                    guard.retain(|_, v| v.cached_at.elapsed() <= ttl);
                }
            }
        })
    }

    pub fn shared(&self) -> Arc<RwLock<HashMap<Key, Tier0Result>>> {
        self.inner.clone()
    }
}

impl Default for SuspicionMap {
    fn default() -> Self {
        Self::new()
    }
}

pub fn in_suspicion_window(score: f64, warn_threshold: f64, block_threshold: f64) -> bool {
    score >= warn_threshold && score < block_threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn insert_and_get_round_trips() {
        let map = SuspicionMap::new();
        let r = Tier0Result {
            score: 0.25,
            signals: vec![],
            cached_at: Instant::now(),
        };
        map.insert("axios", "1.14.1", r);
        let fetched = map.get("axios", "1.14.1").expect("present");
        assert_eq!(fetched.score, 0.25);
    }

    #[test]
    fn miss_on_unknown_key() {
        let map = SuspicionMap::new();
        assert!(map.get("unknown", "0.0.1").is_none());
    }

    #[test]
    fn ttl_expiry_hides_stale_entries() {
        let map = SuspicionMap::with_ttl(Duration::from_millis(40));
        map.insert(
            "axios",
            "1.14.1",
            Tier0Result {
                score: 0.4,
                signals: vec![],
                cached_at: Instant::now(),
            },
        );
        assert!(map.get("axios", "1.14.1").is_some());
        sleep(Duration::from_millis(80));
        assert!(map.get("axios", "1.14.1").is_none());
    }

    #[test]
    fn sweep_removes_stale() {
        let map = SuspicionMap::with_ttl(Duration::from_millis(20));
        map.insert(
            "a",
            "1",
            Tier0Result {
                score: 0.4,
                signals: vec![],
                cached_at: Instant::now(),
            },
        );
        assert_eq!(map.len(), 1);
        sleep(Duration::from_millis(60));
        let removed = map.sweep();
        assert_eq!(removed, 1);
        assert!(map.is_empty());
    }

    #[test]
    fn sweeper_thread_runs() {
        let map = SuspicionMap::with_ttl(Duration::from_millis(20));
        map.insert(
            "a",
            "1",
            Tier0Result {
                score: 0.4,
                signals: vec![],
                cached_at: Instant::now(),
            },
        );
        let stop = Arc::new(AtomicBool::new(false));
        let handle = map.start_sweeper(Duration::from_millis(15), stop.clone());
        sleep(Duration::from_millis(100));
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
        assert!(map.is_empty());
    }

    #[test]
    fn window_helper_bounds() {
        assert!(!in_suspicion_window(0.14, 0.15, 0.6));
        assert!(in_suspicion_window(0.15, 0.15, 0.6));
        assert!(in_suspicion_window(0.4, 0.15, 0.6));
        assert!(!in_suspicion_window(0.6, 0.15, 0.6));
        assert!(!in_suspicion_window(0.9, 0.15, 0.6));
    }
}
