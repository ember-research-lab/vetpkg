//! Phase 2 Task 1: verify streaming-forward behaviour against a localhost
//! mock upstream. No external network. The mock writes N MB of deterministic
//! pseudo-random bytes; the test consumes them via stream_forward into a
//! bounded-memory sink and asserts byte-identical content + correct size.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use vetpkg::crypto::sha256::sha256_hex;
use vetpkg::net::streaming::{stream_forward, STREAM_CHUNK_SIZE};

fn synthetic_payload(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut state: u64 = 0xcafef00d_deadbeef;
    while out.len() < n {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(n);
    out
}

fn spawn_mock(payload: Vec<u8>) -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let handle = thread::spawn(move || loop {
        if stop2.load(Ordering::Relaxed) {
            break;
        }
        match listener.accept() {
            Ok((mut s, _)) => {
                s.set_nonblocking(false).unwrap();
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                s.write_all(header.as_bytes()).unwrap();
                s.write_all(&payload).unwrap();
                let _ = s.shutdown(Shutdown::Write);
                let mut discard = Vec::new();
                let _ = s.read_to_end(&mut discard);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    });
    (port, stop, handle)
}

struct CountingSink<'a> {
    inner: &'a mut Vec<u8>,
    peak_buffered: usize,
}

impl<'a> Write for CountingSink<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.peak_buffered = self.peak_buffered.max(buf.len());
        self.inner.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn streams_10mb_with_bounded_chunks() {
    let payload = synthetic_payload(10 * 1024 * 1024);
    let payload_hash = sha256_hex(&payload);
    let (port, stop, handle) = spawn_mock(payload.clone());

    let mut received: Vec<u8> = Vec::with_capacity(payload.len());
    let peak;
    let stats;
    {
        let mut sink = CountingSink {
            inner: &mut received,
            peak_buffered: 0,
        };
        let url = format!("http://127.0.0.1:{port}/tarball");
        stats = stream_forward(&url, &mut sink, 30).unwrap();
        peak = sink.peak_buffered;
    }
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();

    assert_eq!(stats.upstream_status, 200);
    assert_eq!(stats.bytes as usize, payload.len());
    assert_eq!(sha256_hex(&received), payload_hash);
    assert!(
        peak <= STREAM_CHUNK_SIZE,
        "per-write peak {} exceeded chunk size {}",
        peak,
        STREAM_CHUNK_SIZE
    );
}

#[test]
fn streams_50mb_integrity_preserved() {
    let payload = synthetic_payload(50 * 1024 * 1024);
    let payload_hash = sha256_hex(&payload);
    let (port, stop, handle) = spawn_mock(payload.clone());

    let mut received: Vec<u8> = Vec::with_capacity(payload.len());
    let url = format!("http://127.0.0.1:{port}/tarball");
    let stats = stream_forward(&url, &mut received, 60).unwrap();
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();

    assert_eq!(stats.upstream_status, 200);
    assert_eq!(stats.bytes as usize, payload.len());
    assert_eq!(sha256_hex(&received), payload_hash);
}

#[test]
fn no_external_network_guard_blocks_https_in_test() {
    std::env::set_var("VETPKG_NO_EXTERNAL_NETWORK", "1");
    let r = stream_forward(
        "https://registry.npmjs.org/axios/-/axios-1.0.0.tgz",
        &mut Vec::new(),
        10,
    );
    std::env::remove_var("VETPKG_NO_EXTERNAL_NETWORK");
    assert!(r.is_err(), "guard should block external URL");
    assert!(r.unwrap_err().contains("VETPKG_NO_EXTERNAL_NETWORK"));
}
