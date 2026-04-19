use crate::engine::SecurityEngine;
use crate::net::http_server::{read_request, HttpResponse};
use crate::types::PolicyConfig;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

const MAX_CONCURRENT: usize = 32;

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
    eprintln!("  pip    /pip/*     Phase 4");
    eprintln!("  cargo  /cargo/*   Phase 4");

    let engine = Arc::new(SecurityEngine::new(config));
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
        let engine = engine.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            let _permit = permit;
            let _ = handle_connection(stream, &engine, &stop);
        });
    }
    Ok(0)
}

pub fn serve_on_listener(
    listener: TcpListener,
    config: PolicyConfig,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let engine = Arc::new(SecurityEngine::new(config));
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
                let engine = engine.clone();
                let stop = stop.clone();
                thread::spawn(move || {
                    let _permit = permit;
                    let _ = handle_connection(stream, &engine, &stop);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(20));
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
    _engine: &SecurityEngine,
    _stop: &AtomicBool,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let req = match read_request(&stream) {
        Ok(r) => r,
        Err(e) => {
            let resp = HttpResponse::new(400, "Bad Request", format!("bad: {e}\n").into_bytes())
                .header("Content-Type", "text/plain");
            return resp.write_to(&mut stream);
        }
    };
    let resp = route(&req.method, &req.path);
    resp.write_to(&mut stream)
}

fn route(method: &str, path: &str) -> HttpResponse {
    if method != "GET" {
        return HttpResponse::new(405, "Method Not Allowed", b"method not allowed\n".to_vec())
            .header("Content-Type", "text/plain");
    }
    if path == "/" || path == "/health" {
        return HttpResponse::new(200, "OK", b"vetpkg: up\n".to_vec())
            .header("Content-Type", "text/plain");
    }
    if path == "/status" {
        return HttpResponse::new(200, "OK", b"{\"status\":\"ok\"}\n".to_vec())
            .header("Content-Type", "application/json");
    }
    if path.starts_with("/npm/") {
        return match crate::net::package_path::parse_npm_path(path) {
            Some(parsed) => {
                let body = format!(
                    "{{\"package\":{:?},\"tarball\":{}}}\n",
                    parsed.package,
                    parsed
                        .tarball
                        .as_ref()
                        .map(|t| format!("{:?}", t))
                        .unwrap_or_else(|| "null".to_string()),
                );
                HttpResponse::new(200, "OK", body.into_bytes())
                    .header("Content-Type", "application/json")
            }
            None => HttpResponse::new(400, "Bad Request", b"invalid npm package path\n".to_vec())
                .header("Content-Type", "text/plain"),
        };
    }
    if path.starts_with("/pip/") {
        return HttpResponse::new(
            501,
            "Not Implemented",
            b"pip routes arrive in Phase 4\n".to_vec(),
        )
        .header("Content-Type", "text/plain");
    }
    if path.starts_with("/cargo/") {
        return HttpResponse::new(
            501,
            "Not Implemented",
            b"cargo routes arrive in Phase 4\n".to_vec(),
        )
        .header("Content-Type", "text/plain");
    }
    HttpResponse::new(404, "Not Found", b"no such route\n".to_vec())
        .header("Content-Type", "text/plain")
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

    fn client_request(port: u16, path: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
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
    fn proxy_routes_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let handle = thread::spawn(move || {
            let _ = serve_on_listener(listener, PolicyConfig::default(), stop2);
        });

        let r = client_request(port, "/health");
        assert!(r.contains("200 OK"));
        let r = client_request(port, "/npm/express");
        assert!(r.contains("200 OK"));
        assert!(r.contains("\"package\":\"express\""));
        assert!(r.contains("\"tarball\":null"));

        let r = client_request(port, "/npm/@vercel%2fnext");
        assert!(r.contains("200 OK"));
        assert!(r.contains("\"package\":\"@vercel/next\""));

        let r = client_request(port, "/npm/@vercel/next");
        assert!(r.contains("200 OK"));
        assert!(r.contains("\"package\":\"@vercel/next\""));

        let r = client_request(port, "/npm/@vercel/next/-/next-14.0.0.tgz");
        assert!(r.contains("200 OK"));
        assert!(r.contains("\"tarball\":\"next-14.0.0.tgz\""));

        let r = client_request(port, "/npm/UPPERCASE");
        assert!(r.contains("400"));

        let r = client_request(port, "/pip/requests");
        assert!(r.contains("501"));
        let r = client_request(port, "/cargo/serde");
        assert!(r.contains("501"));
        let r = client_request(port, "/nope");
        assert!(r.contains("404"));

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
