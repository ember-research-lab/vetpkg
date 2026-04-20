use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;

/// Hard caps on inbound HTTP parsing. These protect against clients that
/// try to exhaust memory with pathological request shapes.
pub const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_HEADERS: usize = 100;
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == n)
            .map(|(_, v)| v.as_str())
    }
}

pub fn read_request<R: Read>(stream: R) -> io::Result<HttpRequest> {
    let mut rdr = BufReader::new(stream);
    let line = read_bounded_line(&mut rdr, MAX_REQUEST_LINE_BYTES)?;
    if line.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty request",
        ));
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing path"))?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing version"))?
        .to_string();
    if !version.starts_with("HTTP/") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad version"));
    }

    let mut headers = Vec::new();
    loop {
        if headers.len() >= MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many headers",
            ));
        }
        let h = read_bounded_line(&mut rdr, MAX_HEADER_BYTES)?;
        if h.is_empty() {
            break;
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        // Reject header names containing ASCII control chars to defeat
        // request-smuggling / response-splitting tricks an upstream proxy
        // might probe against us.
        if let Some(colon) = h.find(':') {
            let name = h[..colon].trim();
            let value = h[colon + 1..].trim();
            if name.bytes().any(|b| b < 0x20 || b == 0x7F) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bad header name",
                ));
            }
            if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bad header value",
                ));
            }
            headers.push((name.to_string(), value.to_string()));
        }
    }

    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);

    if content_length > MAX_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Content-Length {} exceeds {}",
                content_length, MAX_BODY_BYTES
            ),
        ));
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        rdr.read_exact(&mut body)?;
    }

    Ok(HttpRequest {
        method,
        path,
        version,
        headers,
        body,
    })
}

/// Read one \n-terminated line but refuse anything longer than `cap`.
/// Returns an empty string on EOF.
fn read_bounded_line<R: BufRead>(rdr: &mut R, cap: usize) -> io::Result<String> {
    let mut buf = Vec::with_capacity(256.min(cap));
    loop {
        let available = match rdr.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            break;
        }
        let (consumed, done) = match available.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None => (available.len(), false),
        };
        if buf.len() + consumed > cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("HTTP line exceeds {cap} bytes"),
            ));
        }
        buf.extend_from_slice(&available[..consumed]);
        rdr.consume(consumed);
        if done {
            break;
        }
    }
    String::from_utf8(buf).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 line"))
}

pub struct HttpResponse {
    pub status: u16,
    pub reason: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: u16, reason: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            reason,
            headers: Vec::new(),
            body,
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn write_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        write!(w, "HTTP/1.1 {} {}\r\n", self.status, self.reason)?;
        let mut have_cl = false;
        let mut have_ct = false;
        for (k, v) in &self.headers {
            write!(w, "{}: {}\r\n", k, v)?;
            if k.eq_ignore_ascii_case("content-length") {
                have_cl = true;
            }
            if k.eq_ignore_ascii_case("content-type") {
                have_ct = true;
            }
        }
        if !have_ct {
            write!(w, "Content-Type: application/octet-stream\r\n")?;
        }
        if !have_cl {
            write!(w, "Content-Length: {}\r\n", self.body.len())?;
        }
        write!(w, "Connection: close\r\n\r\n")?;
        w.write_all(&self.body)?;
        Ok(())
    }
}

pub fn write_chunked_start<W: Write>(
    w: &mut W,
    status: u16,
    reason: &str,
    content_type: &str,
) -> io::Result<()> {
    write!(w, "HTTP/1.1 {} {}\r\n", status, reason)?;
    write!(w, "Content-Type: {}\r\n", content_type)?;
    write!(w, "Transfer-Encoding: chunked\r\n")?;
    write!(w, "Connection: close\r\n\r\n")?;
    Ok(())
}

pub fn write_chunk<W: Write>(w: &mut W, chunk: &[u8]) -> io::Result<()> {
    write!(w, "{:x}\r\n", chunk.len())?;
    w.write_all(chunk)?;
    write!(w, "\r\n")?;
    Ok(())
}

pub fn end_chunked<W: Write>(w: &mut W) -> io::Result<()> {
    write!(w, "0\r\n\r\n")
}

pub fn send(stream: &mut TcpStream, resp: &HttpResponse) -> io::Result<()> {
    resp.write_to(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_get() {
        let req =
            b"GET /npm/express HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n";
        let r = read_request(&req[..]).unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/npm/express");
        assert_eq!(r.version, "HTTP/1.1");
        assert_eq!(r.header("host"), Some("localhost"));
        assert_eq!(r.header("Accept"), Some("application/json"));
    }

    #[test]
    fn parse_post_with_body() {
        let req = b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let r = read_request(&req[..]).unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.body, b"hello");
    }

    #[test]
    fn case_insensitive_headers() {
        let req = b"GET / HTTP/1.1\r\nX-CUSTOM: yes\r\n\r\n";
        let r = read_request(&req[..]).unwrap();
        assert_eq!(r.header("x-custom"), Some("yes"));
        assert_eq!(r.header("X-Custom"), Some("yes"));
    }

    #[test]
    fn response_round_trip() {
        let resp = HttpResponse::new(200, "OK", b"hello".to_vec()).header("X-Test", "1");
        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("X-Test: 1\r\n"));
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.ends_with("hello"));
    }

    #[test]
    fn chunked_format() {
        let mut buf = Vec::new();
        write_chunked_start(&mut buf, 200, "OK", "application/json").unwrap();
        write_chunk(&mut buf, b"hi ").unwrap();
        write_chunk(&mut buf, b"there").unwrap();
        end_chunked(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("\r\n3\r\nhi \r\n5\r\nthere\r\n0\r\n\r\n"));
    }

    #[test]
    fn bad_request_errors() {
        let req = b"BAD\r\n";
        assert!(read_request(&req[..]).is_err());
    }

    #[test]
    fn rejects_oversized_content_length() {
        let req = format!(
            "POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let err = read_request(req.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn rejects_too_many_headers() {
        let mut buf = String::from("GET / HTTP/1.1\r\n");
        for i in 0..MAX_HEADERS + 5 {
            buf.push_str(&format!("X-H{i}: v\r\n"));
        }
        buf.push_str("\r\n");
        let err = read_request(buf.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("too many headers"));
    }

    #[test]
    fn rejects_oversized_request_line() {
        let mut buf = String::from("GET /");
        buf.push_str(&"a".repeat(MAX_REQUEST_LINE_BYTES + 100));
        buf.push_str(" HTTP/1.1\r\n\r\n");
        let err = read_request(buf.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn rejects_header_with_crlf_in_value() {
        // With the hardened parser, a bare CR inside a header value is
        // rejected outright (defense against response-splitting probes).
        let req = "GET / HTTP/1.1\r\nX-Bad: one\rtwo\r\n\r\n";
        let err = read_request(req.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("bad header"));
    }
}
