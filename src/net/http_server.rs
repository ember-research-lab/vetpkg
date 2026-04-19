use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;

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
    let mut line = String::new();
    rdr.read_line(&mut line)?;
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
        let mut h = String::new();
        let n = rdr.read_line(&mut h)?;
        if n == 0 {
            break;
        }
        let h = h.trim_end_matches(['\r', '\n']).to_string();
        if h.is_empty() {
            break;
        }
        if let Some(colon) = h.find(':') {
            let name = h[..colon].trim().to_string();
            let value = h[colon + 1..].trim().to_string();
            headers.push((name, value));
        }
    }

    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);

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
}
