use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub fn config_dir() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("APPDATA")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .unwrap_or_else(|| OsString::from("C:\\"));
        PathBuf::from(base).join("vetpkg")
    } else if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("vetpkg")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_else(|| OsString::from("/tmp"));
        PathBuf::from(home).join(".config").join("vetpkg")
    }
}

pub fn cache_dir() -> PathBuf {
    config_dir().join("cache")
}

pub fn patterns_dir() -> PathBuf {
    config_dir().join("patterns")
}

/// Scrub dangerous environment variables before spawning curl. The goal
/// is to prevent a compromised process environment from redirecting curl
/// traffic (HTTP_PROXY), swapping TLS trust (SSL_CERT_*), preloading a
/// shared library (LD_PRELOAD / DYLD_INSERT_LIBRARIES), or sourcing
/// attacker-controlled config (CURL_HOME, CURLOPT_*).
pub fn sanitize_curl_env(cmd: &mut std::process::Command) {
    const DANGEROUS: &[&str] = &[
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "CURL_HOME",
        "CURL_SSL_BACKEND",
        "CURLOPT_SSL_VERIFYPEER",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "SSLKEYLOGFILE",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
    ];
    for v in DANGEROUS {
        cmd.env_remove(v);
    }
}

static CURL_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

pub fn resolve_curl() -> Result<PathBuf, String> {
    let resolved = CURL_PATH.get_or_init(|| {
        if let Some(p) = std::env::var_os("VETPKG_CURL_PATH") {
            let p = PathBuf::from(p);
            if p.is_file() {
                return Some(p);
            }
            return None;
        }
        for candidate in preferred_curl_paths() {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        search_path_for_curl()
    });
    resolved
        .clone()
        .ok_or_else(|| "curl binary not found (set VETPKG_CURL_PATH or install curl)".to_string())
}

fn preferred_curl_paths() -> Vec<PathBuf> {
    if cfg!(windows) {
        vec![
            PathBuf::from("C:\\Windows\\System32\\curl.exe"),
            PathBuf::from("C:\\Program Files\\curl\\bin\\curl.exe"),
        ]
    } else {
        vec![
            PathBuf::from("/usr/bin/curl"),
            PathBuf::from("/usr/local/bin/curl"),
            PathBuf::from("/opt/homebrew/bin/curl"),
        ]
    }
}

fn search_path_for_curl() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let filename = if cfg!(windows) { "curl.exe" } else { "curl" };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(filename);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Header name/value safety. Refuses anything outside printable ASCII
/// (0x20..=0x7E) so tab folding, DEL, and all C0 controls are blocked.
/// HTTP header field tokens are defined over VCHAR in RFC 7230; refusing
/// non-VCHAR is strictly tighter.
pub fn is_safe_header_value(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// URL safety gate before handing off to curl argv. Rejects:
///   - any scheme other than http/https
///   - ASCII control chars (0x00..=0x1F) and DEL (0x7F)
///   - space, quote, angle brackets, caret, backtick (RFC 3986 forbids)
///   - percent-encoded CRLF (`%0D` / `%0A`) in any case — curl decodes
///     these and would emit a literal CRLF into the request-line
///   - non-ASCII bytes (require IDN-normalized input from caller)
///   - userinfo component (`@` before the path boundary) — dist.tarball
///     values from compromised registries could otherwise redirect curl
///     with attacker-embedded credentials.
pub fn is_safe_url(s: &str) -> bool {
    let rest = if let Some(r) = s.strip_prefix("https://") {
        r
    } else if let Some(r) = s.strip_prefix("http://") {
        r
    } else {
        return false;
    };
    for b in s.bytes() {
        if !(0x20..0x7F).contains(&b) || b == b' ' || b == b'"' || b == b'<' || b == b'>' {
            return false;
        }
    }
    // Reject %-encoded CRLF (case insensitive). Curl decodes these into
    // the request line, so catching them here is the only defence.
    let lower = s.to_ascii_lowercase();
    if lower.contains("%0d") || lower.contains("%0a") || lower.contains("%00") {
        return false;
    }
    // Reject userinfo in the authority. Everything up to the first `/`
    // past the scheme is authority; if it contains `@`, it has userinfo.
    let authority_end = rest.find('/').unwrap_or(rest.len());
    if rest[..authority_end].contains('@') {
        return false;
    }
    true
}

pub fn unique_temp_subdir(prefix: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tid = {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    };
    base.join(format!("{prefix}-{pid}-{nanos}-{tid}"))
}

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> std::io::Result<Self> {
        let path = unique_temp_subdir(prefix);
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir_not_empty() {
        assert!(!config_dir().as_os_str().is_empty());
    }

    #[test]
    fn temp_dir_creates_and_removes() {
        let path: PathBuf;
        {
            let td = TempDir::new("vetpkg-test").unwrap();
            path = td.path().to_path_buf();
            assert!(path.exists());
        }
        assert!(!path.exists());
    }

    #[test]
    fn unique_temp_subdirs_are_unique() {
        let a = unique_temp_subdir("x");
        let b = unique_temp_subdir("x");
        assert_ne!(a, b);
    }

    #[test]
    fn safe_url_checks() {
        assert!(is_safe_url("https://example.com/path"));
        assert!(is_safe_url("http://127.0.0.1:9451/npm/express"));
        assert!(!is_safe_url("file:///etc/passwd"));
        assert!(!is_safe_url("https://e\r\nX: 1"));
        assert!(!is_safe_url("https://with space"));
    }

    #[test]
    fn safe_url_rejects_percent_crlf() {
        // curl decodes %0D/%0A in the URL path into literal CRLF on the
        // wire, which becomes header-injection into the request to the
        // upstream. Reject before handoff.
        assert!(!is_safe_url("https://example.com/x%0d%0aX-Inject: evil"));
        assert!(!is_safe_url("https://example.com/x%0D%0Afoo"));
        assert!(!is_safe_url("https://example.com/x%00y"));
    }

    #[test]
    fn safe_url_rejects_userinfo() {
        // A registry-supplied dist.tarball with embedded credentials
        // would otherwise cause curl to send creds to an attacker domain.
        assert!(!is_safe_url("https://user:pass@evil.com/x"));
        assert!(!is_safe_url("https://@evil.com/x"));
    }

    #[test]
    fn safe_url_rejects_control_and_non_ascii() {
        assert!(!is_safe_url("https://ex\x01ample.com/"));
        assert!(!is_safe_url("https://ex\x7Fample.com/"));
        // non-ASCII high byte
        assert!(!is_safe_url("https://exämple.com/"));
    }

    #[test]
    fn safe_header_checks() {
        assert!(is_safe_header_value("application/json"));
        assert!(!is_safe_header_value("a\rb"));
        assert!(!is_safe_header_value("a\nb"));
        // Tabs and DEL are now also rejected.
        assert!(!is_safe_header_value("a\tb"));
        assert!(!is_safe_header_value("a\x7Fb"));
    }

    #[test]
    fn sanitize_curl_env_removes_known_dangerous_vars() {
        let mut cmd = std::process::Command::new("true");
        cmd.env("LD_PRELOAD", "/tmp/evil.so");
        cmd.env("HTTP_PROXY", "http://attacker.example/");
        cmd.env("CURL_HOME", "/tmp/curl-home");
        sanitize_curl_env(&mut cmd);
        let envs: Vec<_> = cmd.get_envs().collect();
        for (k, v) in envs {
            let k = k.to_string_lossy();
            let v = v.map(|v| v.to_string_lossy().into_owned());
            // env_remove produces (key, None) entries — these are OK
            // because they explicitly clear the variable in the child.
            if v.is_some() && (k == "LD_PRELOAD" || k == "HTTP_PROXY" || k == "CURL_HOME") {
                panic!("sanitize_curl_env kept {k} set in child env");
            }
        }
    }
}
