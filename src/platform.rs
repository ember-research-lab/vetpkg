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

pub fn is_safe_header_value(s: &str) -> bool {
    !s.chars().any(|c| c == '\r' || c == '\n' || c == '\0')
}

pub fn is_safe_url(s: &str) -> bool {
    if !s.starts_with("http://") && !s.starts_with("https://") {
        return false;
    }
    !s.chars()
        .any(|c| c == '\r' || c == '\n' || c == '\0' || c == ' ')
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
    fn safe_header_checks() {
        assert!(is_safe_header_value("application/json"));
        assert!(!is_safe_header_value("a\rb"));
        assert!(!is_safe_header_value("a\nb"));
    }
}
