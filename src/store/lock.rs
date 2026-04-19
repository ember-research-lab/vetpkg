use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub struct FileLock {
    path: PathBuf,
}

impl FileLock {
    pub fn acquire(target: &Path, wait: Duration, stale_after: Duration) -> io::Result<Self> {
        let path = lock_path(target);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let start = std::time::Instant::now();
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Self { path }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    if let Ok(meta) = fs::metadata(&path) {
                        if let Ok(mtime) = meta.modified() {
                            if SystemTime::now()
                                .duration_since(mtime)
                                .map(|d| d > stale_after)
                                .unwrap_or(false)
                            {
                                let _ = fs::remove_file(&path);
                                continue;
                            }
                        }
                    }
                    if start.elapsed() >= wait {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "lock held by another process",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

fn lock_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::TempDir;

    #[test]
    fn acquire_and_release() {
        let td = TempDir::new("vetpkg-lock").unwrap();
        let target = td.path().join("data.json");
        let _lock = FileLock::acquire(&target, Duration::from_millis(100), Duration::from_secs(60))
            .unwrap();
        drop(_lock);
        let _lock2 =
            FileLock::acquire(&target, Duration::from_millis(100), Duration::from_secs(60))
                .unwrap();
    }

    #[test]
    fn second_acquire_blocks() {
        let td = TempDir::new("vetpkg-lock").unwrap();
        let target = td.path().join("data.json");
        let _l1 =
            FileLock::acquire(&target, Duration::from_millis(50), Duration::from_secs(60)).unwrap();
        let l2 = FileLock::acquire(&target, Duration::from_millis(100), Duration::from_secs(60));
        assert!(l2.is_err());
    }
}
