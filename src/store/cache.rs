use crate::json::{parse, to_json_string, JsonValue};
use crate::store::lock::FileLock;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct Store {
    base_dir: PathBuf,
    analysis: HashMap<String, JsonValue>,
}

impl Store {
    pub fn open(base_dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(base_dir).map_err(|e| format!("create {:?}: {e}", base_dir))?;
        let analysis_path = base_dir.join("analysis.json");
        let analysis = load_map(&analysis_path)?;
        Ok(Self {
            base_dir: base_dir.to_path_buf(),
            analysis,
        })
    }

    pub fn get_analysis(&self, eco: &str, pkg: &str, ver: &str) -> Option<&JsonValue> {
        self.analysis.get(&key(eco, pkg, ver))
    }

    pub fn put_analysis(
        &mut self,
        eco: &str,
        pkg: &str,
        ver: &str,
        data: JsonValue,
    ) -> Result<(), String> {
        self.analysis.insert(key(eco, pkg, ver), data);
        let path = self.base_dir.join("analysis.json");
        write_map(&path, &self.analysis)
    }

    pub fn len(&self) -> usize {
        self.analysis.len()
    }

    pub fn is_empty(&self) -> bool {
        self.analysis.is_empty()
    }
}

fn key(eco: &str, pkg: &str, ver: &str) -> String {
    format!("{eco}:{pkg}:{ver}")
}

fn load_map(path: &Path) -> Result<HashMap<String, JsonValue>, String> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let text = fs::read_to_string(path).map_err(|e| format!("read {:?}: {e}", path))?;
    if text.trim().is_empty() {
        return Ok(HashMap::new());
    }
    let v = parse(&text).map_err(|e| format!("parse {:?}: {e}", path))?;
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{:?}: expected object", path))?;
    let mut m = HashMap::new();
    for (k, val) in obj {
        m.insert(k.clone(), val.clone());
    }
    Ok(m)
}

fn write_map(path: &Path, map: &HashMap<String, JsonValue>) -> Result<(), String> {
    let _lock = FileLock::acquire(path, Duration::from_secs(5), Duration::from_secs(60))
        .map_err(|e| format!("lock {:?}: {e}", path))?;
    let mut obj: Vec<(String, JsonValue)> =
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    obj.sort_by(|a, b| a.0.cmp(&b.0));
    let json = to_json_string(&JsonValue::Object(obj));

    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(|e| format!("create {:?}: {e}", tmp))?;
        f.write_all(json.as_bytes())
            .map_err(|e| format!("write {:?}: {e}", tmp))?;
        f.sync_all().map_err(|e| format!("sync {:?}: {e}", tmp))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("rename {:?}->{:?}: {e}", tmp, path))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::TempDir;

    #[test]
    fn put_get_persists() {
        let td = TempDir::new("vetpkg-store").unwrap();
        {
            let mut s = Store::open(td.path()).unwrap();
            s.put_analysis("npm", "express", "4.18.2", JsonValue::Number(0.05))
                .unwrap();
        }
        let s2 = Store::open(td.path()).unwrap();
        let v = s2.get_analysis("npm", "express", "4.18.2").unwrap();
        assert_eq!(v.as_f64(), Some(0.05));
    }

    #[test]
    fn fresh_store_is_empty() {
        let td = TempDir::new("vetpkg-store").unwrap();
        let s = Store::open(td.path()).unwrap();
        assert!(s.is_empty());
    }
}
