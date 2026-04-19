pub fn inflate(_data: &[u8]) -> Result<Vec<u8>, String> {
    Err("DEFLATE not yet implemented (Phase 0 follow-up: 2-day pure-Rust timebox, then vendor miniz.c)".into())
}

pub fn inflate_available() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_reports_unavailable() {
        assert!(!inflate_available());
        assert!(inflate(&[]).is_err());
    }
}
