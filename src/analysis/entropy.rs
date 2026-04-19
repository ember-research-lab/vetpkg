pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for c in counts.iter() {
        if *c == 0 {
            continue;
        }
        let p = *c as f64 / len;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeros_have_zero_entropy() {
        assert_eq!(shannon_entropy(&[0u8; 1024]), 0.0);
    }

    #[test]
    fn uniform_has_max_entropy() {
        let data: Vec<u8> = (0u32..256 * 10).map(|i| (i & 0xff) as u8).collect();
        let h = shannon_entropy(&data);
        assert!((h - 8.0).abs() < 1e-6, "entropy = {h}");
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn english_in_reasonable_range() {
        let s = b"the quick brown fox jumps over the lazy dog. the quick brown fox jumps over the lazy dog.";
        let h = shannon_entropy(s);
        assert!((3.5..=5.5).contains(&h), "english entropy = {h}");
    }
}
