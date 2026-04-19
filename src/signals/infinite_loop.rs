//! InfiniteLoop: Tier 2 signal for sabotage-style payloads like the 2022
//! colors/faker incident — the malicious behaviour lives in top-level source
//! code, not an install hook, and the attack is deliberate denial-of-service
//! by starving the event loop.
//!
//! Narrow by design. We only flag syntactically obvious cases:
//!   - `while (true)` / `while(true)`
//!   - `for (;;)` / `for(;;)`
//!   - `do { ... } while (true);`
//!
//! Comments (`//` prefix, trailing ` //`, `/* … */` block) are stripped
//! before matching. Strings are not excluded — a pragmatic trade-off.

use crate::types::Signal;

pub fn scan_content(file: &str, content: &str) -> Vec<Signal> {
    let mut out = Vec::new();
    let mut in_block_comment = false;
    for raw in content.lines() {
        let cleaned = strip_comments(raw, &mut in_block_comment);
        if cleaned.trim().is_empty() {
            continue;
        }
        let no_space: String = cleaned.chars().filter(|c| !c.is_whitespace()).collect();
        for pat in &["while(true)", "while(!false)", "for(;;)", "do{}while(true)"] {
            if no_space.contains(pat) {
                out.push(Signal::InfiniteLoop {
                    file: file.to_string(),
                    pattern: (*pat).to_string(),
                });
                return out;
            }
        }
    }
    out
}

fn strip_comments(raw: &str, in_block: &mut bool) -> String {
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if *in_block {
            if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                *in_block = false;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            *in_block = true;
            i += 2;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            break;
        }
        if bytes[i] == b'#' {
            break;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_while_true() {
        let sigs = scan_content("a.js", "while (true) { console.log('x'); }\n");
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn catches_for_empty() {
        let sigs = scan_content("a.js", "for(;;) { doWork(); }\n");
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn comments_do_not_trigger() {
        let sigs = scan_content("a.js", "// while (true) never executes\n");
        assert!(sigs.is_empty());
    }

    #[test]
    fn block_comment_stripped() {
        let sigs = scan_content("a.js", "/* while(true) */ const x = 1;\n");
        assert!(sigs.is_empty());
    }

    #[test]
    fn clean_code_does_not_trigger() {
        let sigs = scan_content(
            "a.js",
            "while (x > 0) { x -= 1; }\nfor (let i = 0; i < n; i++) {}\n",
        );
        assert!(sigs.is_empty());
    }
}
