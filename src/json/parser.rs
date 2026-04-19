use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    Str(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub msg: String,
    pub pos: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.msg, self.pos)
    }
}

impl std::error::Error for ParseError {}

impl JsonValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&[(String, JsonValue)]> {
        match self {
            JsonValue::Object(o) => Some(o),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, JsonValue::Null)
    }
}

pub fn parse(s: &str) -> Result<JsonValue, ParseError> {
    let bytes = s.as_bytes();
    let mut p = Parser { bytes, pos: 0 };
    p.skip_ws();
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos != bytes.len() {
        return Err(p.err("trailing content after value"));
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, msg: &str) -> ParseError {
        ParseError {
            msg: msg.to_string(),
            pos: self.pos,
        }
    }
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }
    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }
    fn expect(&mut self, c: u8) -> Result<(), ParseError> {
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected '{}'", c as char)))
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, ParseError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => self.parse_string().map(JsonValue::Str),
            Some(b't') | Some(b'f') => self.parse_bool(),
            Some(b'n') => self.parse_null(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(c) => Err(self.err(&format!("unexpected byte 0x{:02x}", c))),
            None => Err(self.err("unexpected EOF")),
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, ParseError> {
        self.expect(b'{')?;
        self.skip_ws();
        let mut out = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(out));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let v = self.parse_value()?;
            out.push((key, v));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
        Ok(JsonValue::Object(out))
    }

    fn parse_array(&mut self) -> Result<JsonValue, ParseError> {
        self.expect(b'[')?;
        self.skip_ws();
        let mut out = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(out));
        }
        loop {
            out.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
        Ok(JsonValue::Array(out))
    }

    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self.bump().ok_or_else(|| ParseError {
                msg: "unterminated string".into(),
                pos: self.pos,
            })?;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.bump().ok_or_else(|| ParseError {
                        msg: "dangling escape".into(),
                        pos: self.pos,
                    })?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\x08'),
                        b'f' => out.push('\x0c'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&hi) {
                                if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                    return Err(self.err("expected low surrogate"));
                                }
                                let lo = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return Err(self.err("invalid low surrogate"));
                                }
                                let cp =
                                    0x10000 + (((hi as u32 - 0xD800) << 10) | (lo as u32 - 0xDC00));
                                if let Some(c) = char::from_u32(cp) {
                                    out.push(c);
                                } else {
                                    return Err(self.err("invalid surrogate codepoint"));
                                }
                            } else if (0xDC00..=0xDFFF).contains(&hi) {
                                return Err(self.err("orphan low surrogate"));
                            } else if let Some(c) = char::from_u32(hi as u32) {
                                out.push(c);
                            } else {
                                return Err(self.err("invalid codepoint"));
                            }
                        }
                        other => return Err(self.err(&format!("bad escape \\{}", other as char))),
                    }
                }
                b if b < 0x20 => return Err(self.err("control char in string")),
                b => {
                    if b < 0x80 {
                        out.push(b as char);
                    } else {
                        let start = self.pos - 1;
                        let len = utf8_len(b).ok_or_else(|| ParseError {
                            msg: "bad utf-8 lead byte".into(),
                            pos: start,
                        })?;
                        for _ in 1..len {
                            self.bump().ok_or_else(|| ParseError {
                                msg: "truncated utf-8".into(),
                                pos: self.pos,
                            })?;
                        }
                        let chunk = &self.bytes[start..self.pos];
                        match std::str::from_utf8(chunk) {
                            Ok(s) => out.push_str(s),
                            Err(_) => return Err(self.err("invalid utf-8 in string")),
                        }
                    }
                }
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, ParseError> {
        let mut v = 0u16;
        for _ in 0..4 {
            let b = self.bump().ok_or_else(|| ParseError {
                msg: "truncated \\uXXXX".into(),
                pos: self.pos,
            })?;
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(self.err("bad hex digit")),
            };
            v = (v << 4) | d as u16;
        }
        Ok(v)
    }

    fn parse_bool(&mut self) -> Result<JsonValue, ParseError> {
        if self.bytes[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(JsonValue::Bool(true))
        } else if self.bytes[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(JsonValue::Bool(false))
        } else {
            Err(self.err("bad literal"))
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, ParseError> {
        if self.bytes[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(JsonValue::Null)
        } else {
            Err(self.err("bad literal"))
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            while let Some(b) = self.peek() {
                if b.is_ascii_digit() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            while let Some(b) = self.peek() {
                if b.is_ascii_digit() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| ParseError {
            msg: "bad number utf-8".into(),
            pos: start,
        })?;
        let n: f64 = s.parse().map_err(|_| ParseError {
            msg: format!("bad number: {s}"),
            pos: start,
        })?;
        Ok(JsonValue::Number(n))
    }
}

fn utf8_len(lead: u8) -> Option<usize> {
    if lead < 0x80 {
        Some(1)
    } else if lead & 0xe0 == 0xc0 {
        Some(2)
    } else if lead & 0xf0 == 0xe0 {
        Some(3)
    } else if lead & 0xf8 == 0xf0 {
        Some(4)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives() {
        assert_eq!(parse("null").unwrap(), JsonValue::Null);
        assert_eq!(parse("true").unwrap(), JsonValue::Bool(true));
        assert_eq!(parse("false").unwrap(), JsonValue::Bool(false));
        assert_eq!(parse("42").unwrap(), JsonValue::Number(42.0));
        assert_eq!(parse("-1.5").unwrap(), JsonValue::Number(-1.5));
        assert_eq!(parse("1e3").unwrap(), JsonValue::Number(1000.0));
        assert_eq!(parse("\"hi\"").unwrap(), JsonValue::Str("hi".into()));
    }

    #[test]
    fn empty_structures() {
        assert_eq!(parse("[]").unwrap(), JsonValue::Array(vec![]));
        assert_eq!(parse("{}").unwrap(), JsonValue::Object(vec![]));
    }

    #[test]
    fn nested() {
        let v = parse(r#"{"a":[1,{"b":"c"}]}"#).unwrap();
        let a = v.get("a").unwrap().as_array().unwrap();
        assert_eq!(a[0], JsonValue::Number(1.0));
        assert_eq!(a[1].get("b").unwrap().as_str().unwrap(), "c");
    }

    #[test]
    fn string_escapes() {
        let v = parse(r#""\n\t\\\"\u0041""#).unwrap();
        assert_eq!(v.as_str().unwrap(), "\n\t\\\"A");
    }

    #[test]
    fn surrogate_pair_emoji() {
        let v = parse(r#""\uD83D\uDE00""#).unwrap();
        assert_eq!(v.as_str().unwrap(), "😀");
    }

    #[test]
    fn unterminated_string_is_error() {
        assert!(parse("\"abc").is_err());
    }

    #[test]
    fn trailing_comma_is_error() {
        assert!(parse(r#"[1,2,]"#).is_err());
        assert!(parse(r#"{"a":1,}"#).is_err());
    }

    #[test]
    fn trailing_garbage_is_error() {
        assert!(parse("[] junk").is_err());
    }
}
