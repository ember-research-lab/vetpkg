use super::parser::JsonValue;

pub fn to_json_string(v: &JsonValue) -> String {
    let mut out = String::new();
    write_value(v, &mut out);
    out
}

fn write_value(v: &JsonValue, out: &mut String) {
    match v {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Number(n) => write_number(*n, out),
        JsonValue::Str(s) => write_string(s, out),
        JsonValue::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        JsonValue::Object(obj) => {
            out.push('{');
            for (i, (k, val)) in obj.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(val, out);
            }
            out.push('}');
        }
    }
}

fn write_number(n: f64, out: &mut String) {
    if n.is_nan() || n.is_infinite() {
        out.push_str("null");
        return;
    }
    if n == n.trunc() && n.abs() < 1e16 {
        out.push_str(&format!("{}", n as i64));
    } else {
        out.push_str(&format!("{}", n));
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parser::parse;

    #[test]
    fn round_trip_primitive() {
        let samples = ["null", "true", "false", "42", "-3.14", "\"hi\""];
        for s in samples {
            let v = parse(s).unwrap();
            let out = to_json_string(&v);
            let v2 = parse(&out).unwrap();
            assert_eq!(v, v2, "{} -> {}", s, out);
        }
    }

    #[test]
    fn round_trip_nested() {
        let input = r#"{"a":[1,{"b":"c"},null],"d":true}"#;
        let v = parse(input).unwrap();
        let out = to_json_string(&v);
        let v2 = parse(&out).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn escapes_control_chars() {
        let v = JsonValue::Str("\n\t\x01".into());
        let out = to_json_string(&v);
        let parsed = parse(&out).unwrap();
        assert_eq!(parsed.as_str().unwrap(), "\n\t\x01");
    }
}
