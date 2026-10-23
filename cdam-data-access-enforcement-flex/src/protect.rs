// Copyright 2026 Salesforce, Inc. All rights reserved.
//! CDAM data protection techniques applied to one JSON value (no PDK imports).
//!
//! A data protection lists techniques per data type (`appliesToDataType`); the
//! technique for the value's JSON type is used, else the `UNKNOWN` (any type) one,
//! else the value is redacted with null.
//!
//! Supported: `RETAIN_FUNCTION`, `REDACT_WITH_NULL_FUNCTION` and `TRUNCATE_FUNCTION`
//! (keep the first or last N characters of a string). Tokenisation
//! (`TOKENISE_FUNCTION`, `NUMERIC_TOKENISE_FUNCTION`) needs CDAM's tokenisation keys,
//! which the gateway does not hold, so it is substituted with redact-with-null. Any
//! other technique is also redacted with null and reported as unsupported.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The technique was applied as CDAM defines it.
    Applied(String),
    /// A technique the gateway cannot reproduce; the value was redacted with null.
    Substituted(String),
    /// An unknown technique; the value was redacted with null.
    Unsupported(String),
}

impl Outcome {
    pub fn technique(&self) -> &str {
        match self {
            Outcome::Applied(t) | Outcome::Substituted(t) | Outcome::Unsupported(t) => t,
        }
    }
}

pub const REDACT: &str = "REDACT_WITH_NULL_FUNCTION";
const RETAIN: &str = "RETAIN_FUNCTION";
const TRUNCATE: &str = "TRUNCATE_FUNCTION";
const TOKENISE: &[&str] = &["TOKENISE_FUNCTION", "NUMERIC_TOKENISE_FUNCTION"];

/// The `appliesToDataType` values that match a JSON value, most specific first.
fn data_types(v: &Value) -> &'static [&'static str] {
    match v {
        Value::String(_) => &["STRING"],
        Value::Number(n) if n.is_i64() || n.is_u64() => &["INTEGER", "LONG", "BIGINT", "NUMBER", "NUMERIC", "DECIMAL"],
        Value::Number(_) => &["DECIMAL", "DOUBLE", "FLOAT", "NUMBER", "NUMERIC"],
        Value::Bool(_) => &["BOOLEAN"],
        _ => &[],
    }
}

/// The technique of a protection that applies to `v`.
pub fn select<'a>(techniques: &'a [Value], v: &Value) -> Option<&'a Value> {
    let applies = |t: &&Value| t.get("appliesToDataType").and_then(Value::as_str).unwrap_or("UNKNOWN").to_ascii_uppercase();
    for dt in data_types(v) {
        if let Some(t) = techniques.iter().find(|t| applies(t) == *dt) {
            return Some(t);
        }
    }
    techniques.iter().find(|t| applies(t) == "UNKNOWN")
}

fn truncate(s: &str, params: Option<&Value>) -> Option<String> {
    let p = params?;
    let n = match p.get("length")? {
        Value::String(s) => s.trim().parse::<usize>().ok()?,
        Value::Number(n) => n.as_u64()? as usize,
        _ => return None,
    };
    let chars: Vec<char> = s.chars().collect();
    let keep = n.min(chars.len());
    match p.get("behaviour").or_else(|| p.get("behavior")).and_then(Value::as_str)? {
        "PRESERVE_FIRST_FEW_CHARACTERS" => Some(chars[..keep].iter().collect()),
        "PRESERVE_LAST_FEW_CHARACTERS" => Some(chars[chars.len() - keep..].iter().collect()),
        _ => None,
    }
}

/// Apply a data protection's techniques to `v` in place. A null value stays null.
pub fn protect(v: &mut Value, techniques: &[Value]) -> Outcome {
    let Some(t) = select(techniques, v) else {
        *v = Value::Null;
        return Outcome::Applied(REDACT.to_string());
    };
    let kind = t.get("dataProtectionTechniqueType").and_then(Value::as_str).unwrap_or("").to_string();
    match kind.as_str() {
        RETAIN => Outcome::Applied(kind),
        REDACT => {
            *v = Value::Null;
            Outcome::Applied(kind)
        }
        TRUNCATE => match v.as_str().and_then(|s| truncate(s, t.get("parameters"))) {
            Some(s) => {
                *v = Value::String(s);
                Outcome::Applied(kind)
            }
            None if v.is_null() => Outcome::Applied(kind),
            None => {
                *v = Value::Null;
                Outcome::Unsupported(kind)
            }
        },
        k if TOKENISE.contains(&k) => {
            *v = Value::Null;
            Outcome::Substituted(kind)
        }
        _ => {
            *v = Value::Null;
            Outcome::Unsupported(kind)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tech(kind: &str, dt: &str, params: Value) -> Value {
        json!({"dataProtectionTechniqueType": kind, "appliesToDataType": dt, "parameters": params})
    }

    #[test]
    fn truncate_first_and_last() {
        let last4 = [tech(REDACT, "UNKNOWN", Value::Null),
                     tech(TRUNCATE, "STRING", json!({"length": "4", "behaviour": "PRESERVE_LAST_FEW_CHARACTERS"}))];
        let mut v = json!("4111-1111-1111-1234");
        assert_eq!(protect(&mut v, &last4), Outcome::Applied(TRUNCATE.into()));
        assert_eq!(v, json!("1234"));
        let year = [tech(TRUNCATE, "STRING", json!({"length": 4, "behaviour": "PRESERVE_FIRST_FEW_CHARACTERS"}))];
        let mut v = json!("1985-03-12");
        protect(&mut v, &year);
        assert_eq!(v, json!("1985"));
        let mut short = json!("ab");
        protect(&mut short, &last4);
        assert_eq!(short, json!("ab"));
    }

    #[test]
    fn type_specific_then_unknown_then_redact() {
        let t = [tech(REDACT, "UNKNOWN", Value::Null), tech(RETAIN, "STRING", Value::Null)];
        let mut s = json!("x");
        assert_eq!(protect(&mut s, &t), Outcome::Applied(RETAIN.into()));
        assert_eq!(s, json!("x"));
        let mut n = json!(12.5);
        assert_eq!(protect(&mut n, &t), Outcome::Applied(REDACT.into()));
        assert_eq!(n, Value::Null);
        let only_string = [tech(RETAIN, "STRING", Value::Null)];
        let mut i = json!(7);
        assert_eq!(protect(&mut i, &only_string), Outcome::Applied(REDACT.into()));
        assert_eq!(i, Value::Null);
        let int = [tech(RETAIN, "INTEGER", Value::Null)];
        let mut i = json!(7);
        protect(&mut i, &int);
        assert_eq!(i, json!(7));
    }

    #[test]
    fn tokenise_is_substituted_and_unknown_is_redacted() {
        let tok = [tech(REDACT, "UNKNOWN", Value::Null), tech("TOKENISE_FUNCTION", "STRING", json!({"regex": ".*", "consistent": true}))];
        let mut v = json!("gina@example.com");
        assert_eq!(protect(&mut v, &tok), Outcome::Substituted("TOKENISE_FUNCTION".into()));
        assert_eq!(v, Value::Null);
        let odd = [tech("SHUFFLE_FUNCTION", "UNKNOWN", Value::Null)];
        let mut v = json!("x");
        assert_eq!(protect(&mut v, &odd), Outcome::Unsupported("SHUFFLE_FUNCTION".into()));
        assert_eq!(v, Value::Null);
        let bad = [tech(TRUNCATE, "UNKNOWN", json!({"length": "x"}))];
        let mut v = json!("abcdef");
        assert_eq!(protect(&mut v, &bad), Outcome::Unsupported(TRUNCATE.into()));
        assert_eq!(v, Value::Null);
    }
}
