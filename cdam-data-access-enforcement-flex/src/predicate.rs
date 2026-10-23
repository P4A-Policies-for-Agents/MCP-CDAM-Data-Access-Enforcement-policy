// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Evaluator for CDAM's `structured-predicate` conditions (no PDK imports).
//!
//! A CDAM condition is `{"dialect":"structured-predicate","version":"1.0","predicate":P}`
//! where P nests `and` / `or` / `not` around `isAnyOf` / `isNotAnyOf` comparisons:
//! `{"isAnyOf":[subject, constant...]}`. A subject is a request-context path
//! (`{"path":"context::request.usage"}`) or a record field located by classification
//! (`{"fieldValue":{"fieldLocatorQuery":{...}}}`).
//!
//! Evaluation is three-valued: anything this gateway does not understand (an operator,
//! dialect, context path or locator) is `Unknown`, and callers resolve `Unknown`
//! toward the more protective outcome.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tri {
    True,
    False,
    Unknown,
}

/// What a predicate can look up. `None` means the path or locator is not supported.
pub trait Env {
    /// Values of a request-context path such as `context::request.usage`.
    fn context(&self, path: &str) -> Option<Vec<String>>;
    /// Values of the record fields a `fieldLocatorQuery` selects (empty = absent).
    fn field(&self, locator: &Value) -> Option<Vec<String>>;
}

/// Evaluate a condition wrapper. A missing or null condition always holds.
pub fn eval_condition(cond: Option<&Value>, env: &dyn Env) -> Tri {
    match cond {
        None | Some(Value::Null) => Tri::True,
        Some(c) => {
            if c.get("dialect").and_then(Value::as_str) != Some("structured-predicate") {
                return Tri::Unknown;
            }
            match c.get("predicate") {
                Some(p) => eval(p, env),
                None => Tri::Unknown,
            }
        }
    }
}

/// Evaluate one predicate node.
pub fn eval(p: &Value, env: &dyn Env) -> Tri {
    let Some(obj) = p.as_object() else { return Tri::Unknown };
    if obj.len() != 1 {
        return Tri::Unknown;
    }
    let (op, arg) = obj.iter().next().unwrap();
    match op.as_str() {
        "and" => all(arg, env),
        "or" => any(arg, env),
        "not" => match eval(arg, env) {
            Tri::True => Tri::False,
            Tri::False => Tri::True,
            Tri::Unknown => Tri::Unknown,
        },
        "isAnyOf" => member(arg, env),
        "isNotAnyOf" => match member(arg, env) {
            Tri::True => Tri::False,
            Tri::False => Tri::True,
            Tri::Unknown => Tri::Unknown,
        },
        _ => Tri::Unknown,
    }
}

fn all(arg: &Value, env: &dyn Env) -> Tri {
    let Some(items) = arg.as_array() else { return Tri::Unknown };
    let mut unknown = false;
    for i in items {
        match eval(i, env) {
            Tri::False => return Tri::False,
            Tri::Unknown => unknown = true,
            Tri::True => {}
        }
    }
    if unknown { Tri::Unknown } else { Tri::True }
}

fn any(arg: &Value, env: &dyn Env) -> Tri {
    let Some(items) = arg.as_array() else { return Tri::Unknown };
    let mut unknown = false;
    for i in items {
        match eval(i, env) {
            Tri::True => return Tri::True,
            Tri::Unknown => unknown = true,
            Tri::False => {}
        }
    }
    if unknown { Tri::Unknown } else { Tri::False }
}

/// `[subject, constant...]`: true when any subject value equals any constant.
fn member(arg: &Value, env: &dyn Env) -> Tri {
    let Some(items) = arg.as_array() else { return Tri::Unknown };
    let Some((subject, constants)) = items.split_first() else { return Tri::Unknown };
    let Some(values) = subject_values(subject, env) else { return Tri::Unknown };
    let mut wanted = Vec::new();
    for c in constants {
        match c.get("constant") {
            Some(v) => flatten_constant(v, &mut wanted),
            None => return Tri::Unknown,
        }
    }
    if values.iter().any(|v| wanted.contains(v)) { Tri::True } else { Tri::False }
}

fn subject_values(subject: &Value, env: &dyn Env) -> Option<Vec<String>> {
    if let Some(path) = subject.get("path").and_then(Value::as_str) {
        return env.context(path);
    }
    let locator = subject.get("fieldValue")?.get("fieldLocatorQuery")?;
    env.field(locator)
}

/// A constant is a string or number, an identifier object (`{"__type":
/// "group_identifier","id":...}`), or an array of those.
fn flatten_constant(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Array(a) => a.iter().for_each(|x| flatten_constant(x, out)),
        Value::Object(o) => {
            if let Some(id) = o.get("id").and_then(Value::as_str) {
                out.push(id.to_string());
            }
        }
        other => {
            if let Some(s) = scalar(other) {
                out.push(s);
            }
        }
    }
}

/// A JSON scalar as a comparable string (strings are trimmed).
pub fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Every `fieldLocatorQuery` inside a predicate (used to find a filter's record level).
pub fn field_locators<'a>(p: &'a Value, out: &mut Vec<&'a Value>) {
    match p {
        Value::Object(o) => {
            if let Some(l) = o.get("fieldLocatorQuery") {
                out.push(l);
            }
            o.values().for_each(|v| field_locators(v, out));
        }
        Value::Array(a) => a.iter().for_each(|v| field_locators(v, out)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct E {
        usage: Vec<String>,
        groups: Vec<String>,
        country: Option<Vec<String>>,
    }
    impl Env for E {
        fn context(&self, path: &str) -> Option<Vec<String>> {
            match path {
                "context::request.usage" => Some(self.usage.clone()),
                "context::principal.groups" => Some(self.groups.clone()),
                _ => None,
            }
        }
        fn field(&self, _locator: &Value) -> Option<Vec<String>> {
            self.country.clone()
        }
    }
    fn env(usage: &[&str], groups: &[&str]) -> E {
        E { usage: usage.iter().map(|s| s.to_string()).collect(), groups: groups.iter().map(|s| s.to_string()).collect(), country: Some(vec![]) }
    }
    fn cond(p: Value) -> Value {
        json!({"dialect": "structured-predicate", "version": "1.0", "predicate": p})
    }

    #[test]
    fn usage_or_group() {
        let c = cond(json!({"or": [
            {"isAnyOf": [{"path": "context::request.usage"}, {"constant": "U-REG"}]},
            {"isAnyOf": [{"path": "context::principal.groups"}, {"constant": {"__type": "group_identifier", "type": "IDMC", "id": "G-1"}}]}
        ]}));
        assert_eq!(eval_condition(Some(&c), &env(&["U-REG"], &[])), Tri::True);
        assert_eq!(eval_condition(Some(&c), &env(&[], &["G-0", "G-1"])), Tri::True);
        assert_eq!(eval_condition(Some(&c), &env(&["U-AN"], &["G-0"])), Tri::False);
        assert_eq!(eval_condition(Some(&c), &env(&[], &[])), Tri::False);
    }

    #[test]
    fn missing_condition_holds_and_unknowns_propagate() {
        assert_eq!(eval_condition(None, &env(&[], &[])), Tri::True);
        assert_eq!(eval_condition(Some(&Value::Null), &env(&[], &[])), Tri::True);
        let other = json!({"dialect": "knowledge-graph-search", "query": {}});
        assert_eq!(eval_condition(Some(&other), &env(&[], &[])), Tri::Unknown);
        let p = cond(json!({"or": [
            {"isAnyOf": [{"path": "context::principal.department"}, {"constant": "x"}]},
            {"isAnyOf": [{"path": "context::request.usage"}, {"constant": "U"}]}
        ]}));
        assert_eq!(eval_condition(Some(&p), &env(&["U"], &[])), Tri::True); // or: a true branch wins
        assert_eq!(eval_condition(Some(&p), &env(&[], &[])), Tri::Unknown);
        let a = cond(json!({"and": [{"bogusOp": []}, {"isAnyOf": [{"path": "context::request.usage"}, {"constant": "U"}]}]}));
        assert_eq!(eval_condition(Some(&a), &env(&[], &[])), Tri::False); // and: a false branch wins
        assert_eq!(eval_condition(Some(&a), &env(&["U"], &[])), Tri::Unknown);
    }

    #[test]
    fn not_any_of_on_record_field() {
        let p = json!({"or": [{"isNotAnyOf": [
            {"fieldValue": {"fieldLocatorQuery": {"dialect": "basic-object-locator", "query": {"path": "cdgc::dataelement.classifications[*].id", "value": "C"}}, "type": "STRING"}},
            {"constant": "United States"}
        ]}]});
        let mut e = env(&[], &[]);
        e.country = Some(vec!["United States".into()]);
        assert_eq!(eval(&p, &e), Tri::False);
        e.country = Some(vec!["Germany".into()]);
        assert_eq!(eval(&p, &e), Tri::True);
        e.country = Some(vec![]); // absent value is "not any of"
        assert_eq!(eval(&p, &e), Tri::True);
        e.country = None;
        assert_eq!(eval(&p, &e), Tri::Unknown);
        let mut locs = Vec::new();
        field_locators(&p, &mut locs);
        assert_eq!(locs.len(), 1);
    }

    #[test]
    fn not_and_constant_arrays() {
        let p = json!({"not": {"isAnyOf": [{"path": "context::request.usage"}, {"constant": ["A", "B"]}]}});
        assert_eq!(eval(&p, &env(&["B"], &[])), Tri::False);
        assert_eq!(eval(&p, &env(&["C"], &[])), Tri::True);
        assert_eq!(eval(&json!({"isAnyOf": [{"path": "context::request.usage"}, {"bad": 1}]}), &env(&["A"], &[])), Tri::Unknown);
        assert_eq!(eval(&json!("x"), &env(&[], &[])), Tri::Unknown);
    }
}
