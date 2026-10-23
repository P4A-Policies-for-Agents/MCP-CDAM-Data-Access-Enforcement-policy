// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Applying CDAM to an MCP tool result payload (no PDK imports).
//!
//! A catalog field's name is its path in the payload: `orders[].iban`,
//! `$.orders[*].iban` or `header.customer_name`. A field's *record* is the element of
//! the innermost array on its path (an order for `orders[].iban`); a field outside
//! any array belongs to the whole payload.
//!
//! Data filters run first: a filter rule's predicate is evaluated per record, with
//! each `fieldValue` resolved through the catalog fields its locator selects, and the
//! records it matches (or cannot decide) are removed. Then every governed field is
//! de-identified per the CDAM decision.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::cdam::{applicable_filters, decide, locator_matches, techniques, Caller, Decision, GovernedField, PolicySet};
use crate::predicate::{eval_condition, field_locators, scalar, Env, Tri};
use crate::protect::{protect, Outcome, REDACT};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg {
    Key(String),
    Each,
}

/// Parse a field path: `a.b`, `a[].b`, `a[*].b`, `$.a[*].b`, `a/b`.
pub fn segments(path: &str) -> Vec<Seg> {
    let p = path.trim();
    let p = p.strip_prefix("$.").or_else(|| p.strip_prefix('$')).unwrap_or(p);
    let mut out = Vec::new();
    for part in p.split(['.', '/']).filter(|s| !s.is_empty()) {
        let mut rest = part;
        let mut arrays = 0;
        while let Some(r) = rest.strip_suffix("[]").or_else(|| rest.strip_suffix("[*]")) {
            rest = r;
            arrays += 1;
        }
        if !rest.is_empty() {
            out.push(Seg::Key(rest.to_string()));
        }
        out.extend(std::iter::repeat(Seg::Each).take(arrays));
    }
    out
}

/// The record prefix (up to and including the innermost `Each`; empty = the whole
/// payload) and the field's path within the record.
fn split_record(segs: &[Seg]) -> (&[Seg], &[Seg]) {
    let i = segs.iter().rposition(|s| *s == Seg::Each).map_or(0, |i| i + 1);
    (&segs[..i], &segs[i..])
}

pub fn values_at<'a>(v: &'a Value, segs: &[Seg], out: &mut Vec<&'a Value>) {
    match segs.split_first() {
        None => out.push(v),
        Some((Seg::Key(k), rest)) => {
            if let Some(c) = v.get(k.as_str()) {
                values_at(c, rest, out);
            }
        }
        Some((Seg::Each, rest)) => {
            if let Some(a) = v.as_array() {
                a.iter().for_each(|e| values_at(e, rest, out));
            }
        }
    }
}

/// Visit every existing value at `segs` (keys are never created).
pub fn for_each_mut(v: &mut Value, segs: &[Seg], f: &mut dyn FnMut(&mut Value)) {
    match segs.split_first() {
        None => f(v),
        Some((Seg::Key(k), rest)) => {
            if let Some(c) = v.get_mut(k.as_str()) {
                for_each_mut(c, rest, f);
            }
        }
        Some((Seg::Each, rest)) => {
            if let Some(a) = v.as_array_mut() {
                a.iter_mut().for_each(|e| for_each_mut(e, rest, f));
            }
        }
    }
}

/// A record and the catalog fields that live in it, for a filter predicate.
struct RecordEnv<'a> {
    caller: &'a Caller,
    record: &'a Value,
    /// Fields of the tool: (field, record prefix, path within the record).
    fields: &'a [(&'a GovernedField, Vec<Seg>, Vec<Seg>)],
    prefix: &'a [Seg],
}

impl Env for RecordEnv<'_> {
    fn context(&self, path: &str) -> Option<Vec<String>> {
        self.caller.context(path)
    }
    fn field(&self, locator: &Value) -> Option<Vec<String>> {
        let mut out = Vec::new();
        for (f, prefix, rel) in self.fields {
            match locator_matches(locator, f) {
                None => return None,
                Some(false) => continue,
                Some(true) if prefix.as_slice() != self.prefix => return None, // another record level
                Some(true) => {
                    let mut vs = Vec::new();
                    values_at(self.record, rel, &mut vs);
                    out.extend(vs.into_iter().filter_map(scalar));
                }
            }
        }
        Some(out)
    }
}

/// What enforcing CDAM did to a payload.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    /// Field path → technique, for fields that were not retained as is.
    pub fields: BTreeMap<String, String>,
    /// Fields whose technique was substituted with redact-with-null (e.g. tokenise).
    pub substituted: Vec<String>,
    pub unsupported: Vec<String>,
    /// Policies that could not be evaluated (their fields were redacted with null).
    pub uncertain: Vec<String>,
    /// Applied data filter rules ("policy / rule").
    pub filters: Vec<String>,
    pub rows_removed: usize,
}

impl Report {
    pub fn to_json(&self) -> Value {
        json!({
            "fields": self.fields,
            "substituted": self.substituted,
            "unsupported": self.unsupported,
            "uncertain": self.uncertain,
            "filters": self.filters,
            "rowsRemoved": self.rows_removed,
        })
    }
}

/// Field decisions for a tool (computed once per call, before the body is read).
pub fn plan(fields: &[GovernedField], caller: &Caller, set: &PolicySet, now_ms: i64) -> Vec<(GovernedField, Decision)> {
    fields.iter().map(|f| (f.clone(), decide(f, caller, set, now_ms))).collect()
}

/// Apply the data filters, then the de-identification plan, to a tool result payload.
pub fn enforce(payload: &mut Value, plan: &[(GovernedField, Decision)], caller: &Caller, set: &PolicySet, now_ms: i64) -> Report {
    let mut report = Report::default();
    let fields: Vec<GovernedField> = plan.iter().map(|(f, _)| f.clone()).collect();
    apply_filters(payload, &fields, caller, set, now_ms, &mut report);

    for (field, decision) in plan {
        let segs = segments(&field.path);
        let mut present = false;
        let mut outcome: Option<Outcome> = None;
        match decision {
            Decision::Retain => continue,
            Decision::DefaultRedact | Decision::Uncertain { .. } => {
                for_each_mut(payload, &segs, &mut |v| {
                    present = true;
                    *v = Value::Null;
                });
                if let Decision::Uncertain { policy } = decision {
                    if !report.uncertain.contains(policy) {
                        report.uncertain.push(policy.clone());
                    }
                }
                outcome = Some(Outcome::Applied(REDACT.to_string()));
            }
            Decision::Protect { protection_id, .. } => {
                let t = techniques(set, protection_id).map(|(_, t)| t).unwrap_or(&[]);
                for_each_mut(payload, &segs, &mut |v| {
                    present = true;
                    let o = protect(v, t);
                    // Report the strongest outcome seen across the field's values.
                    if outcome.as_ref().is_none_or(|prev| matches!(prev, Outcome::Applied(_))) {
                        outcome = Some(o);
                    }
                });
            }
        }
        let Some(o) = outcome.filter(|_| present) else { continue };
        if o.technique() == "RETAIN_FUNCTION" {
            continue;
        }
        match &o {
            Outcome::Substituted(_) => report.substituted.push(field.path.clone()),
            Outcome::Unsupported(_) => report.unsupported.push(field.path.clone()),
            Outcome::Applied(_) => {}
        }
        report.fields.insert(field.path.clone(), o.technique().to_string());
    }
    report
}

fn apply_filters(payload: &mut Value, fields: &[GovernedField], caller: &Caller, set: &PolicySet, now_ms: i64, report: &mut Report) {
    let located: Vec<(&GovernedField, Vec<Seg>, Vec<Seg>)> = fields.iter().map(|f| {
        let segs = segments(&f.path);
        let (prefix, rel) = split_record(&segs);
        (f, prefix.to_vec(), rel.to_vec())
    }).collect();

    for rule in applicable_filters(set, caller, now_ms) {
        let predicate = rule.filter.get("predicate").unwrap_or(&Value::Null);
        let mut locs = Vec::new();
        field_locators(predicate, &mut locs);
        // The record levels of the fields the filter refers to. A filter on fields this
        // tool does not return does not apply to it.
        let mut prefixes: Vec<Vec<Seg>> = Vec::new();
        let mut unsupported_locator = false;
        for l in &locs {
            for (f, prefix, _) in &located {
                match locator_matches(l, f) {
                    Some(true) if !prefixes.contains(prefix) => prefixes.push(prefix.clone()),
                    None => unsupported_locator = true,
                    _ => {}
                }
            }
        }
        if prefixes.is_empty() && !unsupported_locator {
            continue;
        }
        report.filters.push(format!("{} / {}", rule.policy, rule.rule));
        if prefixes.is_empty() {
            prefixes.push(Vec::new()); // cannot locate anything: the whole payload is the record
        }
        for prefix in &prefixes {
            let removes = |record: &Value| -> bool {
                let env = RecordEnv { caller, record, fields: &located, prefix };
                eval_condition(Some(&rule.filter), &env) != Tri::False
            };
            if let Some((Seg::Each, arrays)) = prefix.split_last() {
                // The records are the elements of the arrays at `arrays`.
                let mut removed = 0;
                for_each_mut(payload, arrays, &mut |arr| {
                    if let Some(a) = arr.as_array_mut() {
                        let before = a.len();
                        a.retain(|r| !removes(r));
                        removed += before - a.len();
                    }
                });
                report.rows_removed += removed;
            } else if removes(payload) {
                *payload = json!({});
                report.rows_removed += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdam::{CTX_GROUPS, CTX_USAGE, LOC_CLASSIFICATION};

    fn loc(class: &str) -> Value {
        json!({"dialect": "basic-object-locator", "version": "1.0", "query": {"path": LOC_CLASSIFICATION, "value": class}})
    }
    fn cond(usage: &str) -> Value {
        json!({"dialect": "structured-predicate", "version": "1.0",
               "predicate": {"or": [{"isAnyOf": [{"path": CTX_USAGE}, {"constant": usage}]},
                                    {"isAnyOf": [{"path": CTX_GROUPS}, {"constant": {"__type": "group_identifier", "type": "IDMC", "id": "G-REG"}}]}]}})
    }
    fn fp(class: &str, prot: &str) -> Value {
        json!({"dataProtectionInternalId": prot, "fieldLocatorQuery": loc(class)})
    }
    fn tech(kind: &str, dt: &str, params: Value) -> Value {
        json!({"dataProtectionTechniqueType": kind, "appliesToDataType": dt, "parameters": params})
    }
    fn set() -> PolicySet {
        PolicySet {
            deidentifications: vec![json!({"id": "P", "name": "De-Id", "enabled": true, "condition": null, "precedenceTier": "T",
                "dataDeIdentificationRules": [
                    {"ruleName": "Regulatory", "rank": 1, "enabled": true, "condition": cond("U-REG"),
                     "fieldLevelProtections": [fp("C-COUNTRY", "RETAIN"), fp("C-EMAIL", "RETAIN"), fp("C-CARD", "LAST4")]},
                    {"ruleName": "Analytics", "rank": 2, "enabled": true, "condition": cond("U-AN"),
                     "fieldLevelProtections": [fp("C-COUNTRY", "RETAIN"), fp("C-EMAIL", "TOK"), fp("C-CARD", "LAST4")]}]})],
            filters: vec![json!({"name": "Filter", "enabled": true, "condition": null, "dataFilterRules": [
                {"ruleName": "US only", "rank": 1, "enabled": true, "condition": cond("U-REG"),
                 "filter": {"dialect": "structured-predicate", "version": "1.0", "predicate": {"or": [{"isNotAnyOf": [
                     {"fieldValue": {"fieldLocatorQuery": loc("C-COUNTRY"), "type": "STRING"}}, {"constant": "United States"}]}]}}}]})],
            protections: vec![
                json!({"id": "RETAIN", "name": "Retain", "dataProtectionTechniques": [tech("RETAIN_FUNCTION", "UNKNOWN", Value::Null)]}),
                json!({"id": "TOK", "name": "Tokenise", "dataProtectionTechniques": [tech(REDACT, "UNKNOWN", Value::Null), tech("TOKENISE_FUNCTION", "STRING", json!({}))]}),
                json!({"id": "LAST4", "name": "Last 4", "dataProtectionTechniques": [tech("TRUNCATE_FUNCTION", "STRING", json!({"length": "4", "behaviour": "PRESERVE_LAST_FEW_CHARACTERS"}))]}),
            ],
            tiers: vec![json!({"id": "T", "rank": 1, "policyOrdering": []})],
        }
    }
    fn fields() -> Vec<GovernedField> {
        let f = |p: &str, c: &[&str]| GovernedField { path: p.into(), classifications: c.iter().map(|s| s.to_string()).collect(), terms: vec![] };
        vec![f("orders[].shipping_country", &["C-COUNTRY"]), f("orders[].customer_email", &["C-EMAIL"]),
             f("orders[].card_number", &["C-CARD"]), f("orders[].iban", &["C-IBAN"]), f("orders[].status", &[])]
    }
    fn orders() -> Value {
        json!({"orders": [
            {"shipping_country": "United States", "customer_email": "a@x.com", "card_number": "4111111111111234", "iban": "DE89", "status": "OPEN"},
            {"shipping_country": "Germany", "customer_email": "b@x.com", "card_number": "4111111111115678", "iban": "DE12", "status": "SHIPPED"},
            {"customer_email": "c@x.com"}
        ], "total": 3})
    }
    fn run(caller: &Caller) -> (Value, Report) {
        let s = set();
        let p = plan(&fields(), caller, &s, 0);
        let mut v = orders();
        let r = enforce(&mut v, &p, caller, &s, 0);
        (v, r)
    }

    #[test]
    fn paths() {
        let k = |s: &str| Seg::Key(s.into());
        assert_eq!(segments("orders[].iban"), vec![k("orders"), Seg::Each, k("iban")]);
        assert_eq!(segments("$.orders[*].lines[*].sku"), vec![k("orders"), Seg::Each, k("lines"), Seg::Each, k("sku")]);
        assert_eq!(segments("header.name"), vec![k("header"), k("name")]);
        assert_eq!(segments("[]"), vec![Seg::Each]);
    }

    #[test]
    fn regulatory_sees_us_rows_with_email_and_last4() {
        let (v, r) = run(&Caller { usage: Some("U-REG".into()), groups: vec![] });
        let o = &v["orders"];
        assert_eq!(o.as_array().unwrap().len(), 1, "{v}");
        assert_eq!(o[0]["customer_email"], "a@x.com");
        assert_eq!(o[0]["card_number"], "1234");
        assert_eq!(o[0]["iban"], Value::Null);
        assert_eq!(o[0]["status"], "OPEN");
        assert_eq!(v["total"], 3);
        assert_eq!(r.rows_removed, 2); // Germany, and the record without a country
        assert_eq!(r.filters, vec!["Filter / US only"]);
        assert_eq!(r.fields.get("orders[].iban").map(String::as_str), Some(REDACT));
        assert!(!r.fields.contains_key("orders[].customer_email"));
    }

    #[test]
    fn group_membership_also_triggers_the_filter() {
        let (v, _) = run(&Caller { usage: Some("U-AN".into()), groups: vec!["G-REG".into()] });
        assert_eq!(v["orders"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn analytics_sees_all_rows_with_tokenised_email_redacted() {
        let (v, r) = run(&Caller { usage: Some("U-AN".into()), groups: vec![] });
        let o = v["orders"].as_array().unwrap();
        assert_eq!(o.len(), 3);
        assert_eq!(o[1]["customer_email"], Value::Null);
        assert_eq!(o[1]["card_number"], "5678");
        assert_eq!(o[1]["shipping_country"], "Germany");
        assert_eq!(r.substituted, vec!["orders[].customer_email"]);
        assert_eq!(r.rows_removed, 0);
    }

    #[test]
    fn no_usage_context_redacts_every_classified_field() {
        let (v, r) = run(&Caller::default());
        let o = v["orders"].as_array().unwrap();
        assert_eq!(o.len(), 3);
        for k in ["shipping_country", "customer_email", "card_number", "iban"] {
            assert_eq!(o[0][k], Value::Null, "{k}");
        }
        assert_eq!(o[0]["status"], "OPEN");
        assert_eq!(r.fields.len(), 4);
        assert!(r.filters.is_empty());
    }

    #[test]
    fn filter_on_fields_the_tool_does_not_return_does_not_apply() {
        let s = set();
        let caller = Caller { usage: Some("U-REG".into()), groups: vec![] };
        let only_status = vec![GovernedField { path: "items[].sku".into(), classifications: vec!["C-SKU".into()], terms: vec![] }];
        let p = plan(&only_status, &caller, &s, 0);
        let mut v = json!({"items": [{"sku": "A"}, {"sku": "B"}]});
        let r = enforce(&mut v, &p, &caller, &s, 0);
        assert_eq!(v["items"].as_array().unwrap().len(), 2);
        assert!(r.filters.is_empty());
    }

    #[test]
    fn object_payload_is_its_own_record() {
        let s = set();
        let caller = Caller { usage: Some("U-REG".into()), groups: vec![] };
        let f = vec![GovernedField { path: "order.shipping_country".into(), classifications: vec!["C-COUNTRY".into()], terms: vec![] }];
        let p = plan(&f, &caller, &s, 0);
        let mut de = json!({"order": {"shipping_country": "Germany"}});
        enforce(&mut de, &p, &caller, &s, 0);
        assert_eq!(de, json!({}));
        let mut us = json!({"order": {"shipping_country": "United States"}});
        enforce(&mut us, &p, &caller, &s, 0);
        assert_eq!(us["order"]["shipping_country"], "United States");
    }
}
