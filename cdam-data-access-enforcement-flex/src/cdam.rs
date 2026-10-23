// Copyright 2026 Salesforce, Inc. All rights reserved.
//! CDAM policy model and decisions (no PDK imports).
//!
//! The published Data De-Identification, Data Filter, Data Protection and Precedence
//! Tier assets are kept as the raw JSON items of `/data360/dam/api/v1/*` and evaluated
//! the way CDAM documents it:
//!
//! - **De-identification**: precedence tiers in rank order, then the tier's policy
//!   ordering; within a policy whose trigger holds, rules in rank order. The first
//!   matching rule with a protection for one of the field's classifications (or
//!   terms) wins. A classified field no rule protects is redacted with null; an
//!   unclassified field is retained.
//! - **Data filters** are cumulative: every rule whose condition holds removes the
//!   records its filter predicate matches.
//!
//! Anything the gateway cannot evaluate resolves toward more protection: an unknown
//! de-identification condition redacts the field, an unknown filter condition applies
//! the filter, and an unknown filter predicate removes the record.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::predicate::{eval_condition, Env, Tri};

pub const LOC_CLASSIFICATION: &str = "cdgc::dataelement.classifications[*].id";
pub const LOC_GLOSSARY: &str = "cdgc::dataelement.glossaries[*].id";
pub const CTX_USAGE: &str = "context::request.usage";
pub const CTX_GROUPS: &str = "context::principal.groups";

/// One MCP tool output field from the catalog.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GovernedField {
    /// Path in the tool result, e.g. "orders[].iban".
    pub path: String,
    #[serde(default)]
    pub classifications: Vec<String>,
    #[serde(default)]
    pub terms: Vec<String>,
}

impl GovernedField {
    pub fn is_classified(&self) -> bool {
        !self.classifications.is_empty()
    }
}

/// The published CDAM assets, as returned by the DAM API (`items[]` of each list).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PolicySet {
    #[serde(default)]
    pub deidentifications: Vec<Value>,
    #[serde(default)]
    pub filters: Vec<Value>,
    #[serde(default)]
    pub protections: Vec<Value>,
    #[serde(default)]
    pub tiers: Vec<Value>,
}

/// The caller's CDAM request context.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Caller {
    pub usage: Option<String>,
    pub groups: Vec<String>,
}

impl Env for Caller {
    fn context(&self, path: &str) -> Option<Vec<String>> {
        match path {
            CTX_USAGE => Some(self.usage.iter().cloned().collect()),
            CTX_GROUPS => Some(self.groups.clone()),
            _ => None,
        }
    }
    fn field(&self, _locator: &Value) -> Option<Vec<String>> {
        None // record fields are not in scope of a trigger or rule condition
    }
}

/// Whether a `basic-object-locator` selects `field`. `None` = unsupported locator.
pub fn locator_matches(locator: &Value, field: &GovernedField) -> Option<bool> {
    if locator.get("dialect").and_then(Value::as_str) != Some("basic-object-locator") {
        return None;
    }
    let q = locator.get("query")?;
    let value = q.get("value").and_then(Value::as_str)?;
    match q.get("path").and_then(Value::as_str)? {
        LOC_CLASSIFICATION => Some(field.classifications.iter().any(|c| c == value)),
        LOC_GLOSSARY => Some(field.terms.iter().any(|t| t == value)),
        _ => None,
    }
}

/// How a field is rendered for this caller.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Retain,
    Protect { protection_id: String, policy: String, rule: String },
    /// Classified, but no rule protects it: CDAM's default, redact with null.
    DefaultRedact,
    /// A policy could not be evaluated here: redact with null.
    Uncertain { policy: String },
}

fn name(v: &Value) -> String {
    v.get("name").or_else(|| v.get("ruleName")).and_then(Value::as_str).unwrap_or("").to_string()
}
fn rank(v: &Value) -> i64 {
    v.get("rank").and_then(Value::as_i64).unwrap_or(i64::MAX)
}
fn enabled(v: &Value) -> bool {
    v.get("enabled").and_then(Value::as_bool).unwrap_or(true)
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// An effective/end date as Unix ms: epoch-ms numbers, or ISO strings ("2026-10-23",
/// "2026-10-23T..."; the date part is used). `Err` = present but unreadable.
fn date_ms(v: Option<&Value>) -> Result<Option<i64>, ()> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_i64().map(Some).ok_or(()),
        Some(Value::String(s)) => {
            let d: Vec<i64> = s.get(..10).ok_or(())?.split('-').map(|p| p.parse::<i64>().map_err(|_| ())).collect::<Result<_, _>>()?;
            if d.len() != 3 {
                return Err(());
            }
            Ok(Some(days_from_civil(d[0], d[1], d[2]) * 86_400_000))
        }
        _ => Err(()),
    }
}

/// Whether a policy is in force now: enabled and within its effective/end dates.
pub fn in_force(policy: &Value, now_ms: i64) -> Tri {
    if !enabled(policy) {
        return Tri::False;
    }
    let (Ok(from), Ok(to)) = (date_ms(policy.get("effectiveDate")), date_ms(policy.get("endDate"))) else {
        return Tri::Unknown;
    };
    if from.is_some_and(|f| now_ms < f) || to.is_some_and(|t| now_ms >= t + 86_400_000) {
        return Tri::False;
    }
    Tri::True
}

/// De-identification policies in evaluation order: tier rank, then the tier's policy
/// ordering, then name. Policies without a known tier come last.
pub fn ordered_deidentifications(set: &PolicySet) -> Vec<&Value> {
    let tier_of = |p: &Value| -> (i64, usize) {
        let tid = p.get("precedenceTier").and_then(Value::as_str);
        let pid = p.get("id").and_then(Value::as_str);
        match set.tiers.iter().find(|t| tid.is_some() && t.get("id").and_then(Value::as_str) == tid) {
            Some(t) => {
                let order = t.get("policyOrdering").and_then(Value::as_array);
                let pos = order.and_then(|o| o.iter().position(|x| {
                    x.as_str().or_else(|| x.get("id").and_then(Value::as_str)) == pid
                }));
                (rank(t), pos.unwrap_or(usize::MAX))
            }
            None => (i64::MAX, usize::MAX),
        }
    };
    let mut v: Vec<&Value> = set.deidentifications.iter().collect();
    v.sort_by(|a, b| tier_of(a).cmp(&tier_of(b)).then_with(|| name(a).cmp(&name(b))));
    v
}

fn rules<'a>(policy: &'a Value, key: &str) -> Vec<&'a Value> {
    let mut r: Vec<&Value> = policy.get(key).and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
    r.sort_by_key(|x| rank(x));
    r
}

/// The de-identification decision for one field.
pub fn decide(field: &GovernedField, caller: &Caller, set: &PolicySet, now_ms: i64) -> Decision {
    if field.classifications.is_empty() && field.terms.is_empty() {
        return Decision::Retain; // nothing can select it
    }
    for p in ordered_deidentifications(set) {
        let uncertain = || Decision::Uncertain { policy: name(p) };
        match in_force(p, now_ms) {
            Tri::False => continue,
            Tri::Unknown => return uncertain(),
            Tri::True => {}
        }
        match eval_condition(p.get("condition"), caller) {
            Tri::False => continue,
            Tri::Unknown => return uncertain(),
            Tri::True => {}
        }
        for r in rules(p, "dataDeIdentificationRules") {
            if !enabled(r) {
                continue;
            }
            match eval_condition(r.get("condition"), caller) {
                Tri::False => continue,
                Tri::Unknown => return uncertain(),
                Tri::True => {}
            }
            if r.get("cellLevelProtections").and_then(Value::as_array).is_some_and(|c| !c.is_empty()) {
                return uncertain(); // cell-level (value-dependent) protections are not mirrored
            }
            for fp in r.get("fieldLevelProtections").and_then(Value::as_array).into_iter().flatten() {
                let Some(locator) = fp.get("fieldLocatorQuery") else { return uncertain() };
                match locator_matches(locator, field) {
                    Some(true) => {
                        let Some(pid) = fp.get("dataProtectionInternalId").and_then(Value::as_str) else { return uncertain() };
                        return Decision::Protect { protection_id: pid.to_string(), policy: name(p), rule: name(r) };
                    }
                    Some(false) => {}
                    None => return uncertain(),
                }
            }
        }
    }
    if field.is_classified() { Decision::DefaultRedact } else { Decision::Retain }
}

/// A data filter rule that applies to this caller.
#[derive(Debug, Clone, PartialEq)]
pub struct FilterRule {
    pub policy: String,
    pub rule: String,
    /// The rule's `filter` condition: records it matches are removed.
    pub filter: Value,
}

/// The data filter rules in force for this caller (cumulative).
pub fn applicable_filters(set: &PolicySet, caller: &Caller, now_ms: i64) -> Vec<FilterRule> {
    let mut out = Vec::new();
    for p in &set.filters {
        if in_force(p, now_ms) == Tri::False || eval_condition(p.get("condition"), caller) == Tri::False {
            continue;
        }
        for r in rules(p, "dataFilterRules") {
            if !enabled(r) || eval_condition(r.get("condition"), caller) == Tri::False {
                continue;
            }
            out.push(FilterRule {
                policy: name(p),
                rule: name(r),
                filter: r.get("filter").cloned().unwrap_or(Value::Null),
            });
        }
    }
    out
}

/// The techniques of a data protection, by its id.
pub fn techniques<'a>(set: &'a PolicySet, protection_id: &str) -> Option<(&'a str, &'a [Value])> {
    let p = set.protections.iter().find(|p| p.get("id").and_then(Value::as_str) == Some(protection_id))?;
    let t = p.get("dataProtectionTechniques")?.as_array()?;
    Some((p.get("name").and_then(Value::as_str).unwrap_or(""), t.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cond(usage: &str) -> Value {
        json!({"dialect": "structured-predicate", "version": "1.0",
               "predicate": {"or": [{"isAnyOf": [{"path": CTX_USAGE}, {"constant": usage}]}]}})
    }
    fn fp(class: &str, prot: &str) -> Value {
        json!({"dataProtectionInternalId": prot, "fieldLocatorQuery": {"dialect": "basic-object-locator",
               "query": {"path": LOC_CLASSIFICATION, "value": class}, "version": "1.0"}})
    }
    pub fn set() -> PolicySet {
        PolicySet {
            deidentifications: vec![json!({
                "id": "P1", "name": "De-Identification", "enabled": true, "condition": null, "precedenceTier": "T1",
                "dataDeIdentificationRules": [
                    {"ruleName": "Analytics", "rank": 2, "enabled": true, "condition": cond("U-AN"),
                     "fieldLevelProtections": [fp("C-EMAIL", "TOK"), fp("C-CARD", "LAST4")], "cellLevelProtections": null},
                    {"ruleName": "Regulatory", "rank": 1, "enabled": true, "condition": cond("U-REG"),
                     "fieldLevelProtections": [fp("C-EMAIL", "RETAIN"), fp("C-CARD", "LAST4")]}
                ]})],
            filters: vec![],
            protections: vec![],
            tiers: vec![json!({"id": "T1", "rank": 1, "policyOrdering": []})],
        }
    }
    fn field(classes: &[&str]) -> GovernedField {
        GovernedField { path: "x".into(), classifications: classes.iter().map(|s| s.to_string()).collect(), terms: vec![] }
    }
    fn caller(usage: Option<&str>) -> Caller {
        Caller { usage: usage.map(str::to_string), groups: vec![] }
    }
    fn protect(id: &str, rule: &str) -> Decision {
        Decision::Protect { protection_id: id.into(), policy: "De-Identification".into(), rule: rule.into() }
    }

    #[test]
    fn rule_by_usage_and_rank() {
        let s = set();
        assert_eq!(decide(&field(&["C-EMAIL"]), &caller(Some("U-REG")), &s, 0), protect("RETAIN", "Regulatory"));
        assert_eq!(decide(&field(&["C-EMAIL"]), &caller(Some("U-AN")), &s, 0), protect("TOK", "Analytics"));
    }

    #[test]
    fn defaults_redact_classified_retain_unclassified() {
        let s = set();
        assert_eq!(decide(&field(&["C-EMAIL"]), &caller(None), &s, 0), Decision::DefaultRedact);
        assert_eq!(decide(&field(&["C-IBAN"]), &caller(Some("U-REG")), &s, 0), Decision::DefaultRedact);
        assert_eq!(decide(&field(&[]), &caller(None), &s, 0), Decision::Retain);
        let termed = GovernedField { path: "x".into(), classifications: vec![], terms: vec!["T".into()] };
        assert_eq!(decide(&termed, &caller(Some("U-AN")), &s, 0), Decision::Retain);
    }

    #[test]
    fn first_rule_with_an_instruction_for_the_field_wins() {
        let mut s = set();
        // Both rules match a caller who is in a group and declares Regulatory; the
        // rank-1 rule has no row for C-CARD2, so the rank-2 rule's row applies.
        s.deidentifications[0]["dataDeIdentificationRules"][0]["condition"] = Value::Null;
        s.deidentifications[0]["dataDeIdentificationRules"][0]["fieldLevelProtections"] = json!([fp("C-CARD2", "NULL")]);
        assert_eq!(decide(&field(&["C-CARD2"]), &caller(Some("U-REG")), &s, 0), protect("NULL", "Analytics"));
    }

    #[test]
    fn unknown_conditions_and_cell_level_are_uncertain() {
        let mut s = set();
        s.deidentifications[0]["condition"] = json!({"dialect": "knowledge-graph-search", "query": {}});
        assert!(matches!(decide(&field(&["C-EMAIL"]), &caller(Some("U-REG")), &s, 0), Decision::Uncertain { .. }));
        assert_eq!(decide(&field(&[]), &caller(Some("U-REG")), &s, 0), Decision::Retain);
        let mut s = set();
        s.deidentifications[0]["dataDeIdentificationRules"][1]["cellLevelProtections"] = json!([{"x": 1}]);
        assert!(matches!(decide(&field(&["C-EMAIL"]), &caller(Some("U-REG")), &s, 0), Decision::Uncertain { .. }));
    }

    #[test]
    fn disabled_and_dated_policies() {
        let mut s = set();
        s.deidentifications[0]["enabled"] = json!(false);
        assert_eq!(decide(&field(&["C-EMAIL"]), &caller(Some("U-REG")), &s, 0), Decision::DefaultRedact);
        let day = 86_400_000;
        let mut p = json!({"enabled": true, "effectiveDate": "1970-01-03", "endDate": 4 * day});
        assert_eq!(in_force(&p, day), Tri::False);
        assert_eq!(in_force(&p, 3 * day), Tri::True);
        assert_eq!(in_force(&p, 5 * day + 1), Tri::False);
        p["endDate"] = json!("soon");
        assert_eq!(in_force(&p, 3 * day), Tri::Unknown);
        assert_eq!(days_from_civil(2026, 10, 23), 20_749);
    }

    #[test]
    fn tier_rank_then_policy_ordering() {
        let mut s = set();
        let mut other = s.deidentifications[0].clone();
        other["id"] = json!("P0");
        other["name"] = json!("Zeta");
        other["precedenceTier"] = json!("T0");
        other["dataDeIdentificationRules"] = json!([{"ruleName": "All", "rank": 1, "enabled": true, "condition": null,
                                                     "fieldLevelProtections": [fp("C-EMAIL", "NULL")]}]);
        s.deidentifications.push(other);
        s.tiers.push(json!({"id": "T0", "rank": 0, "policyOrdering": []}));
        let d = decide(&field(&["C-EMAIL"]), &caller(Some("U-REG")), &s, 0);
        assert_eq!(d, Decision::Protect { protection_id: "NULL".into(), policy: "Zeta".into(), rule: "All".into() });
        // Same tier: policyOrdering decides.
        s.tiers = vec![json!({"id": "T1", "rank": 1, "policyOrdering": ["P1", "P0"]})];
        s.deidentifications[1]["precedenceTier"] = json!("T1");
        assert_eq!(ordered_deidentifications(&s)[0]["id"], "P1");
    }

    #[test]
    fn filters_are_cumulative_and_fail_toward_filtering() {
        let mut s = set();
        s.filters = vec![json!({"name": "F", "enabled": true, "condition": cond("U-REG"), "dataFilterRules": [
            {"ruleName": "US only", "rank": 1, "enabled": true, "condition": null, "filter": {"x": 1}},
            {"ruleName": "Unknown", "rank": 2, "enabled": true, "condition": {"dialect": "other"}, "filter": {"y": 1}},
            {"ruleName": "Off", "rank": 3, "enabled": false, "condition": null, "filter": {}}
        ]})];
        let names: Vec<String> = applicable_filters(&s, &caller(Some("U-REG")), 0).into_iter().map(|f| f.rule).collect();
        assert_eq!(names, vec!["US only", "Unknown"]);
        assert!(applicable_filters(&s, &caller(Some("U-AN")), 0).is_empty());
    }

    #[test]
    fn locators() {
        let f = GovernedField { path: "x".into(), classifications: vec!["C".into()], terms: vec!["T".into()] };
        assert_eq!(locator_matches(&fp("C", "P")["fieldLocatorQuery"], &f), Some(true));
        assert_eq!(locator_matches(&fp("D", "P")["fieldLocatorQuery"], &f), Some(false));
        let g = json!({"dialect": "basic-object-locator", "query": {"path": LOC_GLOSSARY, "value": "T"}});
        assert_eq!(locator_matches(&g, &f), Some(true));
        let u = json!({"dialect": "basic-object-locator", "query": {"path": "cdgc::dataelement.name", "value": "x"}});
        assert_eq!(locator_matches(&u, &f), None);
    }
}
