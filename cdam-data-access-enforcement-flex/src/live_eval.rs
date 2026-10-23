// Copyright 2026 Salesforce, Inc. All rights reserved.
//! Opt-in check of the enforcement logic against a real tenant's data:
//! `CDAM_EVAL_DIR=<dir> cargo test --lib live_eval -- --ignored --nocapture`, where the
//! directory holds `policies.json` (a `PolicySet`), `catalog.json` (tool name →
//! fields), `callers.json` (user name → `CallerInfo`) and optionally `result.json`
//! (tool name → a sample tool result payload; otherwise one is synthesised).

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::caller::{select_usage, CallerInfo};
use crate::cdam::{Caller, GovernedField, PolicySet};
use crate::payload::{enforce, plan, segments, Seg};

fn read<T: serde::de::DeserializeOwned>(dir: &str, name: &str) -> Option<T> {
    serde_json::from_slice(&std::fs::read(format!("{dir}/{name}")).ok()?).ok()
}

/// Two records per array: one in the United States, one in Germany.
fn synthesise(fields: &[GovernedField]) -> Value {
    let mut root = json!({});
    for (i, country) in ["United States", "Germany"].iter().enumerate() {
        for f in fields {
            let segs = segments(&f.path);
            let leaf = match segs.last() { Some(Seg::Key(k)) => k.clone(), _ => continue };
            let value = match leaf.as_str() {
                l if l.contains("country") => json!(country),
                l if l.contains("email") => json!(format!("person{i}@example.com")),
                l if l.contains("card_number") => json!(format!("4111-1111-1111-{:04}", 1234 + i)),
                l if l.contains("date_of_birth") => json!("1985-03-12"),
                l if l.contains("qty") || l.contains("quantity") || l.contains("days") || l.contains("point") => json!(5 + i),
                l if l.contains("cost") || l.contains("price") || l.contains("total") || l.contains("pct")
                    || l.contains("value") || l.contains("commission") || l.contains("limit") => json!(100.5 + i as f64),
                l => json!(format!("{l}-{i}")),
            };
            let (Some(Seg::Key(array)), true) = (segs.first(), segs.get(1) == Some(&Seg::Each)) else { continue };
            let rows = root.as_object_mut().unwrap().entry(array.clone()).or_insert_with(|| json!([]));
            let rows = rows.as_array_mut().unwrap();
            if rows.len() <= i { rows.push(json!({})); }
            rows[i][leaf] = value;
        }
    }
    root
}

#[test]
#[ignore]
fn live_eval() {
    let Ok(dir) = std::env::var("CDAM_EVAL_DIR") else { return };
    let set: PolicySet = read(&dir, "policies.json").expect("policies.json");
    let catalog: BTreeMap<String, Vec<GovernedField>> = read(&dir, "catalog.json").expect("catalog.json");
    let callers: BTreeMap<String, CallerInfo> = read(&dir, "callers.json").expect("callers.json");
    let results: BTreeMap<String, Value> = read(&dir, "result.json").unwrap_or_default();
    let now = 1_792_700_000_000;
    let mut who: Vec<(String, Option<String>)> = callers.keys().map(|u| (u.clone(), None)).collect();
    who.push(("(no consumer access)".into(), None));
    for (tool, fields) in &catalog {
        for (user, declared) in &who {
            let info = callers.get(user).cloned().unwrap_or_default();
            let caller = match select_usage(&info, declared.as_deref(), &[], false) {
                Ok(g) => Caller { usage: g.map(|g| g.usage.id), groups: info.groups.clone() },
                Err(d) => panic!("{:?}", d),
            };
            let p = plan(fields, &caller, &set, now);
            let mut v = results.get(tool).cloned().unwrap_or_else(|| synthesise(fields));
            let r = enforce(&mut v, &p, &caller, &set, now);
            println!("\n=== {tool} / {user} usage={:?} groups={}", caller.usage, caller.groups.len());
            println!("report: {}", r.to_json());
            println!("result: {v}");
        }
    }
}
