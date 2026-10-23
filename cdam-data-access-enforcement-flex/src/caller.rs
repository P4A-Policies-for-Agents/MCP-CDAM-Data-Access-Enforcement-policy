// Copyright 2026 Salesforce, Inc. All rights reserved.
//! The caller's verified CDAM context (no PDK imports).
//!
//! A caller only gets the usage context they were granted: the IDMC user (from a
//! header or JWT claim) is resolved to its IDMC user id and groups, and their Data
//! Marketplace consumer accesses give the usage contexts they may use. A declared
//! usage context must be one of those; with none declared, a single granted usage
//! context is used.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A usage context, as Data Marketplace names it.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Usage {
    pub id: String,
    #[serde(default)]
    pub ref_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

impl Usage {
    fn is(&self, declared: &str) -> bool {
        let d = declared.trim();
        self.id == d
            || self.ref_id.as_deref().is_some_and(|r| r.eq_ignore_ascii_case(d))
            || self.name.as_deref().is_some_and(|n| n.trim().eq_ignore_ascii_case(d))
    }
}

/// One available consumer access of the caller.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Grant {
    pub access_id: String,
    #[serde(default)]
    pub access_ref: Option<String>,
    #[serde(default)]
    pub collection_id: Option<String>,
    #[serde(default)]
    pub collection_name: Option<String>,
    pub usage: Usage,
}

/// The resolved caller, cached per user name.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CallerInfo {
    /// `None` = no IDMC user with that name.
    pub user_id: Option<String>,
    pub groups: Vec<String>,
    pub grants: Vec<Grant>,
    pub timestamp: i64,
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::trim).filter(|x| !x.is_empty()).map(str::to_string)
}

/// The user id and group ids of `user_name` in a platform `GET /public/core/v3/users`
/// response.
pub fn parse_user(users: &Value, user_name: &str) -> Option<(String, Vec<String>)> {
    let list = users.as_array().or_else(|| users.get("users").and_then(Value::as_array))?;
    let u = list.iter().find(|u| s(u, "userName").is_some_and(|n| n.eq_ignore_ascii_case(user_name.trim())))?;
    let groups = u.get("groups").and_then(Value::as_array).map(|g| g.iter().filter_map(|x| s(x, "id")).collect()).unwrap_or_default();
    Some((s(u, "id")?, groups))
}

/// Ids of the AVAILABLE consumer accesses (v2 list `items[]`) held by the user or by
/// one of their groups.
pub fn candidate_accesses(items: &[Value], user_id: &str, groups: &[String]) -> Vec<String> {
    items.iter()
        .filter(|a| s(a, "status").as_deref() == Some("AVAILABLE"))
        .filter(|a| {
            let holder = a.get("consumer").and_then(|c| s(c, "stakeholderId"));
            holder.is_some_and(|h| h == user_id || groups.contains(&h))
        })
        .filter_map(|a| s(a, "id"))
        .collect()
}

/// A consumer access detail (v1 `consumerAccess/{id}`) as a grant, if it is available
/// and names a usage context.
pub fn parse_grant(detail: &Value) -> Option<Grant> {
    if s(detail, "status").as_deref() != Some("AVAILABLE") {
        return None;
    }
    let u = detail.get("usageContext")?;
    let c = detail.get("dataCollection");
    Some(Grant {
        access_id: s(detail, "id")?,
        access_ref: s(detail, "refId").or_else(|| s(detail, "externalId")),
        collection_id: c.and_then(|c| s(c, "id")),
        collection_name: c.and_then(|c| s(c, "name")),
        usage: Usage { id: s(u, "id")?, ref_id: s(u, "refId"), name: s(u, "name") },
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum Denial {
    /// No user name on the request.
    NoConsumer,
    /// No IDMC user with that name.
    UnknownUser,
    /// No available consumer access to the configured data collections.
    NoAccess,
    /// The declared usage context is not one the caller was granted.
    UsageNotGranted(String),
    /// No usage context declared and several are granted.
    UsageRequired(Vec<String>),
}

impl Denial {
    pub fn message(&self) -> String {
        match self {
            Denial::NoConsumer => "No IDMC user identified for this call.".to_string(),
            Denial::UnknownUser => "The calling user is not an IDMC user of this organisation.".to_string(),
            Denial::NoAccess => "The calling user has no available Data Marketplace access to the data collection behind this MCP server.".to_string(),
            Denial::UsageNotGranted(u) => format!("Usage context '{u}' is not granted to the calling user by Data Marketplace."),
            Denial::UsageRequired(names) => format!("Declare a usage context for this call; granted: {}.", names.join(", ")),
        }
    }
}

/// The grants that count for this MCP server: any collection when none is configured.
pub fn relevant<'a>(grants: &'a [Grant], collections: &[String]) -> Vec<&'a Grant> {
    grants.iter()
        .filter(|g| collections.is_empty() || g.collection_id.as_ref().is_some_and(|c| collections.contains(c)))
        .collect()
}

/// The verified usage context for the call. `require` = deny when it cannot be
/// established; otherwise an unverifiable context resolves to none (CDAM then
/// applies its default protection).
pub fn select_usage(info: &CallerInfo, declared: Option<&str>, collections: &[String], require: bool) -> Result<Option<Grant>, Denial> {
    let deny = |d: Denial| if require { Err(d) } else { Ok(None) };
    if info.user_id.is_none() {
        return deny(Denial::UnknownUser);
    }
    let grants = relevant(&info.grants, collections);
    if grants.is_empty() {
        return deny(Denial::NoAccess);
    }
    match declared.map(str::trim).filter(|d| !d.is_empty()) {
        Some(d) => match grants.into_iter().find(|g| g.usage.is(d)) {
            Some(g) => Ok(Some(g.clone())),
            None => deny(Denial::UsageNotGranted(d.to_string())),
        },
        None => {
            let mut distinct: Vec<&Grant> = Vec::new();
            for g in grants {
                if !distinct.iter().any(|x| x.usage.id == g.usage.id) {
                    distinct.push(g);
                }
            }
            if distinct.len() == 1 {
                Ok(Some(distinct[0].clone()))
            } else {
                deny(Denial::UsageRequired(distinct.iter().map(|g| g.usage.name.clone().unwrap_or_else(|| g.usage.id.clone())).collect()))
            }
        }
    }
}

/// Percent-encode a query parameter value (RFC 3986 unreserved characters kept).
pub fn encode_query(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn grant(id: &str, coll: &str, usage: &str, name: &str) -> Grant {
        Grant {
            access_id: id.into(), access_ref: None, collection_id: Some(coll.into()), collection_name: None,
            usage: Usage { id: usage.into(), ref_id: Some(format!("REF-{usage}")), name: Some(name.into()) },
        }
    }
    fn info(grants: Vec<Grant>) -> CallerInfo {
        CallerInfo { user_id: Some("U1".into()), groups: vec![], grants, timestamp: 0 }
    }

    #[test]
    fn parses_users_accesses_and_details() {
        let users = json!([{"id": "U1", "userName": "Bob", "groups": [{"id": "G1", "userGroupName": "Reporters"}]}]);
        assert_eq!(parse_user(&users, "bob"), Some(("U1".into(), vec!["G1".into()])));
        assert_eq!(parse_user(&users, "gina"), None);
        let items = vec![
            json!({"id": "A1", "status": "AVAILABLE", "consumer": {"stakeholderId": "U1", "userType": "USER"}}),
            json!({"id": "A2", "status": "WITHDRAWN", "consumer": {"stakeholderId": "U1"}}),
            json!({"id": "A3", "status": "AVAILABLE", "consumer": {"stakeholderId": "G1", "userType": "GROUP"}}),
            json!({"id": "A4", "status": "AVAILABLE", "consumer": {"stakeholderId": "U2"}}),
        ];
        assert_eq!(candidate_accesses(&items, "U1", &["G1".into()]), vec!["A1", "A3"]);
        let d = json!({"id": "A1", "refId": "ACC-1", "status": "AVAILABLE", "dataCollection": {"id": "C1", "name": "Customers"},
                       "usageContext": {"id": "UC1", "refId": "USG-1", "name": "Analytics"}});
        let g = parse_grant(&d).unwrap();
        assert_eq!((g.collection_id.as_deref(), g.usage.id.as_str()), (Some("C1"), "UC1"));
        assert_eq!(parse_grant(&json!({"id": "A", "status": "WITHDRAWN", "usageContext": {"id": "x"}})), None);
    }

    #[test]
    fn declared_usage_must_be_granted() {
        let i = info(vec![grant("A1", "C1", "UC-AN", "Analytics"), grant("A2", "C2", "UC-REG", "Regulatory Reporting")]);
        assert_eq!(select_usage(&i, Some("UC-AN"), &[], true).unwrap().unwrap().access_id, "A1");
        assert_eq!(select_usage(&i, Some("regulatory reporting"), &[], true).unwrap().unwrap().access_id, "A2");
        assert_eq!(select_usage(&i, Some("ref-uc-reg"), &[], true).unwrap().unwrap().access_id, "A2");
        assert_eq!(select_usage(&i, Some("Marketing"), &[], true), Err(Denial::UsageNotGranted("Marketing".into())));
        assert_eq!(select_usage(&i, Some("Marketing"), &[], false), Ok(None));
        // Only collection C1 counts for this server.
        assert_eq!(select_usage(&i, Some("UC-REG"), &["C1".into()], true), Err(Denial::UsageNotGranted("UC-REG".into())));
    }

    #[test]
    fn undeclared_usage_needs_a_single_grant() {
        let one = info(vec![grant("A1", "C1", "UC-AN", "Analytics"), grant("A9", "C9", "UC-AN", "Analytics")]);
        assert_eq!(select_usage(&one, None, &[], true).unwrap().unwrap().usage.id, "UC-AN");
        let two = info(vec![grant("A1", "C1", "UC-AN", "Analytics"), grant("A2", "C1", "UC-REG", "Reg")]);
        assert!(matches!(select_usage(&two, Some(" "), &[], true), Err(Denial::UsageRequired(n)) if n.len() == 2));
        assert_eq!(select_usage(&info(vec![]), None, &[], true), Err(Denial::NoAccess));
        assert_eq!(select_usage(&info(vec![grant("A1", "C2", "U", "U")]), None, &["C1".into()], true), Err(Denial::NoAccess));
        let unknown = CallerInfo::default();
        assert_eq!(select_usage(&unknown, None, &[], true), Err(Denial::UnknownUser));
        assert_eq!(select_usage(&unknown, None, &[], false), Ok(None));
    }

    #[test]
    fn query_encoding() {
        assert_eq!(encode_query(r#"userName=="a.b@x.com""#), "userName%3D%3D%22a.b%40x.com%22");
    }
}
