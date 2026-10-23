// Copyright 2026 Salesforce, Inc. All rights reserved.
//! MCP CDAM Data Access Enforcement — inbound Omni/Flex Gateway policy.
//!
//! Enforces Informatica Cloud Data Access Management (CDAM) on MCP tool results, the
//! way CDAM's own enforcement points do for SQL: the published **Data Filter** and
//! **Data De-Identification** policies are evaluated for the caller's verified
//! context, and the tool result's records and fields are filtered and protected
//! before they reach the agent.
//!
//! **Request leg** (`tools/call` only): the caller's IDMC user name comes from a header
//! or JWT claim. The policy resolves it to the user's IDMC groups (platform user API)
//! and their available Data Marketplace consumer accesses, each of which grants a
//! usage context. The usage context the caller declares must be one of those (or,
//! undeclared, the only one); otherwise the call is answered with a 403 JSON-RPC error
//! (`requireConsumerAccess`). The verified usage context and groups are CDAM's
//! `context::request.usage` and `context::principal.groups`.
//!
//! **Response leg**: the MCP server's tools and output fields come from CDGC (the
//! configured MCP Server asset, its MCP Tools and their output fields with their
//! accepted data element classifications and glossary terms). For the called tool,
//! data filter rules remove records and de-identification rules protect fields; see
//! `cdam`, `payload` and `protect`. Tokenisation is substituted with redact-with-null.
//! The outcome rides in a `_cdam` annotation in the payload and `x-cdam-*` headers.
//!
//! IDMC data is cached (lazy refresh, single-flight): CDAM policies
//! (`policyRefreshSeconds`), the catalog (`catalogRefreshSeconds`) and each caller
//! (`callerRefreshSeconds`). A failed refresh keeps using stale data. With no data at
//! all, `failOpenOnIdmcError` decides: false (default) answers with a JSON-RPC error,
//! true lets the call through (the request leg then continues without a usage
//! context; the response leg passes the result through unprotected).
//!
//! JSON and single-message SSE results are handled; whole-stream SSE rewrites are out
//! of scope.

mod caller;
mod cdam;
mod claims;
mod generated;
#[cfg(test)]
mod live_eval;
mod payload;
mod predicate;
mod protect;

use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use pdk::data_storage::{DataStorage, DataStorageBuilder, DataStorageError, StoreMode};
use pdk::hl::timer::Clock;
use pdk::hl::*;
use pdk::logger;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::caller::{candidate_accesses, encode_query, parse_grant, parse_user, select_usage, CallerInfo, Denial, Grant};
use crate::cdam::{Caller, Decision, GovernedField, PolicySet};
use crate::generated::config::Config;

const CACHE_NAMESPACE: &str = "cdam-cache";
const LOCK_NAMESPACE: &str = "cdam-refresh-lock";
const POLICIES_KEY: &str = "cdam-policies";
const CATALOG_KEY_PREFIX: &str = "cdam-catalog-";
const CALLER_KEY_PREFIX: &str = "cdam-caller-";
const LOCK_KEY_PREFIX: &str = "cdam-lock-";
const REFRESH_LOCK_TTL_SECONDS: i64 = 30;
const REFRESH_LOCK_TTL_MS: u32 = (REFRESH_LOCK_TTL_SECONDS as u32) * 1000;
const STORE_TTL_MS: u32 = 7 * 24 * 60 * 60 * 1000;
const CAS_MAX_RETRIES: u32 = 3;
const DEFAULT_TIMEOUT_MS: i64 = 5_000;
/// Budget for one chained refresh (login, JWT, then the lists or lookups).
const REFRESH_BUDGET_MS: i64 = 15_000;
const DEFAULT_POLICY_REFRESH_SECONDS: i64 = 300;
const DEFAULT_CATALOG_REFRESH_SECONDS: i64 = 3_600;
const DEFAULT_CALLER_REFRESH_SECONDS: i64 = 300;
const PAGE_SIZE: usize = 100;
const MAX_PAGES: usize = 20;

const SEARCH_PATH: &str = "/ccgf-searchv2/api/v1/search";
const DAM_PATH: &str = "/data360/dam/api/v1";
const MARKETPLACE_V2: &str = "/cdmp-marketplace/api/v2/consumer-accesses";
const MARKETPLACE_V1: &str = "/cdmp-marketplace/api/v1/consumerAccess";
const USERS_PATH: &str = "/saas/public/core/v3/users";
const TOOL_CLASS_TYPES: &[&str] = &["a2d.agentic.McpTool", "protocol.mcp.McpTool"];
const DEFAULT_FIELD_CLASS_TYPES: &[&str] = &["a2d.agentic.McpToolOutputField"];
const REL_CLASSIFIED_AS: &str = "core.ClassifiedAs";
const REL_TECH_GLOSSARY: &str = "com.infa.ccgf.models.governance.IClassTechnicalGlossaryBase";
const ATTR_CURATION: &str = "core.curationStatus";

const DEFAULT_CONSUMER_HEADER: &str = "x-idmc-user";
const DEFAULT_USAGE_HEADER: &str = "x-usage-context";
const USAGE_HEADER_OUT: &str = "x-cdam-usage-context";
const PROTECTED_HEADER: &str = "x-cdam-protected-fields";
const STATUS_HEADER: &str = "x-cdam-status";
const RPC_ERR_FORBIDDEN: i64 = -32003;
const RPC_ERR_UNAVAILABLE: i64 = -32603;

#[derive(Deserialize)]
struct LoginResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "orgId")]
    org_id: String,
}
#[derive(Deserialize)]
struct JwtResponse {
    jwt_token: String,
}

/// An authenticated IDMC session.
struct Session {
    session_id: String,
    jwt: String,
    org: String,
}

/// A cached value and when it was fetched (Unix seconds).
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Cached<T> {
    value: T,
    timestamp: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct RefreshLock {
    acquired_at: i64,
}

/// The MCP server's tools and their output fields, from CDGC.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Catalog {
    server_name: Option<String>,
    tools: BTreeMap<String, Vec<GovernedField>>,
}

/// What the request leg hands the response leg.
#[derive(Clone)]
struct Ctx {
    tool: String,
    rpc_id: Value,
    user: Option<String>,
    caller: Caller,
    grant: Option<Grant>,
}

fn now_secs(clock: &Clock) -> i64 {
    clock.now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
fn now_ms(clock: &Clock) -> i64 {
    clock.now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Per-call timeouts within one refresh budget.
struct Budget<'a> {
    clock: &'a Clock,
    start: SystemTime,
    per_call_ms: i64,
}

impl Budget<'_> {
    fn next(&self, what: &str) -> Result<Duration> {
        let elapsed = self.clock.now().duration_since(self.start).map(|d| d.as_millis() as i64).unwrap_or(0);
        let remaining = REFRESH_BUDGET_MS - elapsed;
        if remaining <= 0 {
            return Err(anyhow!("IDMC refresh budget spent before {what}"));
        }
        Ok(Duration::from_millis(self.per_call_ms.min(remaining).max(1) as u64))
    }
}

fn budget<'a>(config: &Config, clock: &'a Clock) -> Budget<'a> {
    Budget { clock, start: clock.now(), per_call_ms: config.timeout.unwrap_or(DEFAULT_TIMEOUT_MS) }
}

fn nonce(now: SystemTime) -> String {
    now.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_nanos().to_string()).unwrap_or_else(|_| "0".to_string())
}

/// IDMC Login → JWT.
async fn login(client: &HttpClient, config: &Config, b: &Budget<'_>) -> Result<Session> {
    let body = serde_json::to_vec(&json!({"username": config.cdgc_org_username, "password": config.cdgc_org_password}))?;
    let resp = client.request(&config.cdgc_login_url).path("/identity-service/api/v1/Login")
        .headers(vec![("Content-Type", "application/json")]).body(&body).timeout(b.next("login")?).post().await
        .map_err(|e| anyhow!("IDMC login failed: {e}"))?;
    if resp.status_code() >= 300 {
        return Err(anyhow!("IDMC login status {}", resp.status_code()));
    }
    let l: LoginResponse = serde_json::from_slice(resp.body()).map_err(|e| anyhow!("parse login: {e}"))?;
    let cookie = format!("USER_SESSION={}", l.session_id);
    let resp = client.request(&config.cdgc_login_url)
        .path(&format!("/identity-service/api/v1/jwt/Token?client_id=idmc_api&nonce={}", nonce(b.clock.now())))
        .headers(vec![("cookie", cookie.as_str()), ("IDS-SESSION-ID", l.session_id.as_str())])
        .timeout(b.next("JWT")?).get().await.map_err(|e| anyhow!("IDMC JWT failed: {e}"))?;
    if resp.status_code() >= 300 {
        return Err(anyhow!("IDMC JWT status {}", resp.status_code()));
    }
    let j: JwtResponse = serde_json::from_slice(resp.body()).map_err(|e| anyhow!("parse jwt: {e}"))?;
    Ok(Session { session_id: l.session_id, jwt: j.jwt_token, org: l.org_id })
}

/// GET a JSON document from the CDGC API host with the session's JWT.
async fn api_get(client: &HttpClient, config: &Config, b: &Budget<'_>, s: &Session, path: &str) -> Result<Value> {
    let authz = format!("Bearer {}", s.jwt);
    let resp = client.request(&config.cdgc_api_url).path(path)
        .headers(vec![("Authorization", authz.as_str()), ("X-INFA-ORG-ID", s.org.as_str()), ("Accept", "application/json")])
        .timeout(b.next(path)?).get().await.map_err(|e| anyhow!("GET {path} failed: {e}"))?;
    if resp.status_code() >= 300 {
        return Err(anyhow!("GET {path} status {}", resp.status_code()));
    }
    serde_json::from_slice(resp.body()).map_err(|e| anyhow!("parse {path}: {e}"))
}

/// One ccgf-searchv2 query; returns the hits' `sourceAsMap`s.
async fn search(client: &HttpClient, config: &Config, b: &Budget<'_>, s: &Session, query: Value, size: usize) -> Result<Vec<Value>> {
    let authz = format!("Bearer {}", s.jwt);
    let payload = serde_json::to_vec(&json!({"from": 0, "size": size, "query": query}))?;
    let resp = client.request(&config.cdgc_api_url).path(SEARCH_PATH)
        .headers(vec![
            ("Authorization", authz.as_str()),
            ("X-INFA-ORG-ID", s.org.as_str()),
            ("X-INFA-SEARCH-LANGUAGE", "elasticsearch"),
            ("Content-Type", "application/json"),
        ])
        .body(&payload).timeout(b.next("search")?).post().await
        .map_err(|e| anyhow!("CDGC search failed: {e}"))?;
    if resp.status_code() >= 300 {
        return Err(anyhow!("CDGC search status {}", resp.status_code()));
    }
    let v: Value = serde_json::from_slice(resp.body()).map_err(|e| anyhow!("parse search: {e}"))?;
    Ok(v.pointer("/hits/hits").and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|h| h.get("sourceAsMap").cloned()).collect())
        .unwrap_or_default())
}

fn s(map: &Value, key: &str) -> Option<String> {
    map.get(key).and_then(Value::as_str).map(str::to_string)
}

/// Every item of a paged list (`items[]`), following offset/limit.
async fn list_all(client: &HttpClient, config: &Config, b: &Budget<'_>, sess: &Session, path: &str) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for page in 0..MAX_PAGES {
        let sep = if path.contains('?') { '&' } else { '?' };
        let v = api_get(client, config, b, sess, &format!("{path}{sep}offset={}&limit={PAGE_SIZE}", page * PAGE_SIZE)).await?;
        let items = v.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
        let n = items.len();
        out.extend(items);
        let total = v.get("totalCount").or_else(|| v.pointer("/pageInfo/totalCount")).and_then(Value::as_u64);
        if n < PAGE_SIZE || total.is_some_and(|t| out.len() as u64 >= t) {
            return Ok(out);
        }
    }
    Ok(out)
}

/// The published CDAM assets.
async fn fetch_policies(client: &HttpClient, config: &Config, clock: &Clock) -> Result<PolicySet> {
    let b = budget(config, clock);
    let sess = login(client, config, &b).await?;
    Ok(PolicySet {
        deidentifications: list_all(client, config, &b, &sess, &format!("{DAM_PATH}/data-deidentifications")).await?,
        filters: list_all(client, config, &b, &sess, &format!("{DAM_PATH}/data-filters")).await?,
        protections: list_all(client, config, &b, &sess, &format!("{DAM_PATH}/data-protections")).await?,
        tiers: list_all(client, config, &b, &sess, &format!("{DAM_PATH}/precedence-tiers")).await?,
    })
}

fn field_class_types(config: &Config) -> Vec<String> {
    let v: Vec<String> = config.field_class_types.as_deref().unwrap_or_default().iter()
        .map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if v.is_empty() { DEFAULT_FIELD_CLASS_TYPES.iter().map(|s| s.to_string()).collect() } else { v }
}

/// Links that count: anything but a rejected curation.
fn accepted(rel: &Value) -> bool {
    s(rel, ATTR_CURATION).is_none_or(|c| !c.eq_ignore_ascii_case("REJECTED"))
}

/// The MCP server's tools and output fields, with classifications and terms.
async fn fetch_catalog(client: &HttpClient, config: &Config, clock: &Clock) -> Result<Catalog> {
    let b = budget(config, clock);
    let sess = login(client, config, &b).await?;
    let server_id = config.mcp_server_asset_id.trim();
    let server = search(client, config, &b, &sess, json!({"bool": {"must": [
        {"terms": {"elementType": ["OBJECT"]}}, {"terms": {"core.identity": [server_id]}}]}}), 1).await?
        .into_iter().next().ok_or_else(|| anyhow!("MCP server asset '{server_id}' not found"))?;
    let location = s(&server, "core.location").ok_or_else(|| anyhow!("MCP server asset has no core.location"))?;
    // `path_hierarchy.parent` matches direct children: tools under the server, fields
    // under their tool.
    let under = |classes: Vec<String>, parents: Vec<String>| json!({"bool": {
        "must": [{"terms": {"core.classType": classes}}],
        "filter": [{"terms": {"core.location::path_hierarchy.parent": parents}}]}});

    let tools = search(client, config, &b, &sess, under(TOOL_CLASS_TYPES.iter().map(|s| s.to_string()).collect(), vec![location]), 1000).await?;
    let tool_locations: Vec<String> = tools.iter().filter_map(|t| s(t, "core.location")).collect();
    let fields = if tool_locations.is_empty() {
        Vec::new()
    } else {
        search(client, config, &b, &sess, under(field_class_types(config), tool_locations), 5000).await?
    };
    let field_ids: Vec<String> = fields.iter().filter_map(|f| s(f, "core.identity")).collect();
    let mut classes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut terms: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if !field_ids.is_empty() {
        let rels = search(client, config, &b, &sess, json!({"bool": {"must": [
            {"terms": {"elementType": ["RELATIONSHIP"]}},
            {"terms": {"type": [REL_CLASSIFIED_AS, REL_TECH_GLOSSARY]}},
            {"terms": {"core.sourceIdentity": field_ids}}]}}), 10_000).await?;
        for r in rels.iter().filter(|r| accepted(r)) {
            let (Some(src), Some(tgt)) = (s(r, "core.sourceIdentity"), s(r, "core.targetIdentity")) else { continue };
            let kind = r.get("type").map(|t| t.to_string()).unwrap_or_default();
            let map = if kind.contains(REL_CLASSIFIED_AS) { &mut classes } else { &mut terms };
            map.entry(src).or_default().push(tgt);
        }
    }

    // A field belongs to the tool whose location is the longest prefix of its own.
    let tool_locs: Vec<(String, String)> = tools.iter()
        .filter_map(|t| Some((s(t, "core.location")?, s(t, "core.name")?.trim().to_string()))).collect();
    let mut catalog = Catalog { server_name: s(&server, "core.name"), tools: BTreeMap::new() };
    for (_, name) in &tool_locs {
        catalog.tools.entry(name.clone()).or_default();
    }
    for f in &fields {
        let (Some(id), Some(path), Some(loc)) = (s(f, "core.identity"), s(f, "core.name"), s(f, "core.location")) else { continue };
        let Some((_, tool)) = tool_locs.iter()
            .filter(|(tl, _)| loc.starts_with(&format!("{tl}/")))
            .max_by_key(|(tl, _)| tl.len()) else { continue };
        catalog.tools.entry(tool.clone()).or_default().push(GovernedField {
            path,
            classifications: classes.remove(&id).unwrap_or_default(),
            terms: terms.remove(&id).unwrap_or_default(),
        });
    }
    Ok(catalog)
}

/// The caller's IDMC user, groups and Data Marketplace grants.
async fn fetch_caller(client: &HttpClient, config: &Config, clock: &Clock, user_name: &str) -> Result<CallerInfo> {
    let b = budget(config, clock);
    let sess = login(client, config, &b).await?;
    let q = encode_query(&format!("userName==\"{}\"", user_name.trim()));
    let resp = client.request(&config.idmc_pod_url).path(&format!("{USERS_PATH}?q={q}"))
        .headers(vec![("INFA-SESSION-ID", sess.session_id.as_str()), ("Accept", "application/json")])
        .timeout(b.next("users")?).get().await.map_err(|e| anyhow!("IDMC users failed: {e}"))?;
    if resp.status_code() >= 300 {
        return Err(anyhow!("IDMC users status {}", resp.status_code()));
    }
    let users: Value = serde_json::from_slice(resp.body()).map_err(|e| anyhow!("parse users: {e}"))?;
    let Some((user_id, groups)) = parse_user(&users, user_name) else {
        return Ok(CallerInfo::default());
    };
    let accesses = list_all(client, config, &b, &sess, MARKETPLACE_V2).await?;
    let mut grants = Vec::new();
    for id in candidate_accesses(&accesses, &user_id, &groups) {
        let detail = api_get(client, config, &b, &sess, &format!("{MARKETPLACE_V1}/{id}")).await?;
        grants.extend(parse_grant(&detail));
    }
    Ok(CallerInfo { user_id: Some(user_id), groups, grants, timestamp: 0 })
}

// ---- caches ----

async fn read_cached<S: DataStorage, T: DeserializeOwned>(store: &S, key: &str) -> Option<Cached<T>> {
    match store.get::<Cached<T>>(key).await {
        Ok(Some((c, _))) => Some(c),
        Ok(None) => None,
        Err(e) => {
            logger::warn!("cdam: cache read failed for {key}: {e}");
            None
        }
    }
}
async fn write_cached<S: DataStorage, T: Serialize + DeserializeOwned>(store: &S, key: &str, entry: &Cached<T>) {
    for _ in 0..CAS_MAX_RETRIES {
        let mode = match store.get::<Cached<T>>(key).await {
            Ok(Some((_, v))) => StoreMode::Cas(v),
            Ok(None) => StoreMode::Absent,
            Err(e) => { logger::warn!("cdam: read-before-persist failed for {key}: {e}"); return; }
        };
        match store.store(key, &mode, entry).await {
            Ok(()) => return,
            Err(DataStorageError::CasMismatch) => continue,
            Err(e) => { logger::warn!("cdam: persist failed for {key}: {e}"); return; }
        }
    }
}
async fn try_acquire_refresh_lock<S: DataStorage>(store: &S, key: &str, now: i64) -> Result<bool, DataStorageError> {
    let entry = RefreshLock { acquired_at: now };
    match store.store(key, &StoreMode::Absent, &entry).await {
        Ok(()) => Ok(true),
        Err(DataStorageError::CasMismatch) => match store.get::<RefreshLock>(key).await? {
            Some((existing, v)) if now - existing.acquired_at >= REFRESH_LOCK_TTL_SECONDS => {
                match store.store(key, &StoreMode::Cas(v), &entry).await {
                    Ok(()) => Ok(true),
                    Err(DataStorageError::CasMismatch) => Ok(false),
                    Err(e) => Err(e),
                }
            }
            Some(_) => Ok(false),
            None => match store.store(key, &StoreMode::Absent, &entry).await {
                Ok(()) => Ok(true),
                Err(DataStorageError::CasMismatch) => Ok(false),
                Err(e) => Err(e),
            },
        },
        Err(e) => Err(e),
    }
}

/// A cached value, refreshed when older than `ttl` seconds. Only one replica/worker
/// refreshes stale data while the others keep serving it; with nothing cached, every
/// caller fetches. A failed refresh falls back to stale data.
async fn cached<S, T, F, Fut>(store: &S, locks: &S, key: &str, ttl: i64, now: i64, fetch: F) -> Option<T>
where
    S: DataStorage,
    T: Serialize + DeserializeOwned + Clone,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let current = read_cached::<S, T>(store, key).await;
    if let Some(c) = &current {
        if now - c.timestamp < ttl {
            return Some(c.value.clone());
        }
        if !try_acquire_refresh_lock(locks, &format!("{LOCK_KEY_PREFIX}{key}"), now).await.unwrap_or(true) {
            return Some(c.value.clone());
        }
    }
    match fetch().await {
        Ok(value) => {
            write_cached(store, key, &Cached { value: value.clone(), timestamp: now }).await;
            Some(value)
        }
        Err(e) => {
            logger::warn!("cdam: refresh of {key} failed: {e}");
            current.map(|c| c.value)
        }
    }
}

// ---- JSON-RPC helpers ----

fn rpc_error(id: &Value, code: i64, message: &str, data: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message, "data": data}})
}

fn deny(status: u32, body: Value) -> Response {
    Response::new(status)
        .with_headers(vec![
            ("content-type".to_string(), "application/json".to_string()),
            (STATUS_HEADER.to_string(), "denied".to_string()),
        ])
        .with_body(body.to_string())
}

fn parse_rpc(text: &str, is_sse: bool) -> Option<Value> {
    if !is_sse {
        return serde_json::from_str(text).ok();
    }
    text.lines()
        .filter_map(|l| l.trim_start().strip_prefix("data:"))
        .find_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
}
fn frame(rpc: &Value, is_sse: bool) -> String {
    let j = rpc.to_string();
    if is_sse { format!("event: message\ndata: {j}\n\n") } else { j }
}

fn called_tool(rpc: &Value) -> Option<&str> {
    if rpc.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    rpc.pointer("/params/name")?.as_str().map(str::trim).filter(|s| !s.is_empty())
}

// ---- request leg ----

#[allow(clippy::too_many_arguments)]
async fn request_filter<S: DataStorage>(
    request_state: RequestState,
    config: Rc<Config>,
    client: Rc<HttpClient>,
    clock: Rc<Clock>,
    store: Rc<S>,
    locks: Rc<S>,
) -> Flow<Option<Ctx>> {
    let state = request_state.into_headers_body_state().await;
    let h = state.handler();
    let ct = h.header("content-type").unwrap_or_default();
    if !ct.starts_with("application/json") || !state.contains_body() {
        return Flow::Continue(None);
    }
    let Ok(rpc) = serde_json::from_slice::<Value>(&h.body()) else { return Flow::Continue(None) };
    let Some(tool) = called_tool(&rpc).map(str::to_string) else { return Flow::Continue(None) };
    let rpc_id = rpc.get("id").cloned().unwrap_or(Value::Null);

    // A configured claim (from an upstream-validated Bearer token) wins over the header.
    let jwt_claims = if config.consumer_claim.is_some() || config.usage_context_claim.is_some() {
        claims::decode_bearer_claims(h.header("authorization").as_deref())
    } else {
        None
    };
    let from_claim = |name: &Option<String>| claims::claim_str(jwt_claims.as_ref()?, name.as_deref()?);
    let header = |name: Option<&str>, default: &str| {
        h.header(&name.unwrap_or(default).to_ascii_lowercase()).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
    };
    let user = from_claim(&config.consumer_claim).or_else(|| header(config.consumer_header.as_deref(), DEFAULT_CONSUMER_HEADER));
    let declared = from_claim(&config.usage_context_claim).or_else(|| header(config.usage_context_header.as_deref(), DEFAULT_USAGE_HEADER));

    let require = config.require_consumer_access.unwrap_or(true);
    let collections = config.data_collection_ids.clone().unwrap_or_default();
    let unverified = Ctx { tool: tool.clone(), rpc_id: rpc_id.clone(), user: user.clone(), caller: Caller::default(), grant: None };
    let denied = |d: &Denial| {
        logger::info!("cdam: DENY tool={tool} user={user:?} usage={declared:?}: {}", d.message());
        Flow::Break(deny(403, rpc_error(&rpc_id, RPC_ERR_FORBIDDEN, &d.message(), json!({
            "policy": "cdam-data-access-enforcement", "user": user, "usageContext": declared}))))
    };

    let Some(user_name) = user.clone() else {
        return if require { denied(&Denial::NoConsumer) } else { Flow::Continue(Some(unverified)) };
    };
    let ttl = config.caller_refresh_seconds.unwrap_or(DEFAULT_CALLER_REFRESH_SECONDS);
    let key = format!("{CALLER_KEY_PREFIX}{}", user_name.to_lowercase());
    let info = cached(&*store, &*locks, &key, ttl, now_secs(&clock), || fetch_caller(&client, &config, &clock, &user_name)).await;
    let Some(info) = info else {
        if config.fail_open_on_idmc_error.unwrap_or(false) {
            logger::warn!("cdam: caller '{user_name}' unresolved (IDMC unavailable); continuing without a usage context");
            return Flow::Continue(Some(unverified));
        }
        return Flow::Break(deny(503, rpc_error(&rpc_id, RPC_ERR_UNAVAILABLE,
            "Data access could not be verified: IDMC is unavailable.", json!({"policy": "cdam-data-access-enforcement"}))));
    };
    match select_usage(&info, declared.as_deref(), &collections, require) {
        Err(d) => denied(&d),
        Ok(grant) => {
            let caller = Caller { usage: grant.as_ref().map(|g| g.usage.id.clone()), groups: info.groups.clone() };
            logger::info!("cdam: ALLOW tool={tool} user={user_name} usage={:?} access={:?}",
                grant.as_ref().and_then(|g| g.usage.name.clone()), grant.as_ref().map(|g| g.access_id.clone()));
            Flow::Continue(Some(Ctx { caller, grant, ..unverified }))
        }
    }
}

// ---- response leg ----

/// Enforce on one payload and annotate it.
fn enforce_one(v: &mut Value, plan: &[(GovernedField, Decision)], ctx: &Ctx, set: &PolicySet, now: i64) -> payload::Report {
    let report = payload::enforce(v, plan, &ctx.caller, set, now);
    if let Value::Object(root) = v {
        let mut a = report.to_json();
        a["user"] = json!(ctx.user);
        a["usageContext"] = json!(ctx.grant.as_ref().map(|g| json!({"id": g.usage.id, "name": g.usage.name})));
        a["consumerAccess"] = json!(ctx.grant.as_ref().map(|g| g.access_ref.clone().unwrap_or_else(|| g.access_id.clone())));
        a["tool"] = json!(ctx.tool);
        a["source"] = json!("cdam");
        root.insert("_cdam".to_string(), a);
    }
    report
}

#[allow(clippy::too_many_arguments)]
async fn response_filter<S: DataStorage>(
    response_state: ResponseState,
    request_data: RequestData<Option<Ctx>>,
    config: Rc<Config>,
    client: Rc<HttpClient>,
    clock: Rc<Clock>,
    store: Rc<S>,
    locks: Rc<S>,
) {
    let RequestData::Continue(Some(ctx)) = request_data else { return };
    let now = now_secs(&clock);
    let server = config.mcp_server_asset_id.trim().to_string();
    let catalog: Option<Catalog> = cached(&*store, &*locks, &format!("{CATALOG_KEY_PREFIX}{server}"),
        config.catalog_refresh_seconds.unwrap_or(DEFAULT_CATALOG_REFRESH_SECONDS), now,
        || fetch_catalog(&client, &config, &clock)).await;
    let policies: Option<PolicySet> = cached(&*store, &*locks, POLICIES_KEY,
        config.policy_refresh_seconds.unwrap_or(DEFAULT_POLICY_REFRESH_SECONDS), now,
        || fetch_policies(&client, &config, &clock)).await;

    let hs = response_state.into_headers_state().await;
    let ct = hs.handler().header("content-type").unwrap_or_default();
    let is_sse = ct.contains("event-stream");
    if !is_sse && !ct.contains("json") {
        return;
    }
    let (Some(catalog), Some(set)) = (catalog, policies) else {
        if config.fail_open_on_idmc_error.unwrap_or(false) {
            logger::warn!("cdam: no CDAM policies or catalog (IDMC unavailable); tool={} passed through unprotected", ctx.tool);
            hs.handler().set_header(STATUS_HEADER, "unenforced");
            return;
        }
        hs.handler().set_header(STATUS_HEADER, "unavailable");
        hs.handler().remove_header("content-length");
        hs.handler().remove_header("content-encoding");
        let bs = hs.into_body_state().await;
        let err = rpc_error(&ctx.rpc_id, RPC_ERR_UNAVAILABLE, "Data access policies could not be enforced: IDMC is unavailable.",
            json!({"policy": "cdam-data-access-enforcement"}));
        if let Err(e) = bs.handler().set_body(frame(&err, is_sse).as_bytes()) {
            logger::warn!("cdam: set_body failed: {e:?}");
        }
        return;
    };
    let Some(fields) = catalog.tools.get(&ctx.tool) else {
        logger::info!("cdam: tool '{}' is not an MCP Tool of '{}' in CDGC; result not governed", ctx.tool,
            catalog.server_name.as_deref().unwrap_or(&server));
        return;
    };
    let now_ms = now_ms(&clock);
    let plan = payload::plan(fields, &ctx.caller, &set, now_ms);
    let protected = plan.iter().filter(|(_, d)| *d != Decision::Retain).count();

    // Caller-level facts go in headers now; record-level ones ride in `_cdam`.
    hs.handler().set_header(STATUS_HEADER, "enforced");
    hs.handler().set_header(PROTECTED_HEADER, &protected.to_string());
    if let Some(name) = ctx.grant.as_ref().and_then(|g| g.usage.name.as_deref()) {
        hs.handler().set_header(USAGE_HEADER_OUT, name);
    }
    hs.handler().remove_header("content-length");
    hs.handler().remove_header("content-encoding");
    let bs = hs.into_body_state().await;
    let Ok(text) = String::from_utf8(bs.handler().body()) else { return };
    let Some(mut rpc) = parse_rpc(&text, is_sse) else { return };
    let Some(result) = rpc.get_mut("result").and_then(Value::as_object_mut) else { return };

    let mut reports = Vec::new();
    if let Some(sc) = result.get_mut("structuredContent") {
        reports.push(enforce_one(sc, &plan, &ctx, &set, now_ms));
        // The text mirror must not carry what structuredContent no longer does.
        let mirror = sc.to_string();
        result.insert("content".to_string(), json!([{"type": "text", "text": mirror}]));
    } else if let Some(items) = result.get_mut("content").and_then(Value::as_array_mut) {
        for item in items.iter_mut().filter(|i| i.get("type").and_then(Value::as_str) == Some("text")) {
            let Some(t) = item.get("text").and_then(Value::as_str) else { continue };
            match serde_json::from_str::<Value>(t) {
                Ok(mut v) if v.is_object() || v.is_array() => {
                    reports.push(enforce_one(&mut v, &plan, &ctx, &set, now_ms));
                    item["text"] = Value::String(v.to_string());
                }
                // Free text cannot be governed field by field.
                _ if protected > 0 => item["text"] = Value::String("[withheld by CDAM: unstructured tool output]".to_string()),
                _ => {}
            }
        }
    }
    let rows: usize = reports.iter().map(|r| r.rows_removed).sum();
    let fields_changed: usize = reports.first().map(|r| r.fields.len()).unwrap_or(0);
    logger::info!("cdam: tool={} user={:?} usage={:?} fields_protected={fields_changed} rows_removed={rows}",
        ctx.tool, ctx.user, ctx.caller.usage);

    if let Err(e) = bs.handler().set_body(frame(&rpc, is_sse).as_bytes()) {
        logger::warn!("cdam: set_body failed: {e:?}");
    }
}

fn launch_policy<S: DataStorage + 'static>(
    launcher: Launcher, config: Rc<Config>, client: Rc<HttpClient>, clock: Rc<Clock>, store: Rc<S>, locks: Rc<S>,
) -> impl std::future::Future<Output = Result<()>> {
    let (c1, cl1, ck1, s1, l1) = (config.clone(), client.clone(), clock.clone(), store.clone(), locks.clone());
    let filter = on_request(move |rs| {
        let (c, cl, ck, st, lk) = (c1.clone(), cl1.clone(), ck1.clone(), s1.clone(), l1.clone());
        async move { request_filter(rs, c, cl, ck, st, lk).await }
    })
    .on_response(move |rs, rd| {
        let (c, cl, ck, st, lk) = (config.clone(), client.clone(), clock.clone(), store.clone(), locks.clone());
        async move { response_filter(rs, rd, c, cl, ck, st, lk).await }
    });
    async move { launcher.launch(filter).await.map_err(Into::into) }
}

#[entrypoint]
async fn configure(
    launcher: Launcher,
    Configuration(bytes): Configuration,
    client: HttpClient,
    storage_builder: DataStorageBuilder,
    clock: Clock,
) -> Result<()> {
    // Never echo the configuration: it carries the service-account password.
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| anyhow!("Failed to parse configuration: {err}"))?;
    let (config, client, clock) = (Rc::new(config), Rc::new(client), Rc::new(clock));
    if config.distributed.unwrap_or(false) {
        let store = Rc::new(storage_builder.remote(CACHE_NAMESPACE, STORE_TTL_MS));
        let locks = Rc::new(storage_builder.remote(LOCK_NAMESPACE, REFRESH_LOCK_TTL_MS));
        launch_policy(launcher, config, client, clock, store, locks).await
    } else {
        let store = Rc::new(storage_builder.local(CACHE_NAMESPACE));
        let locks = Rc::new(storage_builder.local(LOCK_NAMESPACE));
        launch_policy(launcher, config, client, clock, store, locks).await
    }
}
