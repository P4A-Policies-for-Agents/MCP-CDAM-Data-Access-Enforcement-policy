# MCP CDAM Data Access Enforcement — MuleSoft Omni/Flex Gateway Policy

A custom policy for MCP APIs on the MuleSoft Omni/Flex Gateway. It applies **Informatica
Cloud Data Access Management (CDAM)** to MCP tool results, the same way the CDAM proxy does
for JDBC:

- **Data Filter** policies remove the records the caller may not see. For example, an
  "Access for Regulatory Reporting" rule keeps only US customers.
- **Data De-Identification** policies protect each field according to its CDGC
  classification and the caller's **usage context**. Depending on the rule, a card number
  is cut to its last 4 digits, an email is nulled, or a date of birth is kept to its year.

Nothing is configured per field. The fields come from the MCP Server asset in CDGC
(tools → output fields → data element classifications), and the rules come from the
published CDAM assets. Change a rule in CDAM and the gateway follows it after the next
cache refresh.

Built with PDK 1.10, Rust → `wasm32-wasip1`. Applies to MCP APIs only (`assetTypes: mcp`)
and inspects JSON-RPC `tools/call` traffic only.

---

## Flow

```
tools/call ──► request leg
                 caller = consumerClaim | consumerHeader  (IDMC user name)
                 declared usage = usageContextClaim | usageContextHeader
                 IDMC user → id + groups; Marketplace consumer accesses → granted usage contexts
                 not granted & requireConsumerAccess → 403 JSON-RPC error (-32003)
           ──► upstream MCP server
           ◄── response leg
                 catalog: MCP Server → tool (by name) → output fields + classifications
                 CDAM: de-identifications, filters, protections, precedence tiers
                 data filters, then field de-identification
                 result + headers x-cdam-status / x-cdam-usage-context / x-cdam-protected-fields
```

## How the caller is verified

A caller cannot just claim a usage context. Each call carries the caller's IDMC user name
(set by an upstream identity policy) and, optionally, a declared usage context (its id, its
reference id such as `USG-7`, or its name). The policy then:

1. Logs in as the service account and finds the user with
   `GET {idmcPodUrl}/saas/public/core/v3/users`. That gives the user's id and IDMC groups.
2. Lists Data Marketplace consumer accesses (`/cdmp-marketplace/api/v2/consumer-accesses`)
   and keeps the **AVAILABLE** ones held by the user or by one of their groups. Each access's
   detail (`/api/v1/consumerAccess/{id}`) gives its usage context and data collection.
   If `dataCollectionIds` is set, only accesses to those collections count.
3. Checks the declared usage context. It must be one of those granted. If none is
   declared, the call succeeds only when exactly one distinct usage context is granted.

The CDAM context is then `context::request.usage` = the verified usage context id and
`context::principal.groups` = the user's IDMC group ids.

When `requireConsumerAccess` is true (the default), a call fails with HTTP 403 and a
JSON-RPC error that gives the reason in these cases:

- the user is missing or unknown;
- the user has no access;
- the declared usage context is not granted;
- no usage context is declared and the user holds several.

When it is false, those calls run with no usage context, and CDAM's default (redact every
classified field) applies.

## CDAM semantics at the gateway

| CDAM | Gateway |
|---|---|
| De-identification order | Precedence tier rank, then the tier's policy ordering, then rules by rank. The first rule that matches and has a protection for one of the field's classifications or terms wins. |
| Classified field with no protecting rule | Redacted with null (CDAM default). |
| Unclassified field | Retained. |
| Data filters | Cumulative. Each rule whose condition holds removes the records its predicate matches. A filter whose locators match none of the tool's fields does not apply to that tool. |
| Record | An element of the innermost array on a field's path (`orders[].iban` → each order). A field outside arrays makes the whole result the record; if it is filtered, the result becomes `{}`. |
| Predicates | `and` / `or` / `not` / `isAnyOf` / `isNotAnyOf` over `context::request.usage`, `context::principal.groups`, constants (including group identifiers) and `fieldValue` locators on `cdgc::dataelement.classifications[*].id` or `glossaries[*].id`. |
| Policy dates | `enabled`, `effectiveDate`, `endDate` respected. |
| Techniques | `RETAIN_FUNCTION`, `REDACT_WITH_NULL_FUNCTION`, `TRUNCATE_FUNCTION` (`PRESERVE_FIRST/LAST_FEW_CHARACTERS`). The technique for the value's type is used, else the `UNKNOWN` one. |
| Tokenisation | `TOKENISE_FUNCTION` and `NUMERIC_TOKENISE_FUNCTION` become redact-with-null, because the gateway does not have CDAM's tokenisation keys. Each such field is listed under `_cdam.substituted`. |

**Anything the gateway cannot evaluate is resolved toward more protection.**

- An unknown condition dialect, an unsupported locator, cell-level protections, or an
  unreadable date redact the affected fields. The policy name is listed under
  `_cdam.uncertain`.
- An unknown filter condition applies the filter.
- A filter predicate that cannot be decided for a record removes that record.
- An unknown technique redacts the value, and the field is listed under `_cdam.unsupported`.

## What the client receives

- **`structuredContent`**: CDAM is applied to it, and `content` is replaced with a single
  text item that mirrors it.
- **Otherwise**: each JSON `text` content item is enforced. A non-JSON text item is replaced
  with `[withheld by CDAM: unstructured tool output]` if any of the tool's fields is
  protected.
- Each enforced payload gets a `_cdam` object. It contains the protected fields with their
  techniques, the substituted, unsupported and uncertain lists, the applied filters,
  `rowsRemoved`, the user, the usage context, the consumer access and the tool.
- Response headers:
  - `x-cdam-status`: `enforced`, `unenforced`, `denied` or `unavailable`;
  - `x-cdam-usage-context`;
  - `x-cdam-protected-fields`.

## Failure handling

- **IDMC unreachable with no cached data**: the tool result is replaced with a JSON-RPC
  error (`-32603`), and a caller lookup fails with 503. Set `failOpenOnIdmcError: true` to
  pass results through unprotected instead.
- **Stale cache**: always served when a refresh fails.
- **Caches**: PDK DataStorage, lazy refresh, one refresher at a time per key. Set
  `distributed: true` to share them across replicas.
- **Logging**: credentials are `security:sensitive`. Session ids, tokens and IDMC bodies
  are never logged.
- **Tool not in the catalog**: passed through, and a log line is written.

## Configuration

| Property | Default | Purpose |
|---|---|---|
| `cdgcLoginUrl` | — | IDMC login base, e.g. `https://dm-us.informaticacloud.com` |
| `cdgcApiUrl` | — | CDGC API base (search, CDAM, Marketplace), e.g. `https://cdgc-api.dm-us.informaticacloud.com` |
| `idmcPodUrl` | — | Pod REST base for the user API, e.g. `https://usw3.dm-us.informaticacloud.com` |
| `cdgcOrgUsername` / `cdgcOrgPassword` | — | Service account. Needs read access to the catalog, Data Access assets, consumer accesses and users. |
| `mcpServerAssetId` | — | CDGC id of the MCP Server asset. Tools are matched to `params.name` by exact name. |
| `fieldClassTypes` | `[a2d.agentic.McpToolOutputField]` | Output-field classes. A field's name is its path, e.g. `orders[].iban`. |
| `dataCollectionIds` | `[]` | Collections whose consumer access counts. Empty = any. |
| `consumerHeader` / `consumerClaim` | `x-idmc-user` / — | Where the IDMC user name is read from. The claim wins when set and present. |
| `usageContextHeader` / `usageContextClaim` | `x-usage-context` / — | Where the declared usage context is read from. |
| `requireConsumerAccess` | `true` | Deny calls whose usage context cannot be verified. |
| `policyRefreshSeconds` / `catalogRefreshSeconds` / `callerRefreshSeconds` | 300 / 3600 / 300 | Cache TTLs. |
| `failOpenOnIdmcError` | `false` | See Failure handling. |
| `distributed` | `false` | Share caches across replicas. |
| `timeout` | 5000 | Per-call IDMC timeout (ms), within a ~15 s refresh budget. |

The caller identity header must come from a trusted upstream policy, such as JWT
validation that maps the subject to the header. Otherwise a client could name another
user. Prefer `consumerClaim` on a validated token.

## Build

```bash
cd cdam-data-access-enforcement-definition && make release-local   # local publish (~/.exchange)
cd ../cdam-data-access-enforcement-flex && make build              # wasm + implementation
cargo test --lib                                                   # unit tests
```

Publishing to Exchange (`make publish` / `make release`) and applying the policy to an
API instance are separate, deliberate steps.

## Evaluating against a real tenant (offline)

`src/live_eval.rs` is an ignored test. It runs the real decision code over JSON exports
of a tenant and makes no network calls:

```bash
CDAM_EVAL_DIR=/path/to/export cargo test --lib live_eval -- --ignored --nocapture
```

The directory holds:

- `policies.json`: the CDAM lists;
- `catalog.json`: tools → fields;
- `callers.json`: user → groups and grants;
- optionally `result.json`: a tool result to enforce.

Without `result.json`, the test makes one US and one German record per array. For each
caller, and for a caller without consumer access, it prints the verified usage context,
the report and the protected result. Keep the exports out of the repo.

## Demo (`demo/`)

`demo/demo.sh` sends the same `tools/call` as two IDMC users with different Data
Marketplace usage contexts, and prints what each one receives. The real values live in
gitignored files; copy each `.example` and fill it in:

| File | Contents |
|---|---|
| `config.json` | this policy's configuration (IDMC URLs, service account, MCP server asset, data collections) |
| `jwt-config.json` | JWT Validation configuration for the identity provider realm |
| `env.local.sh` | gateway URL, token endpoint, client and demo user credentials |

The setup it expects:

- **Identity provider:** an OpenID Connect realm with a confidential client
  (direct access grants on). The client has an audience mapper for the API and a
  user-attribute mapper that puts the user's IDMC user name in an `idmc_user` claim.
  Each demo user has `idmc_user` set to an IDMC user that holds a Data Marketplace
  consumer access.
- **JWT Validation** (`jwt-validation` 0.12.0; 1.4.x has no Flex 1.14 implementation)
  runs first and checks the RSA signature against the realm's public key, plus `aud`
  and `exp`. Its schema needs the placeholder values in `jwt-config.json.example` for
  the branches that are not used. Do not add an `iss` custom claim check. A literal
  URL containing a port made the gateway answer every request with an empty 503. The
  realm key already ties tokens to the realm.
- **Policy order:** JWT Validation, then the MCP support and validation policies, then
  this policy, then the routing and transcoding policies. Gateway policies that change
  tool results (for example a field-masking filter) run on the response before this
  policy sees it; the demo sends whatever headers such a policy needs to let the
  original values through, so that CDAM makes the decision.

Expected results:

- **No token:** 400 from JWT Validation.
- **Regulatory Reporting user:** non-US rows removed by the data filter, fields
  protected per the Regulatory Reporting rule (for example the card number truncated
  to its last 4 characters).
- **Analytics user:** all rows, with the Analytics rule applied.
- **Analytics user declaring Regulatory Reporting:** 403, usage context not granted.

`ARGS` and `TOOL` override the call, for example
`TOOL=<tool> ARGS='{"customer_id":"..."}' demo/demo.sh`.
