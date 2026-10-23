# Demo walkthrough: same tool, two usage contexts

This demo sends the same MCP `tools/call` through the gateway as two IDMC users who
hold different Data Marketplace usage contexts, and shows what each one receives. The
upstream MCP server returns identical data to everyone. The policy decides, from the
published CDAM Data Filter and Data De-Identification assets, which records each caller
keeps and how each field is protected.

Nothing in the policy is configured per field. Field classifications come from the MCP
Server asset in CDGC, and the rules come from CDAM.

## Files

| File | Tracked | Contents |
|---|---|---|
| `demo.sh` | yes | Gets a token for each demo user and sends the four calls below |
| `show.py` | yes | Prints the records and the `_cdam` summary of a `tools/call` response |
| `config.json.example` | yes | This policy's configuration, with placeholders |
| `jwt-config.json.example` | yes | JWT Validation configuration, with placeholders |
| `env.local.sh.example` | yes | Gateway URL, token endpoint, client and demo user credentials, with placeholders |
| `config.json`, `jwt-config.json`, `env.local.sh` | **no** (gitignored) | Your real values |

Copy each `.example` file without the suffix and fill it in. Never commit the copies.

## The callers

| Caller | IDMC user holds | Declares |
|---|---|---|
| Bob | consumer access with the **Regulatory Reporting** usage context | Regulatory Reporting |
| Gina | consumer access with the **Analytics** usage context | Analytics |

Each user exists in the identity provider realm with an `idmc_user` attribute pointing at
their IDMC user. The policy reads that claim (`consumerClaim: idmc_user`) from the
validated token and the declared usage context from the `x-usage-context` header.

## How the policy decides

**Request leg.** The policy looks up the IDMC user, lists the AVAILABLE Data Marketplace
consumer accesses held by that user or their groups (limited to `dataCollectionIds`), and
checks that the declared usage context is one of them. If not, the call is denied with
HTTP 403 and JSON-RPC error `-32003` before it reaches the upstream.

**Response leg.** The policy resolves the tool in CDGC (MCP Server → tool → output fields
→ classifications), then applies CDAM:

1. **Data filters**: each rule whose condition holds for the caller removes the records
   its predicate matches. For example, *Access for Regulatory Reporting* keeps only US
   customers.
2. **De-identification**: for each classified field, the first matching rule (by
   precedence tier, policy order and rule rank) chooses the technique: retain, redact with
   null, or truncate. A classified field with no protecting rule is redacted with null.

Anything the gateway cannot evaluate resolves toward more protection.

---

## Call 1: no token → rejected by JWT Validation

No `Authorization` header. JWT Validation runs first and answers **400**. The CDAM policy
never runs.

## Call 2: Bob, Regulatory Reporting → filtered and truncated

- Usage context *Regulatory Reporting* is granted to Bob → allowed.
- The Regulatory Reporting data filter applies → non-US rows are removed.
- The Regulatory Reporting de-identification rule applies → for example, the card number
  is truncated to its last 4 characters.

What `show.py` prints (illustrative values):

```text
  {"order_id": "SO-1", "customer_id": "CUST-9001", "country": "US", "card_number": "4242", ...}
  _cdam: {"user": "<bob's IDMC user>", "usageContext": {"id": "<id>", "name": "Regulatory Reporting"},
          "consumerAccess": "<access ref>", "filters": ["<filter policy> / <rule>"], "rowsRemoved": 1,
          "substituted": [], "uncertain": []}
HTTP/1.1 200 OK
x-cdam-status: enforced
x-cdam-usage-context: Regulatory Reporting
x-cdam-protected-fields: <field paths>
```

## Call 3: Gina, Analytics → all rows, Analytics rule

- Usage context *Analytics* is granted to Gina → allowed.
- The Regulatory Reporting filter's condition does not hold → no rows removed.
- The Analytics de-identification rule applies to each classified field.

```text
  {"order_id": "SO-1", "country": "US", ...}
  {"order_id": "SO-2", "country": "DE", ...}
  _cdam: {"user": "<gina's IDMC user>", "usageContext": {"id": "<id>", "name": "Analytics"},
          "filters": [], "rowsRemoved": 0, ...}
x-cdam-status: enforced
x-cdam-usage-context: Analytics
```

## Call 4: Gina declaring Regulatory Reporting → denied

Gina's IDMC user holds no access with the Regulatory Reporting usage context, so she
cannot claim it. The policy answers **403** with a JSON-RPC error that says the usage
context is not granted, and `x-cdam-status: denied`.

---

## Why this matters

Same tool, same data, same endpoint. The gateway, not the upstream MCP server and not the
agent, enforces the CDAM policies that already govern JDBC access through the CDAM proxy.
A caller cannot pick a more permissive usage context than the one Data Marketplace
granted. Change a rule in CDAM, or reclassify a field in CDGC, and the gateway follows it
after the next cache refresh (`policyRefreshSeconds`, `catalogRefreshSeconds`) with no
policy edit.

## Reading the response

- `_cdam` in the payload: protected fields with their techniques, `filters`,
  `rowsRemoved`, `substituted` (tokenisation replaced by redact-with-null), `unsupported`,
  `uncertain` (policies that could not be evaluated, whose fields were redacted), and the
  user, usage context, consumer access and tool.
- Headers: `x-cdam-status` (`enforced`, `unenforced`, `denied`, `unavailable`),
  `x-cdam-usage-context`, `x-cdam-protected-fields`.

---

## Provisioning

### Things this demo wires up (fill each with your own tenant's values)

| Thing | Value |
|---|---|
| Anypoint org / env | `<orgId>` / `<envId>` |
| MCP API instance | `<apiInstanceId>` on a Flex gateway `<gatewayId>` (Flex 1.14) |
| Governed endpoint | `https://<gatewayPublicHost>/<basePath>/mcp` → `CDAM_GW_URL` |
| CDGC MCP Server asset | `<mcpServerAssetId>`, with tool output fields classified |
| Data Marketplace collection | `<dataCollectionId>`, with consumer accesses for both usage contexts |
| CDAM assets | a Data Filter and a Data De-Identification, published |
| IDMC service account | read access to the catalog, Data Access assets, consumer accesses and users |
| Identity provider realm | `<realm>` at `<idpUrl>`, confidential client `<clientId>` |

### 1. Identity provider

Create an OpenID Connect realm with a confidential client (direct access grants on). Add
an audience mapper for the API and a user-attribute mapper that puts the `idmc_user`
attribute in an `idmc_user` claim. Create `bob` and `gina` with `idmc_user` set to IDMC
users that hold the matching consumer accesses.

### 2. Policies on the API instance

Apply in this order:

1. **JWT Validation** `jwt-validation` 0.12.0 (1.4.x has no Flex 1.14 implementation)
   with `jwt-config.json`. Put the realm's RSA public key in `textKey` and the client's
   audience in `supportedAudiences`. Keep the placeholder values for the branches that are
   not used. Do not add an `iss` custom claim check: a literal URL containing a port made
   the gateway answer every request with an empty 503.
2. The MCP support and validation policies.
3. **This policy** with `config.json`.
4. The routing and transcoding policies.

```bash
cp config.json.example config.json           # IDMC URLs, service account, asset and collection ids
cp jwt-config.json.example jwt-config.json   # realm key and audience
anypoint-cli-v4 api-mgr:policy:apply <apiInstanceId> jwt-validation \
  --environment <env> --policyVersion 0.12.0 --configFile ./jwt-config.json
anypoint-cli-v4 api-mgr:policy:apply <apiInstanceId> cdam-data-access-enforcement \
  --environment <env> --groupId <orgId> --policyVersion <version> --configFile ./config.json
```

Gateway policies that change tool results before this one sees them (for example a
field-masking filter) can hide the original values from CDAM. `demo.sh` sends the headers
such a policy needs to let them through (`x-dp-clearance`, `x-dp-purpose`), so CDAM makes
the decision.

### 3. Egress

The gateway must reach `cdgcLoginUrl`, `cdgcApiUrl` and `idmcPodUrl`
(`*.informaticacloud.com`).

## Run it yourself

```bash
cp env.local.sh.example env.local.sh   # gateway URL, IdP, client secret, demo user passwords
./demo.sh
```

Override the call with `TOOL` and `ARGS`:

```bash
TOOL=<tool> ARGS='{"customer_id":"..."}' ./demo.sh
```

The usage context names declared in `demo.sh` must match the names (or ids, or reference
ids such as `USG-7`) of the usage contexts in your tenant.
