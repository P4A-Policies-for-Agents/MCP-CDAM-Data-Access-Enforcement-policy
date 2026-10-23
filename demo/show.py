"""Pretty-print a tools/call response: the records and the _cdam summary."""
import json, sys
raw = sys.stdin.read()
try:
    d = json.loads(raw)
except ValueError:
    print(raw[:600]); sys.exit()
if "error" in d:
    print("error:", json.dumps(d["error"])); sys.exit()
r = d.get("result", {})
payload = r.get("structuredContent")
if payload is None:
    for c in r.get("content", []):
        try:
            payload = json.loads(c.get("text", "")); break
        except ValueError:
            print("text:", c.get("text", "")[:300])
if payload is None:
    print(json.dumps(r)[:600]); sys.exit()
s = payload.pop("_cdam", {})
payload.pop("_entitlement", None)
for k, v in payload.items():
    if isinstance(v, list):
        for rec in v:
            print(" ", json.dumps(rec, ensure_ascii=False))
    else:
        print(f"  {k}: {v}")
print("  _cdam:", json.dumps({k: s.get(k) for k in ["user", "usageContext", "consumerAccess", "filters", "rowsRemoved", "substituted", "uncertain"]}, ensure_ascii=False))
