# Changelog

## 1.0.0

- First release. Enforces published CDAM Data Filter and Data De-Identification
  policies on MCP `tools/call` results, using the MCP Server's output-field
  classifications from CDGC.
- Gets the caller's usage context from their Data Marketplace consumer accesses
  (held directly or through an IDMC group). The policy reads their IDMC groups for
  `context::principal.groups`.
- Supports retain, redact-with-null and truncate. Tokenise and numeric tokenise are
  replaced with redact-with-null, because the gateway does not have CDAM's
  tokenisation keys.
