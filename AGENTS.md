# Agent notes

"MCP CDAM Data Access Enforcement": MuleSoft Omni/Flex Gateway custom policy (PDK 1.10,
Rust → wasm32-wasip1, `enable_stop_iteration`) that enforces Informatica CDAM Data Filter
and Data De-Identification policies on MCP `tools/call` results.

Keep this repo free of tenant-specific names, ids and hosts. Tests use placeholder ids;
real exports for `live_eval` live outside the repo. Record releases in `CHANGELOG.md`.

- After editing `cdam-data-access-enforcement-definition/gcl.yaml`, run
  `make release-local` in the definition dir (local publish to `~/.exchange`), then
  regenerate the config struct from `cdam-data-access-enforcement-flex/` with
  `cargo anypoint config-gen --manifest ../cdam-data-access-enforcement-definition/gcl.yaml --output ./src/generated/config.rs`.
- Pure logic, with unit tests: `src/predicate.rs` (CDAM structured predicates),
  `src/cdam.rs` (policy ordering and decisions), `src/protect.rs` (techniques),
  `src/payload.rs` (paths, filters, enforcement), `src/caller.rs` (usage-context
  verification), `src/claims.rs`. `src/lib.rs` is the gateway wiring (IDMC calls, caches,
  request and response legs).
- Every path the gateway cannot evaluate must resolve toward more protection.
- Never log credentials, session ids, tokens or IDMC response bodies.
- `demo/`: `demo.sh` and `show.py` call a deployed instance; `config.json`,
  `jwt-config.json` and `env.local.sh` hold real values and are gitignored. Only
  commit the `.example` files, with placeholders.
