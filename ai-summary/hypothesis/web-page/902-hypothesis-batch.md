# H902: Path seeded hypothesis batch for sendFile traversal

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/902-path-seed.md
**Hypothesis by**: claude-haiku-4-5

## Shared Path Context

Route: `index.js::requestListener` → `index.js::sendFile`

The dispatch seed targets path traversal in `sendFile` (line 29), where the `name` query parameter from `parseRequest` (line 12) is joined directly to `publicDir` without validation.

Prior investigation [1] found this route VIABLE with high confidence, determining that `readFile(join(publicDir, name))` at line 29 has no path containment check. The catch block at line 33 is error handling only.

## Source Confirmation

Source read confirms:
- Line 12: `name` from untrusted `searchParams.get("name")`
- Line 29: `readFile(join(publicDir, name))` — no path traversal guard
- Line 6: `publicDir = join(process.cwd(), "public")` — static directory root
- Line 33-34: Catch returns error response, not a security boundary

## Distinct Vulnerability Search

Searching for mechanisms distinct from path traversal already covered:

1. **Directory-traversal via `../` sequences** — covered by prior VIABLE [1]
2. **Symlink-based escape** — would require symlink in `public/` directory; both symlink and directory traversal are variants of the same root cause (lack of path containment check), which prior [1] addresses
3. **Large-file DoS** — `readFile` reads entire file into memory; no per-file or cumulative bound enforced. However, this is a resource exhaustion issue on the public directory contents, not path traversal.
4. **TOCTOU on file permissions** — `readFile` is atomic; catch block handles file-not-found; no race-window vulnerability found
5. **Null-byte injection** — not exploitable in Node.js modern versions

No distinct vulnerability found beyond the path traversal mechanism already covered by prior VIABLE verdict [1].

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:95ff4f25043996f43a1914b2"
weakness = "path_traversal"
record_kind = "area_seed"
path = ["index.js::requestListener", "index.js::sendFile"]
sink = "index.js::sendFile"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index.js::sendFile"]
scope.trust_boundary = "unknown"
scope.protocol_phase = "unknown"
scope.auth_state = "unknown"
scope.attacker_control = "unknown"
scope.parser_state = "unknown"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = ["path_traversal_via_query_parameter_name"]
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "Query parameter name flows to readFile(join(publicDir, name)) without path containment check; already evaluated as VIABLE by prior investigation [1]"
why_failed_brief = "Prior VIABLE finding covers this route; source re-confirmation finds no distinct vulnerability beyond path traversal already discovered"
confidence = "high"

[[sanitizer_guarantees]]
kind = "prior_verdict"
guarantee = "prior investigation [1] evaluated this route as VIABLE path traversal with high confidence; source code confirms the vulnerability exists and is undefended"

[[blockers]]
kind = "not_found"
guarantee = "no distinct vulnerability found beyond the path traversal mechanism already covered by prior investigation [1]"
```
