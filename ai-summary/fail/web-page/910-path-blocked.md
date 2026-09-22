# F910: Path blocked: File response writeback via unsanitized path

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/910-file-response-writeback.md
**Verdict**: NOT_VIABLE

## Path Checked

`index.js::requestListener → index.js::sendFile`

## Blocker

Path traversal vulnerability on this route is already confirmed VIABLE in prior investigations (route_ids codeql:95ff4f25043996f43a1914b2 and codeql:111472ce8048392f42cae643). The dispatch seed's new route_id represents the identical code path without additional security logic. requestListener is a thin wrapper calling parseRequest→sendFile, where the unsanitized `name` parameter flows directly to path.join(publicDir, name) without validation. No distinct vulnerability mechanism exists beyond the already-viable path traversal.

## Evidence

- `index.js:29` - `readFile(join(publicDir, name))` has no path validation; path.join resolves `..` sequences allowing traversal
- `index.js:12` - `searchParams.get("name")` returns unsanitized user input
- `index.js:38-41` - `requestListener` passes parsed.name directly to sendFile with no intervening validation
- Prior [1] score=0.91: Identical path already adjudicated VIABLE with high confidence
- Prior [2] score=0.80: requestListener confirmed as nested wrapper with no additional security
- Prior [4] score=0.28: parseRequest→sendFile path confirmed VIABLE; requestListener does not add distinct mechanism

## Negative Scope

- Rules out: Re-reporting identical path_traversal vulnerability already confirmed VIABLE
- Does not rule out: Other potential vulnerabilities on entirely different paths (e.g., denial-of-service through resource exhaustion via extremely large filenames, though unlikely to be distinct from traversal)

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:123d50e8c0444662b1e4543d"
weakness = "http_response_writeback"
record_kind = "single_path"
path = ["index.js::requestListener", "index.js::sendFile"]
sink = "index.js::sendFile"
sink_role = "http_response_writeback"
impact_class = ""
route_family = "http_response_writeback"
material_effect = "http_response_writeback"
target_functions = ["index.js::requestListener"]
scope.trust_boundary = "unknown"
scope.protocol_phase = "unknown"
scope.auth_state = "unknown"
scope.attacker_control = "unknown"
scope.parser_state = "unknown"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["path_traversal_already_viable_prior_investigation"]
rules_out = ["exact_duplicate_of_viable_prior_finding"]
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "Path traversal via unsanitized query parameter flowing to unvalidated path.join(publicDir, name)"
why_failed_brief = "Identical vulnerability already confirmed VIABLE in prior investigations; no distinct mechanism exists on this new route_id"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_sanitizer"
guarantee = "No path validation guards the join(publicDir, name) operation"

[[blockers]]
kind = "prior_viable_investigation"
guarantee = "Path traversal on identical path already adjudicated VIABLE in prior investigations codeql:95ff4f25043996f43a1914b2 and codeql:111472ce8048392f42cae643 with high confidence; this route_id is a duplicate analysis"
```
