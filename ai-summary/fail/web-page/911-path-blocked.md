# F911: Path blocked: HTTP query parameter to file response

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/911-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`requestListener → sendFile`

## Blocker

The `name` query parameter is extracted from the HTTP request URL without validation and passed directly to `path.join(publicDir, name)` at line 29. This enables path traversal attacks via both relative (`../../../etc/passwd`) and absolute (`/etc/passwd`) path components. However, this vulnerability has already been adjudicated as VIABLE in prior investigations [1][2][4]. Source review confirms no distinct failure mode, alternative attack surface, or mechanism beyond the known path traversal exists on this route.

## Evidence

- `index.js:12` - `name: searchParams.get("name")` extracted without path validation
- `index.js:29` - `readFile(join(publicDir, name))` called with attacker-controlled filename
- Prior investigations [1][2][4] explicitly confirm path traversal VIABLE and document search for distinct mechanisms with negative result

## Negative Scope

- Rules out: distinct vulnerability mechanism beyond path traversal on this route
- Does not rule out: other routes, sinks, or trust boundaries that may have distinct vulnerabilities

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:123d50e8c0444662b1e4543d"
weakness = "http_response_writeback"
record_kind = "area_seed"
path = ["index.js::requestListener", "index.js::sendFile"]
sink = "index.js::sendFile"
sink_role = "http_response_writeback"
impact_class = ""
route_family = "http_response_writeback"
material_effect = "http_response_writeback"
target_functions = ["worktrees/read/index.js::requestListener"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unbounded"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["path_traversal_already_viable_from_prior_1_2_4"]
rules_out = ["distinct_vulnerability_mechanism_beyond_known_path_traversal"]
does_not_rule_out = []
assumptions = ["prior VIABLE findings [1][2][4] accurately characterize the path traversal attack surface on this route"]
mechanism_brief = "Path traversal via unvalidated query parameter in path.join"
why_failed_brief = "path traversal vulnerability already confirmed VIABLE in prior investigations; source review found no additional distinct mechanisms"
confidence = "high"

[[sanitizer_guarantees]]
kind = "prior_comprehensive_search"
guarantee = "prior investigations explicitly searched for distinct mechanisms and documented result as found none; source confirms no path canonicalization or containment validation exists"

[[blockers]]
kind = "prior_viable_finding"
guarantee = "prior investigations [1][2][4] found path traversal VIABLE on this exact route with high confidence"
```
