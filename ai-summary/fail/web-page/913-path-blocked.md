# F913: Path blocked: sendFile query traversal duplicate

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/913-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index.js::sendFile → response::end`

## Blocker

This route is an exact duplicate of the path traversal vulnerability already found VIABLE in prior investigations [1], [3], and [4]. The `name` parameter is extracted from the HTTP query string (line 12) without validation and passed directly to `path.join(publicDir, name)` (line 29). An attacker can traverse the directory structure using sequences like `../../etc/passwd`. The identical code path and attack surface have already been adjudicated as VIABLE; no distinct mechanism exists on this route.

## Evidence

- `index.js:12` - Query parameter `name` extracted and returned without validation
- `index.js:27-29` - `sendFile` receives unvalidated `name` and joins it directly with `publicDir`
- `index.js:32` - Response body sent via `response.end(body)` with file contents

## Negative Scope

- Rules out: re-reporting path traversal on this exact code path; investigating the same failure mode again
- Does not rule out: distinct vulnerabilities on sibling routes or alternative attack vectors not yet traced

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:a42ce805d0af41e29becbeb7"
weakness = "information_disclosure"
record_kind = "single_path"
path = ["index.js::sendFile", "response::end"]
sink = "response::end"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index.js:sendFile"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["path_traversal_on_sendfile_response_path_duplicate"]
rules_out = ["distinct_mechanism_on_identical_sendfile_unvalidated_join_path"]
does_not_rule_out = ["sibling_routes_or_alternative_attack_vectors"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "identical unvalidated path join vulnerability to prior VIABLE findings; no distinct mechanism on this exact route"
why_failed_brief = "prior investigations [1], [3], [4] already found path traversal VIABLE on this code path; current dispatch is duplicate with no new attack surface"
confidence = "high"

[[sanitizer_guarantees]]
kind = "source_verified"
guarantee = "no sanitization or validation of name parameter before path.join at line 29; source confirms identical vulnerability to prior VIABLE adjudication"

[[blockers]]
kind = "prior_viable_duplicate"
guarantee = "identical unvalidated path.join(publicDir, name) at line 29; prior investigations already adjudicated this as VIABLE; no distinct failure mode identified on this route"
```
