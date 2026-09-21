# F002: Path blocked: sendFile response emission route already covered by prior path traversal finding

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/002-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index::sendFile → http::writeHead`

## Blocker

Prior investigations already identified path traversal as VIABLE on the related parseRequest → sendFile route (route_id: codeql:807d154e17582e8b07d5733c). Source verification confirms no path containment check guards the `path.join(publicDir, name)` call at line 29 of `index.js:sendFile`. The dispatch seed's specific question about "path traversal protection between parameter acceptance and response emission" is answered by that prior VIABLE finding. No source-confirmed distinct vulnerabilities (beyond path traversal variants) are reachable on the sendFile → writeHead segment within this investigation budget.

## Evidence

- `index.js:sendFile:29` - `join(publicDir, name)` with no validation that result stays under public/
- `index.js:sendFile:31-32` - Result passed directly to `response.writeHead()` and `response.end()`
- `index.js:sendFile:33-35` - Error handling is only for file read failures, not path validation
- Prior investigations (route_id codeql:807d154e17582e8b07d5733c) - path traversal confirmed VIABLE with high confidence; no source-proven path containment check found

## Negative Scope

- Rules out: New/distinct vulnerability candidates beyond path traversal on this dispatch path/sink
- Does not rule out: Symlink traversal attacks, case-sensitivity attacks, or other path traversal variants (already covered by prior VIABLE finding as part of same vulnerability class)

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:383df8b1224ab6a122806546"
weakness = "path_traversal"
record_kind = "single_path"
path = ["index::sendFile", "http::writeHead"]
sink = "http::writeHead"
sink_role = "response_emission"
impact_class = ""
route_family = "response_emission"
material_effect = "response_emission"
target_functions = ["index::sendFile"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "filesystem_limited"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["path_traversal"]
rules_out = ["distinct non-path-traversal vulnerabilities on sendFile→writeHead segment"]
does_not_rule_out = ["prior VIABLE path traversal finding on parseRequest→sendFile (already reviewed/confirmed)"]
assumptions = ["path traversal vulnerability class is already covered by prior VIABLE finding; no additional distinct vulnerability class found through source trace"]
mechanism_brief = "Dispatch seed's path traversal question already answered by prior investigations; no new candidates identified"
why_failed_brief = "Prior investigations (high confidence) already identified path traversal as VIABLE on this vulnerable function; dispatch path does not expose additional distinct vulnerability"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_new_candidates"
guarantee = "source trace confirms no path containment check at line 29; prior VIABLE finding is sufficient; no distinct new vulnerability mechanism found"

[[blockers]]
kind = "already_investigated"
guarantee = "prior VIABLE finding on related route (parseRequest→sendFile, route_id codeql:807d154e17582e8b07d5733c) already confirmed path traversal for same vulnerable function"
```

