# F904: Path blocked: sendFile→response path covered by prior VIABLE finding

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/904-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index.js::sendFile → external::end` (HTTP response write via file read)

Area seed targets: sendFile, sendGreeting

## Blocker

The path traversal vulnerability on sendFile is already confirmed VIABLE in prior investigation [4] (route_id codeql:807d154e17582e8b07d5733c). Source confirms no path containment check at line 29 (`join(publicDir, name)` without validation) and no security boundary in the catch block (line 33 is generic error handling only). No distinct vulnerability mechanisms are reachable on this path: symlink attacks require attacker write access to public/; null byte injection is rejected by Node.js fs.readFile; sendGreeting target receives only hardcoded strings, not user input.

## Evidence

- `index.js:27-36` - sendFile receives attacker-controlled name parameter, passes directly to join() with no path containment logic
- `index.js:8-14` - parseRequest extracts name from query parameter with no validation
- `index.js:33-35` - catch block generic error handling, not a security boundary
- `index.js:20-24` - sendGreeting called from error path and root route, only writes hardcoded strings

## Negative Scope

- Rules out: path traversal as new distinct candidate on sendFile→response path (already VIABLE in prior [4])
- Does not rule out: other HTTP response write targets or request entry points outside sendFile

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:432f0ea511c0cf59bff6c437"
weakness = "information_disclosure"
record_kind = "area_seed"
path = ["index.js::sendFile", "external::end"]
sink = "external::end"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index.js::sendGreeting"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unbounded"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["path_traversal_already_viable_in_prior_4"]
rules_out = ["distinct_vulnerability_on_sendfile_response_path"]
does_not_rule_out = ["other_http_response_sinks", "other_entry_points_to_sendfile"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "sendFile path traversal already confirmed VIABLE in prior investigation [4]; no distinct mechanisms found on this path segment"
why_failed_brief = "path traversal vulnerability is already covered by prior VIABLE finding; no new distinct failure modes discovered"
confidence = "high"

[[sanitizer_guarantees]]
kind = "prior_viable_finding"
guarantee = "path traversal on sendFile route already found VIABLE with high confidence in prior investigation [4]"

[[blockers]]
kind = "prior_investigation"
guarantee = "route already adjudicated as VIABLE in prior investigation [4] with identical sink (external::end) and no distinct mechanisms available"
```
