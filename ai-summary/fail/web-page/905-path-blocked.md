# F905: Path blocked: HTTP response write via sendGreeting

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/905-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index.js::sendGreeting` → `external::end`

## Blocker

The `sendGreeting` function (lines 20–25) receives only hardcoded response bodies from `buildGreeting()`, which returns one of two fixed strings ("Hello, world!\n" or "Not found\n") based solely on the parsed route identifier. HTTP headers are also hardcoded. No user input flows through this path; the function cannot be used to disclose information via the response.

## Evidence

- `index.js:buildGreeting:16-18` - Returns only hardcoded strings; no user input included in return value
- `index.js:parseRequest:8-14` - Returns only hardcoded route identifiers; query parameters are not passed to buildGreeting
- `index.js:sendGreeting:20-25` - Response headers and status code logic depend only on hardcoded string comparisons; body parameter is always a fixed string

## Negative Scope

- Rules out: HTTP response information disclosure on sendGreeting path via attacker-controlled data
- Does not rule out: Vulnerabilities on sendFile path (prior investigations confirm VIABLE path traversal); potential response timing side channels (orthogonal to this dispatch route family)

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:c82617544f840ac081294c95"
weakness = "http_response_write"
record_kind = "area_seed"
path = ["index.js::sendGreeting", "external::end"]
sink = "external::end"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["worktrees/read/index.js::sendGreeting"]
scope.trust_boundary = "http_response"
scope.protocol_phase = "response_generation"
scope.auth_state = "unauthenticated"
scope.attacker_control = "none"
scope.parser_state = "post_parse"
scope.size_class = "bounded_constant"
input_shape_tags = []
defense_tags = ["hardcoded_response_body"]
negative_claim.rules_out_codes = ["hardcoded_all_response_data"]
rules_out = ["http_response_information_disclosure_on_sendgreeting_path"]
does_not_rule_out = ["sendfile_path_traversal"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "No attacker-controlled data reachable in sendGreeting response path"
why_failed_brief = "All response bodies and headers are hardcoded; buildGreeting produces only two fixed strings independent of user input"
confidence = "high"

[[sanitizer_guarantees]]
kind = "hardcoded_response_data"
guarantee = "sendGreeting receives only hardcoded strings from buildGreeting; response headers and status code depend solely on hardcoded string comparison logic"

[[blockers]]
kind = "no_user_input"
guarantee = "No user-controlled data flows into sendGreeting response writes; parseRequest returns hardcoded route identifiers; buildGreeting produces fixed strings based on route type only"
```
