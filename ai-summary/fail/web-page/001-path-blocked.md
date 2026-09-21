# F001: Path blocked: HTTP response write from request listener

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/001-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index.js::requestListener` → `index.js::sendGreeting`

## Blocker

Response body passed to `response.end()` in `sendGreeting` is guaranteed to be one of exactly two hardcoded strings: `"Hello, world!\n"` or `"Not found\n"`. The untrusted `request.url` is processed through safe URL parsing and a hardcoded binary decision on pathname, eliminating all attacker control over the response body.

## Evidence

- `index.js:6` - `new URL(rawUrl, "http://localhost")` safely parses request URL
- `index.js:8` - Binary comparison `pathname === "/"` converts untrusted input to fixed string
- `index.js:12-13` - Hardcoded return values in `buildGreeting` guarantee exactly two possible outputs
- `index.js:19` - `response.end(body)` receives only hardcoded strings, never untrusted input

## Negative Scope

- Rules out: HTTP response injection, header injection, XXS attacks via response body
- Does not rule out: Attacks not involving the response body content (out of scope for this route)

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:88734216b62a9cd890156edb"
weakness = "http_response_write"
record_kind = "area_seed"
path = ["index.js::requestListener", "index.js::sendGreeting"]
sink = "index.js::sendGreeting"
sink_role = "http_response_write"
impact_class = ""
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index.js::requestListener"]
scope.trust_boundary = "http_request_boundary"
scope.protocol_phase = "request_processing"
scope.auth_state = "unknown"
scope.attacker_control = "none_over_response_body"
scope.parser_state = "parsed_to_fixed_strings"
scope.size_class = "fixed_output"
input_shape_tags = []
defense_tags = ["hardcoded_output"]
negative_claim.rules_out_codes = ["response_injection", "header_injection"]
rules_out = ["untrusted_data_in_response_body"]
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "Attacker-controlled request.url passes through safe URL parsing and hardcoded binary decision, resulting in guaranteed fixed response strings with no injection surface"
why_failed_brief = "Response body is guaranteed to be one of exactly two hardcoded strings; no attacker control reaches response.end()"
confidence = "high"

[[sanitizer_guarantees]]
kind = "hardcoded_output"
guarantee = "buildGreeting returns one of two hardcoded strings; no attacker input reaches response body"

[[blockers]]
kind = "safe_url_parsing_and_hardcoded_decision"
guarantee = "parseRequest converts untrusted URL to one of two fixed strings via safe URL parsing and exact pathname comparison"
```
