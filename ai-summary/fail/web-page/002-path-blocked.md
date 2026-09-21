# F002: Path blocked: HTTP response write from requestListener

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/002-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index.js::requestListener -> index.js::sendGreeting`

## Blocker

Untrusted input (`request.url`) is parsed by `parseRequest` to a bounded set of two fixed return values ("root" or "not-found"). These values are used only to select from a fixed set of response body strings via `buildGreeting`. The response body, status code, and headers written by `sendGreeting` never incorporate or interpolate untrusted input; they are always one of two fixed, hardcoded outputs.

## Evidence

- `index.js:5-9` - `parseRequest` validates and normalizes `request.url` using `new URL()`, returning only two fixed strings
- `index.js:11-13` - `buildGreeting` is a pure function that returns one of two fixed strings ("Hello, world!\n" or "Not found\n")
- `index.js:15-20` - `sendGreeting` writes the fixed greeting and derives status/headers only from comparison to fixed strings; no user input flows to any response field

## Negative Scope

- Rules out: HTTP response body/header injection via untrusted request input; status code manipulation via request manipulation
- Does not rule out: Other input shapes (e.g., timing-based attacks on URL parsing, resource exhaustion) not relevant to http_response_write weaknesses

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
scope.auth_state = "none"
scope.attacker_control = "http_request_url"
scope.parser_state = "url_normalized"
scope.size_class = "fixed_output"
input_shape_tags = []
defense_tags = ["data_isolation", "fixed_output_set"]
negative_claim.rules_out_codes = ["http_response_write:injection"]
rules_out = ["untrusted_data_in_response_body", "header_injection", "status_code_manipulation"]
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "All request input is normalized to one of two fixed values, used only to select from two fixed response outputs"
why_failed_brief = "untrusted input is isolated by parsing to bounded fixed values; no attacker-controlled data reaches response boundary"
confidence = "high"

[[sanitizer_guarantees]]
kind = "normalization_gate"
guarantee = "parseRequest normalizes request.url via URL constructor, returning only two fixed values"

[[sanitizer_guarantees]]
kind = "fixed_output_mapping"
guarantee = "buildGreeting maps bounded input set to fixed response body strings with no interpolation"

[[blockers]]
kind = "data_isolation"
guarantee = "response body, status, and headers are always fixed values or derived from fixed value comparison; no untrusted input propagates to response boundary"
```
