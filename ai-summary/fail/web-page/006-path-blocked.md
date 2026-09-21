# F006: Path blocked: response content always hardcoded

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/006-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index.js::requestListener -> index.js::buildGreeting`

## Blocker

Response content is always one of two fixed, hardcoded strings selected entirely by parsing the request URL pathname. The `buildGreeting` function returns a constant string literal (`"Hello, world!\n"` or `"Not found\n"`) with no embedding, interpolation, or concatenation of request data. Request data cannot reach the response content body.

## Evidence

- `index.js:11-13` - `buildGreeting` returns hardcoded string literals; no string concatenation or template operations
- `index.js:22-26` - `requestListener` passes only the parsed route identifier (`"root"` or `"not-found"`) to `buildGreeting`, not the original URL
- `index.js:5-9` - `parseRequest` reduces raw URL to a single route identifier string; content of URL is not preserved

## Negative Scope

- Rules out: Response content construction from user-controlled input via the request listener path
- Does not rule out: Potential denial-of-service via URL parsing error (unrelated to response_content_build weakness family)

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:6f339d4b9346de62b2b7b6d4"
weakness = "response_content_build"
record_kind = "area_seed"
path = ["index.js::requestListener", "index.js::buildGreeting"]
sink = "index.js::buildGreeting"
sink_role = "response_content_build"
impact_class = ""
route_family = "response_content_build"
material_effect = "response_content_build"
target_functions = ["index.js::requestListener"]
scope.trust_boundary = "http_request_boundary"
scope.protocol_phase = "request_handling"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_request_url"
scope.parser_state = "post_url_parsing"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["response_content_build"]
rules_out = ["response content construction from user input"]
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "response content is always a fixed hardcoded string selected by route; no user data embedded"
why_failed_brief = "response content is invariantly hardcoded; no response_content_build path exists"
confidence = "high"

[[sanitizer_guarantees]]
kind = "structural_invariant"
guarantee = "buildGreeting returns fixed string literals regardless of input; response body cannot contain request data"

[[blockers]]
kind = "source_proven_guard"
guarantee = "response content is selected from two hardcoded strings; no interpolation, concatenation, or templating of request data"
```
