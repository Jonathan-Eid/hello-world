# F008: Path blocked: Greeting Response Construction

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/008-greeting-response-construction.md
**Verdict**: NOT_VIABLE

## Path Checked

`requestListener -> buildGreeting`

## Blocker

The greeting response content is constructed from a fixed, attacker-independent boolean result. The `buildGreeting` function receives only two possible route values—"root" or "not-found"—derived from a simple pathname equality check in `parseRequest`. The function returns only two hardcoded strings: "Hello, world!\n" or "Not found\n". No attacker-controlled input reaches the response body construction.

## Evidence

- `index.js:5-9` - parseRequest returns only "root" or "not-found"; no other values are reachable
- `index.js:11-13` - buildGreeting returns only two hardcoded strings; response content is not derived from request data
- `index.js:23-24` - route passed to buildGreeting is the output of parseRequest, restricted to two values

## Negative Scope

- Rules out: Any mechanism that requires attacker-controlled content in the response body
- Does not rule out: Vulnerabilities in other response paths (e.g., parseRequest URL constructor handling, which is covered by prior VIABLE finding codeql:1632c2a743acc8a6af077193)

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:8ae25132dd9cff8c533e1cbe"
weakness = "response_content_construction"
record_kind = "area_seed"
path = ["index.js::requestListener", "index.js::buildGreeting"]
sink = "index.js::buildGreeting"
sink_role = "response_content_construction"
impact_class = ""
route_family = "response_content_construction"
material_effect = "response_content_construction"
target_functions = ["index.js::requestListener"]
scope.trust_boundary = "http_request_boundary"
scope.protocol_phase = "response_generation"
scope.auth_state = "unauthenticated"
scope.attacker_control = "request_url"
scope.parser_state = "parsed_pathname"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = ["response_content_injection_via_request_data"]
does_not_rule_out = ["URL_constructor_vulnerabilities_in_parseRequest_path"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "buildGreeting response is hardcoded; no attacker input reaches response construction"
why_failed_brief = "response content depends only on pathname === '/' boolean; impossible to inject attacker-controlled data into fixed greeting strings"
confidence = "high"

[[sanitizer_guarantees]]
kind = "hardcoded_response"
guarantee = "response body is one of two fixed strings; buildGreeting cannot output attacker-controlled content"

[[blockers]]
kind = "restricted_input_domain"
guarantee = "parseRequest returns only 'root' or 'not-found'; buildGreeting cannot receive any other value"
```
