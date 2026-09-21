# F007: Path blocked: buildGreeting response content

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/007-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index.js::requestListener` → `index.js::buildGreeting`

## Blocker

The `buildGreeting` function (lines 11–12) returns one of two hardcoded string literals with no dependence on attacker-controlled input. Its parameter `route` is normalized by `parseRequest` to only `"root"` or `"not-found"`, eliminating any opportunity for response content manipulation through this path.

## Evidence

- `index.js:buildGreeting:11–12` - Function implementation returns fixed greeting strings keyed only to route equality check, never modifying or interpolating request data.
- `index.js:requestListener:23–24` - Route parameter passed to `buildGreeting` always originates from `parseRequest`, which normalizes raw URL to one of two values.
- `index.js:parseRequest:5–9` - Normalization ternary returns only `"root"` or `"not-found"`, constraining all downstream `buildGreeting` invocations.

## Negative Scope

- Rules out: Response content build vulnerabilities on the `buildGreeting` path when content is limited to hardcoded strings.
- Does not rule out: Separate vulnerabilities in upstream `parseRequest` path (URL constructor behavior, already tracked in prior investigation route codeql:1632c2a743acc8a6af077193).

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:6f339d4b9346de62b2b7b6d4"
weakness = "response_content_build"
record_kind = "single_path"
path = ["index.js::requestListener", "index.js::buildGreeting"]
sink = "index.js::buildGreeting"
sink_role = "response_content_build"
impact_class = ""
route_family = "response_content_build"
material_effect = "response_content_build"
target_functions = ["index.js::requestListener"]
scope.trust_boundary = "http_boundary"
scope.protocol_phase = "response_generation"
scope.auth_state = "unauthenticated"
scope.attacker_control = "request_url"
scope.parser_state = "normalized_by_parseRequest"
scope.size_class = "fixed_hardcoded_strings"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = ["response_content_manipulation_via_buildGreeting"]
does_not_rule_out = ["vulnerabilities_in_parseRequest_URL_constructor"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "Response content is limited to two hardcoded strings, eliminating attacker control over response body after normalization."
why_failed_brief = "buildGreeting returns only fixed strings with no dependency on raw request data; normalization in parseRequest prevents attacker influence on response content."
confidence = "high"

[[sanitizer_guarantees]]
kind = "hardcoded_output"
guarantee = "buildGreeting output is one of two fixed string literals, never constructed from or interpolating request data"

[[blockers]]
kind = "output_bound"
guarantee = "Function implementation at lines 11–12 demonstrates output always equals one of two hardcoded values independent of input"
```
