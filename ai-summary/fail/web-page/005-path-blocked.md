# F005: Path blocked: HTTP response write from hardcoded greeting

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/005-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index::requestListener -> index::sendGreeting`

## Blocker

The HTTP response body is always one of two hardcoded strings (`"Hello, world!\n"` or `"Not found\n"`) determined by exact pathname matching, independent of the raw request URL. The attacker-controlled `request.url` is safely parsed using Node's built-in `URL` constructor, which extracts only the pathname component, then compared exactly to `"/"`. The response is written via `response.end(body)` where body is always hardcoded; no user input reaches the response write operation.

## Evidence

- `index.js:5-9` (`parseRequest`) - URL parsed safely via `new URL()`, pathname extracted, exact match check returns only hardcoded strings "root" or "not-found"
- `index.js:11-13` (`buildGreeting`) - Deterministic hardcoded output: "Hello, world!\n" or "Not found\n", no dependency on URL input
- `index.js:15-20` (`sendGreeting`) - Response body parameter is always one of two hardcoded values; `response.end(body)` writes hardcoded content only

## Negative Scope

- Rules out: Attacker-controlled data reaching HTTP response body via request URL parameter
- Does not rule out: Other response write paths not covered by this dispatch seed, or response header injection through separate routes

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:7fa24f28ef66728dd851151a"
weakness = "http_response_write"
record_kind = "area_seed"
path = ["index::requestListener", "index::sendGreeting"]
sink = "index::sendGreeting"
sink_role = "http_response_write"
impact_class = ""
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index::requestListener"]
scope.trust_boundary = "http_request_boundary"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "request_url"
scope.parser_state = "url_parsed_and_validated"
scope.size_class = "bounded_hardcoded"
input_shape_tags = []
defense_tags = ["url_parsing", "exact_match", "hardcoded_output"]
negative_claim.rules_out_codes = ["http_response_injection_via_request_url"]
rules_out = ["User input from request.url reaching HTTP response body"]
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "HTTP response write from request handler entry point to sendGreeting sink"
why_failed_brief = "Attacker-controlled request.url is safely parsed, sanitized to pathname only, exactly matched, and replaced with hardcoded string before response write. No injection vector."
confidence = "high"

[[sanitizer_guarantees]]
kind = "safe_url_parsing"
guarantee = "request.url parsed via new URL() constructor; only pathname extracted; exact equality check on pathname determines response"

[[blockers]]
kind = "hardcoded_output"
guarantee = "HTTP response body is always one of two hardcoded strings independent of input URL value"
```
