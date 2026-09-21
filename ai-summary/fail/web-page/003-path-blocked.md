# F003: Path blocked: HTTP response write via sendGreeting

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/003-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`requestListener` → `sendGreeting`

## Blocker

Response body and headers written to the HTTP response are completely hardcoded. The `sendGreeting` function receives a body parameter derived only from `buildGreeting(route)`, which returns one of two fixed strings ("Hello, world!\n" or "Not found\n") based on URL pathname comparison. HTTP headers are literal constants. No attacker-controlled data reaches the response write operations.

## Evidence

- `index.js:11-12` - `buildGreeting` returns only two hardcoded strings; no attacker input incorporated
- `index.js:15-19` - `sendGreeting` uses hardcoded headers `{ "content-type": "text/plain; charset=utf-8" }` and hardcoded status code logic based only on greeting comparison
- `index.js:5-8` - `parseRequest` returns only "root" or "not-found"; URL pathname is safely parsed and not propagated to response body

## Negative Scope

- Rules out: HTTP response injection, header injection, response splitting, encoding bypass on response body
- Does not rule out: Vulnerabilities in unrelated routes or entirely different weakness families

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:36a06ea295f63b294bbe8425"
weakness = "http_response_write"
record_kind = "area_seed"
path = ["worktrees/read/index.js::requestListener", "worktrees/read/index.js::sendGreeting"]
sink = "worktrees/read/index.js::sendGreeting"
sink_role = "http_response_write"
impact_class = ""
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["worktrees/read/index.js::requestListener"]
scope.trust_boundary = "network"
scope.protocol_phase = "response_generation"
scope.auth_state = "unauthenticated"
scope.attacker_control = "url_only"
scope.parser_state = "safe_url_parsing"
scope.size_class = "fixed"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["http_response_write"]
rules_out = ["attacker-controlled response body injection", "attacker-controlled header injection"]
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "Response body and headers are completely hardcoded; attacker input (URL) is safe-parsed and never reaches response write operations."
why_failed_brief = "Path blocked by hardcoded response body and header constants with no attacker control vector"
confidence = "high"

[[sanitizer_guarantees]]
kind = "hardcoded_constants"
guarantee = "Response bodies are always one of two fixed ASCII strings; headers are literal string constants"

[[blockers]]
kind = "no_attacker_control"
guarantee = "URL pathname input is compared for equality only; result flows only to greeting selection, not response body construction"
```
