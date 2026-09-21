# F004: Path blocked: Request parsing entry point

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/004-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index.js::requestListener` → `index.js::parseRequest`

## Blocker

The `parseRequest` function safely normalizes the URL using the URL constructor, which handles percent-encoding, path segments, and special characters according to RFC 3986. The extracted pathname is compared against a single literal ("/") and mapped to one of two output strings ("root" or "not-found"). These constrained output values are never reflected directly in responses; instead, hardcoded greeting strings are selected based on the binary route classification. No parsed URL component reaches downstream operations as attacker-controlled data.

## Evidence

- `index.js:5-9` - `parseRequest` uses `new URL()` to normalize input and extract pathname
- `index.js:5-9` - Only two literal return values: "root" for "/" or "not-found" for all other paths
- `index.js:11-13` - `buildGreeting()` uses simple string equality check against hardcoded literals
- `index.js:15-20` - `sendGreeting()` uses hardcoded response bodies based on greeting value

## Negative Scope

- Rules out: Request parsing information disclosure, pathname normalization bypass, injection via URL encoding
- Does not rule out: Unrelated vulnerabilities in other parts of the application (e.g., upstream HTTP handling)

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:9e3fd769fcec27629302f744"
weakness = "request_parsing"
record_kind = "area_seed"
path = ["index.js::requestListener", "index.js::parseRequest"]
sink = "index.js::parseRequest"
sink_role = "request_parsing"
impact_class = ""
route_family = "request_parsing"
material_effect = "request_parsing"
target_functions = ["index.js::requestListener"]
scope.trust_boundary = "http_entry"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "url_path_and_query"
scope.parser_state = "normalized"
scope.size_class = "bounded"
input_shape_tags = []
defense_tags = ["url_normalization", "output_constraint"]
negative_claim.rules_out_codes = ["request_parsing:injection", "request_parsing:bypass"]
rules_out = ["information disclosure through parsed URL reflection", "pathname normalization bypass via encoding", "unintended routing via special URL characters"]
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "HTTP request parsing with URL normalization and output constraint"
why_failed_brief = "parsed request data is constrained to binary classification (root vs not-found) and never reflected in output; downstream operations use only hardcoded strings"
confidence = "high"

[[sanitizer_guarantees]]
kind = "url_normalization"
guarantee = "URL constructor normalizes all input according to RFC 3986, preventing bypass via encoding or path traversal"

[[sanitizer_guarantees]]
kind = "output_constraint"
guarantee = "parseRequest returns only two literal string values, which are never directly reflected in responses"

[[blockers]]
kind = "safe_design"
guarantee = "parsed URL components are not used in downstream operations; only derived binary classification is used"
```
