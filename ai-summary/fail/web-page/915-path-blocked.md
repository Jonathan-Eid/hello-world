# F915: Path blocked: sendFile error path no information disclosure

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/915-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`sendFile → sendGreeting`

## Blocker

The error-handling path in sendFile that routes to sendGreeting (line 34) returns only a fixed "Not found\n" message and does not disclose file contents. While the name parameter is vulnerable to path traversal on line 29 (readFile(join(publicDir, name))), the error branch invoked when file access fails sends a generic response through sendGreeting rather than returning the file contents. Information disclosure via this path requires the HTTP response to contain the accessed file data, which only occurs on the normal path (line 32: response.end(body)), not through the sendGreeting error handler.

## Evidence

- `index.js:27-36` sendFile function - error path at line 34 calls sendGreeting instead of writing file contents
- `index.js:20-25` sendGreeting function - writes fixed status code and generic "Not found\n" message body
- `index.js:29` readFile call has unvalidated path traversal via name parameter, but vulnerability is only exploitable if contents reach response

## Negative Scope

- Rules out: information_disclosure via sendFile→sendGreeting error path
- Does not rule out: information_disclosure via sendFile→response.end direct path (line 32), which is a sibling route where unvalidated name parameter directly controls file read and response body

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:2b1443928168b834498e78bd"
weakness = "http_response_write"
record_kind = "single_path"
path = ["index::sendFile", "index::sendGreeting"]
sink = "index::sendGreeting"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index::sendFile"]
scope.trust_boundary = "http_request_boundary"
scope.protocol_phase = "http_request_handling"
scope.auth_state = "unauthenticated"
scope.attacker_control = "name_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["information_disclosure_via_sendGreeting"]
rules_out = ["information_disclosure through sendFile error path via sendGreeting"]
does_not_rule_out = ["information_disclosure through sendFile normal path via response.end at line 32"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "error path in sendFile routes to sendGreeting with fixed response, not file contents"
why_failed_brief = "error branch does not disclose file data; information_disclosure material effect requires response body to contain file contents, which only occurs on normal path"
confidence = "high"

[[sanitizer_guarantees]]
kind = "fixed_response"
guarantee = "sendGreeting returns fixed body independent of file access result"

[[blockers]]
kind = "error_handler"
guarantee = "sendFile error branch (line 34) calls sendGreeting with fixed message instead of file contents"
```
