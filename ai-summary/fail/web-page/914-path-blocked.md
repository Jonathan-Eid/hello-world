# F914: Path blocked: sendFile to sendGreeting information disclosure

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/914-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index::sendFile` → `index::sendGreeting` (error-handling path)

## Blocker

The `sendFile` function calls `sendGreeting` only in its error-handling path (catch block, line 34), which returns a generic "Not found\n" message. This error path does not leak information disclosure of file contents, file permissions, or file system details. The attacker-controlled path traversal vulnerability exists on the normal response path (line 32: `response.end(body)`), not on the error path routed through `sendGreeting`. Since the error path provides no information disclosure distinct from the already-documented path traversal mechanism on the normal path, no additional vulnerability is viable here.

## Evidence

- `index.js:27-36` - `sendFile` function contains two response paths: normal (line 32) with `response.end(body)` and error (line 34) with `sendGreeting(response, "Not found\n")`
- `index.js:20-25` - `sendGreeting` function returns the passed body text directly with status code 404; in error case from sendFile, body is hard-coded "Not found\n" with no file system information
- `index.js:29` - File read via `join(publicDir, name)` with no path validation allows path traversal, but this vulnerability is on the normal response path, not the error path dispatched in this seed

## Negative Scope

- **Rules out**: Distinct information disclosure mechanism on the `sendFile → sendGreeting` error-handling path
- **Does not rule out**: Path traversal vulnerability on the normal `sendFile → response.end` path (line 32), already documented as VIABLE in prior investigation [3]

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:2b1443928168b834498e78bd"
weakness = "information_disclosure"
record_kind = "area_seed"
path = ["index::sendFile", "index::sendGreeting"]
sink = "index::sendGreeting"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index::requestListener"]
scope.trust_boundary = "unknown"
scope.protocol_phase = "http_request_handling"
scope.auth_state = "unauthenticated"
scope.attacker_control = "name_query_parameter"
scope.parser_state = "url_parsed"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["sendFile_sendGreeting_error_path"]
rules_out = ["distinct_information_disclosure_via_sendGreeting_error_path"]
does_not_rule_out = ["path_traversal_on_normal_sendFile_response_path"]
assumptions = ["sendFile calls sendGreeting only in error-handling catch block (line 34)", "error-handling path returns generic 'Not found' message without file system details", "information_disclosure vulnerability on normal path already accounted for in prior VIABLE findings"]
mechanism_brief = "sendFile error path routes through sendGreeting returning generic error message"
why_failed_brief = "error path does not leak information; vulnerability is path traversal on normal response path already documented"
confidence = "high"

[[sanitizer_guarantees]]
kind = "generic_error_message"
guarantee = "sendGreeting error path returns hard-coded 'Not found\\n' without leaking file system details"

[[blockers]]
kind = "error_message_sanitization"
guarantee = "error-handling path in sendFile (line 34) provides no information disclosure channel distinct from normal path"
```
