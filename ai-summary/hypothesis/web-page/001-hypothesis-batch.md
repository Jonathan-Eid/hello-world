# H001: Hypothesis batch for path traversal via /file endpoint

**Date**: 2026-09-22
**Subsystem**: web-page
**Source Dispatch Seed**: /file endpoint path traversal
**Hypothesis by**: claude-haiku-4-5

## Shared Path Context

The `/file` route at `GET /file?name=<user-input>` receives an untrusted `name` query parameter from `parseRequest` (line 12, `index.js`). The parameter flows directly to `sendFile` (line 41), which joins it with the `publicDir` prefix using `path.join(publicDir, name)` (line 29) with no post-join validation to ensure the result remains within the `public/` directory. Node.js `path.join()` resolves relative path components (`.` and `..`) by default, allowing `../` sequences to escape the intended directory boundary.

## Candidate 1

**Candidate ID**: C1
**Severity**: High
**Impact**: Arbitrary file read / Information disclosure
**Mechanism**: Path traversal via `path.join()` resolution of relative path components
**Trigger**: Attacker sends `GET /file?name=../../../etc/passwd` (or other relative path with `..` sequences to traverse up the directory tree)
**Target Functions**:
- `index.js:sendFile:27-36`
- `index.js:parseRequest:8-14`

### Expected Behavior

The server should only allow reading files within the `public/` directory. Any attempt to escape that boundary should fail.

### Evidence

- `index.js:12` - `name: searchParams.get("name") || "hello.txt"` extracts the parameter with no validation
- `index.js:27-36` - `sendFile` function receives the raw `name` parameter
- `index.js:29` - `const body = await readFile(join(publicDir, name));` joins the untrusted `name` with `publicDir`
- Node.js `path.join()` documentation confirms it resolves relative path components, so `join("/path/to/public", "../../../etc/passwd")` resolves to `/etc/passwd`
- No post-join check validates that the result stays within `publicDir` (e.g., no `path.resolve()` + prefix comparison)

### Anti-Evidence

- The try-catch at lines 28-35 catches `readFile` errors and returns "Not found\n", but this is error handling, not a security control. It does not prevent reading files outside the intended directory—it only masks the error if the file doesn't exist or is unreadable. An attacker can still read any file the process has permission to access (e.g., `/etc/passwd` is world-readable on most systems).

```toml-index
schema = 1
verdict = "CANDIDATE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "web_page_file_path_traversal"
weakness = "path_traversal"
record_kind = "single_path"
path = ["GET /file", "sendFile"]
sink = "fs.readFile"
sink_role = "file_read_operation"
impact_class = "arbitrary_file_read"
route_family = "path_traversal"
material_effect = "information_disclosure"
target_functions = ["index.js:sendFile", "index.js:parseRequest"]
scope.trust_boundary = "attacker_controls_query_parameter"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "GET_query_parameter_name"
scope.parser_state = "url_parsed_before_join"
scope.size_class = "arbitrary"
input_shape_tags = ["relative_path_with_parent_refs"]
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "attacker_controlled_name_parameter_flows_to_path_join_without_post_join_validation"
why_failed_brief = "not failed; candidate survived checked blockers"
confidence = "high"

[[sanitizer_guarantees]]
kind = "none_found"
guarantee = "no input validation or sanitization on name parameter before path.join"

[[blockers]]
kind = "not_found"
guarantee = "no post-join validation to ensure result stays within publicDir"
```
