# H001: Hypothesis batch for unbounded path join in file serving

**Date**: 2026-09-23
**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/001-path-seed.md
**Hypothesis by**: claude-haiku-4-5

## Shared Path Context

Entry point `requestListener` (index.js:38) receives unauthenticated HTTP requests, extracts the `name` query parameter via `parseRequest` (index.js:12), and routes file requests to `sendFile` (index.js:27). The `sendFile` function joins the user-supplied `name` directly onto `publicDir` using `path.join(publicDir, name)` without validating that the result remains within the intended directory boundary. The resulting path is passed to `readFile`, and the file content is written to the HTTP response. No prior memory records block this route.

## Candidate 1

**Candidate ID**: C1
**Severity**: High
**Impact**: information_disclosure
**Mechanism**: Path traversal via relative path components (`..`) in the `name` query parameter allows reading files outside the `public/` directory
**Trigger**: HTTP GET request with `name` query parameter containing path traversal sequences (e.g., `?name=../index.js`, `?name=../../etc/passwd`)

**Target Functions**:
- `index.js:sendFile:27-36`
- `index.js:requestListener:38-44`
- `index.js:parseRequest:8-14`

### Expected Behavior

The file-serving endpoint should read only files under the `public/` directory, regardless of the attacker-supplied `name` parameter. Requests attempting path traversal (e.g., `../`, `..\\`) should either be rejected, normalized, or the resolved path should be validated to remain within `public/` before being opened.

### Evidence

- `index.js:6` - `publicDir` is set to `join(process.cwd(), "public")`, establishing the intended boundary
- `index.js:12` - `parseRequest` extracts the raw `name` parameter from `searchParams.get("name")` with no sanitization
- `index.js:29` - `readFile(join(publicDir, name))` directly joins and reads without validating the result path
- `index.js:41` - `sendFile` is called with the unsanitized parameter from `parsed.name`
- `index.js:31-32` - File content is written to HTTP response, providing attacker with content disclosure

The Node.js `path.join()` method does not restrict path traversal; it normalizes relative paths including `..` sequences. For example:
- `join("/app/workspace/public", "../index.js")` → `/app/workspace/index.js`
- `join("/app/workspace/public", "../../etc/passwd")` → `/etc/passwd`

No check confirms the final path remains under `publicDir`, so any file readable by the process can be leaked via the HTTP response.

### Anti-Evidence

- Exception handler (index.js:33-35) catches `readFile` failures and returns a generic error, but does not prevent the attempt and does not restrict which paths are readable
- The error response still identifies failure as "Not found", which leaks whether a path is accessible without confirming it is within bounds
- No permission boundary: the Node.js process inherits user/group permissions, and any readable file is exfiltrable

```toml-index
schema = 1
verdict = "CANDIDATE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:95ff4f25043996f43a1914b2"
weakness = "path_traversal"
record_kind = "single_path"
path = ["index.js::requestListener", "index.js::sendFile"]
sink = "index.js::sendFile"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index.js:sendFile:27-36", "index.js:requestListener:38-44", "index.js:parseRequest:8-14"]
scope.trust_boundary = "http_client_unauthenticated"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "name_query_parameter"
scope.parser_state = "raw_relative_path"
scope.size_class = "unbounded_string"
input_shape_tags = ["path_traversal_syntax"]
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "HTTP listener routes unsanitized user-supplied path parameter directly to path.join(), which normalizes relative path traversal sequences without validating final path remains within public directory"
why_failed_brief = "not failed; candidate survived checked blockers"
confidence = "high"

[[sanitizer_guarantees]]
kind = "absent"
guarantee = "no path canonicalization, allowlist validation, or directory bounds check before readFile"

[[blockers]]
kind = "not_found"
guarantee = "no source-proven blocker prevents path traversal via .. sequences"
```
