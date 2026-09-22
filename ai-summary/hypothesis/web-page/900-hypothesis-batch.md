# H900: Hypothesis batch for file_endpoint_path_traversal

**Date**: 2026-09-22
**Subsystem**: web-page
**Source Dispatch Seed**: ai-summary/dispatch/web-page/900-residual-seed.md
**Hypothesis by**: claude-haiku-4-5, default

## Shared Path Context

The `/file` endpoint at `index.js:27-36` accepts an attacker-controlled `name` query parameter, joins it with the `public/` directory using `path.join()`, and reads the resulting file with `readFile()`. The parameter is URL-decoded by the `URL` constructor before reaching `sendFile`. No path boundary validation occurs before or after the join operation.

## Candidate 1

**Candidate ID**: C1
**Severity**: High
**Impact**: information_disclosure
**Mechanism**: Path traversal via relative path sequences in unvalidated `path.join()` call
**Trigger**: HTTP GET request with attacker-controlled `name` query parameter containing relative path sequences (e.g., `../../../etc/passwd` or `../index.js`)
**Target Functions**:
- `index.js:sendFile:27-36`
- `index.js:parseRequest:8-14`

### Expected Behavior

The application should restrict file reads to the `public/` directory. A request for `GET /file?name=../../../etc/passwd` should either reject the traversal sequence or return an error, never reading files outside `public/`.

### Evidence

- `index.js:6` - `publicDir` is initialized once at startup as `join(process.cwd(), "public")`
- `index.js:12` - `name` parameter extracted directly from `searchParams.get("name")` with no validation
- `index.js:29` - `readFile(join(publicDir, name))` joins the attacker-controlled `name` with `publicDir` but `path.join()` in Node.js does NOT restrict the result to stay within a base directory
- Node.js `path.join("/path/to/public", "../../../etc/passwd")` resolves to `/path/etc/passwd`, completely escaping the public directory
- No guard code, validation check, or bounds enforcement exists between query parameter extraction and the file read call

### Anti-Evidence

- The catch block at `index.js:33-34` handles file read errors, but does not prevent the traversal; it simply returns "Not found" if the file is unreadable for any reason (including permission denial)
- No filesystem permission model or OS-level restriction is enforced in code; safety would depend entirely on process permissions, which are not code-level guarantees

```toml-index
schema = 1
verdict = "CANDIDATE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "file_endpoint_path_traversal"
weakness = "path_traversal"
record_kind = "single_path"
path = ["GET /file", "parseRequest", "sendFile", "readFile(join(publicDir, name))"]
sink = "readFile(join(publicDir, name))"
sink_role = "file_access"
impact_class = "information_disclosure"
route_family = "file_access"
material_effect = "read_arbitrary_files"
target_functions = ["index.js:sendFile:27-36", "index.js:parseRequest:8-14"]
scope.trust_boundary = "http_request"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "query_parameter_name"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = ["path_traversal_sequence"]
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = ["symlink race conditions on the same endpoint", "other file-read endpoints or injection vectors"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "path.join() does not restrict relative paths; attacker-controlled name parameter with ../ sequences escapes public/ directory"
why_failed_brief = "not failed; candidate survived checked blockers"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_guard"
source = "index.js:12, index.js:29"
guarantee = "no path validation, normalization, or boundary checking between query parameter and readFile call"

[[blockers]]
kind = "not_found"
guarantee = "no code-level blocker prevents relative path traversal via path.join()"
```

