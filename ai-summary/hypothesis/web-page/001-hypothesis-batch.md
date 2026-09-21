# H001: Hypothesis batch for response_emission path

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/001-path-seed.md
**Hypothesis by**: claude-haiku-4-5

## Shared Path Context

The dispatch seed identifies `requestListener -> sendGreeting` as the primary path, with `sendFile` as a material target function. The `/file` route accepts a `name` query parameter, which is passed directly to `sendFile` without validation. `sendFile` joins the attacker-controlled `name` with the `publicDir` path using `path.join()` and reads the result file. There is no check to ensure the resulting path stays within the `public/` directory.

## Candidate 1

**Candidate ID**: C1
**Severity**: High
**Impact**: Arbitrary File Read
**Mechanism**: Path traversal via unvalidated directory join
**Trigger**: HTTP GET request to `/file?name=../../../etc/passwd` or similar traversal sequences. The `name` query parameter is parsed at line 12 and passed directly to `sendFile` at line 41, which joins it with `publicDir` at line 29 without bounds checking.
**Target Functions**:
- `index.js:sendFile:27-35`
- `index.js:parseRequest:8-14`
- `index.js:requestListener:38-44`

### Expected Behavior

The server should only serve files within the `public/` directory. Requests with path traversal sequences like `../` should be rejected or resolved to stay within bounds.

### Evidence

- `index.js:12` — `searchParams.get("name")` provides attacker control over the filename parameter with no initial validation
- `index.js:29` — `join(publicDir, name)` combines the public directory with the unsanitized name without verifying the result stays within `publicDir`
- `index.js:34` — Error handling catches filesystem errors but does not prevent the traversal attempt
- `index.js:8-14` — `parseRequest` performs no validation on the `name` parameter, only extraction

The `path.join()` function resolves relative path segments like `../` in its arguments. For example, `join('/app/public', '../etc/passwd')` resolves to `/app/etc/passwd`, escaping the intended public directory. No subsequent check verifies that the final path is within bounds.

### Anti-Evidence

- The error handler at line 33-35 will catch filesystem permission errors if the process lacks read permissions on parent directories, but this is not a reliable or intentional guard — it is an artifact of error handling, not a deliberate bounds check
- `publicDir` is constructed with `join(process.cwd(), "public")` at line 6, but this does not prevent escaping via the `name` parameter

```toml-index
schema = 1
verdict = "CANDIDATE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:807d154e17582e8b07d5733c"
weakness = "path_traversal"
record_kind = "single_path"
path = ["index::requestListener", "index::sendFile"]
sink = "index::sendFile"
sink_role = "file_read_emission"
impact_class = "arbitrary_file_read"
route_family = "response_emission"
material_effect = "response_emission"
target_functions = ["index.js:sendFile", "index.js:parseRequest", "index.js:requestListener"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unbounded"
input_shape_tags = ["path_traversal_sequence"]
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "Attacker-controlled HTTP query parameter name flows directly to path.join() without validation that result stays within public directory, enabling directory traversal to read arbitrary files"
why_failed_brief = "not failed; candidate survived checked blockers"
confidence = "high"

[[sanitizer_guarantees]]
kind = "not_present"
guarantee = "no path normalization or bounds check guards the join result"

[[blockers]]
kind = "not_found"
guarantee = "no source-proven path containment check found"
```
