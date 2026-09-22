# H900: Hypothesis batch for path traversal re-investigation

**Date**: 2026-09-22
**Subsystem**: web-page
**Source Dispatch Seed**: ai-summary/dispatch/web-page/900-residual-seed.md
**Hypothesis by**: claude-haiku-4-5

## Shared Path Context

This batch re-investigates the viability of C1 (path traversal to read arbitrary files) via the `/file` endpoint. The dispatch seed is an escalation that specifically asks whether "path traversal via C1 remains viable" given that C2 (a target-variant of C1) was ruled NOT_VIABLE due to subsumption. The route is:

- **Entry**: HTTP request to `/file` with untrusted `name` query parameter
- **Path**: `GET /file` → `parseRequest` (line 12 extracts `name` parameter) → `sendFile` (line 27-36) → `readFile(join(publicDir, name))` (line 29)
- **Sink**: `fs.readFile` call with the result of `path.join(publicDir, name)`
- **Auth state**: Unauthenticated HTTP request
- **Parser state**: URL-decoded query parameter

The code uses only Node.js built-ins (`node:http`, `node:fs/promises`, `node:path`) with no middleware or validation layers.

## Candidate 1

**Candidate ID**: C1
**Severity**: High
**Impact**: Arbitrary file read, information disclosure
**Mechanism**: Path traversal via unvalidated `path.join()` result
**Trigger**: HTTP GET request with `name` query parameter containing `../` sequences (e.g., `GET /file?name=../../../../etc/passwd`)
**Target Functions**:
- `index.js:parseRequest:8-14`
- `index.js:sendFile:27-36`
- `index.js:requestListener:38-44`

### Expected Behavior

The `/file` endpoint should only serve files from the `public/` directory. A request to `/file?name=../../../../etc/passwd` should be rejected or serve "Not found", not return the contents of `/etc/passwd`.

### Evidence

1. **Attacker control of parameter**: `parseRequest` at line 12 extracts the `name` query parameter directly from `searchParams.get("name")` with no validation. The URL API provides URL-decoded parameter values.

2. **Vulnerable path.join() call**: `sendFile` at line 29 calls `path.join(publicDir, name)` where:
   - `publicDir` is set to `join(process.cwd(), "public")` (line 6)
   - `name` is the attacker-controlled query parameter
   - `path.join()` normalizes relative path components including `..` sequences

3. **No post-join validation**: There is no check after line 29 to verify that the result of `path.join(publicDir, name)` remains within the intended `publicDir` boundary. The code immediately calls `readFile()` on the joined path.

4. **No alternative protections**: The code does not use:
   - `path.resolve()` with a boundary comparison
   - `path.relative()` with `../` prefix check
   - `path.normalize()` with boundary validation
   - Any custom sanitization logic

5. **Error handling does not prevent traversal**: The try-catch block (lines 28-35) catches exceptions but does not prevent the file access. It returns "Not found\n" on error, but if a file exists at the traversed path, `readFile()` succeeds and the attacker receives the file contents.

### Anti-Evidence

- The code does include a try-catch wrapper, which mitigates information leakage via error messages (attackers cannot distinguish between "file not found" and "access denied"). However, this does not prevent successful file reads when the target file exists.
- The error path returns "Not found\n" rather than exposing error details, so error-based enumeration is slightly hindered. However, attackers can still determine file existence by response differences (success vs. error).
- No explicit assertion checked (these are design-level mitigations, not source-proven guards on this specific path).

```toml-index
schema = 1
verdict = "CANDIDATE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "file_endpoint_path_traversal"
weakness = "path_traversal"
record_kind = "single_path"
path = ["GET /file", "parseRequest", "sendFile", "readFile(join(publicDir, name))"]
sink = "readFile"
sink_role = "file_access"
impact_class = "information_disclosure"
route_family = "file_read_endpoint"
material_effect = "arbitrary_file_read"
target_functions = ["index.js:parseRequest:8-14", "index.js:sendFile:27-36", "index.js:requestListener:38-44"]
scope.trust_boundary = "http_request"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "query_parameter_name"
scope.parser_state = "url_decoded"
scope.size_class = "unbounded"
input_shape_tags = ["relative_path_with_parent_refs"]
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "attacker_controlled_name_parameter_joined_without_post_join_boundary_validation"
why_failed_brief = "candidate survived all checked source guards; no blocker found"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_guard"
guarantee = "no input validation or sanitization on name parameter before passing to sendFile (line 12 extracts directly)"

[[blockers]]
kind = "not_found"
guarantee = "no post-join validation to ensure path.join result remains within publicDir (line 29 calls readFile immediately)"
```

