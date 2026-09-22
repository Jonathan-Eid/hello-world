# H900: Hypothesis batch for /file endpoint path traversal (C1 re-investigation)

**Date**: 2026-09-22
**Subsystem**: web-page
**Source Dispatch Seed**: ai-summary/dispatch/web-page/900-residual-seed.md
**Hypothesis by**: claude-haiku-4-5

## Shared Path Context

**Path**: `GET /file` with query parameter `name` → `parseRequest()` → `sendFile()` → `readFile(join(publicDir, name))`

**Trust Boundary**: HTTP request; unauthenticated access to `/file` endpoint

**Parser State**: URL-decoded query string parameter

**Vulnerable Code**: `index.js` lines 12 and 29
- Line 6: `const publicDir = join(process.cwd(), "public");`
- Line 12: `name: searchParams.get("name") || "hello.txt"` — attacker fully controls `name`
- Line 29: `readFile(join(publicDir, name))` — no validation before join

**Prior Memory**: F001 ruled out C2 (system-file variant) as subsumed by C1. This re-investigation confirms whether C1 (source-code traversal) is viable with escalated budget.

## Candidate 1

**Candidate ID**: C1
**Severity**: High
**Impact**: Information Disclosure (arbitrary file read)
**Mechanism**: Path traversal via unvalidated query parameter joined with `path.join()`
**Trigger**: `GET /file?name=../index.js` or any traversal sequence (`../../`, `../../../`, etc.)
**Target Functions**:
- `index.js:parseRequest:8-14`
- `index.js:sendFile:27-36`

### Expected Behavior

The `/file` endpoint should return only files from the `public/` directory. A request for `/file?name=../index.js` should either:
1. Reject the request due to path boundary validation, or
2. Treat `../` as a literal filename (returning a 404 since no such file exists in `public/`).

Instead, the application reads files outside `public/`.

### Evidence

**Attack vector**: `GET /file?name=../index.js`
- `parseRequest()` at line 12: Extracts `name = "../index.js"` directly from `searchParams.get("name")`
- No validation, sanitization, or whitelist applied
- Value passed directly to `sendFile(response, name)`

**Sink**: `index.js:29` — `readFile(join(publicDir, name))`
- `publicDir` is `{cwd}/public/` (line 6)
- `join(publicDir, "../index.js")` normalizes to `{cwd}/index.js`
- `readFile()` reads the normalized path without re-validating it stays under `publicDir`
- The file contents are returned as the HTTP response body (line 32)

**Why `path.join()` does not protect**:
- `path.join()` normalizes path segments and resolves `..` correctly
- But it does **not** validate that the result stays within a boundary
- `path.join("/app/public", "../index.js")` → `/app/index.js` (escapes successfully)

### Anti-Evidence

**Try-catch (lines 33-35)**: Catches read errors but does not prevent path traversal. If the file exists and is readable by the process, it is returned. A 404 is only returned if the file does not exist or is not readable—not as a result of boundary checking.

**Process permissions**: The analysis assumes the Node process can read files outside `public/`. Standard practice: a web server running as a regular user can typically read files in the project root (application source, package.json, etc.). This is a realistic assumption for a development or deployed service.

**No additional guards found**: No path canonicalization, whitelist, regular expressions, or explicit boundary check between the join and the readFile call.

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
target_functions = ["index.js:parseRequest:8-14", "index.js:sendFile:27-36"]
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
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "path traversal via unvalidated query parameter joined without boundary validation"
why_failed_brief = "not failed; candidate survived checked blockers and source-verified path"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_guard"
source = "index.js:sendFile:29"
guarantee = "no path validation guard; path.join() normalizes but does not validate boundary"

[[blockers]]
kind = "not_found"
source = "index.js:8-36"
guarantee = "no blocker found; traversal path undefended"
```
