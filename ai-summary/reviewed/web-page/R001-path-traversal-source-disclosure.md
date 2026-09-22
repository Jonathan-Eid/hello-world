# R001: Path traversal enabling arbitrary file read via `/file` endpoint

**Date**: 2026-09-22
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/900-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: VIABLE
**Severity**: High
**Reviewed by**: claude-haiku-4-5

## Trace Summary

The `/file` HTTP endpoint is vulnerable to path traversal via the unvalidated `name` query parameter. The code path is:

1. **Entry (line 12)**: `parseRequest` extracts `name` from `searchParams.get("name")` with no validation and returns it as-is.
2. **Propagation (line 39-41)**: `requestListener` calls `parseRequest`, and if the route is `"file"`, invokes `sendFile(response, parsed.name)`.
3. **Sink (line 29)**: `sendFile` calls `readFile(join(publicDir, name))` where `publicDir` is `join(process.cwd(), "public")`.
4. **No boundary check**: There is no validation after the `path.join()` call to verify the result stays within the intended `public/` directory.

`path.join()` normalizes relative path components including `..` sequences. An attacker can supply `name` values like `../../../../etc/passwd` which normalize through the boundary and result in absolute paths outside `public/`.

## Findings

**Vulnerability**: Path traversal via unvalidated `path.join()` result allows arbitrary file read.

**Mechanism**: The code uses `path.join(publicDir, name)` to construct a file path, then immediately passes the result to `fs.readFile()` without checking that the result stays within `publicDir`. When `name` contains `../` sequences, `path.join()` normalizes them, and the attacker gains read access to any file readable by the Node process.

**Exploitability**: An attacker can:
- Request `GET /file?name=../../../../etc/passwd` to read `/etc/passwd`
- Request `GET /file?name=../index.js` to read the source code
- Request `GET /file?name=../../../../var/log/syslog` to read system logs (if readable)
- Use knowledge of process privileges to enumerate sensitive files

The error handling at lines 33-34 does not prevent traversal—it only returns a generic "Not found\n" on read failure. Successful reads (when the target file exists and is readable) return the file contents to the attacker.

**Impact**: Information disclosure of arbitrary files readable by the Node process, including source code, configuration, system files, and credentials.

## PoC Guidance

**Test file**: `test/path-traversal.test.js` (or append to existing test suite)

**Setup**:
- Start the server (listening on configurable port)
- Create a test file outside `public/` (e.g., at `../secret.txt` relative to `public/`)

**Steps**:
1. Make an HTTP GET request to `/file?name=../secret.txt`
2. Verify the response status code is 200
3. Verify the response body contains the contents of the secret file outside `public/`

**Assertion**: `response.statusCode === 200 && response.body === expectedFileContents`

```toml-index
schema = 1
verdict = "VIABLE"
failed_at = "reviewer"
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
negative_claim.claim_kind = "viable_candidate_not_blocked"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["candidate_not_blocked_after_source_trace"]
rules_out = ["no input validation on name parameter before sendFile (line 12 extracts directly from query params)", "no post-join boundary validation to ensure join result stays within publicDir (line 29 calls readFile immediately)", "no path.resolve() with boundary comparison", "no path.relative() with ../ prefix check", "error handling does not prevent successful file reads outside public/"]
does_not_rule_out = ["variants using different root directories", "variants using different parameter names"]
assumptions = ["path.join() normalizes .. sequences as documented in Node.js built-ins", "attacker can control query parameter values via HTTP request", "error handling returns generic message without blocking traversal"]
mechanism_brief = "attacker_controlled_name_parameter_joined_without_post_join_boundary_validation"
why_failed_brief = "viable; source trace confirms path traversal is not blocked"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_guard"
source = "index.js:parseRequest:12"
guarantee = "no input validation or sanitization on name parameter before passing to sendFile"

[[blockers]]
kind = "not_found"
source = "index.js:sendFile:29"
guarantee = "no post-join validation to ensure path.join result remains within publicDir; readFile called directly on joined path"
```
