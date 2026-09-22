# R001: Path traversal via unvalidated path.join()

**Date**: 2026-09-22
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/900-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: VIABLE
**Severity**: High
**Reviewed by**: claude-haiku-4-5, default

## Trace Summary

The `/file` endpoint (index.js:27-36) accepts the `name` query parameter from line 12, passes it without validation to `sendFile()` at line 41, and joins it directly with the `publicDir` using `path.join(publicDir, name)` at line 29. Node.js's `path.join()` resolves relative path sequences (e.g., `../`) in the second argument, allowing the attacker to escape the `public/` directory boundary entirely. A request like `GET /file?name=../../../etc/passwd` will resolve to a path outside `public/` and read arbitrary files on the system (subject to process permissions).

## Findings

**Information Disclosure via Path Traversal**: An unauthenticated attacker can read any file on the system that the Node.js process has permission to access by providing relative path sequences in the `name` query parameter. For example:
- `GET /file?name=../../../etc/passwd` reads `/etc/passwd`
- `GET /file?name=../index.js` reads the application source code
- No validation, path normalization check, or boundary enforcement exists in the code path

**Expected behavior**: The application should restrict file reads to files within the `public/` directory and reject or sanitize traversal sequences. **Actual behavior**: The application joins the attacker-controlled `name` directly with `publicDir` using `path.join()`, which does not enforce directory boundaries.

## PoC Guidance

- **Test file**: Add to existing test suite or create `test.js`
- **Setup**: Start the server on `http://localhost:3000`
- **Steps**:
  1. Send `GET /file?name=../index.js`
  2. Capture the response body
- **Assertion**: Response status is 200 and response body contains the contents of `index.js` (e.g., includes `createServer` or `publicDir`)

```toml-index
schema = 1
verdict = "VIABLE"
failed_at = "reviewer"
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
negative_claim.claim_kind = "viable_candidate_not_blocked"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["candidate_not_blocked_after_source_trace"]
rules_out = ["source trace confirms path.join() does not enforce directory boundaries; no validation exists between query parameter extraction (line 12) and readFile call (line 29)"]
does_not_rule_out = ["symlink race conditions on the same endpoint", "other file-read endpoints or injection vectors"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "path.join() resolves relative path sequences without enforcing base directory boundary; attacker-controlled name parameter with ../ sequences escapes public/ directory"
why_failed_brief = "viable; not failed"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_guard"
source = "index.js:12, index.js:29"
guarantee = "no path validation, normalization, or boundary checking exists between query parameter extraction and readFile call"

[[blockers]]
kind = "not_found"
source = "index.js:27-36"
guarantee = "no code-level blocker prevents relative path traversal via path.join()"
```
