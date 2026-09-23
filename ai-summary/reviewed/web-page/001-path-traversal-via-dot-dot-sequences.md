# R001: Path traversal via `../` sequences in `/file` endpoint

**Date**: 2026-09-23
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/003-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: VIABLE
**Severity**: High
**Reviewed by**: claude-haiku-4-5, default

## Trace Summary

The `/file` endpoint (line 38-44 in `index.js`) accepts a user-supplied `name` query parameter, extracts it via `searchParams.get("name")` (line 12), and passes it directly to `sendFile` (line 41). The `sendFile` function (lines 27-36) constructs a file path by calling `join(publicDir, name)` (line 29) without any validation that the final path remains within `publicDir`. 

Node.js `path.join()` resolves `..` sequences during path normalization. A request to `/file?name=../../../etc/passwd` would result in:
- Input: `name = "../../../etc/passwd"`
- `join("/path/to/repo/public", "../../../etc/passwd")` resolves to `/etc/passwd`
- The absolute path escapes the `public/` directory boundary
- `readFile()` reads the actual system file at that location
- The file contents are returned in the HTTP response (line 32)

No guard prevents this escape. There is no post-join check verifying `finalPath.startsWith(publicDir)`, no path canonicalization/validation before `readFile()`, and no input filter rejecting `..` sequences.

## Findings

**Information Disclosure via Arbitrary File Read**: An unauthenticated attacker can read any file accessible to the Node.js process by supplying path traversal sequences in the `name` query parameter. This includes sensitive system files (`/etc/passwd`), application configuration files, environment variables, private keys, or source code. The HTTP response returns the raw file contents with no filtering.

**Attack Surface**: The vulnerability requires only network access to the HTTP service and knowledge of the `/file` endpoint. No authentication or special privileges are required. The attacker can enumerate the filesystem hierarchically using various traversal payloads.

## PoC Guidance

**Test file**: Create a test in the same suite as existing endpoint tests

**Setup**: Start the server normally; ensure a known sensitive file exists outside `public/` (e.g., create a test fixture file at `../sensitive.txt`)

**Steps**:
1. Send HTTP GET `/file?name=../sensitive.txt`
2. Capture the response body

**Assertion**: Verify that the response contains the contents of the file outside the `public/` directory (proving escape), or directly verify the HTTP response status is 200 and body matches a known file outside `public/`

```toml-index
schema = 1
verdict = "VIABLE"
failed_at = "reviewer"
subsystem = "web-page"
route_id = "codeql:60ad614455318e24b7d51054"
weakness = "path_traversal"
record_kind = "single_path"
path = ["index.js::requestListener", "index.js::sendFile"]
sink = "index.js::sendFile"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index.js::sendFile:27-36", "index.js::requestListener:38-44"]
scope.trust_boundary = "http_client_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "name_query_parameter"
scope.parser_state = "url_parsed"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.claim_kind = "viable_candidate_not_blocked"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["candidate_not_blocked_after_source_trace"]
rules_out = ["source trace confirms no validation guard exists for path traversal: line 29 calls join(publicDir, name) with no post-join boundary check, no input filtering of .. sequences, no path canonicalization before readFile"]
does_not_rule_out = ["similar path traversal vectors using encoded sequences or alternative traversal syntax remain unassessed in this trace"]
assumptions = ["standard Node.js path.join() behavior resolves .. sequences; the process has read permissions for the target files; HTTP response body carries file contents unredacted"]
mechanism_brief = "Untrusted name parameter from HTTP query string is joined directly to publicDir via path.join(); path traversal sequences like ../ are normalized and escape the directory boundary; no post-join validation confirms the final path remains within publicDir"
why_failed_brief = "viable; not failed"
confidence = "high"

[[sanitizer_guarantees]]
kind = "none_found"
source = "index.js:29"
guarantee = "no validation of name parameter before path.join(); no post-join boundary check; no input filter rejecting .. sequences"

[[blockers]]
kind = "not_found"
source = "index.js:27-36"
guarantee = "no blocker found in sendFile function that prevents path traversal via .. in the name parameter"
```
