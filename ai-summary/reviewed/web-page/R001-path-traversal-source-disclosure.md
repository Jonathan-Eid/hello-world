# R001: Path traversal to read application source code

**Date**: 2026-09-22
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/001-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: VIABLE
**Severity**: High
**Reviewed by**: claude-haiku-4-5

## Trace Summary

The `/file` endpoint at `index.js:27-36` accepts a `name` query parameter (extracted at line 12 with no validation) and passes it directly to `path.join(publicDir, name)` at line 29. The `publicDir` is set to `join(process.cwd(), "public")` at startup. The `path.join()` function normalizes path segments but does NOT prevent `../` traversal outside the base directory. The try-catch at lines 33-34 catches file-not-found errors but does not validate that the resolved path remains within `public/`. An attacker can send `GET /file?name=../index.js` to read the application source code directly, since `path.join('/app/workspace/public', '../index.js')` resolves to `/app/workspace/index.js` outside the intended directory.

## Findings

The vulnerability is a classic path traversal (CWE-22) allowing arbitrary file read. The impact is **Information Disclosure (High)** of application source code, which may contain:
- Internal logic and business logic flaws
- Hardcoded secrets or configuration values
- Other endpoint implementations

The attack is **easily exploitable**: a single HTTP GET request with a `../` sequence in the query parameter is sufficient. No authentication is required.

## PoC Guidance

The PoC should:
1. Start the server with `/app/workspace` as the working directory
2. Send `GET /file?name=../index.js` to the `/file` endpoint
3. Assert that the response status is 200 and the body contains the JavaScript source code from `index.js`
4. Verify the response contains recognizable code patterns (e.g., `import`, `createServer`, `readFile`)

This demonstrates that `path.join()` alone is insufficient to prevent directory traversal and that no boundary validation guards the `readFile` sink.

```toml-index
schema = 1
verdict = "VIABLE"
failed_at = "reviewer"
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
negative_claim.claim_kind = "viable_candidate_not_blocked"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["candidate_not_blocked_after_source_trace"]
rules_out = ["path.join() is documented to normalize but NOT validate path boundaries; source trace confirms no additional path validation guards the readFile sink"]
does_not_rule_out = ["other file-read endpoints using similar patterns", "variants targeting different file types via the same traversal mechanism"]
assumptions = ["Node.js path.join() behaves as documented", "working directory is under /app/workspace or similar filesystem", "Node process has read access to the file being traversed"]
mechanism_brief = "path.join(publicDir, name) with attacker-controlled name containing ../ sequences; no path validation or boundary check"
why_failed_brief = "viable; not failed"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_guard"
source = "index.js:sendFile:29"
guarantee = "no path validation guard between query parameter and readFile sink"

[[blockers]]
kind = "not_found"
source = "index.js"
guarantee = "no path.resolve() + startsWith() check or similar boundary validation present in sendFile or parseRequest"
```
