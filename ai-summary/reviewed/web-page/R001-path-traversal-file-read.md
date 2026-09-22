# R001: Path Traversal in /file Endpoint Allows Arbitrary File Read

**Date**: 2026-09-22
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/001-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: VIABLE
**Severity**: High
**Reviewed by**: claude-haiku-4-5

## Trace Summary

The `/file` endpoint accepts an untrusted `name` query parameter at `parseRequest()` line 12, which is passed directly to `sendFile()` without any validation. The `sendFile()` function at line 27 joins the parameter with `publicDir` using `path.join()` at line 29, but performs no post-join validation to verify the result remains within the intended directory boundary. Node.js `path.join()` normalizes relative path components including `..` sequences, allowing an attacker to escape the `public/` directory and read arbitrary files accessible to the process.

## Findings

An attacker can craft a request like `GET /file?name=../../../etc/passwd` to traverse up the directory tree and read any file the Node.js process has permission to access. This includes:
- System configuration files (e.g., `/etc/passwd`, `/etc/hosts`)
- Application source code and secrets stored outside the public directory
- Other application files and credentials

The error handling at lines 28-35 only masks filesystem errors by returning "Not found\n" to the client. It does not prevent the file access—it only hides the error when a file is truly inaccessible, while allowing successful reads of files outside the intended scope. The vulnerability is confirmed at the source code level with no guards preventing exploitation.

## PoC Guidance

- **Test file**: Create a test that verifies path traversal is blocked
- **Setup**: Start the server with a test-accessible filesystem structure (e.g., a file outside `public/` directory)
- **Steps**: Issue a request like `GET /file?name=../package.json` or similar traversal path
- **Assertion**: Verify the response returns "Not found\n" and does not leak file contents from outside `public/`

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
rules_out = ["source trace confirms no post-join validation, no path.resolve comparison, and no sanitization of .. components"]
does_not_rule_out = ["variant path traversal attacks using different relative path patterns or combined with other input methods"]
assumptions = ["process has read permission on traversed files", "no filesystem ACLs or container restrictions beyond process user permissions"]
mechanism_brief = "attacker_controlled_name_parameter_joined_with_path_join_without_post_join_boundary_validation"
why_failed_brief = "viable; not failed"
confidence = "high"

[[sanitizer_guarantees]]
kind = "none_found"
source = "index.js:12"
guarantee = "no input validation or sanitization on name parameter before passing to sendFile"

[[blockers]]
kind = "not_found"
source = "index.js:29"
guarantee = "no post-join validation to ensure path.join result remains within publicDir"
```
