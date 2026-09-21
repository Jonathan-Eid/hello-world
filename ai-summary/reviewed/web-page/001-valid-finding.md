# R001: Unhandled TypeError on asterisk-form HTTP request-target

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/006-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: VIABLE
**Severity**: Medium
**Reviewed by**: claude-haiku-4-5

## Trace Summary

The `parseRequest` function at line 6 directly calls `new URL(rawUrl, "http://localhost")` without try-catch or input validation. The `requestListener` at line 23 passes `request.url` directly to `parseRequest` without error handling. When an HTTP OPTIONS request with asterisk-form request-target (`OPTIONS * HTTP/1.1`) arrives, Node.js HTTP module preserves this as `request.url = "*"`. The `new URL()` constructor throws `TypeError: Invalid URL` for the string `"*"`, and this exception propagates uncaught through the call stack, crashing the process.

## Findings

**Mechanism**: Unhandled TypeError from URL constructor on RFC 7230-compliant asterisk-form request-target.

**Exploitability**: An attacker can send a single HTTP OPTIONS request with asterisk-form (e.g., `OPTIONS * HTTP/1.1`) to trigger process termination.

**Impact**: Denial of Service — the service crashes and must be manually restarted.

**Likelihood**: High — asterisk-form is explicitly permitted by HTTP specification for OPTIONS requests, and Node.js HTTP module passes it through unchanged.

## PoC Guidance

**Test file**: Create a test file `test-asterisk-form.js` or append to existing tests.

**Setup**: 
- Start the service on a local port
- Use the `node:http` module to construct a raw HTTP request

**Steps**:
1. Create raw HTTP request: `OPTIONS * HTTP/1.1\r\nHost: localhost:3000\r\n\r\n`
2. Send this request to the running service
3. Observe process termination (exit code non-zero, stderr shows `TypeError: Invalid URL`)

**Assertion**: 
- Assert that the process exits with error status
- Assert stderr contains `TypeError: Invalid URL`

```toml-index
schema = 1
verdict = "VIABLE"
failed_at = "reviewer"
subsystem = "web-page"
route_id = "codeql:1632c2a743acc8a6af077193"
weakness = "request_url_parse"
record_kind = "single_path"
path = ["index::requestListener", "index::parseRequest"]
sink = "index::parseRequest"
sink_role = "request_url_parse"
impact_class = "denial_of_service"
route_family = "request_url_parse"
material_effect = "request_url_parse"
target_functions = ["index.js:parseRequest", "index.js:requestListener"]
scope.trust_boundary = "http_request_boundary"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_request_target_form"
scope.parser_state = "raw_request_target"
scope.size_class = "single_request"
input_shape_tags = ["asterisk_form_request_target"]
defense_tags = []
negative_claim.claim_kind = "viable_candidate_not_blocked"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["candidate_not_blocked_after_source_trace"]
rules_out = ["source trace confirms no input validation or error handling guards the URL constructor call in the request parsing path"]
does_not_rule_out = ["other malformed request-targets may also cause unhandled exceptions", "other RFC 7230-compliant request forms may be similarly vulnerable"]
assumptions = ["Node.js HTTP module preserves asterisk-form in request.url property", "new URL() constructor throws TypeError for asterisk string as per ECMAScript URL spec", "uncaught exceptions in requestListener callback terminate the process"]
mechanism_brief = "Asterisk-form request-target from HTTP OPTIONS request reaches new URL() constructor without validation or try-catch, causing unhandled TypeError"
why_failed_brief = "viable; real vulnerability confirmed by source trace"
confidence = "high"

[[sanitizer_guarantees]]
kind = "missing_guard"
source = "index.js:parseRequest"
guarantee = "no input validation before URL constructor call"

[[sanitizer_guarantees]]
kind = "missing_guard"
source = "index.js:requestListener"
guarantee = "no error handling around parseRequest call"

[[blockers]]
kind = "not_found"
source = "index.js:5-27"
guarantee = "no defensive guard prevents asterisk-form input from reaching new URL() constructor"
```
