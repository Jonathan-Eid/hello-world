# H006: Hypothesis batch for request URL parsing

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/006-path-seed.md
**Hypothesis by**: claude-haiku-4-5, default

## Shared Path Context

The dispatch path traces from HTTP request entry (`requestListener`) through URL parsing (`parseRequest`) into downstream response handling. The `parseRequest` function accepts raw `request.url` from the Node.js HTTP listener without validation and directly passes it to the `URL()` constructor. The HTTP specification allows multiple forms of request-target (origin-form `/path`, absolute-form `http://host/path`, authority-form `host:port`, and asterisk-form `*`). Node.js http module preserves the raw request-target in the `request.url` property.

## Candidate 1

**Candidate ID**: C1
**Severity**: Medium
**Impact**: Denial of Service
**Mechanism**: Unhandled TypeError from URL constructor on asterisk-form request-target
**Trigger**: HTTP OPTIONS request with asterisk-form request-target (`OPTIONS * HTTP/1.1`), causing `request.url = "*"`

**Target Functions**:
- `index.js:parseRequest:5-8`
- `index.js:requestListener:22-26`

### Expected Behavior

The service should either:
1. Validate and reject invalid request-targets before URL parsing, OR
2. Wrap URL parsing in error handling to gracefully fail without crashing

### Evidence

- **`index.js:5-8`**: `parseRequest` directly calls `new URL(rawUrl, "http://localhost")` without try-catch. The `URL` constructor throws `TypeError` when given invalid URL syntax.
- **`index.js:22-26`**: `requestListener` calls `parseRequest(request.url)` without error handling. No guard between request listener and URL parsing sink.
- **Reachability**: RFC 7230 section 5.3 defines asterisk-form as valid for OPTIONS requests. Node.js HTTP parser preserves request-target as-is in `request.url`.
- **Trigger validation**: `new URL("*", "http://localhost")` throws `TypeError: Invalid URL` in Node.js runtime. Sending `OPTIONS * HTTP/1.1` causes `request.url` to be set to the string `"*"`.

### Anti-Evidence

- No explicit validation guard found in the path, but no other guards bypass attempts either.
- The vulnerability depends on Node.js http module actually setting `request.url = "*"` for OPTIONS requests. This is standard HTTP behavior and supported by Node.js.

```toml-index
schema = 1
verdict = "CANDIDATE"
failed_at = "hypothesis"
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
negative_claim.rules_out_codes = []
rules_out = ["only_relative_url_paths_accepted"]
does_not_rule_out = ["other_request_target_forms", "other_malformed_urls"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "Asterisk-form request-target in HTTP OPTIONS request causes new URL() constructor to throw TypeError without error handling"
why_failed_brief = "not failed; unhandled exception vulnerability confirmed"
confidence = "high"

[[sanitizer_guarantees]]
kind = "missing_guard"
guarantee = "no error handling around URL constructor call"

[[blockers]]
kind = "not_found"
guarantee = "no defensive guard prevents asterisk-form input from reaching new URL()"
```
