# H900: Hypothesis batch for parseRequest URL constructor vulnerabilities

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/900-residual-seed.md
**Hypothesis by**: claude-haiku-4-5

## Shared Path Context

Residual escalation re-investigating parseRequest URL constructor vulnerabilities. Prior investigation found asterisk-form input reaches `new URL()` without defensive guards. The dispatch targets `requestListener -> buildGreeting` path with sink at `buildGreeting`. parseRequest is called within requestListener to parse `request.url` (attacker-controlled HTTP request target). Scope: HTTP/1.1 request boundary, unauthenticated, response generation phase.

## Candidate 1

**Candidate ID**: C1
**Severity**: High
**Impact**: Denial of Service via unhandled exception
**Mechanism**: Asterisk-form or authority-form HTTP request triggers unhandled TypeError in URL constructor
**Trigger**: HTTP request with request-target in asterisk form (`*`) or authority form (`example.com:port`), valid per HTTP/1.1 spec for OPTIONS and CONNECT methods
**Target Functions**:
- `index.js:parseRequest:6`
- `index.js:requestListener:23`

### Expected Behavior

parseRequest should safely extract pathname from any valid HTTP/1.1 request-target form. At minimum, invalid forms should be caught and handled (e.g., 400 Bad Request).

### Evidence

**URL Constructor Behavior**:
- Line 6: `const { pathname } = new URL(rawUrl, "http://localhost");` called without try/catch
- Asterisk form: `new URL("*", "http://localhost")` throws `TypeError: Invalid URL` (test: `node -e "new URL('*', 'http://localhost')"` fails)
- Authority form: `new URL("example.com:80", "http://localhost")` throws `TypeError: Invalid URL` (test: `node -e "new URL('example.com:80', 'http://localhost')"` fails)

**Attacker-Controlled Path**:
- Line 23: parseRequest receives `request.url` from `request` parameter (HTTP request object)
- HTTP/1.1 RFC allows asterisk form for OPTIONS (e.g., `OPTIONS * HTTP/1.1`) and authority form for CONNECT (e.g., `CONNECT example.com:80 HTTP/1.1`)
- These are valid protocol forms; no HTTP parsing validation precedes parseRequest

**Exception Propagation**:
- Line 6 exception is unhandled (no try/catch in parseRequest or requestListener)
- Propagates to HTTP server's listener, resulting in connection error/closure or 500 response
- Prevents normal flow (buildGreeting never called, no controlled response sent)

### Anti-Evidence

- No validator or guard on request.url before parseRequest call (line 23)
- No try/catch in parseRequest (line 5-9)
- No error handler in requestListener (line 22-27)
- buildGreeting always returns hardcoded strings, so if URL parsing were to succeed, no injection through buildGreeting exists; but parseRequest throws before buildGreeting is reached

```toml-index
schema = 1
verdict = "CANDIDATE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:6f339d4b9346de62b2b7b6d4"
weakness = "response_content_build"
record_kind = "single_path"
path = ["index.js::requestListener", "index.js::buildGreeting"]
sink = "index.js::buildGreeting"
sink_role = "response_content_build"
impact_class = "denial_of_service"
route_family = "response_content_build"
material_effect = "server crash/unavailability on asterisk or authority form request"
target_functions = ["index.js:parseRequest:6", "index.js:requestListener:23"]
scope.trust_boundary = "http_boundary"
scope.protocol_phase = "response_generation"
scope.auth_state = "unauthenticated"
scope.attacker_control = "request_url"
scope.parser_state = "normalized_by_parseRequest"
scope.size_class = "fixed_hardcoded_strings"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "asterisk or authority form request-target causes unhandled TypeError in URL constructor"
why_failed_brief = "not failed; mechanism survives all checked blockers"
confidence = "high"

[[sanitizer_guarantees]]
kind = "absence_of_guard"
guarantee = "no input validation or error handling guards the URL constructor call"

[[blockers]]
kind = "not_found"
guarantee = "no defensive guard prevents asterisk-form or authority-form input from reaching new URL() constructor"
```
