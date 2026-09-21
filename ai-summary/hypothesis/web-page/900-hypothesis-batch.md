# H900: Hypothesis batch for path traversal via sendFile

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/900-residual-seed.md
**Hypothesis by**: claude-haiku-4-5

## Shared Path Context

The `/file` route accepts a `name` query parameter, URL-decodes it via Node's URL parser, and passes it directly to `sendFile`. The `sendFile` function joins the attacker-controlled `name` onto `publicDir` without any path containment validation. The only exception handler (line 33-35) catches runtime errors and returns a generic 404 response; it does not validate or reject traversal sequences. The attacker is unauthenticated and controls the full `name` value via HTTP query parameter.

## Candidate 1

**Candidate ID**: C1
**Severity**: High
**Impact**: information_disclosure
**Mechanism**: Path traversal via `path.join` without containment check
**Trigger**: HTTP GET request to `/file?name=../../../../etc/passwd` (or any file traversal sequence)
**Target Functions**:
- `index.js:sendFile:27-36`
- `index.js:parseRequest:8-14`

### Expected Behavior

The `sendFile` function should only read files within the `public/` directory. A request with `name` containing `..` or absolute path sequences should be rejected or safely normalized to stay within bounds.

### Evidence

- `index.js:6` - `publicDir` is fixed: `const publicDir = join(process.cwd(), "public")`
- `index.js:12` - `name` extracted from query param: `searchParams.get("name")`
- `index.js:29` - Unsafe join with no post-join validation: `const body = await readFile(join(publicDir, name))`
- `index.js:33-35` - Catch block only handles runtime exceptions, does not validate the path

### Anti-Evidence

Checked: Node.js `path.join()` does not prevent or sanitize path traversal. Checked: No additional guards exist between parsing and file read. Checked: Catch block addresses errors, not attacker input.

```toml-index
schema = 1
verdict = "CANDIDATE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:383df8b1224ab6a122806546"
weakness = "path_traversal"
record_kind = "single_path"
path = ["index::sendFile", "http::writeHead"]
sink = "http::writeHead"
sink_role = "response_emission"
impact_class = "information_disclosure"
route_family = "response_emission"
material_effect = "arbitrary file read"
target_functions = ["index.js:sendFile", "index.js:parseRequest"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "filesystem_limited"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "path traversal: attacker passes ../../../ sequences in name query parameter; path.join normalizes without containment check"
why_failed_brief = "not failed; candidate survived checked blockers"
confidence = "high"

[[sanitizer_guarantees]]
kind = "checked_guard"
guarantee = "no path containment check found in sendFile between join result and readFile"

[[blockers]]
kind = "not_found"
guarantee = "catch block is exception handler only, not a path validator"
```
