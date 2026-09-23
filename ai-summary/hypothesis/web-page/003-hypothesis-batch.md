# H003: Hypothesis batch for file delivery without directory bounds

**Date**: 2026-09-23
**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/003-path-seed.md
**Hypothesis by**: claude-haiku-4-5, default

## Shared Path Context

The web-page service exposes a `/file?name=<param>` endpoint that constructs a file path by joining the user-supplied `name` parameter directly onto the `public/` directory using `path.join()`, then reads and returns the file content via HTTP response. The `name` parameter originates from the untrusted HTTP query string and is not validated to ensure the resolved path remains within `public/`.

**Route**: `requestListener` → `sendFile` → `response.end(body)`
**Entry**: HTTP query parameter `name`
**Parser state**: URL parsed, raw relative path extracted
**Trust boundary**: Untrusted HTTP client input

## Candidate 1

**Candidate ID**: C1
**Severity**: High
**Impact**: Information Disclosure
**Mechanism**: Path Traversal via directory-escape sequences in `path.join()`
**Trigger**: HTTP GET `/file?name=../../../etc/passwd` or equivalent traversal sequence targeting system or application files

**Target Functions**:
- `index.js::sendFile:27-36`
- `index.js::requestListener:38-44`

### Expected Behavior

The code should restrict file access to the `public/` directory. Paths like `../../../etc/passwd` should either be rejected or canonicalized and validated to ensure the final resolved path is within `public/`.

### Evidence

**Source (index.js:6)**: `const publicDir = join(process.cwd(), "public");` — intended directory boundary set at module load.

**Source (index.js:12)**: `name: searchParams.get("name") || "hello.txt"` — attacker controls the `name` parameter directly from query string, no validation applied.

**Source (index.js:29)**: `const body = await readFile(join(publicDir, name));` — the `name` parameter is passed to `path.join()` without any validation. Node.js `path.join()` resolves `..` sequences to navigate the filesystem hierarchy; a sequence like `../../../etc/passwd` will escape `publicDir`.

**Source (index.js:31-32)**: `response.writeHead(200, ...); response.end(body);` — the file content is sent directly in the HTTP response body without filtering or redaction.

**Path.join() Behavior**: When `path.join("/path/to/public", "../../../etc/passwd")` is called, Node.js resolves the relative sequences and returns `/etc/passwd`, completely outside the intended `public/` directory.

### Anti-Evidence

No path canonicalization or validation occurs before or after `path.join()`. There is no check that the final resolved path starts with `publicDir`. The error handler (line 33-35) only catches filesystem errors; it does not prevent traversal. The `name` parameter has no length limit or character filter that would block `..` sequences.

```toml-index
schema = 1
verdict = "CANDIDATE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:60ad614455318e24b7d51054"
weakness = "path_traversal"
record_kind = "single_path"
path = ["index.js::sendFile", "index.js::sendGreeting"]
sink = "index.js::sendGreeting"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index.js::sendFile"]
scope.trust_boundary = "http_client_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "name_query_parameter"
scope.parser_state = "url_parsed"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "path.join(publicDir, untrusted_name) does not validate that the final path remains within publicDir; traversal sequences like ../ are resolved and escape the boundary"
why_failed_brief = "not failed; candidate survived source trace — no validator or guard prevents directory escape via .. sequences"
confidence = "high"

[[sanitizer_guarantees]]
kind = "none_found"
guarantee = "no validation of name parameter before path.join()"

[[blockers]]
kind = "not_found"
guarantee = "no source check verifies resolved path remains within publicDir"
```
