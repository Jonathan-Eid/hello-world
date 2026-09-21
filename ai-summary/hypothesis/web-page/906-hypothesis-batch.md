# H906: Hypothesis batch for path traversal via unvalidated filename

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/906-path-seed.md
**Hypothesis by**: claude-haiku-4-5

## Shared Path Context

The `/file` endpoint accepts a `name` query parameter that flows through `parseRequest` (line 12) into `sendFile` (line 27). The `name` value is URL-decoded automatically by Node.js's `URL` API and passed directly to `path.join(publicDir, name)` (line 29) without any path validation. The `publicDir` is set to the current working directory's `public/` subdirectory (line 6).

## Candidate 1

**Candidate ID**: C1
**Severity**: High
**Impact**: Information Disclosure via Filesystem Read
**Mechanism**: Directory traversal via path normalization bypass
**Trigger**: HTTP GET request with `../` sequences in the `name` query parameter, e.g., `/file?name=../../etc/passwd`
**Target Functions**:
- `index.js:sendFile:27-36`

### Expected Behavior

The `sendFile` function should restrict file reads to the `public/` directory. Any request with path traversal sequences should either be rejected or normalized to stay within bounds.

### Evidence

- `index.js:8-14` - The `parseRequest` function extracts the `name` query parameter via `searchParams.get("name")`, which returns the URL-decoded value.
- `index.js:27-36` - The `sendFile` function passes the decoded `name` directly to `path.join(publicDir, name)` without validation.
- `index.js:6` - `publicDir` is defined as a fixed directory relative to the current working directory.
- Node.js `path.join()` normalizes path sequences (removing `.` and `..`) but does not prevent upward traversal when `..` appears in the input. For example, `path.join('/app/workspace/public', '../../etc/passwd')` normalizes to `/app/workspace/etc/passwd`, crossing the intended boundary.

### Anti-Evidence

- The error handler (line 33-35) catches `readFile` errors and returns a generic "Not found" response, preventing direct error-based information leakage about file existence. However, this does not prevent successful reads of accessible files outside the intended directory.

```toml-index
schema = 1
verdict = "CANDIDATE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:ba4783688eb4a1dfa64ae1d4"
weakness = "path_traversal"
record_kind = "single_path"
path = ["index::sendFile", "fs::readFile"]
sink = "fs::readFile"
sink_role = "filesystem_read"
impact_class = "information_disclosure"
route_family = "filesystem_read"
material_effect = "filesystem_read"
target_functions = ["index.js:sendFile"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = ["path_traversal_via_normalization"]
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "URL-decoded query parameter flows into path.join without bounds checking; path normalization allows upward traversal"
why_failed_brief = "candidate survives source review; path.join does not prevent traversal attacks"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_guard"
guarantee = "no path validation or canonicalization guard exists before path.join call"

[[blockers]]
kind = "not_found"
guarantee = "no source-proven blocker prevents upward traversal in path.join output"
```
