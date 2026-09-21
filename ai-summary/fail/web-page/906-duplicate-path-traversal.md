# F906: Duplicate path traversal finding

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/906-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: NOT_VIABLE
**Failed At**: reviewer
**Reviewed by**: claude-haiku-4-5

## Trace Summary

The candidate documents a path traversal vulnerability in the `/file` endpoint via the `name` query parameter flowing through `parseRequest` (line 12) to `sendFile` (line 29), where it is joined directly into a filesystem read without validation. This is the exact same vulnerability mechanism, entry point, attacker control surface, and scope as prior investigation [3].

## Why It Failed

Prior investigation [3] (VIABLE, high confidence) already adjudicated the identical path traversal vulnerability at `index.js:parseRequest; index.js:sendFile` with the same scope (`http_untrusted/request_parsing/unauthenticated/http_query_parameter/url_decoded`). That investigation confirmed no path containment check guards the `path.join` result at line 29. C1 documents the same vulnerability from a slightly lower angle in the call stack (sendFile→readFile vs parseRequest→sendFile), but the security finding is identical: an unvalidated name parameter enables directory traversal.

Both candidates establish that:
- The `name` parameter is URL-decoded and extracted at line 12
- No path validation occurs before `path.join(publicDir, name)` at line 29
- The catch block at line 33 is error handling only, not a security boundary
- Directory traversal sequences like `../../etc/passwd` are normalized by path.join but not prevented

The vulnerability is already VIABLE with high confidence under prior [3]. This candidate adds no distinct mechanism, trust boundary variant, or security-relevant code path that prior [3] did not already cover.

## What This Rules Out

Distinct vulnerability claim on this route beyond the path traversal already found VIABLE in prior [3]; new mechanism claim for path containment bypass on sendFile.

## What This Does Not Rule Out

Other vulnerability classes on the web-page route (e.g., timing attacks, error-message leakage, other endpoints) remain unassessed.

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "reviewer"
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
negative_claim.claim_kind = "exact_typed_duplicate"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["subsumed_by_prior_viable_investigation_3"]
rules_out = ["duplicate finding already adjudicated as VIABLE in prior investigation [3] at parseRequest→sendFile with identical scope and mechanism; no distinct variant present"]
does_not_rule_out = ["other vulnerability classes on web-page subsystem; other endpoints or trust boundaries"]
assumptions = ["prior investigation [3] correctly traced the absence of path containment checks; source code unchanged since prior investigation"]
mechanism_brief = "Path traversal via unvalidated name parameter in path.join call"
why_failed_brief = "exact duplicate of prior investigation [3] VIABLE finding; same vulnerability already established with high confidence"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_guard"
source = "index.js:sendFile"
guarantee = "no path validation or containment check guards the join result at line 29"

[[blockers]]
kind = "prior_viable_record"
source = "prior_investigation_3"
guarantee = "identical vulnerability route already found VIABLE with high confidence; duplicate candidate adds no new mechanism or scope variant"
```
