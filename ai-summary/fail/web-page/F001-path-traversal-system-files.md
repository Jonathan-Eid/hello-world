# F001: Path traversal to read system files (subsumption of C1)

**Date**: 2026-09-22
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/001-hypothesis-batch.md
**Candidate ID**: C2
**Verdict**: NOT_VIABLE
**Failed At**: reviewer
**Reviewed by**: claude-haiku-4-5, default

## Trace Summary

Candidate C2 targets the same vulnerability path as C1: the `/file` endpoint at `index.js:27-36` with path traversal via `../` sequences in the `name` query parameter. The code path is identical (lines 12, 29) with no boundary validation. The only difference between C1 and C2 is the target file: C1 targets application source (`../index.js`), while C2 targets system files (`../../../../etc/passwd`).

## Why It Failed

C2 is **NOT_VIABLE due to subsumption**. It describes an instance of the same underlying path traversal vulnerability already identified in C1, differing only in the target file class. Both candidates exploit the same code path:
- Same entry point: `GET /file?name=<traversal>`
- Same vulnerable line: `readFile(join(publicDir, name))` at line 29
- Same root cause: `path.join()` does not validate path boundaries

The path traversal mechanism in C2 is proven VIABLE via C1. Once the general path traversal is confirmed, whether the target is application source, system files, or any other readable file is a matter of filesystem state and process permissions, not of a distinct vulnerability. Listing separate candidates for each target file is not productive; the PoC for C1 proves the vulnerability, and the exploit extends to any readable file.

## What This Rules Out

The exact mechanism ruled out is: **path traversal targeting system files via the same unvalidated `path.join()` as a distinct, non-subsumed finding**. C2 is not a separate vulnerability — it is a variant of C1 applied to a different asset.

## What This Does Not Rule Out

Nearby variants remain unassessed:
- Path traversal via other query parameters (if additional endpoints exist)
- Other file-read endpoints with similar patterns
- Symbolic link following or race conditions on the same endpoint (different attack mechanism)
- Denial of service via repeated traversal requests (different impact class)

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "reviewer"
subsystem = "web-page"
route_id = "file_endpoint_path_traversal"
weakness = "path-traversal"
record_kind = "single_path"
path = ["GET /file", "parseRequest", "sendFile", "readFile(join(publicDir, name))"]
sink = "readFile"
sink_role = "file_access"
impact_class = "information_disclosure"
route_family = "file_read_endpoint"
material_effect = "read_arbitrary_files"
target_functions = ["index.js:sendFile:27-36", "index.js:parseRequest:8-14"]
scope.trust_boundary = "http_request"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "query_parameter_name"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = ["path_traversal_sequence"]
defense_tags = []
negative_claim.claim_kind = "not_exploitable_under_scope"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["subsumption_of_c1"]
rules_out = ["C2 is true typed subsumption of C1: both exploit the same path.join() vulnerability at the same sink with the same attacker control; the sole difference is target file, which is a variant of C1 rather than a distinct route"]
does_not_rule_out = ["path traversal via C1 remains viable", "other file-read endpoints or endpoints with different traversal mechanisms", "multi-stage attacks combining path traversal with other bugs"]
assumptions = ["C1 vulnerability (path traversal at readFile sink) is confirmed", "subsumption is defined as same root cause + same sink + same attacker control + different target only"]
mechanism_brief = "same path.join() vulnerability as C1, targeting different file class (system files vs source code)"
why_failed_brief = "subsumption: C1 already covers the path traversal; C2 applies the same exploit to a different file target"
confidence = "high"

[[sanitizer_guarantees]]
kind = "no_guard"
source = "index.js:sendFile:29"
guarantee = "no path validation guard between query parameter and readFile sink; subsumption by C1"

[[blockers]]
kind = "subsumption"
source = "C1:path_traversal_source_disclosure"
guarantee = "C2 is subsumed by C1; the underlying path traversal vulnerability covers both source files and system files as target variants"
```
