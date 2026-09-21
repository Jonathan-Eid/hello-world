# F909: Path blocked: sendFile HTTP response write

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/909-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index::sendFile → index::sendFile::end` (HTTP response write of file content)

## Blocker

The path-traversal vulnerability on this route (attacker-controlled `name` parameter used in `join(publicDir, name)` with no containment check) is already documented and adjudicated as VIABLE in published record R001-path-traversal-sendfile.md. Source review confirms no invariants (normalization, containment, traversal guards) prevent directory traversal at line 29 of index.js. No distinct vulnerability mechanism independent of path traversal exists on this sink. Per hypothesis procedure: do not re-report known VIABLE findings.

## Evidence

- `index.js:29` - `join(publicDir, name)` constructs path with no boundary validation  
- `index.js:29` - No rejection of `..` sequences; path.join normalizes but does not prevent traversal  
- `index.js:29-32` - No pre-read containment check (realpath, within-bounds assertion)  
- Prior record: path_traversal mechanism already VIABLE on identical route; attempts to identify distinct mechanisms (R001, prior investigations [2] and [4]) found none

## Negative Scope

- Rules out: New distinct mechanism on sendFile sink  
- Does not rule out: Variants of path_traversal with different input shapes or alternative entry points (parseRequest, requestListener) if not yet investigated under distinct scope

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:712aeaa05e0d555760d482bb"
weakness = "information-disclosure"
record_kind = "area_seed"
path = ["index::sendFile", "index::sendFile::end"]
sink = "index::sendFile::end"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index::sendFile"]
scope.trust_boundary = "unknown"
scope.protocol_phase = "unknown"
scope.auth_state = "unknown"
scope.attacker_control = "unknown"
scope.parser_state = "unknown"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = ["distinct_mechanism_on_sendFile_sink"]
does_not_rule_out = ["parseRequest_entry_variants", "requestListener_entry_variants"]
assumptions = ["path_traversal mechanism already confirmed VIABLE on this route via R001", "prior investigations [2] and [4] identified no additional distinct mechanisms despite source review"]
mechanism_brief = "sendFile constructs file path from untrusted HTTP parameter with no containment checks; path traversal via .. sequences reaches arbitrary files"
why_failed_brief = "mechanism already VIABLE and documented; no distinct mechanism found; per procedure, not re-reporting same vulnerability"
confidence = "high"

[[sanitizer_guarantees]]
kind = "not_present"
guarantee = "no containment check, traversal guard, or validation present on joined path"

[[blockers]]
kind = "duplicate_viable_finding"
guarantee = "path_traversal on this route already adjudicated VIABLE in R001-path-traversal-sendfile.md; source-confirmed no additional mechanism exists"
```
