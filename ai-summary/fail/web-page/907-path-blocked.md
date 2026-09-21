# F907: Path blocked: sendFile filesystem read route

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/907-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index::sendFile → fs::readFile`

## Blocker

The path_traversal vulnerability on this route is already identified and adjudicated as VIABLE in prior investigation. No distinct vulnerability mechanism—different failure mode, input shape variant, or sibling sink—survives source trace. The unsanitized `name` parameter allows `../` traversal (already VIABLE); no alternative attack vector discovered.

## Evidence

- `index.js:12` - Query parameter `name` extracted without validation and passed to `sendFile`
- `index.js:29` - Path joined via `join(publicDir, name)` with no escape prevention
- `index.js:27-36` - `sendFile` passes joined path directly to `readFile`; any filesystem error returns generic "Not found" (no distinct information disclosure)

## Negative Scope

- Rules out: No new candidate mechanism on `sendFile` for attacker-controlled `name` parameter
- Does not rule out: Distinct vulnerabilities on other routes or sinks not covered by prior investigation

```toml-index
schema = 1
verdict = "NOT_VIABLE"
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
target_functions = ["index::sendFile"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["path_traversal_already_viable"]
rules_out = ["distinct_vulnerability_on_sendFile_fs_readFile_route"]
does_not_rule_out = ["other_routes", "other_sinks"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "Query parameter joined directly into filesystem path without validation; vulnerability already identified as VIABLE in prior investigation"
why_failed_brief = "path_traversal already adjudicated VIABLE; no distinct mechanism found; per instructions, do not re-report identical vulnerability"
confidence = "high"

[[sanitizer_guarantees]]
kind = "prior_viable_finding"
guarantee = "path_traversal on this exact route already found VIABLE with high confidence in prior investigation"

[[blockers]]
kind = "duplicate_prior_finding"
guarantee = "no new distinct vulnerability mechanism found; path_traversal mechanism already covered by prior VIABLE investigation"
```
