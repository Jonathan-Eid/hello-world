# F902: SendFile path traversal (duplicate of prior VIABLE)

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/902-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: NOT_VIABLE
**Failed At**: reviewer
**Reviewed by**: claude-haiku-4-5

## Trace Summary

The batch re-analyzes the sendFile path traversal route: `index.js::requestListener` → `index.js::sendFile`.

Source trace (index.js):
- **Line 12**: `name: searchParams.get("name")` — attacker-controlled query parameter
- **Line 29**: `const body = await readFile(join(publicDir, name))` — direct join without path containment
- **Line 6**: `publicDir = join(process.cwd(), "public")` — static directory root
- **Line 33-34**: Catch block handles errors only, not a security gate

The vulnerability exists: an attacker can supply `name=../../../etc/passwd` to read files outside `public/`.

## Why It Failed

This candidate is an exact duplicate of prior VIABLE investigation [1], which already evaluated this same route with high confidence:
- Prior finding: VIABLE path traversal confirmed
- Prior scope: `http_untrusted/request_parsing/unauthenticated/http_query_parameter/url_decoded`
- Prior conclusion: source trace confirms no path containment check at line 29

The current batch explored 5 potential variant mechanisms (directory-traversal, symlinks, DoS, TOCTOU, null-byte injection) and determined none are new distinct vulnerabilities beyond the already-documented path traversal.

## What This Rules Out

- **New variant findings**: The systematic search for distinct mechanisms on this route found none. Directory traversal via `../` is already covered. Symlink-based escape is a variant of the same root cause (missing path containment). DoS, TOCTOU, and null-byte injection do not apply to this route.

## What This Does Not Rule Out

- **Alternative entry points**: Other HTTP routes or handlers may have path traversal variants not covered by prior work.
- **Severity or exploit posture changes**: This verdict does not assess whether the prior VIABLE finding's severity or exploitability has changed.

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "reviewer"
subsystem = "web-page"
route_id = "codeql:95ff4f25043996f43a1914b2"
weakness = "path_traversal"
record_kind = "single_path"
path = ["index.js::requestListener", "index.js::sendFile"]
sink = "index.js::sendFile"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index.js::sendFile"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.claim_kind = "duplicate_prior_viable"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["candidate_subsumed_by_prior_viable_investigation"]
rules_out = ["path_traversal_on_this_route_already_found_viable_in_prior_investigation_1_with_high_confidence"]
does_not_rule_out = ["path_traversal_variants_on_other_routes_or_entry_points"]
assumptions = ["prior investigation [1] verdict and confidence assessment is still valid and current-source-applicable"]
mechanism_brief = "Query parameter name flows to readFile(join(publicDir, name)) without path containment check; exact duplicate of prior VIABLE route [1]"
why_failed_brief = "Candidate is subsumed by prior VIABLE investigation [1] which already determined this route is vulnerable to path traversal with high confidence; batch systematic search for variant mechanisms found none new"
confidence = "high"

[[sanitizer_guarantees]]
kind = "prior_verdict"
source = "prior investigation [1]"
guarantee = "prior investigation found this route VIABLE for path traversal; source trace confirmed no path containment check at line 29"

[[blockers]]
kind = "duplicate_prior_record"
source = "prior investigation [1]"
guarantee = "this candidate is an exact duplicate of an existing VIABLE finding; no new distinct vulnerability discovered in variant mechanism search"
```
