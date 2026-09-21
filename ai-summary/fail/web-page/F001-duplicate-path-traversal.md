# F001: Duplicate path traversal via sendFile

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/900-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: NOT_VIABLE
**Failed At**: reviewer
**Reviewed by**: claude-haiku-4-5

## Trace Summary

The candidate describes a path traversal vulnerability in the `/file` route (index.js:sendFile, lines 27-36):
- Line 12: `name` extracted from untrusted query parameter
- Line 29: `join(publicDir, name)` joins without post-join validation
- Line 33-35: catch block provides exception handling only, not path validation
- No path containment check exists

## Why It Failed

This candidate is an exact typed duplicate of prior record `codeql:807d154e17582e8b07d5733c` from prior investigations, which was already reviewed as VIABLE with high confidence. The candidate and the prior record describe:
- The same entry point (query parameter `name` in `/file` route)
- The same target functions (parseRequest and sendFile)
- The same sink (response.writeHead via readFile)
- The same mechanism (unsafe path.join without containment check)
- The same attack vector (HTTP GET request with traversal sequences)
- Identical scope: http_untrusted/request_parsing/unauthenticated/http_query_parameter/url_decoded

The vulnerability has already been discovered, analyzed, and documented. Re-reviewing the identical code path produces no new security insight.

## What This Rules Out

Exact duplicate candidate of prior VIABLE record. No new path variant is involved.

## What This Does Not Rule Out

Distinct path variants or mechanisms not yet discovered in the codebase. Other routes or entry points may have similar vulnerabilities with different scope or preconditions.

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "reviewer"
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
negative_claim.claim_kind = "exact_typed_duplicate"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["candidate_exact_duplicate_of_prior_viable_record"]
rules_out = ["exact duplicate of prior record codeql:807d154e17582e8b07d5733c with verdict=VIABLE confidence=high; no new security assessment needed"]
does_not_rule_out = ["other routes or entry points with similar mechanisms but different scope or trust boundaries"]
assumptions = ["prior record codeql:807d154e17582e8b07d5733c is still valid and represents the current code state"]
mechanism_brief = "path traversal: attacker passes ../../../ sequences in name query parameter; path.join normalizes without containment check; prior record already documents this"
why_failed_brief = "exact typed duplicate of prior VIABLE record; candidate provides no new finding"
confidence = "high"

[[sanitizer_guarantees]]
kind = "not_applicable"
source = "prior_record"
guarantee = "prior record already assessed all guards in sendFile; no new guards found in current source"

[[blockers]]
kind = "duplicate_prior_record"
source = "codeql:807d154e17582e8b07d5733c"
guarantee = "candidate is exact duplicate of existing VIABLE finding; reuse prior analysis"
```
```
