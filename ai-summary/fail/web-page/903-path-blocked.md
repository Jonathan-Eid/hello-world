# F903: Path blocked: requestListener to sendFile path traversal

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/903-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index::requestListener -> index::sendFile`

## Blocker

This dispatch route is subsumed by the prior VIABLE finding on the parseRequest→sendFile route (route_id codeql:807d154e17582e8b07d5733c). The requestListener entry point (line 38) is a nested call wrapper around parseRequest: it receives the HTTP request, calls parseRequest at line 39 to extract and parse the `name` query parameter, then conditionally routes to sendFile at line 41. Prior investigation explicitly searched for distinct vulnerability variants on the requestListener entry point and found none—the path_traversal vulnerability exists identically on both routes because both eventually reach the unguarded join at sendFile line 29.

## Evidence

- `index.js::requestListener:38-41` - Receives HTTP request, calls parseRequest, routes to sendFile with parsed.name
- `index.js::parseRequest:8-12` - Extracts name from query parameter (line 12)
- `index.js::sendFile:29` - Joins publicDir with attacker-controlled name parameter without path containment validation
- Prior Investigation [3]: VIABLE path_traversal finding on parseRequest→sendFile route; source confirms no guard exists

## Negative Scope

- Rules out: New distinct path_traversal variant on requestListener entry point (prior variant search found none)
- Does not rule out: Applicability of the prior VIABLE finding; related routes with different entry points

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:111472ce8048392f42cae643"
weakness = "path_traversal"
record_kind = "single_path"
path = ["index::requestListener", "index::sendFile"]
sink = "index::sendFile"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index::requestListener"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["distinct_variant_on_requestListener_entry_point"]
rules_out = ["path_traversal_variant_on_this_entry_point_with_distinct_mechanism"]
does_not_rule_out = ["prior_VIABLE_finding_codeql:807d154e17582e8b07d5733c_remains_valid"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "requestListener is a wrapper entry point around parseRequest; both reach the same unguarded join at sendFile line 29"
why_failed_brief = "Prior VIABLE finding already covers this route; source verification confirms requestListener has no distinct defenses relative to parseRequest entry point"
confidence = "high"

[[sanitizer_guarantees]]
kind = "not_found"
guarantee = "No path containment check guards the join result at sendFile line 29"

[[blockers]]
kind = "duplicate_covered_by_prior_viable"
guarantee = "Prior investigation found VIABLE path_traversal on identical path (parseRequest→sendFile); requestListener is nested wrapper with no additional security logic"
```
