# F902: Path blocked: requestListener → sendFile (duplicate of existing VIABLE)

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/902-residual-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`index.js::requestListener -> index.js::sendFile`

## Blocker

The dispatch seed's residual question asks whether `requestListener → sendFile` represents a distinct path-traversal variant from the already-VIABLE finding on `parseRequest → sendFile`. Source review confirms no such variant exists. `requestListener` (line 38) is the HTTP entry point that immediately calls `parseRequest` (line 39) to parse the URL, which extracts the `name` parameter from query params (line 12). Control then flows directly to `sendFile` (line 41) with the name parameter. There is no alternate control flow, input source, guard, or encoding step between `requestListener` and `sendFile`. Both paths route through identical parsing and reach the same vulnerable `join(publicDir, name)` at line 29 with no validation. The catch block (line 33) is error handling, not a security boundary. This is a duplicate of the existing VIABLE finding [reference: index.js::parseRequest -> index.js::sendFile].

## Evidence

- `index.js:38-44::requestListener` - HTTP entry point that calls parseRequest and routes to sendFile for "/file" requests
- `index.js:8-14::parseRequest` - Parses URL and extracts name parameter; called inline by requestListener
- `index.js:27-36::sendFile` - Performs `join(publicDir, name)` at line 29 with no path containment check; same sink reached by both paths

## Negative Scope

- Rules out: distinct path-traversal variant on `requestListener → sendFile` not already captured by existing VIABLE on `parseRequest → sendFile`
- Does not rule out: the existing VIABLE finding [reference: index.js::parseRequest -> index.js::sendFile] remains valid and confirmed

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:95ff4f25043996f43a1914b2"
weakness = "http_response_write"
record_kind = "single_path"
path = ["index.js::requestListener", "index.js::sendFile"]
sink = "index.js::sendFile"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "re-investigate residual lead"
target_functions = ["index.js::requestListener", "index.js::sendFile"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["candidate_subsumed_by_prior_viable_investigation"]
rules_out = ["distinct_variant_on_requestListener_entry_point"]
does_not_rule_out = ["existing_VIABLE_finding_parseRequest_sendFile"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "residual escalation investigated: requestListener→sendFile confirmed as duplicate entry point to same vulnerable sendFile sink"
why_failed_brief = "identical input source and sink to already-VIABLE parseRequest→sendFile; no distinct variant mechanism found"
confidence = "high"

[[sanitizer_guarantees]]
kind = "checked_guard"
guarantee = "no distinct guard or variant input path between requestListener and sendFile; both reach identical sink at line 29"

[[blockers]]
kind = "duplicate_existing_viable"
guarantee = "requestListener entry point is nested call to parseRequest; same vulnerability already found VIABLE on parseRequest→sendFile path"
```
