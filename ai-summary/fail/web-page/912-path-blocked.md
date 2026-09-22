# F912: Path blocked: requestListener area seed - sendGreeting and sendFile targets

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/912-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

Area seed with primary path `requestListener → sendGreeting` and target set `sendFile`.

## Blocker

The area seed contains two sibling targets, each blocked by distinct constraints: (1) The sendGreeting path receives only hardcoded route identifiers from parseRequest; no user-controlled data reaches sendGreeting's response writes. (2) The sendFile target, while receiving the attacker-controlled `name` query parameter and passing it directly to `path.join(publicDir, name)` without bounds enforcement, is already covered by a prior VIABLE finding on the identical path-traversal mechanism via `parseRequest → sendFile` (prior investigations [1], [2], [4]). This route entry point (requestListener vs. parseRequest) does not create a distinct vulnerability mechanism.

## Evidence

- `index.js:38-44` - requestListener entry point routes to sendFile or sendGreeting; no additional guards or sanitization between request parsing and sendFile call
- `index.js:8-14` - parseRequest extracts the query parameter `name` without validation and returns it in the route object
- `index.js:27-36` - sendFile receives the name parameter and uses it directly in `join(publicDir, name)` without directory bounds enforcement; this is the same vulnerable operation already found VIABLE on parseRequest→sendFile path
- `index.js:16-24` - sendGreeting receives only hardcoded route strings ("root" or "not-found") and produces fixed response bodies

## Negative Scope

- Rules out: path-traversal via requestListener entry point on this specific typed route (same mechanism already found VIABLE on parseRequest entry point)
- Does not rule out: other entry points, other sinks, or vulnerability variants not yet investigated

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:88734216b62a9cd890156edb"
weakness = "path-traversal"
record_kind = "area_seed"
path = ["index.js::requestListener", "index.js::sendGreeting"]
sink = "index.js::sendGreeting"
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
scope.size_class = "unbounded"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["path_traversal_via_requestListener_entry_identical_to_prior_viable_parseRequest_route"]
rules_out = ["path_traversal_distinct_variant_on_requestListener_entry_point"]
does_not_rule_out = ["other_entry_points_to_sendFile", "vulnerability_variants_with_different_input_shapes"]
assumptions = ["prior VIABLE finding on parseRequest→sendFile path is accurate; requestListener wraps parseRequest without additional security logic; no distinct mechanism exists on this route"]
mechanism_brief = "HTTP request routing to either sendGreeting (fixed response) or sendFile (filesystem read); sendFile parameter flows directly to path.join without bounds"
why_failed_brief = "sendGreeting path blocked: no user-controlled data; sendFile target blocked: exact duplicate of prior VIABLE parseRequest→sendFile finding with no distinct mechanism"
confidence = "high"

[[sanitizer_guarantees]]
kind = "hardcoded_response_data"
guarantee = "sendGreeting path receives only hardcoded route identifiers; no user-controlled data reaches sendGreeting response writes"

[[blockers]]
kind = "prior_viable_duplicate"
guarantee = "sendFile path covered by prior VIABLE finding on identical path-traversal mechanism (parseRequest→sendFile); no distinct failure mode discovered"
```
