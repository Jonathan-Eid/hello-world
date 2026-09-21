# F908: Path blocked: requestListener entry point for path traversal already covered

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/908-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`requestListener -> sendFile` via `parseRequest`

## Blocker

The dispatch seed's route (`codeql:111472ce8048392f42cae643`) for path traversal in sendFile is already adjudicated as VIABLE via the parseRequest→sendFile path. Source inspection confirms that requestListener is a transparent wrapper around parseRequest with no additional security logic: it calls parseRequest (line 39), receives the parsed route object, and directly delegates to sendFile (line 41) if the route is "file". No validation or sanitization occurs between request parsing and the sendFile delegation. The vulnerability (user-supplied `name` parameter flowing directly to `path.join(publicDir, name)` at line 29) is identical across both entry points.

## Evidence

- `index.js:38-44` - requestListener receives request, calls parseRequest, then conditionally calls sendFile with parsed.name
- `index.js:8-14` - parseRequest extracts name from query parameters with no validation
- `index.js:27-36` - sendFile accepts name and calls readFile(join(publicDir, name)) with no bounds checking

## Negative Scope

- Rules out: path_traversal_variant_on_requestListener_entry_point with distinct mechanism; this dispatch point is a transparent wrapper reachable from the same underlying vulnerability already found VIABLE on parseRequest→sendFile route
- Does not rule out: other entry points to sendFile; sibling sinks on different routes; resource exhaustion or distinct failure modes beyond information_disclosure scope of this dispatch

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:111472ce8048392f42cae643"
weakness = "http_response_write"
record_kind = "single_path"
path = ["index::requestListener", "index::sendFile"]
sink = "index::sendFile"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index::sendFile"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unbounded"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = ["path_traversal_variant_on_this_entry_point_with_distinct_mechanism"]
rules_out = ["path_traversal via requestListener entry point with distinct mechanism"]
does_not_rule_out = ["other entry points; resource exhaustion via large file read"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "Path traversal via name query parameter, identical to parseRequest→sendFile route already adjudicated VIABLE"
why_failed_brief = "Same vulnerability route already found VIABLE via parseRequest entry point; requestListener is transparent wrapper with no added security logic"
confidence = "high"

[[sanitizer_guarantees]]
kind = "checked_guard"
guarantee = "requestListener applies no sanitization, validation, or security check beyond what parseRequest provides"

[[blockers]]
kind = "duplicate_route"
guarantee = "Identical path traversal vulnerability already found VIABLE on same route_id via parseRequest→sendFile; requestListener is transparent wrapper reachable from same underlying parseRequest flow"
```
