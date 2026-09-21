# F003: Dispatch redundant with prior viable finding

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/003-path-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`requestListener -> sendFile` (fs_read sink)

## Blocker

Prior VIABLE finding (route_id: codeql:807d154e17582e8b07d5733c) already covers the exact path traversal mechanism on this route. Source confirmation shows `sendFile` joins the untrusted HTTP `name` query parameter directly with `publicDir` at line 29 with no path containment validation. The dispatch seed asks whether `sendFile` validates or restricts the path parameter; source confirms it does not. This is identical to the mechanism established in the prior VIABLE finding.

## Evidence

- `index.js:parseRequest:12` - HTTP query parameter `name` extracted without validation
- `index.js:requestListener:41` - `name` passed directly to `sendFile` 
- `index.js:sendFile:29` - `path.join(publicDir, name)` with no containment check
- `index.js:sendFile:33-34` - Error handling is not a security boundary; catches all errors and returns 404

## Negative Scope

- Rules out: new hypothesis on this dispatch route
- Does not rule out: sibling routes, alternative file-handling sinks, or distinct failure modes on different code paths

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:5a7daccb1f782610fd034e74"
weakness = "path traversal"
record_kind = "single_path"
path = ["requestListener", "sendFile"]
sink = "sendFile"
sink_role = "fs_read"
impact_class = ""
route_family = "fs_read"
material_effect = "fs_read"
target_functions = ["sendFile"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = ["new_hypothesis_on_this_route"]
does_not_rule_out = ["sibling_sinks", "alternative_code_paths"]
assumptions = ["prior VIABLE finding's source analysis is authoritative for this route", "no additional distinct vulnerability mechanisms are reachable on the sendFile sink"]
mechanism_brief = "dispatch seed route is duplicate of prior VIABLE finding; identical path traversal mechanism"
why_failed_brief = "redundant with prior VIABLE finding; source-confirmed lack of path validation matches prior conclusion"
confidence = "high"

[[sanitizer_guarantees]]
kind = "checked_absence"
guarantee = "no path containment validation found in sendFile or parseRequest; matches prior finding"

[[blockers]]
kind = "prior_finding_duplicate"
guarantee = "prior VIABLE route covers this exact mechanism; no distinct vulnerability"
```
