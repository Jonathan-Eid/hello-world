# Residual escalation D902: path_traversal_variants_on_other_routes_or_entry_points

**Subsystem**: web-page
**Record Kind**: residual_escalation (deeper re-investigation of a near-miss)
**Re-investigates**: ai-summary/fail/web-page/F902-sendfile-duplicate.md

## Primary Question (escalated budget — confirm or refute exactly this)

path_traversal_variants_on_other_routes_or_entry_points

A prior hypothesis ruled out the narrow route but left this specific question
open for lack of source-read budget. Investigate exactly this lead with the
escalated budget; do not merely re-derive the original NOT_VIABLE. Resolve the
named symbols below to a concrete yes/no.

## Suggested Path

1. `index.js::requestListener`
2. `index.js::sendFile`

## Target Set

- `index.js::requestListener`
- `index.js::sendFile`

```toml-index
schema = 1
verdict = "DISPATCH_SEED"
failed_at = "dispatch"
subsystem = "web-page"
route_id = "codeql:95ff4f25043996f43a1914b2"
weakness = "http_response_write"
record_kind = "residual_escalation"
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
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = []
residual_question = "path_traversal_variants_on_other_routes_or_entry_points"
mechanism_brief = "residual re-investigation: path_traversal_variants_on_other_routes_or_entry_points"
why_failed_brief = "residual escalation seed; not adjudicated"
confidence = "medium"
```
