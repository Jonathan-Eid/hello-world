# Residual escalation D909: sibling_routes_or_alternative_attack_vectors

**Subsystem**: web-page
**Record Kind**: residual_escalation (deeper re-investigation of a near-miss)
**Re-investigates**: ai-summary/fail/web-page/913-path-blocked.md

## Primary Question (escalated budget — confirm or refute exactly this)

sibling_routes_or_alternative_attack_vectors

A prior hypothesis ruled out the narrow route but left this specific question
open for lack of source-read budget. Investigate exactly this lead with the
escalated budget; do not merely re-derive the original NOT_VIABLE. Resolve the
named symbols below to a concrete yes/no.

## Suggested Path

1. `index.js::sendFile`
2. `response::end`

## Target Set

- `index.js::sendFile`
- `response::end`

```toml-index
schema = 1
verdict = "DISPATCH_SEED"
failed_at = "dispatch"
subsystem = "web-page"
route_id = "codeql:a42ce805d0af41e29becbeb7"
weakness = "http_response_write"
record_kind = "residual_escalation"
path = ["index.js::sendFile", "response::end"]
sink = "response::end"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "re-investigate residual lead"
target_functions = ["index.js::sendFile", "response::end"]
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
residual_question = "sibling_routes_or_alternative_attack_vectors"
mechanism_brief = "residual re-investigation: sibling_routes_or_alternative_attack_vectors"
why_failed_brief = "residual escalation seed; not adjudicated"
confidence = "medium"
```
