# Residual escalation D908: other_entry_points_to_sendFile

**Subsystem**: web-page
**Record Kind**: residual_escalation (deeper re-investigation of a near-miss)
**Re-investigates**: ai-summary/fail/web-page/912-path-blocked.md

## Primary Question (escalated budget — confirm or refute exactly this)

other_entry_points_to_sendFile

A prior hypothesis ruled out the narrow route but left this specific question
open for lack of source-read budget. Investigate exactly this lead with the
escalated budget; do not merely re-derive the original NOT_VIABLE. Resolve the
named symbols below to a concrete yes/no.

## Suggested Path

1. `index.js::requestListener`
2. `index.js::sendGreeting`

## Target Set

- `index.js::requestListener`
- `index.js::sendGreeting`

```toml-index
schema = 1
verdict = "DISPATCH_SEED"
failed_at = "dispatch"
subsystem = "web-page"
route_id = "codeql:88734216b62a9cd890156edb"
weakness = "http_response_write"
record_kind = "residual_escalation"
path = ["index.js::requestListener", "index.js::sendGreeting"]
sink = "index.js::sendGreeting"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "re-investigate residual lead"
target_functions = ["index.js::requestListener", "index.js::sendGreeting"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "unbounded"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = []
residual_question = "other_entry_points_to_sendFile"
mechanism_brief = "residual re-investigation: other_entry_points_to_sendFile"
why_failed_brief = "residual escalation seed; not adjudicated"
confidence = "medium"
```
