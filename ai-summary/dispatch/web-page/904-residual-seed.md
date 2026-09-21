# Residual escalation D904: other_http_response_sinks

**Subsystem**: web-page
**Record Kind**: residual_escalation (deeper re-investigation of a near-miss)
**Re-investigates**: ai-summary/fail/web-page/904-path-blocked.md

## Primary Question (escalated budget — confirm or refute exactly this)

other_http_response_sinks

A prior hypothesis ruled out the narrow route but left this specific question
open for lack of source-read budget. Investigate exactly this lead with the
escalated budget; do not merely re-derive the original NOT_VIABLE. Resolve the
named symbols below to a concrete yes/no.

## Suggested Path

1. `index.js::sendFile`
2. `external::end`

## Target Set

- `index.js::sendFile`
- `external::end`

```toml-index
schema = 1
verdict = "DISPATCH_SEED"
failed_at = "dispatch"
subsystem = "web-page"
route_id = "codeql:432f0ea511c0cf59bff6c437"
weakness = "http_response_write"
record_kind = "residual_escalation"
path = ["index.js::sendFile", "external::end"]
sink = "external::end"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "re-investigate residual lead"
target_functions = ["index.js::sendFile", "external::end"]
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
residual_question = "other_http_response_sinks"
mechanism_brief = "residual re-investigation: other_http_response_sinks"
why_failed_brief = "residual escalation seed; not adjudicated"
confidence = "medium"
```
