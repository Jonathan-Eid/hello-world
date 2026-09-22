# Residual escalation D910: path_traversal_on_normal_sendFile_response_path

**Subsystem**: web-page
**Record Kind**: residual_escalation (deeper re-investigation of a near-miss)
**Re-investigates**: ai-summary/fail/web-page/914-path-blocked.md

## Primary Question (escalated budget — confirm or refute exactly this)

path_traversal_on_normal_sendFile_response_path

A prior hypothesis ruled out the narrow route but left this specific question
open for lack of source-read budget. Investigate exactly this lead with the
escalated budget; do not merely re-derive the original NOT_VIABLE. Resolve the
named symbols below to a concrete yes/no.

## Suggested Path

1. `index::sendFile`
2. `index::sendGreeting`

## Target Set

- `index::sendFile`
- `index::sendGreeting`

```toml-index
schema = 1
verdict = "DISPATCH_SEED"
failed_at = "dispatch"
subsystem = "web-page"
route_id = "codeql:2b1443928168b834498e78bd"
weakness = "http_response_write"
record_kind = "residual_escalation"
path = ["index::sendFile", "index::sendGreeting"]
sink = "index::sendGreeting"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "re-investigate residual lead"
target_functions = ["index::sendFile", "index::sendGreeting"]
scope.trust_boundary = "unknown"
scope.protocol_phase = "http_request_handling"
scope.auth_state = "unauthenticated"
scope.attacker_control = "name_query_parameter"
scope.parser_state = "url_parsed"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = []
residual_question = "path_traversal_on_normal_sendFile_response_path"
mechanism_brief = "residual re-investigation: path_traversal_on_normal_sendFile_response_path"
why_failed_brief = "residual escalation seed; not adjudicated"
confidence = "medium"
```
