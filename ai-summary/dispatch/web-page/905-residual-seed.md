# Residual escalation D905: sendfile_path_traversal

**Subsystem**: web-page
**Record Kind**: residual_escalation (deeper re-investigation of a near-miss)
**Re-investigates**: ai-summary/fail/web-page/905-path-blocked.md

## Primary Question (escalated budget — confirm or refute exactly this)

sendfile_path_traversal

A prior hypothesis ruled out the narrow route but left this specific question
open for lack of source-read budget. Investigate exactly this lead with the
escalated budget; do not merely re-derive the original NOT_VIABLE. Resolve the
named symbols below to a concrete yes/no.

## Suggested Path

1. `index.js::sendGreeting`
2. `external::end`

## Target Set

- `index.js::sendGreeting`
- `external::end`

```toml-index
schema = 1
verdict = "DISPATCH_SEED"
failed_at = "dispatch"
subsystem = "web-page"
route_id = "codeql:c82617544f840ac081294c95"
weakness = "http_response_write"
record_kind = "residual_escalation"
path = ["index.js::sendGreeting", "external::end"]
sink = "external::end"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "re-investigate residual lead"
target_functions = ["index.js::sendGreeting", "external::end"]
scope.trust_boundary = "http_response"
scope.protocol_phase = "response_generation"
scope.auth_state = "unauthenticated"
scope.attacker_control = "none"
scope.parser_state = "post_parse"
scope.size_class = "bounded_constant"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = []
residual_question = "sendfile_path_traversal"
mechanism_brief = "residual re-investigation: sendfile_path_traversal"
why_failed_brief = "residual escalation seed; not adjudicated"
confidence = "medium"
```
