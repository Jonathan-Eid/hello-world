# Residual escalation D901: alternative_code_paths

**Subsystem**: web-page
**Record Kind**: residual_escalation (deeper re-investigation of a near-miss)
**Re-investigates**: ai-summary/fail/web-page/003-path-blocked.md

## Primary Question (escalated budget — confirm or refute exactly this)

alternative_code_paths

A prior hypothesis ruled out the narrow route but left this specific question
open for lack of source-read budget. Investigate exactly this lead with the
escalated budget; do not merely re-derive the original NOT_VIABLE. Resolve the
named symbols below to a concrete yes/no.

## Suggested Path

1. `requestListener`
2. `sendFile`

## Target Set

- `requestListener`
- `sendFile`

```toml-index
schema = 1
verdict = "DISPATCH_SEED"
failed_at = "dispatch"
subsystem = "web-page"
route_id = "codeql:5a7daccb1f782610fd034e74"
weakness = "fs_read"
record_kind = "residual_escalation"
path = ["requestListener", "sendFile"]
sink = "sendFile"
sink_role = "fs_read"
impact_class = ""
route_family = "fs_read"
material_effect = "re-investigate residual lead"
target_functions = ["requestListener", "sendFile"]
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
residual_question = "alternative_code_paths"
mechanism_brief = "residual re-investigation: alternative_code_paths"
why_failed_brief = "residual escalation seed; not adjudicated"
confidence = "medium"
```
