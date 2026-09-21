# Residual escalation D906: other vulnerability classes on web-page subsystem; other endpoints or ...

**Subsystem**: web-page
**Record Kind**: residual_escalation (deeper re-investigation of a near-miss)
**Re-investigates**: ai-summary/fail/web-page/906-duplicate-path-traversal.md

## Primary Question (escalated budget — confirm or refute exactly this)

other vulnerability classes on web-page subsystem; other endpoints or trust boundaries

A prior hypothesis ruled out the narrow route but left this specific question
open for lack of source-read budget. Investigate exactly this lead with the
escalated budget; do not merely re-derive the original NOT_VIABLE. Resolve the
named symbols below to a concrete yes/no.

## Suggested Path

1. `index::sendFile`
2. `fs::readFile`

## Target Set

- `index::sendFile`
- `fs::readFile`

```toml-index
schema = 1
verdict = "DISPATCH_SEED"
failed_at = "dispatch"
subsystem = "web-page"
route_id = "codeql:ba4783688eb4a1dfa64ae1d4"
weakness = "filesystem_read"
record_kind = "residual_escalation"
path = ["index::sendFile", "fs::readFile"]
sink = "fs::readFile"
sink_role = "filesystem_read"
impact_class = "information_disclosure"
route_family = "filesystem_read"
material_effect = "re-investigate residual lead"
target_functions = ["index::sendFile", "fs::readFile"]
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
residual_question = "other vulnerability classes on web-page subsystem; other endpoints or trust boundaries"
mechanism_brief = "residual re-investigation: other vulnerability classes on web-page subsystem; other endpoints or ..."
why_failed_brief = "residual escalation seed; not adjudicated"
confidence = "medium"
```
