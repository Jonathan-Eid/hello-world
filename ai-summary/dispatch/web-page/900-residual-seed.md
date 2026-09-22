# Residual escalation D900: path traversal via C1 remains viable

**Subsystem**: web-page
**Record Kind**: residual_escalation (deeper re-investigation of a near-miss)
**Re-investigates**: ai-summary/fail/web-page/F001-path-traversal-system-files.md

## Primary Question (escalated budget — confirm or refute exactly this)

path traversal via C1 remains viable

A prior hypothesis ruled out the narrow route but left this specific question
open for lack of source-read budget. Investigate exactly this lead with the
escalated budget; do not merely re-derive the original NOT_VIABLE. Resolve the
named symbols below to a concrete yes/no.

## Suggested Path

1. `GET /file`
2. `readFile(join(publicDir, name))`

## Target Set

- `GET /file`
- `parseRequest`
- `sendFile`
- `readFile(join(publicDir, name))`

```toml-index
schema = 1
verdict = "DISPATCH_SEED"
failed_at = "dispatch"
subsystem = "web-page"
route_id = "file_endpoint_path_traversal"
weakness = "file_access"
record_kind = "residual_escalation"
path = ["GET /file", "parseRequest", "sendFile", "readFile(join(publicDir, name))"]
sink = "readFile(join(publicDir, name))"
sink_role = "file_access"
impact_class = "information_disclosure"
route_family = "file_access"
material_effect = "re-investigate residual lead"
target_functions = ["GET /file", "parseRequest", "sendFile", "readFile(join(publicDir, name))"]
scope.trust_boundary = "http_request"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "query_parameter_name"
scope.parser_state = "url_decoded"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = []
residual_question = "path traversal via C1 remains viable"
mechanism_brief = "residual re-investigation: path traversal via C1 remains viable"
why_failed_brief = "residual escalation seed; not adjudicated"
confidence = "medium"
```
