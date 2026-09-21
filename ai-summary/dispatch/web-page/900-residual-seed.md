# Residual escalation D900: prior VIABLE path traversal finding on parseRequest→sendFile (already ...

**Subsystem**: web-page
**Record Kind**: residual_escalation (deeper re-investigation of a near-miss)
**Re-investigates**: ai-summary/fail/web-page/002-path-blocked.md

## Primary Question (escalated budget — confirm or refute exactly this)

prior VIABLE path traversal finding on parseRequest→sendFile (already reviewed/confirmed)

A prior hypothesis ruled out the narrow route but left this specific question
open for lack of source-read budget. Investigate exactly this lead with the
escalated budget; do not merely re-derive the original NOT_VIABLE. Resolve the
named symbols below to a concrete yes/no.

## Suggested Path

1. `index::sendFile`
2. `http::writeHead`

## Target Set

- `index::sendFile`
- `http::writeHead`

```toml-index
schema = 1
verdict = "DISPATCH_SEED"
failed_at = "dispatch"
subsystem = "web-page"
route_id = "codeql:383df8b1224ab6a122806546"
weakness = "response_emission"
record_kind = "residual_escalation"
path = ["index::sendFile", "http::writeHead"]
sink = "http::writeHead"
sink_role = "response_emission"
impact_class = ""
route_family = "response_emission"
material_effect = "re-investigate residual lead"
target_functions = ["index::sendFile", "http::writeHead"]
scope.trust_boundary = "http_untrusted"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_query_parameter"
scope.parser_state = "url_decoded"
scope.size_class = "filesystem_limited"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = []
residual_question = "prior VIABLE path traversal finding on parseRequest→sendFile (already reviewed/confirmed)"
mechanism_brief = "residual re-investigation: prior VIABLE path traversal finding on parseRequest→sendFile (already ..."
why_failed_brief = "residual escalation seed; not adjudicated"
confidence = "medium"
```
