# Residual escalation D901: URL_constructor_vulnerabilities_in_parseRequest_path

**Subsystem**: web-page
**Record Kind**: residual_escalation (deeper re-investigation of a near-miss)
**Re-investigates**: ai-summary/fail/web-page/008-path-blocked.md

## Primary Question (escalated budget — confirm or refute exactly this)

URL_constructor_vulnerabilities_in_parseRequest_path

A prior hypothesis ruled out the narrow route but left this specific question
open for lack of source-read budget. Investigate exactly this lead with the
escalated budget; do not merely re-derive the original NOT_VIABLE. Resolve the
named symbols below to a concrete yes/no.

## Suggested Path

1. `index.js::requestListener`
2. `index.js::buildGreeting`

## Target Set

- `index.js::requestListener`
- `index.js::buildGreeting`

```toml-index
schema = 1
verdict = "DISPATCH_SEED"
failed_at = "dispatch"
subsystem = "web-page"
route_id = "codeql:8ae25132dd9cff8c533e1cbe"
weakness = "response_content_construction"
record_kind = "residual_escalation"
path = ["index.js::requestListener", "index.js::buildGreeting"]
sink = "index.js::buildGreeting"
sink_role = "response_content_construction"
impact_class = ""
route_family = "response_content_construction"
material_effect = "re-investigate residual lead"
target_functions = ["index.js::requestListener", "index.js::buildGreeting"]
scope.trust_boundary = "http_request_boundary"
scope.protocol_phase = "response_generation"
scope.auth_state = "unauthenticated"
scope.attacker_control = "request_url"
scope.parser_state = "parsed_pathname"
scope.size_class = "unknown"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = []
residual_question = "URL_constructor_vulnerabilities_in_parseRequest_path"
mechanism_brief = "residual re-investigation: URL_constructor_vulnerabilities_in_parseRequest_path"
why_failed_brief = "residual escalation seed; not adjudicated"
confidence = "medium"
```
