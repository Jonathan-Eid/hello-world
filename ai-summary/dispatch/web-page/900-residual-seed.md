# Residual escalation D900: vulnerabilities_in_parseRequest_URL_constructor

**Subsystem**: web-page
**Record Kind**: residual_escalation (deeper re-investigation of a near-miss)
**Re-investigates**: ai-summary/fail/web-page/007-path-blocked.md

## Primary Question (escalated budget — confirm or refute exactly this)

vulnerabilities_in_parseRequest_URL_constructor

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
route_id = "codeql:6f339d4b9346de62b2b7b6d4"
weakness = "response_content_build"
record_kind = "residual_escalation"
path = ["index.js::requestListener", "index.js::buildGreeting"]
sink = "index.js::buildGreeting"
sink_role = "response_content_build"
impact_class = ""
route_family = "response_content_build"
material_effect = "re-investigate residual lead"
target_functions = ["index.js::requestListener", "index.js::buildGreeting"]
scope.trust_boundary = "http_boundary"
scope.protocol_phase = "response_generation"
scope.auth_state = "unauthenticated"
scope.attacker_control = "request_url"
scope.parser_state = "normalized_by_parseRequest"
scope.size_class = "fixed_hardcoded_strings"
input_shape_tags = []
defense_tags = []
negative_claim.rules_out_codes = []
rules_out = []
does_not_rule_out = []
assumptions = []
residual_question = "vulnerabilities_in_parseRequest_URL_constructor"
mechanism_brief = "residual re-investigation: vulnerabilities_in_parseRequest_URL_constructor"
why_failed_brief = "residual escalation seed; not adjudicated"
confidence = "medium"
```
