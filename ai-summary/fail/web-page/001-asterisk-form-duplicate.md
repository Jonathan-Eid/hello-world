# F001: Asterisk-form URL constructor duplicate

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/900-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: NOT_VIABLE
**Failed At**: reviewer
**Reviewed by**: claude-haiku-4-5

## Trace Summary

Source trace confirms the candidate's mechanism:
- Line 6: `const { pathname } = new URL(rawUrl, "http://localhost");` called without try/catch
- Line 23: `parseRequest(request.url)` receives attacker-controlled HTTP request target
- No input validation or error handling guards the URL constructor

The mechanism is accurate: asterisk-form (`*`) or authority-form (`example.com:port`) HTTP request-target forms trigger unhandled TypeError in the URL constructor.

## Why It Failed

This candidate is an **exact typed duplicate** of a prior VIABLE reviewed finding:

**Prior Record**: codeql:1632c2a743acc8a6af077193
- **Verdict**: VIABLE (confidence: high)
- **Path**: index::requestListener; index::parseRequest
- **Scope**: http_request_boundary, request_parsing, unauthenticated, http_request_target_form
- **Mechanism**: asterisk-form input reaches new URL() constructor without defensive guard
- **Blocked by**: no defensive guard prevents asterisk-form input from reaching URL constructor

**Current Candidate C1**:
- Same target function: parseRequest line 6
- Same mechanism: asterisk-form causes unhandled TypeError
- Same scope: http_request_boundary, unauthenticated, attacker-controlled request.url
- Same impact: DoS via unhandled exception
- **Only difference**: route_id differs (CodeQL re-analysis or sweep parameter variation)

The prior record already captures this exact typed route: asterisk-form input → parseRequest → unhandled TypeError in URL constructor.

## What This Rules Out

Exact typed mechanism: asterisk-form or authority-form HTTP request-target reaching unhandled URL() constructor in parseRequest.

## What This Does Not Rule Out

Variants are ruled out:
- Different request-target forms that don't trigger URL constructor TypeError (are still ruled out by the prior record)
- Different entry points into parseRequest (same function, same mechanism)

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "reviewer"
subsystem = "web-page"
route_id = "codeql:6f339d4b9346de62b2b7b6d4"
weakness = "response_content_build"
record_kind = "single_path"
path = ["index.js::requestListener", "index.js::buildGreeting"]
sink = "index.js::buildGreeting"
sink_role = "response_content_build"
impact_class = "denial_of_service"
route_family = "response_content_build"
material_effect = "server crash/unavailability on asterisk or authority form request"
target_functions = ["index.js:parseRequest:6", "index.js:requestListener:23"]
scope.trust_boundary = "http_boundary"
scope.protocol_phase = "response_generation"
scope.auth_state = "unauthenticated"
scope.attacker_control = "request_url"
scope.parser_state = "normalized_by_parseRequest"
scope.size_class = "fixed_hardcoded_strings"
input_shape_tags = []
defense_tags = []
negative_claim.claim_kind = "not_exploitable_under_scope"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["exact_typed_duplicate_of_viable_prior_record"]
rules_out = ["asterisk-form input to URL constructor already reviewed as VIABLE under prior record codeql:1632c2a743acc8a6af077193; exact mechanism, same target function, same scope"]
does_not_rule_out = ["other variants with different mechanisms or different scope boundaries remain unassessed"]
assumptions = ["source-backed assumption: asterisk-form and authority-form are valid HTTP/1.1 request-target forms"]
mechanism_brief = "asterisk or authority form request-target causes unhandled TypeError in URL constructor"
why_failed_brief = "exact typed duplicate of prior VIABLE finding with same mechanism (asterisk-form to URL constructor), same target function (parseRequest), same scope (http_boundary, unauthenticated, request_url)"
confidence = "high"

[[sanitizer_guarantees]]
kind = "none"
source = "prior_record"
guarantee = "prior VIABLE record codeql:1632c2a743acc8a6af077193 already establishes this exact mechanism is viable"

[[blockers]]
kind = "duplicate"
source = "codeql:1632c2a743acc8a6af077193"
guarantee = "exact typed duplicate of VIABLE prior record; no new evidence or scope variant distinguishes this candidate"
```
