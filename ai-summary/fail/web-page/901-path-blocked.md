# F901: Path blocked: no alternative code paths exist

**Subsystem**: web-page
**Source Dispatch Seed**: /app/workspace/ai-summary/dispatch/web-page/901-residual-seed.md
**Verdict**: NOT_VIABLE

## Path Checked

`requestListener -> sendFile` (investigating whether alternative code paths bypass the known vulnerability)

## Blocker

The dispatch seed asks whether "alternative_code_paths" exist from `requestListener` to `sendFile` beyond the single path already confirmed VIABLE. Source trace confirms exactly one code path: `requestListener` line 41 is the sole invocation of `sendFile` in the codebase, reached only when `parseRequest` line 12 matches `pathname === "/file"` (strict equality). No conditional branches, callbacks, or sibling routes create alternative control flow. The prior VIABLE finding (route_id: codeql:807d154e17582e8b07d5733c) covers the only path that exists.

## Evidence

- `index.js:parseRequest:8-14` - Only source of route object; single match for "file" route at line 12
- `index.js:requestListener:39-41` - Line 41 is sole `sendFile` invocation; no alternative callsites
- Global codebase search confirms no other references to `sendFile` function

## Negative Scope

- Rules out: alternative code paths, sibling `sendFile` invocations, variant control flow to same sink
- Does not rule out: distinct failure modes via different input shapes (already covered by prior VIABLE), other sinks in the codebase

```toml-index
schema = 1
verdict = "NOT_VIABLE"
failed_at = "hypothesis"
subsystem = "web-page"
route_id = "codeql:5a7daccb1f782610fd034e74"
weakness = "fs_read"
record_kind = "single_path"
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
rules_out = ["alternative_code_paths"]
does_not_rule_out = ["prior_viable_finding_remains_valid"]
assumptions = ["no additional assumptions beyond cited source evidence"]
mechanism_brief = "escalated recheck confirms no alternative code paths exist to sendFile from requestListener"
why_failed_brief = "code structure is linear and deterministic; single point of invocation at line 41; prior VIABLE finding covers the only path"
confidence = "high"

[[sanitizer_guarantees]]
kind = "code_structure"
guarantee = "requestListener reaches sendFile via exactly one conditional branch; no alternative paths exist in source"

[[blockers]]
kind = "control_flow_constraint"
guarantee = "sendFile called only once in codebase (line 41), only when parseRequest returns route='file', which only occurs for pathname='/file'"
```
