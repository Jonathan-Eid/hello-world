# R001: Unhandled TypeError on asterisk-form HTTP request-target

**Date**: 2026-09-21
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/006-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: VIABLE
**Severity**: Medium
**Reviewed by**: claude-haiku-4-5

## Trace Summary

The `parseRequest` function at line 6 directly calls `new URL(rawUrl, "http://localhost")` without try-catch or input validation. The `requestListener` at line 23 passes `request.url` directly to `parseRequest` without error handling. When an HTTP OPTIONS request with asterisk-form request-target (`OPTIONS * HTTP/1.1`) arrives, Node.js HTTP module preserves this as `request.url = "*"`. The `new URL()` constructor throws `TypeError: Invalid URL` for the string `"*"`, and this exception propagates uncaught through the call stack, crashing the process.

## Findings

**Mechanism**: Unhandled TypeError from URL constructor on RFC 7230-compliant asterisk-form request-target.

**Exploitability**: An attacker can send a single HTTP OPTIONS request with asterisk-form (e.g., `OPTIONS * HTTP/1.1`) to trigger process termination.

**Impact**: Denial of Service — the service crashes and must be manually restarted.

**Likelihood**: High — asterisk-form is explicitly permitted by HTTP specification for OPTIONS requests, and Node.js HTTP module passes it through unchanged.

## PoC Guidance

**Test file**: Create a test file `test-asterisk-form.js` or append to existing tests.

**Setup**: 
- Start the service on a local port
- Use the `node:http` module to construct a raw HTTP request

**Steps**:
1. Create raw HTTP request: `OPTIONS * HTTP/1.1\r\nHost: localhost:3000\r\n\r\n`
2. Send this request to the running service
3. Observe process termination (exit code non-zero, stderr shows `TypeError: Invalid URL`)

**Assertion**: 
- Assert that the process exits with error status
- Assert stderr contains `TypeError: Invalid URL`

```toml-index
schema = 1
verdict = "VIABLE"
failed_at = "reviewer"
subsystem = "web-page"
route_id = "codeql:1632c2a743acc8a6af077193"
weakness = "request_url_parse"
record_kind = "single_path"
path = ["index::requestListener", "index::parseRequest"]
sink = "index::parseRequest"
sink_role = "request_url_parse"
impact_class = "denial_of_service"
route_family = "request_url_parse"
material_effect = "request_url_parse"
target_functions = ["index.js:parseRequest", "index.js:requestListener"]
scope.trust_boundary = "http_request_boundary"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "http_request_target_form"
scope.parser_state = "raw_request_target"
scope.size_class = "single_request"
input_shape_tags = ["asterisk_form_request_target"]
defense_tags = []
negative_claim.claim_kind = "viable_candidate_not_blocked"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["candidate_not_blocked_after_source_trace"]
rules_out = ["source trace confirms no input validation or error handling guards the URL constructor call in the request parsing path"]
does_not_rule_out = ["other malformed request-targets may also cause unhandled exceptions", "other RFC 7230-compliant request forms may be similarly vulnerable"]
assumptions = ["Node.js HTTP module preserves asterisk-form in request.url property", "new URL() constructor throws TypeError for asterisk string as per ECMAScript URL spec", "uncaught exceptions in requestListener callback terminate the process"]
mechanism_brief = "Asterisk-form request-target from HTTP OPTIONS request reaches new URL() constructor without validation or try-catch, causing unhandled TypeError"
why_failed_brief = "viable; real vulnerability confirmed by source trace"
confidence = "high"

[[sanitizer_guarantees]]
kind = "missing_guard"
source = "index.js:parseRequest"
guarantee = "no input validation before URL constructor call"

[[sanitizer_guarantees]]
kind = "missing_guard"
source = "index.js:requestListener"
guarantee = "no error handling around parseRequest call"

[[blockers]]
kind = "not_found"
source = "index.js:5-27"
guarantee = "no defensive guard prevents asterisk-form input from reaching new URL() constructor"
```

---

## PoC Attempt

**Result**: POC_FAIL
**Date**: 2026-09-21
**PoC by**: claude-haiku-4-5, default
**Target Test File**: test-asterisk-form.js
**Test Language**: JavaScript

### Failure Reason

The hypothesis assumes that the ECMAScript URL constructor throws a `TypeError: Invalid URL` when called with the asterisk string. However, testing in Node.js 22.23.2 reveals that `new URL("*", "http://localhost")` does NOT throw an error. Instead, the URL constructor successfully parses the asterisk as a path component, resulting in a URL with `pathname: "/*"`.

The Node.js HTTP module correctly extracts and passes the asterisk-form request-target as `request.url = "*"` to the requestListener callback. When the service calls `parseRequest("*")`, the URL constructor is invoked with this value, but it succeeds rather than throwing, returning a URL object with the expected pathname that would be processed normally.

### Blockers Encountered

1. **URL Constructor Behavior**: The fundamental assumption of the hypothesis — that `new URL("*", "http://localhost")` throws a TypeError — is not valid in Node.js 22.23.2. The URL spec and Node.js implementation treat the asterisk as a valid path component.

2. **No Process Crash**: As a result, the service does not crash when receiving the asterisk-form OPTIONS request. The request is processed successfully, and the service continues running without error.

### Code Attempted

```javascript
import { spawn } from "node:child_process";
import { createConnection } from "node:net";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function testAsteriskFormCrash() {
  return new Promise((resolve, reject) => {
    const port = 9000 + Math.floor(Math.random() * 1000);
    let stderr = "";
    let stdout = "";
    let exitCode = null;

    console.log(`[TEST] Starting service on port ${port}...`);

    const service = spawn("node", [__dirname + "/index.js"], {
      env: { ...process.env, PORT: port },
      stdio: ["ignore", "pipe", "pipe"],
    });

    service.stdout.on("data", (data) => {
      const msg = data.toString();
      stdout += msg;
      console.log("[SERVICE_STDOUT]", msg);
    });

    service.stderr.on("data", (data) => {
      const msg = data.toString();
      stderr += msg;
      console.log("[SERVICE_STDERR]", msg);
    });

    service.on("exit", (code) => {
      exitCode = code;
    });

    setTimeout(() => {
      console.log(`[TEST] Connecting to localhost:${port}...`);
      const socket = createConnection({ port, host: "localhost" });

      socket.on("connect", () => {
        console.log("[TEST] Connected! Sending asterisk-form request...");
        const asteriskRequest =
          "OPTIONS * HTTP/1.1\r\n" +
          `Host: localhost:${port}\r\n` +
          "Connection: close\r\n\r\n";

        console.log("[TEST] Request to send:");
        console.log(JSON.stringify(asteriskRequest));

        socket.write(asteriskRequest);
      });

      socket.on("error", (err) => {
        console.log("[TEST] Socket error:", err.message);
      });

      socket.on("end", () => {
        console.log("[TEST] Socket end");
      });

      socket.on("close", () => {
        console.log("[TEST] Socket closed");
        setTimeout(() => {
          console.log("[TEST] Killing service...");
          service.kill("SIGKILL");

          const didCrash = exitCode !== 0 && exitCode !== null;
          const hasTypeError = stderr.includes("TypeError: Invalid URL");

          console.log("Test Results:");
          console.log("  Exit code:", exitCode);
          console.log("  Process crashed:", didCrash);
          console.log("  TypeError in stderr:", hasTypeError);
          console.log("\nStderr output:");
          console.log(stderr || "(empty)");

          if (didCrash && hasTypeError) {
            console.log("\n✓ Test PASSED - Process crashed with TypeError: Invalid URL");
            resolve(true);
          } else {
            reject(
              new Error(
                `Expected crash with TypeError. Got - Crashed: ${didCrash}, TypeError: ${hasTypeError}`
              )
            );
          }
        }, 200);
      });

      setTimeout(() => {
        console.log("[TEST] Socket connection timeout");
        socket.destroy();
      }, 3000);
    }, 1500);
  });
}

testAsteriskFormCrash()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error("Test error:", err.message);
    process.exit(1);
  });
```

### Test Output

```
[TEST] Starting service on port 9605...
[SERVICE_STDOUT] Hello-world fixture listening on http://localhost:9605

[TEST] Connecting to localhost:9605...
[TEST] Connected! Sending asterisk-form request...
[TEST] Request to send:
"OPTIONS * HTTP/1.1\r\nHost: localhost:9605\r\nConnection: close\r\n\r\n"
[SERVICE_STDOUT] [SERVER] Received request
[SERVICE_STDOUT] [SERVER] request.url: "*"
[SERVER] request.method: OPTIONS

[TEST] Socket connection timeout
[TEST] Socket closed
[TEST] Killing service...
Test Results:
  Exit code: null
  Process crashed: false
  TypeError in stderr: false
```

The test successfully sends an asterisk-form HTTP request. The Node.js HTTP module correctly parses it and calls the requestListener with `request.url = "*"`. However, the service does NOT crash because the URL constructor successfully parses the asterisk as a path component rather than throwing an error.

Verification of URL constructor behavior:
```javascript
node -e "const url = new URL('*', 'http://localhost'); console.log('URL:', url.toString()); console.log('pathname:', url.pathname);"
// Output:
// URL: http://localhost/*
// pathname: /*
```

The asterisk is parsed as a valid path, not as an invalid input.

