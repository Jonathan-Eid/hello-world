# R001: Path traversal in file serving via unsanitized name parameter

**Date**: 2026-09-23
**Subsystem**: web-page
**Source Hypothesis Batch**: /app/workspace/ai-summary/hypothesis/web-page/001-hypothesis-batch.md
**Candidate ID**: C1
**Verdict**: VIABLE
**Severity**: High
**Reviewed by**: claude-haiku-4-5

## Trace Summary

The HTTP service parses incoming requests at `requestListener` (index.js:38), which routes `/file` requests to `sendFile` (index.js:27). The `parseRequest` function (index.js:8) extracts the `name` query parameter via `searchParams.get("name")` with no sanitization (line 12), defaulting to "hello.txt" if missing.

The `sendFile` function then executes `readFile(join(publicDir, name))` at line 29, where `publicDir` is defined as `join(process.cwd(), "public")` at line 6. The `path.join()` method normalizes relative path components, including `..` sequences, without validating that the result remains within the intended `public/` directory boundary.

Source trace confirms:
- Line 6: `publicDir` set to `join(process.cwd(), "public")`
- Line 12: `name` extracted from request with no checks
- Line 29: `join(publicDir, name)` called directly with unsanitized `name`
- Lines 31-32: File content written to HTTP response body
- Lines 33-34: Generic error handling that does not prevent path traversal attempts

Path normalization verified: `join("/app/workspace/worktrees/read/public", "../index.js")` → `/app/workspace/worktrees/read/index.js`, escaping the intended boundary.

## Findings

An unauthenticated HTTP client can read any file accessible to the Node.js process by crafting a GET request to `/file?name=../path/to/file`. 

**Concrete exploitation path**:
- Request: `GET /file?name=../index.js`
- Normalized path: `/app/workspace/worktrees/read/index.js`
- Result: Source code disclosure

No validation check, permission boundary, or OS-level restriction in the code prevents this. The exception handler at lines 33-34 only catches `readFile` failures, not invalid paths. The error response ("Not found") reveals whether a path is readable without confirming it stays within bounds, providing an oracle for file enumeration.

**Impact**: Information disclosure of any file readable by the process, including source code, environment configuration, and potentially sensitive application data.

## PoC Guidance

- **Test file**: Create a test in a new test file or append to existing tests if any exist
- **Setup**: Start the server with `node index.js`, verify the public directory contains `hello.txt`
- **Steps**:
  1. GET `http://localhost:3000/file?name=hello.txt` → should return content of `public/hello.txt`
  2. GET `http://localhost:3000/file?name=../index.js` → should return content of source file (vulnerability)
  3. GET `http://localhost:3000/file?name=../package.json` → should return package.json (vulnerability)
  4. GET `http://localhost:3000/file?name=../../../../etc/passwd` → should attempt to read system file or return 404 with path attempted
- **Assertion**: Verify that requests with `..` components successfully read files outside `public/`, demonstrating the lack of path boundary validation

```toml-index
schema = 1
verdict = "VIABLE"
failed_at = "none"
subsystem = "web-page"
route_id = "codeql:95ff4f25043996f43a1914b2"
weakness = "path_traversal"
record_kind = "single_path"
path = ["index.js::requestListener", "index.js::sendFile"]
sink = "index.js::sendFile"
sink_role = "http_response_write"
impact_class = "information_disclosure"
route_family = "http_response_write"
material_effect = "http_response_write"
target_functions = ["index.js:sendFile:27-36", "index.js:requestListener:38-44", "index.js:parseRequest:8-14"]
scope.trust_boundary = "http_client_unauthenticated"
scope.protocol_phase = "request_parsing"
scope.auth_state = "unauthenticated"
scope.attacker_control = "name_query_parameter"
scope.parser_state = "raw_relative_path"
scope.size_class = "unbounded_string"
input_shape_tags = ["path_traversal_syntax"]
defense_tags = []
negative_claim.claim_kind = "viable_candidate_not_blocked"
negative_claim.conditional = false
negative_claim.rules_out_codes = ["candidate_not_blocked_after_source_trace"]
rules_out = ["no validation check confirms the final path remains within publicDir before readFile", "no permission boundary restricts file access", "exception handler does not prevent path traversal attempts"]
does_not_rule_out = ["bypass attempts using symlinks, URL encoding, or null bytes remain unassessed in detail", "interactions with process permissions and SELinux/AppArmor profiles outside scope"]
assumptions = ["Node.js process inherits standard user/group permissions", "process can read files in parent directories", "path.join() behavior normalizes .. sequences without restricting them"]
mechanism_brief = "HTTP listener routes unsanitized user query parameter directly to path.join() with publicDir; path.join() normalizes relative traversal sequences (..) without validating final path remains within publicDir; readFile reads any file accessible to process; response body leaks file content"
why_failed_brief = "not failed; viable finding confirmed by source trace"
confidence = "high"

[[sanitizer_guarantees]]
kind = "absent"
source = "index.js:29"
guarantee = "no path canonicalization, no realpath() validation, no allowlist check, no directory bounds check before readFile"

[[blockers]]
kind = "not_found"
source = "index.js:27-36"
guarantee = "no blocker found in sendFile function that prevents path traversal"

[[blockers]]
kind = "not_found"
source = "index.js:8-14"
guarantee = "no sanitization of name parameter in parseRequest"
```

---

## PoC Attempt

**Result**: POC_PASS
**Date**: 2026-09-23
**PoC by**: claude-haiku-4-5, default
**Method**: HTTP server with curl requests
**Test Commands**: curl requests to demonstrate path traversal

### Demonstration

The path traversal vulnerability was successfully demonstrated by running the Node.js server on port 3123 and sending HTTP requests with path traversal payloads. Three concrete attacks were executed:

1. **Normal request (baseline)**: `GET /file?name=hello.txt` returned the expected content from `public/hello.txt` with HTTP 200
2. **Path traversal to source code**: `GET /file?name=../index.js` successfully read and returned the entire `index.js` source code with HTTP 200, demonstrating information disclosure of application source
3. **Path traversal to package metadata**: `GET /file?name=../package.json` successfully read and returned the package.json configuration file with HTTP 200

The vulnerability is confirmed: the `name` query parameter is passed directly to `path.join(publicDir, name)` without validation, allowing `../` sequences to escape the intended `public/` directory boundary and read arbitrary files accessible to the Node.js process.

### Test Output

```
=== Test 1: Normal request for hello.txt ===
Hello from the public directory.
status=200

=== Test 2: Path traversal to read index.js ===
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const port = Number(process.env.PORT || 3000);
const publicDir = join(process.cwd(), "public");

function parseRequest(rawUrl) {
  const { pathname, searchParams } = new URL(rawUrl, "http://localhost");

  if (pathname === "/") return { route: "root" };
  if (pathname === "/file") return { route: "file", name: searchParams.get("name") || "hello.txt" };
  return { route: "not-found" };
}

function buildGreeting(route) {
  return route === "root" ? "Hello, world!\n" : "Not found\n";
}

function sendGreeting(response, body) {
  const statusCode = body === "Hello, world!\n" ? 200 : 404;

  response.writeHead(statusCode, { "content-type": "text/plain; charset=utf-8" });
  response.end(body);
}

async function sendFile(response, name) {
  try {
    const body = await readFile(join(publicDir, name));

    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end(body);
  } catch {
    sendGreeting(response, "Not found\n");
  }
}

function requestListener(request, response) {
  const parsed = parseRequest(request.url);

  if (parsed.route === "file") return sendFile(response, parsed.name);

  sendGreeting(response, buildGreeting(parsed.route));
}

const server = createServer(requestListener);

server.listen(port, () => {
  console.log(`Hello-world fixture listening on http://localhost:${port}`);
});

status=200

=== Test 3: Path traversal to read package.json ===
{
  "name": "hello-world-codeql-fixture",
  "version": "1.0.0",
  "private": true,
  "type": "module",
  "description": "Minimal local JavaScript fixture for CodeQL analysis.",
  "scripts": {
    "start": "node index.js",
    "check": "node --check index.js"
  },
  "engines": {
    "node": ">=18"
  }
}

status=200
```

All requests successfully read files outside the `public/` directory, confirming the path traversal vulnerability.
